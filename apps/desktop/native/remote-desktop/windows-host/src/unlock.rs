//! One-shot credential handoff to LogonUI, bound to the live Main connection.
use crate::{pipe::Pipe, security, unlock_protocol::*, win::*};
use std::{
    mem, ptr,
    sync::Mutex,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    System::{Registry::*, RemoteDesktop::*, Threading::*},
};
use zeroize::Zeroizing;

struct Pending {
    id: String,
    session: u32,
    sid: String,
    secret: Option<SavedCredential>,
    until: Instant,
    failed: bool,
    owner: Handle,
    connection: Handle,
}
impl Pending {
    fn take(&mut self, session: u32, id: &str) -> Option<SavedCredential> {
        if !self.live(session) || self.id != id {
            return None;
        }
        self.secret.take()
    }
    fn live(&self, session: u32) -> bool {
        self.session == session
            && Instant::now() < self.until
            && !self.failed
            && unsafe { WaitForSingleObject(self.owner.0, 0) } == WAIT_TIMEOUT
            && unsafe {
                windows_sys::Win32::System::Pipes::PeekNamedPipe(
                    self.connection.0,
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            } != 0
    }
}
static PENDING: Mutex<Option<Pending>> = Mutex::new(None);
static BLOCKED: Mutex<Option<String>> = Mutex::new(None);

pub fn locked(session: u32) -> Result<bool> {
    let mut raw = ptr::null_mut();
    let mut bytes = 0;
    if unsafe {
        WTSQuerySessionInformationW(
            ptr::null_mut(),
            session,
            WTSSessionInfoEx,
            &mut raw,
            &mut bytes,
        )
    } == 0
    {
        return Err(error());
    }
    let result = unsafe {
        if bytes < mem::size_of::<WTSINFOEXW>() as u32 {
            denied()
        } else {
            let info = &*(raw as *const WTSINFOEXW);
            if info.Level != 1
                || info.Data.WTSInfoExLevel1.SessionId != session
                || info.Data.WTSInfoExLevel1.SessionState != WTSActive
            {
                denied()
            } else {
                match info.Data.WTSInfoExLevel1.SessionFlags {
                    0 => Ok(true),
                    1 => Ok(false),
                    _ => denied(),
                }
            }
        }
    };
    unsafe {
        WTSFreeMemory(raw.cast());
    }
    result
}
struct AttemptGuard(String);
impl Drop for AttemptGuard {
    fn drop(&mut self) {
        if let Ok(mut pending) = PENDING.lock() {
            if pending.as_ref().is_some_and(|p| p.id == self.0) {
                *pending = None;
            }
        }
    }
}
pub fn request(mut pipe: Pipe, owner: Handle, session: u32) -> Result<()> {
    if !locked(session)? {
        return pipe.write(b"unlocked\n");
    }
    pipe.write(b"ready\n")?;
    let bytes = Zeroizing::new(pipe.line(MAX_SECRET_BYTES)?);
    let secret: SavedCredential = serde_json::from_slice(&bytes)?;
    if !secret.valid()
        || secret.sid != security::token_user_sid(token(owner.0)?.0)?
        || !locked(session)?
    {
        return denied();
    }
    if BLOCKED.lock().map_err(|_| error())?.as_deref() == Some(secret.revision.as_str()) {
        return denied();
    }
    let id = {
        let mut guid = unsafe { mem::zeroed() };
        if unsafe { windows_sys::Win32::System::Com::CoCreateGuid(&mut guid) } < 0 {
            return denied();
        }
        format!(
            "{:08x}{:04x}{:04x}{}",
            guid.data1,
            guid.data2,
            guid.data3,
            guid.data4
                .iter()
                .map(|v| format!("{v:02x}"))
                .collect::<String>()
        )
    };
    let revision = secret.revision.clone();
    {
        let mut pending = PENDING.lock().map_err(|_| error())?;
        if pending.as_ref().is_some_and(|p| Instant::now() < p.until) {
            return denied();
        }
        *pending = Some(Pending {
            id: id.clone(),
            session,
            sid: secret.sid.clone(),
            secret: Some(secret),
            until: Instant::now() + Duration::from_secs(12),
            failed: false,
            owner: duplicate(owner.0)?,
            connection: pipe.connection_guard()?,
        });
    }
    let _guard = AttemptGuard(id.clone());
    loop {
        if unsafe { WaitForSingleObject(owner.0, 0) } != WAIT_TIMEOUT
            || session != unsafe { WTSGetActiveConsoleSessionId() }
            || !pipe.connected()
        {
            return denied();
        }
        if !locked(session)? {
            return pipe.write(b"unlocked\n");
        }
        let failed = {
            let pending = PENDING.lock().map_err(|_| error())?;
            let Some(pending) = pending.as_ref() else {
                return denied();
            };
            pending.id != id || pending.failed || Instant::now() >= pending.until
        };
        if failed {
            *BLOCKED.lock().map_err(|_| error())? = Some(revision);
            return pipe.write(b"failed\n");
        }
        pipe.write(b"waiting\n")?;
        std::thread::sleep(Duration::from_millis(200));
    }
}
fn serve_provider(mut pipe: Pipe) -> Result<()> {
    let process = process(pipe.client_pid()?)?;
    let token = token(process.0)?;
    let session = session(token.0)?;
    let mut system_directory = [0u16; 32768];
    let size = unsafe {
        windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
            system_directory.as_mut_ptr(),
            system_directory.len() as u32,
        )
    };
    if size == 0 || size as usize >= system_directory.len() {
        return denied();
    }
    let expected =
        std::path::PathBuf::from(String::from_utf16_lossy(&system_directory[..size as usize]))
            .join("LogonUI.exe");
    if !system(token.0)?
        || session != unsafe { WTSGetActiveConsoleSessionId() }
        || !security::same_file(&image(process.0)?, &expected)
        || !locked(session)?
    {
        return denied();
    }
    let line = pipe.line(1024)?;
    let command: serde_json::Value = serde_json::from_slice(&line)?;
    let mut pending = PENDING.lock().map_err(|_| error())?;
    let Some(pending) = pending.as_mut().filter(|p| p.live(session)) else {
        return pipe.write(b"null\n");
    };
    match command["op"].as_str() {
        // Keep this tile stable while Windows authenticates the already-taken
        // credential. Removing it here can cancel an in-flight system logon.
        // `take` remains one-shot even though metadata stays visible.
        Some("poll") => {
            let mut metadata =
                serde_json::to_vec(&serde_json::json!({"id":pending.id, "sid":pending.sid}))?;
            metadata.push(b'\n');
            pipe.write(&metadata)
        }
        Some("take") if command["id"].as_str() == Some(pending.id.as_str()) => {
            let Some(secret) = pending.take(session, command["id"].as_str().unwrap_or("")) else {
                return pipe.write(b"null\n");
            };
            let mut bytes = Zeroizing::new(serde_json::to_vec(&secret)?);
            bytes.push(b'\n');
            pipe.write(&bytes)
        }
        Some("failed") if command["id"].as_str() == Some(pending.id.as_str()) => {
            pending.failed = true;
            pending.secret.take();
            pipe.write(b"null\n")
        }
        _ => pipe.write(b"null\n"),
    }
}
pub fn start_provider_channel(stop: &'static std::sync::atomic::AtomicBool) {
    std::thread::spawn(move || {
        while !stop.load(std::sync::atomic::Ordering::SeqCst) {
            let Ok(name) = crate::pipe_name() else {
                break;
            };
            let Ok(mut pipe) = Pipe::server(&format!("{name}-unlock"), true) else {
                std::thread::sleep(Duration::from_millis(500));
                continue;
            };
            pipe.shutdown = Some(stop);
            if pipe.accept(500).is_ok() {
                let _ = serve_provider(pipe);
            }
        }
        if let Ok(mut pending) = PENDING.lock() {
            *pending = None;
        }
    });
}
fn registry_string(path: &str, name: &str, value: &str) -> Result<()> {
    let mut key = ptr::null_mut();
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            wide(path).as_ptr(),
            0,
            ptr::null(),
            0,
            KEY_SET_VALUE | KEY_WOW64_64KEY,
            ptr::null(),
            &mut key,
            ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    let bytes = wide(value);
    let status = unsafe {
        RegSetValueExW(
            key,
            wide(name).as_ptr(),
            0,
            REG_SZ,
            bytes.as_ptr().cast(),
            (bytes.len() * 2) as u32,
        )
    };
    unsafe {
        RegCloseKey(key);
    }
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}
fn registry_paths(installation: &crate::installation::Installation) -> [String; 2] {
    let id = provider_id(&installation.name);
    let guid = format!(
        "{{{:08x}-{:04x}-{:04x}-{:04x}-{:012x}}}",
        id >> 96,
        (id >> 80) & 0xffff,
        (id >> 64) & 0xffff,
        (id >> 48) & 0xffff,
        id & 0xffffffffffff
    );
    [
        format!(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{guid}"
        ),
        format!(r"SOFTWARE\Classes\CLSID\{guid}"),
    ]
}
pub fn register(installation: &crate::installation::Installation) -> Result<()> {
    security::require_elevated()?;
    let paths = registry_paths(installation);
    let class = format!(r"{}\InprocServer32", paths[1]);
    registry_string(
        &class,
        "",
        &installation.directory.join(PROVIDER_DLL).to_string_lossy(),
    )?;
    registry_string(&class, "ThreadingModel", "Apartment")?;
    registry_string(&paths[0], "", "Cindy remote unlock")
}
pub fn unregister(installation: &crate::installation::Installation) -> Result<()> {
    security::require_elevated()?;
    for path in registry_paths(installation) {
        let status = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, wide(&path).as_ptr()) };
        if status != 0 && status != ERROR_FILE_NOT_FOUND {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unlock_ticket_is_single_use_session_bound_and_cancelled_with_its_connection() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!(
            r"\\.\pipe\cindy-unlock-ticket-{}-{nonce}",
            std::process::id()
        );
        let server = Pipe::server(&name, false).unwrap();
        let client = Pipe::client(&name).unwrap();
        server.accept(1000).unwrap();
        let secret = SavedCredential {
            user: "fake-user".into(),
            domain: "fake-domain".into(),
            password: "NOT-A-REAL-PASSWORD".into(),
            sid: "S-1-5-21-123".into(),
            revision: "1234567890abcdef1234567890abcdef".into(),
        };
        let mut pending = Pending {
            id: "test-ticket".into(),
            session: 42,
            sid: secret.sid.clone(),
            secret: Some(secret),
            until: Instant::now() + Duration::from_secs(5),
            failed: false,
            owner: process(std::process::id()).unwrap(),
            connection: server.connection_guard().unwrap(),
        };
        assert!(pending.live(42));
        assert!(pending.take(43, "test-ticket").is_none());
        assert!(pending.take(42, "another-ticket").is_none());
        assert!(pending.take(42, "test-ticket").is_some());
        assert!(pending.take(42, "test-ticket").is_none());
        pending.failed = true;
        assert!(!pending.live(42));
        pending.failed = false;
        pending.until = Instant::now() - Duration::from_secs(1);
        assert!(!pending.live(42));
        pending.until = Instant::now() + Duration::from_secs(5);
        drop(client);
        assert!(!pending.live(42));
    }
}
