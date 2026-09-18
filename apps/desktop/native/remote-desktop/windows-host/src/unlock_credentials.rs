//! Windows Credential Manager and native password prompt. JavaScript sees only
//! enabled/result booleans; neither passwords nor credential blobs cross N-API.
use crate::{installation::Installation, service_connection, unlock_protocol::*, win::*};
use napi_derive::napi;
use std::{
    mem,
    path::PathBuf,
    ptr,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Credentials::*, *},
    System::{Com::CoTaskMemFree, Threading::GetCurrentProcess},
};
use zeroize::{Zeroize, Zeroizing};

static GENERATION: AtomicU64 = AtomicU64::new(0);
fn failure(_: impl std::fmt::Debug) -> napi::Error {
    napi::Error::from_reason("DESKTOP_AUTO_UNLOCK_FAILED")
}
fn target(binary: &str, scope: &str) -> Result<String> {
    if scope.len() != 64 || !scope.bytes().all(|c| c.is_ascii_hexdigit()) {
        return denied();
    }
    Ok(format!(
        "Cindy/RemoteDesktop/{}/{}",
        Installation::for_source(&PathBuf::from(binary))?.name,
        scope
    ))
}
fn sid(handle: HANDLE) -> Result<String> {
    let mut size = 0;
    unsafe {
        GetTokenInformation(handle, TokenUser, ptr::null_mut(), 0, &mut size);
    }
    if size == 0 || size > 4096 {
        return denied();
    }
    let mut buffer =
        vec![0usize; (size as usize + mem::size_of::<usize>() - 1) / mem::size_of::<usize>()];
    if unsafe {
        GetTokenInformation(
            handle,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    } == 0
    {
        return Err(error());
    }
    let mut raw = ptr::null_mut();
    if unsafe {
        windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW(
            (*(buffer.as_ptr() as *const TOKEN_USER)).User.Sid,
            &mut raw,
        )
    } == 0
    {
        return Err(error());
    }
    let value = unsafe {
        let mut n = 0;
        while *raw.add(n) != 0 {
            n += 1;
        }
        let value = String::from_utf16_lossy(std::slice::from_raw_parts(raw, n));
        LocalFree(raw.cast());
        value
    };
    Ok(value)
}
fn own_sid() -> Result<String> {
    sid(token(unsafe { GetCurrentProcess() })?.0)
}
fn read(name: &str) -> Result<Option<SavedCredential>> {
    let mut raw: *mut CREDENTIALW = ptr::null_mut();
    if unsafe { CredReadW(wide(name).as_ptr(), CRED_TYPE_GENERIC, 0, &mut raw) } == 0 {
        return if unsafe { GetLastError() } == ERROR_NOT_FOUND {
            Ok(None)
        } else {
            Err(error())
        };
    }
    let result = unsafe {
        let value = &mut *raw;
        let result = if value.CredentialBlobSize as usize > MAX_SECRET_BYTES
            || value.CredentialBlob.is_null()
        {
            denied()
        } else {
            let bytes = std::slice::from_raw_parts_mut(
                value.CredentialBlob,
                value.CredentialBlobSize as usize,
            );
            let result = serde_json::from_slice::<SavedCredential>(bytes)
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData));
            bytes.zeroize();
            result
        };
        CredFree(raw.cast());
        result
    }?;
    if !result.valid() || result.sid != own_sid()? {
        return denied();
    }
    Ok(Some(result))
}
fn save(name: &str, value: &SavedCredential) -> Result<()> {
    let mut bytes = Zeroizing::new(serde_json::to_vec(value)?);
    if bytes.len() > CRED_MAX_CREDENTIAL_BLOB_SIZE as usize {
        return denied();
    }
    let mut target = wide(name);
    let mut user = wide(&value.user);
    let record = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: target.as_mut_ptr(),
        CredentialBlobSize: bytes.len() as u32,
        CredentialBlob: bytes.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        UserName: user.as_mut_ptr(),
        ..unsafe { mem::zeroed() }
    };
    if unsafe { CredWriteW(&record, 0) } == 0 {
        return Err(error());
    }
    Ok(())
}
fn prompt(locale: &str) -> Result<Option<SavedCredential>> {
    // The N-API blocking worker is not Electron's initialized UI thread. CredUI
    // enumerates COM credential providers, so establish and release its apartment.
    use windows_sys::Win32::System::Com::{
        CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED,
    };
    if unsafe { CoInitializeEx(ptr::null(), COINIT_APARTMENTTHREADED as u32) } < 0 {
        return denied();
    }
    struct Apartment;
    impl Drop for Apartment {
        fn drop(&mut self) {
            unsafe {
                CoUninitialize();
            }
        }
    }
    let _apartment = Apartment;
    let (caption, message) = match locale {
        "zh-CN" => ("Cindy 自动解锁", "请输入当前 Windows 账户的密码（不是 PIN）。仅加密保存在这台电脑，已授权设备连接时使用。"),
        "zh-TW" => ("Cindy 自動解鎖", "請輸入目前 Windows 帳戶的密碼（不是 PIN）。僅加密儲存在這台電腦，已授權裝置連線時使用。"),
        "ja" => ("Cindy 自動ロック解除", "現在の Windows アカウントのパスワード（PIN ではありません）を入力してください。この PC にのみ暗号化して保存し、許可したデバイスの接続時に使用します。"),
        "ko" => ("Cindy 자동 잠금 해제", "현재 Windows 계정의 암호(PIN 아님)를 입력하세요. 이 PC에만 암호화하여 저장하며 허용된 기기 연결 시 사용합니다."),
        _ => ("Cindy automatic unlock", "Enter your current Windows account password (not a PIN). It is encrypted on this PC only and used when authorized devices connect."),
    };
    let caption = wide(caption);
    let message = wide(message);
    let info = CREDUI_INFOW {
        cbSize: mem::size_of::<CREDUI_INFOW>() as u32,
        pszCaptionText: caption.as_ptr(),
        pszMessageText: message.as_ptr(),
        ..unsafe { mem::zeroed() }
    };
    let mut package = 0;
    let mut raw = ptr::null_mut();
    let mut size = 0;
    let status = unsafe {
        CredUIPromptForWindowsCredentialsW(
            &info,
            0,
            &mut package,
            ptr::null(),
            0,
            &mut raw,
            &mut size,
            ptr::null_mut(),
            CREDUIWIN_GENERIC | CREDUIWIN_ENUMERATE_CURRENT_USER,
        )
    };
    if status == ERROR_CANCELLED {
        return Ok(None);
    }
    if status != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    let mut user = Zeroizing::new(vec![0u16; 514]);
    let mut domain = Zeroizing::new(vec![0u16; 514]);
    let mut password = Zeroizing::new(vec![0u16; 1026]);
    let mut nu = user.len() as u32;
    let mut nd = domain.len() as u32;
    let mut np = password.len() as u32;
    let ok = unsafe {
        CredUnPackAuthenticationBufferW(
            0,
            raw,
            size,
            user.as_mut_ptr(),
            &mut nu,
            domain.as_mut_ptr(),
            &mut nd,
            password.as_mut_ptr(),
            &mut np,
        )
    };
    unsafe {
        std::slice::from_raw_parts_mut(raw.cast::<u8>(), size as usize).zeroize();
        CoTaskMemFree(raw);
    }
    if ok == 0 {
        return Err(error());
    }
    let mut logged = ptr::null_mut();
    if unsafe {
        LogonUserW(
            user.as_ptr(),
            if domain[0] == 0 {
                ptr::null()
            } else {
                domain.as_ptr()
            },
            password.as_ptr(),
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT,
            &mut logged,
        )
    } == 0
    {
        return Err(error());
    }
    let logged = Handle::new(logged)?;
    let user_sid = sid(logged.0)?;
    if user_sid != own_sid()? {
        return denied();
    }
    let text = |value: &[u16]| {
        String::from_utf16_lossy(
            &value[..value.iter().position(|c| *c == 0).unwrap_or(value.len())],
        )
    };
    let mut random = [0u8; 16];
    if unsafe {
        windows_sys::Win32::Security::Cryptography::BCryptGenRandom(
            ptr::null_mut(),
            random.as_mut_ptr(),
            16,
            windows_sys::Win32::Security::Cryptography::BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    } < 0
    {
        return denied();
    }
    let mut account = text(&user);
    let mut account_domain = text(&domain);
    if let Some((prefix, name)) = account.split_once('\\') {
        if !account_domain.is_empty() && !account_domain.eq_ignore_ascii_case(prefix) {
            return denied();
        }
        account_domain = prefix.to_owned();
        account = name.to_owned();
    }
    let credential = SavedCredential {
        user: account,
        domain: account_domain,
        password: text(&password),
        sid: user_sid,
        revision: random.iter().map(|v| format!("{v:02x}")).collect(),
    };
    if !credential.valid() {
        return denied();
    }
    Ok(Some(credential))
}

#[napi]
pub fn cancel_windows_unlock() {
    GENERATION.fetch_add(1, Ordering::SeqCst);
}

#[napi]
pub fn windows_unlock_enabled(binary: String, scope: String) -> napi::Result<bool> {
    read(&target(&binary, &scope).map_err(failure)?)
        .map(|v| v.is_some())
        .map_err(failure)
}

#[napi]
pub async fn configure_windows_unlock(
    binary: String,
    scope: String,
    enabled: bool,
    locale: String,
) -> napi::Result<bool> {
    cancel_windows_unlock();
    let generation = GENERATION.load(Ordering::SeqCst);
    tokio::task::spawn_blocking(move || {
        let name = target(&binary, &scope)?;
        if !enabled {
            if unsafe { CredDeleteW(wide(&name).as_ptr(), CRED_TYPE_GENERIC, 0) } == 0
                && unsafe { GetLastError() } != ERROR_NOT_FOUND
            {
                return Err(error());
            }
            return Ok(false);
        }
        let install = Installation::for_source(&PathBuf::from(binary))?;
        let mut pipe = service_connection::connect(&install.name, &install.binary(), "")?;
        pipe.write(b"{\"mode\":\"probe\"}\n")?;
        if pipe.line(1024)? != b"ready\n" {
            return denied();
        }
        drop(pipe);
        let Some(value) = prompt(&locale)? else {
            return Ok(read(&name)?.is_some());
        };
        if generation != GENERATION.load(Ordering::SeqCst) {
            return denied();
        }
        save(&name, &value)?;
        Ok(true)
    })
    .await
    .map_err(failure)?
    .map_err(failure)
}

#[napi]
pub async fn unlock_windows(binary: String, scope: String) -> napi::Result<bool> {
    let generation = GENERATION.load(Ordering::SeqCst);
    tokio::task::spawn_blocking(move || {
        let credential_target = target(&binary, &scope)?;
        let Some(value) = read(&credential_target)? else {
            return Ok(false);
        };
        let install = Installation::for_source(&PathBuf::from(binary))?;
        let mut pipe = service_connection::connect(&install.name, &install.binary(), "")?;
        pipe.write(b"{\"mode\":\"unlock\"}\n")?;
        let reply = pipe.line(1024)?;
        if reply == b"unlocked\n" {
            return Ok(true);
        }
        if reply != b"ready\n" {
            return denied();
        }
        let mut bytes = Zeroizing::new(serde_json::to_vec(&value)?);
        bytes.push(b'\n');
        if generation != GENERATION.load(Ordering::SeqCst) {
            return denied();
        }
        pipe.write(&bytes)?;
        drop(bytes);
        let revision = value.revision.clone();
        drop(value);
        let deadline = Instant::now() + Duration::from_secs(15);
        while generation == GENERATION.load(Ordering::SeqCst) && Instant::now() < deadline {
            let reply = pipe.line(1024)?;
            if generation != GENERATION.load(Ordering::SeqCst) {
                return denied();
            }
            match reply.as_slice() {
                b"unlocked\n" => return Ok(true),
                b"waiting\n" => (),
                b"failed\n" => {
                    if read(&credential_target)?.is_some_and(|current| current.revision == revision)
                    {
                        unsafe {
                            CredDeleteW(wide(&credential_target).as_ptr(), CRED_TYPE_GENERIC, 0);
                        }
                    }
                    return denied();
                }
                _ => return denied(),
            }
        }
        denied()
    })
    .await
    .map_err(failure)?
    .map_err(failure)
}
