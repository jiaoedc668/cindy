//! Additive, normally invisible Windows credential provider. Windows performs
//! authentication; this DLL only serializes one live, authorized unlock attempt.
#[path = "../../windows-host/src/capture_protocol.rs"]
mod capture_protocol;
#[path = "../../windows-host/src/pipe.rs"]
mod pipe;
#[path = "../../windows-host/src/unlock_protocol.rs"]
mod protocol;
#[path = "../../windows-host/src/service_connection.rs"]
mod service_connection;
#[path = "../../windows-host/src/win.rs"]
mod win;
use std::{
    ffi::c_void,
    mem,
    path::PathBuf,
    ptr,
    sync::{
        atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use windows::{
    core::*,
    Win32::{
        Foundation::*,
        Graphics::Gdi::HBITMAP,
        Security::{Authentication::Identity::*, Credentials::*},
        System::Com::{Marshal::*, StructuredStorage::*, *},
        UI::Shell::*,
    },
};
use zeroize::Zeroizing;
static MODULE: AtomicUsize = AtomicUsize::new(0);
static LIVE_OBJECTS: AtomicUsize = AtomicUsize::new(0);
static SERVER_LOCKS: AtomicUsize = AtomicUsize::new(0);
/// Credui also loads providers to discover supported scenarios. Let Windows
/// unload this DLL after rejecting that scenario, while keeping callbacks live.
struct Lifetime;
impl Lifetime {
    fn new() -> Self {
        LIVE_OBJECTS.fetch_add(1, Ordering::SeqCst);
        Self
    }
}
impl Drop for Lifetime {
    fn drop(&mut self) {
        LIVE_OBJECTS.fetch_sub(1, Ordering::SeqCst);
    }
}
fn rejected() -> Error {
    Error::from(E_ACCESSDENIED)
}
fn invalid() -> Error {
    Error::from(E_INVALIDARG)
}
fn unsupported<T>() -> Result<T> {
    Err(Error::from(E_NOTIMPL))
}

#[derive(Clone)]
struct Endpoint {
    name: String,
    binary: PathBuf,
}
impl Endpoint {
    fn current() -> Result<Self> {
        let mut path = vec![0u16; 32768];
        let count = unsafe {
            windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW(
                MODULE.load(Ordering::SeqCst) as _,
                path.as_mut_ptr(),
                path.len() as u32,
            )
        };
        if count == 0 || count as usize >= path.len() {
            return Err(rejected());
        }
        let file = PathBuf::from(String::from_utf16_lossy(&path[..count as usize]));
        let directory = file.parent().ok_or_else(rejected)?;
        let name = directory
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(rejected)?
            .to_owned();
        if name.len() != 35
            || !name.starts_with("CindyRemoteDesktop-")
            || !name[19..].bytes().all(|v| v.is_ascii_hexdigit())
        {
            return Err(rejected());
        }
        Ok(Self {
            name,
            binary: directory.join("cindy-windows-desktop-host.exe"),
        })
    }
    fn request(&self, op: &str, id: &str) -> Result<Zeroizing<Vec<u8>>> {
        let mut pipe = service_connection::connect(&self.name, &self.binary, "-unlock")
            .map_err(|_| rejected())?;
        let mut message =
            serde_json::to_vec(&serde_json::json!({"op":op,"id":id})).map_err(|_| invalid())?;
        message.push(b'\n');
        pipe.write(&message).map_err(|_| rejected())?;
        pipe.line(protocol::MAX_SECRET_BYTES)
            .map(Zeroizing::new)
            .map_err(|_| rejected())
    }
    fn metadata(&self) -> Option<(String, String)> {
        let bytes = self.request("poll", "").ok()?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        let id = value["id"].as_str()?;
        let sid = value["sid"].as_str()?;
        if id.len() != 32
            || !id.bytes().all(|v| v.is_ascii_hexdigit())
            || !sid.starts_with("S-1-")
            || sid.len() > 184
        {
            return None;
        }
        Some((id.into(), sid.into()))
    }
    fn clsid(&self) -> GUID {
        GUID::from_u128(protocol::provider_id(&self.name))
    }
}
fn copy_string(value: &str) -> Result<PWSTR> {
    let data: Vec<u16> = value.encode_utf16().chain(Some(0)).collect();
    let raw = unsafe { CoTaskMemAlloc(data.len() * 2) }.cast::<u16>();
    if raw.is_null() {
        return Err(Error::from(E_OUTOFMEMORY));
    }
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), raw, data.len());
    }
    Ok(PWSTR(raw))
}

#[implement(ICredentialProvider)]
struct Provider {
    _lifetime: Lifetime,
    endpoint: Endpoint,
    scenario: AtomicI32,
    metadata: Mutex<Option<(String, String)>>,
    watcher: Mutex<Option<Arc<AtomicBool>>>,
}
impl Drop for Provider {
    fn drop(&mut self) {
        if let Ok(w) = self.watcher.get_mut() {
            if let Some(stop) = w.take() {
                stop.store(true, Ordering::SeqCst);
            }
        }
    }
}
impl ICredentialProvider_Impl for Provider_Impl {
    fn SetUsageScenario(&self, usage: CREDENTIAL_PROVIDER_USAGE_SCENARIO, _: u32) -> Result<()> {
        if usage != CPUS_LOGON && usage != CPUS_UNLOCK_WORKSTATION {
            return unsupported();
        }
        self.scenario.store(usage.0, Ordering::SeqCst);
        Ok(())
    }
    fn SetSerialization(
        &self,
        _: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> Result<()> {
        unsupported()
    }
    fn Advise(&self, events: Option<&ICredentialProviderEvents>, context: usize) -> Result<()> {
        self.UnAdvise()?;
        let events = events.ok_or_else(invalid)?;
        let stream = unsafe {
            CoMarshalInterThreadInterfaceInStream(&ICredentialProviderEvents::IID, events)?
        };
        let raw = stream.into_raw() as usize;
        let lifetime = Lifetime::new();
        let endpoint = self.endpoint.clone();
        let stop = Arc::new(AtomicBool::new(false));
        *self.watcher.lock().map_err(|_| rejected())? = Some(stop.clone());
        std::thread::spawn(move || unsafe {
            let _lifetime = lifetime;
            if CoInitializeEx(None, COINIT_MULTITHREADED).is_err() {
                return;
            }
            let stream = IStream::from_raw(raw as _);
            let events: Result<ICredentialProviderEvents> = CoGetInterfaceAndReleaseStream(&stream);
            // CoGetInterfaceAndReleaseStream consumes the marshaled stream reference.
            mem::forget(stream);
            if let Ok(events) = events {
                let mut previous = None;
                while !stop.load(Ordering::SeqCst) {
                    let current = endpoint.metadata().map(|v| v.0);
                    if current != previous {
                        previous = current;
                        if !stop.load(Ordering::SeqCst) {
                            let _ = events.CredentialsChanged(context);
                        }
                    }
                    std::thread::sleep(Duration::from_millis(300));
                }
                drop(events);
            }
            CoUninitialize();
        });
        Ok(())
    }
    fn UnAdvise(&self) -> Result<()> {
        if let Some(stop) = self.watcher.lock().map_err(|_| rejected())?.take() {
            stop.store(true, Ordering::SeqCst);
        }
        Ok(())
    }
    fn GetFieldDescriptorCount(&self) -> Result<u32> {
        Ok(1)
    }
    fn GetFieldDescriptorAt(
        &self,
        index: u32,
    ) -> Result<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
        if index != 0 {
            return Err(invalid());
        }
        let label = copy_string("Cindy")?;
        let raw = unsafe { CoTaskMemAlloc(mem::size_of::<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR>()) }
            .cast::<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR>();
        if raw.is_null() {
            unsafe {
                CoTaskMemFree(Some(label.0.cast()));
            }
            return Err(Error::from(E_OUTOFMEMORY));
        }
        unsafe {
            raw.write(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR {
                dwFieldID: 0,
                cpft: CPFT_LARGE_TEXT,
                pszLabel: label,
                guidFieldType: GUID::zeroed(),
            });
        }
        Ok(raw)
    }
    fn GetCredentialCount(
        &self,
        count: *mut u32,
        default: *mut u32,
        automatic: *mut BOOL,
    ) -> Result<()> {
        if count.is_null() || default.is_null() || automatic.is_null() {
            return Err(invalid());
        }
        let metadata = self.endpoint.metadata();
        let ready = metadata.is_some();
        *self.metadata.lock().map_err(|_| rejected())? = metadata;
        unsafe {
            *count = u32::from(ready);
            *default = if ready {
                0
            } else {
                CREDENTIAL_PROVIDER_NO_DEFAULT
            };
            *automatic = BOOL::from(ready);
        }
        Ok(())
    }
    fn GetCredentialAt(&self, index: u32) -> Result<ICredentialProviderCredential> {
        if index != 0 {
            return Err(invalid());
        }
        let (id, sid) = self
            .metadata
            .lock()
            .map_err(|_| rejected())?
            .clone()
            .ok_or_else(rejected)?;
        Ok(Credential {
            _lifetime: Lifetime::new(),
            endpoint: self.endpoint.clone(),
            id,
            sid,
            scenario: self.scenario.load(Ordering::SeqCst),
            consumed: AtomicBool::new(false),
        }
        .into())
    }
}

#[implement(ICredentialProviderCredential, ICredentialProviderCredential2)]
struct Credential {
    _lifetime: Lifetime,
    endpoint: Endpoint,
    id: String,
    sid: String,
    scenario: i32,
    consumed: AtomicBool,
}
impl ICredentialProviderCredential2_Impl for Credential_Impl {
    fn GetUserSid(&self) -> Result<PWSTR> {
        copy_string(&self.sid)
    }
}
impl ICredentialProviderCredential_Impl for Credential_Impl {
    fn Advise(&self, _: Option<&ICredentialProviderCredentialEvents>) -> Result<()> {
        Ok(())
    }
    fn UnAdvise(&self) -> Result<()> {
        Ok(())
    }
    fn SetSelected(&self) -> Result<BOOL> {
        Ok(BOOL::from(!self.consumed.load(Ordering::SeqCst)))
    }
    fn SetDeselected(&self) -> Result<()> {
        Ok(())
    }
    fn GetFieldState(
        &self,
        field: u32,
        state: *mut CREDENTIAL_PROVIDER_FIELD_STATE,
        interactive: *mut CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    ) -> Result<()> {
        if field != 0 || state.is_null() || interactive.is_null() {
            return Err(invalid());
        }
        unsafe {
            *state = CPFS_DISPLAY_IN_SELECTED_TILE;
            *interactive = CPFIS_NONE;
        }
        Ok(())
    }
    fn GetStringValue(&self, field: u32) -> Result<PWSTR> {
        if field != 0 {
            return Err(invalid());
        }
        copy_string("Cindy")
    }
    fn GetBitmapValue(&self, _: u32) -> Result<HBITMAP> {
        unsupported()
    }
    fn GetCheckboxValue(&self, _: u32, _: *mut BOOL, _: *mut PWSTR) -> Result<()> {
        unsupported()
    }
    fn GetSubmitButtonValue(&self, _: u32) -> Result<u32> {
        unsupported()
    }
    fn GetComboBoxValueCount(&self, _: u32, _: *mut u32, _: *mut u32) -> Result<()> {
        unsupported()
    }
    fn GetComboBoxValueAt(&self, _: u32, _: u32) -> Result<PWSTR> {
        unsupported()
    }
    fn SetStringValue(&self, _: u32, _: &PCWSTR) -> Result<()> {
        unsupported()
    }
    fn SetCheckboxValue(&self, _: u32, _: BOOL) -> Result<()> {
        unsupported()
    }
    fn SetComboBoxSelectedValue(&self, _: u32, _: u32) -> Result<()> {
        unsupported()
    }
    fn CommandLinkClicked(&self, _: u32) -> Result<()> {
        unsupported()
    }
    fn GetSerialization(
        &self,
        response: *mut CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
        out: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        text: *mut PWSTR,
        icon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> Result<()> {
        if response.is_null() || out.is_null() || text.is_null() || icon.is_null() {
            return Err(invalid());
        }
        unsafe {
            *response = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            *out = mem::zeroed();
            *text = PWSTR::null();
            *icon = CPSI_NONE;
        }
        if self.consumed.swap(true, Ordering::SeqCst) {
            return Err(rejected());
        }
        let bytes = self.endpoint.request("take", &self.id)?;
        let secret: protocol::SavedCredential =
            serde_json::from_slice(&bytes).map_err(|_| rejected())?;
        if !secret.valid() || secret.sid != self.sid {
            return Err(rejected());
        }
        let packed = serialize(&secret, self.scenario)?;
        unsafe {
            *out = CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION {
                ulAuthenticationPackage: negotiate()?,
                clsidCredentialProvider: self.endpoint.clsid(),
                cbSerialization: packed.len() as u32,
                rgbSerialization: CoTaskMemAlloc(packed.len()).cast(),
            };
            if (*out).rgbSerialization.is_null() {
                return Err(Error::from(E_OUTOFMEMORY));
            }
            ptr::copy_nonoverlapping(packed.as_ptr(), (*out).rgbSerialization, packed.len());
            *response = CPGSR_RETURN_CREDENTIAL_FINISHED;
        }
        Ok(())
    }
    fn ReportResult(
        &self,
        status: NTSTATUS,
        _: NTSTATUS,
        text: *mut PWSTR,
        icon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> Result<()> {
        if text.is_null() || icon.is_null() {
            return Err(invalid());
        }
        unsafe {
            *text = PWSTR::null();
            *icon = CPSI_NONE;
        }
        if status.0 < 0 {
            let _ = self.endpoint.request("failed", &self.id);
        }
        Ok(())
    }
}
fn negotiate() -> Result<u32> {
    unsafe {
        let mut handle = HANDLE::default();
        if LsaConnectUntrusted(&mut handle).0 < 0 {
            return Err(rejected());
        }
        let mut name = b"Negotiate\0".to_vec();
        let name = LSA_STRING {
            Length: 9,
            MaximumLength: 10,
            Buffer: PSTR(name.as_mut_ptr()),
        };
        let mut package = 0;
        let result = LsaLookupAuthenticationPackage(handle, &name, &mut package);
        let _ = LsaDeregisterLogonProcess(handle);
        if result.0 < 0 {
            return Err(rejected());
        }
        Ok(package)
    }
}
fn serialize(secret: &protocol::SavedCredential, scenario: i32) -> Result<Zeroizing<Vec<u8>>> {
    // This is the Credential Provider contract used by Microsoft's sample:
    // LogonUI consumes a KERB_INTERACTIVE_UNLOCK_LOGON with the password in the
    // temporary serialized buffer. Credential Provider owns no durable copy;
    // every intermediate Rust buffer is zeroized, and the caller owns the final
    // CoTaskMem buffer until Windows consumes it.
    let domain: Vec<u16> = secret.domain.encode_utf16().collect();
    let user: Vec<u16> = secret.user.encode_utf16().collect();
    let password: Vec<u16> = secret.password.encode_utf16().collect();
    let total = mem::size_of::<KERB_INTERACTIVE_UNLOCK_LOGON>()
        + 2 * (domain.len() + user.len() + password.len());
    let mut bytes = Zeroizing::new(vec![0u8; total]);
    let mut logon: KERB_INTERACTIVE_UNLOCK_LOGON = unsafe { mem::zeroed() };
    logon.Logon.MessageType = if scenario == CPUS_UNLOCK_WORKSTATION.0 {
        KerbWorkstationUnlockLogon
    } else {
        KerbInteractiveLogon
    };
    let mut offset = mem::size_of::<KERB_INTERACTIVE_UNLOCK_LOGON>();
    for (text, field) in [
        (&domain[..], &mut logon.Logon.LogonDomainName),
        (&user[..], &mut logon.Logon.UserName),
        (&password[..], &mut logon.Logon.Password),
    ] {
        let length = u16::try_from(text.len() * 2).map_err(|_| invalid())?;
        field.Length = length;
        field.MaximumLength = length;
        field.Buffer = PWSTR(offset as _);
        for value in text {
            bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
            offset += 2;
        }
    }
    unsafe {
        ptr::copy_nonoverlapping(
            (&logon as *const KERB_INTERACTIVE_UNLOCK_LOGON).cast::<u8>(),
            bytes.as_mut_ptr(),
            mem::size_of_val(&logon),
        );
    }
    Ok(bytes)
}
#[implement(IClassFactory)]
struct Factory {
    _lifetime: Lifetime,
}
impl IClassFactory_Impl for Factory_Impl {
    fn CreateInstance(
        &self,
        outer: Option<&IUnknown>,
        iid: *const GUID,
        out: *mut *mut c_void,
    ) -> Result<()> {
        if out.is_null() || iid.is_null() {
            return Err(invalid());
        }
        unsafe {
            *out = ptr::null_mut();
        }
        if outer.is_some() {
            return Err(Error::from(CLASS_E_NOAGGREGATION));
        }
        let provider: ICredentialProvider = Provider {
            _lifetime: Lifetime::new(),
            endpoint: Endpoint::current()?,
            scenario: AtomicI32::new(CPUS_LOGON.0),
            metadata: Mutex::new(None),
            watcher: Mutex::new(None),
        }
        .into();
        unsafe { provider.query(iid, out).ok() }
    }
    fn LockServer(&self, lock: BOOL) -> Result<()> {
        if lock.as_bool() {
            SERVER_LOCKS.fetch_add(1, Ordering::SeqCst);
        } else {
            let _ = SERVER_LOCKS.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_sub(1)
            });
        }
        Ok(())
    }
}
#[no_mangle]
pub unsafe extern "system" fn DllMain(module: *mut c_void, reason: u32, _: *mut c_void) -> i32 {
    if reason == 1 {
        MODULE.store(module as usize, Ordering::SeqCst);
    }
    1
}
#[no_mangle]
pub unsafe extern "system" fn DllCanUnloadNow() -> HRESULT {
    if LIVE_OBJECTS.load(Ordering::SeqCst) == 0 && SERVER_LOCKS.load(Ordering::SeqCst) == 0 {
        S_OK
    } else {
        S_FALSE
    }
}
#[no_mangle]
pub unsafe extern "system" fn DllGetClassObject(
    class: *const GUID,
    iid: *const GUID,
    out: *mut *mut c_void,
) -> HRESULT {
    if class.is_null() || iid.is_null() || out.is_null() {
        return E_INVALIDARG;
    }
    *out = ptr::null_mut();
    let Ok(endpoint) = Endpoint::current() else {
        return CLASS_E_CLASSNOTAVAILABLE;
    };
    if *class != endpoint.clsid() {
        return CLASS_E_CLASSNOTAVAILABLE;
    }
    let factory: IClassFactory = Factory {
        _lifetime: Lifetime::new(),
    }
    .into();
    factory.query(iid, out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absent_authorized_attempt_does_not_add_or_select_a_login_tile() {
        assert_eq!(unsafe { DllCanUnloadNow() }, S_OK);
        let provider: ICredentialProvider = Provider {
            _lifetime: Lifetime::new(),
            endpoint: Endpoint {
                name: format!("cindy-unlock-test-{}", std::process::id()),
                binary: std::env::temp_dir().join("absent-cindy-host.exe"),
            },
            scenario: AtomicI32::new(CPUS_LOGON.0),
            metadata: Mutex::new(None),
            watcher: Mutex::new(None),
        }
        .into();
        assert_eq!(unsafe { DllCanUnloadNow() }, S_FALSE);
        unsafe {
            let mut count = 99;
            let mut default = 0;
            let mut automatic = BOOL(1);
            provider.SetUsageScenario(CPUS_LOGON, 0).unwrap();
            provider
                .GetCredentialCount(&mut count, &mut default, &mut automatic)
                .unwrap();
            assert_eq!(count, 0);
            assert_eq!(default, CREDENTIAL_PROVIDER_NO_DEFAULT);
            assert!(!automatic.as_bool());
            assert!(provider.GetCredentialAt(0).is_err());
            assert!(provider.SetUsageScenario(CPUS_CREDUI, 0).is_err());
            assert!(provider.SetUsageScenario(CPUS_CHANGE_PASSWORD, 0).is_err());
        }
        drop(provider);
        assert_eq!(unsafe { DllCanUnloadNow() }, S_OK);
    }
    #[test]
    fn serialization_uses_bounded_offsets_and_zeroizes_only_temporary_password_buffers() {
        let secret = protocol::SavedCredential {
            user: "fake-user".into(),
            domain: "fake-domain".into(),
            password: "NOT-A-REAL-PASSWORD".into(),
            sid: "S-1-5-21-123".into(),
            revision: "1234567890abcdef1234567890abcdef".into(),
        };
        for (scenario, expected) in [
            (CPUS_LOGON, KerbInteractiveLogon),
            (CPUS_UNLOCK_WORKSTATION, KerbWorkstationUnlockLogon),
        ] {
            let packed = serialize(&secret, scenario.0).unwrap();
            let header = unsafe {
                ptr::read_unaligned(packed.as_ptr().cast::<KERB_INTERACTIVE_UNLOCK_LOGON>())
            };
            assert_eq!(header.Logon.MessageType, expected);
            let fields = [
                header.Logon.LogonDomainName,
                header.Logon.UserName,
                header.Logon.Password,
            ];
            let mut offset = mem::size_of::<KERB_INTERACTIVE_UNLOCK_LOGON>();
            for field in fields {
                assert_eq!(field.Buffer.0 as usize, offset);
                assert_eq!(field.Length, field.MaximumLength);
                offset += field.Length as usize;
                assert!(offset <= packed.len());
            }
            assert_eq!(offset, packed.len());
            let clear: Vec<u8> = secret
                .password
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect();
            // LogonUI must receive the password in the documented Kerberos
            // serialization. The test uses a fake password only.
            assert!(packed.windows(clear.len()).any(|bytes| bytes == clear));
        }
    }
}
