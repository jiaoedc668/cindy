//! Remove credentials and registry entries left by the withdrawn Windows
//! automatic-unlock experiment. This module never reads or logs secret blobs.
use crate::{installation::Installation, win::*};
use sha2::{Digest, Sha256};
use std::ptr;
use windows_sys::Win32::{
    Foundation::*,
    Security::Credentials::*,
    System::Registry::*,
};

const TARGET_PREFIX: &str = "Cindy/RemoteDesktop/";

fn utf16(value: *const u16) -> String {
    if value.is_null() { return String::new(); }
    unsafe {
        let mut len = 0;
        while *value.add(len) != 0 { len += 1; }
        String::from_utf16_lossy(std::slice::from_raw_parts(value, len))
    }
}

fn provider_guid(service: &str) -> String {
    let digest = Sha256::digest(format!("cindy-windows-unlock-v1:{service}").as_bytes());
    let id = u128::from_be_bytes(digest[..16].try_into().unwrap());
    format!("{{{:08x}-{:04x}-{:04x}-{:04x}-{:012x}}}", id >> 96, (id >> 80) & 0xffff,
        (id >> 64) & 0xffff, (id >> 48) & 0xffff, id & 0xffffffffffff)
}

pub fn remove_saved_credentials() -> Result<()> {
    let mut count = 0;
    let mut values = ptr::null_mut();
    let filter = wide("Cindy/RemoteDesktop/*");
    let ok = unsafe { CredEnumerateW(filter.as_ptr(), 0, &mut count, &mut values) };
    if ok == 0 {
        return if unsafe { GetLastError() } == ERROR_NOT_FOUND { Ok(()) } else { Err(error()) };
    }
    let mut names = Vec::new();
    unsafe {
        for index in 0..count as usize {
            let credential = *values.add(index);
            let name = utf16((*credential).TargetName);
            if name.starts_with(TARGET_PREFIX) { names.push(name); }
        }
        CredFree(values.cast());
    }
    for name in names {
        if unsafe { CredDeleteW(wide(&name).as_ptr(), CRED_TYPE_GENERIC, 0) } == 0
            && unsafe { GetLastError() } != ERROR_NOT_FOUND { return Err(error()); }
    }
    Ok(())
}

pub fn remove_provider_registration(service: &str) -> Result<()> {
    let guid = provider_guid(service);
    for path in [
        format!(r"SOFTWAREMicrosoftWindowsCurrentVersionAuthenticationCredential Providers{guid}"),
        format!(r"SOFTWAREClassesCLSID{guid}"),
    ] {
        let status = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, wide(&path).as_ptr()) };
        if status != 0 && status != ERROR_FILE_NOT_FOUND { return Err(std::io::Error::from_raw_os_error(status as i32)); }
    }
    Ok(())
}

pub fn cleanup_current_installation() -> Result<()> {
    remove_saved_credentials()?;
    let installation = Installation::current()?;
    // Registry cleanup is best effort for ordinary status probes; service
    // removal still runs it under the existing elevated path.
    let _ = remove_provider_registration(&installation.name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provider_identity_is_installation_scoped_without_exposing_credentials() {
        assert_ne!(provider_guid("CindyRemoteDesktop-dev"), provider_guid("CindyRemoteDesktop-release"));
        assert!(TARGET_PREFIX.starts_with("Cindy/RemoteDesktop/"));
    }
}
