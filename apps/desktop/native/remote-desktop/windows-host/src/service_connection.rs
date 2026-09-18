//! Authenticate the local broker before sending any operation or credential.
use crate::{pipe::Pipe, win::*};
use std::{path::Path, ptr};
use windows_sys::Win32::System::Services::*;

pub fn connect(name: &str, expected: &Path, suffix: &str) -> Result<Pipe> {
    let pipe = Pipe::client(&format!(r"\\.\pipe\{name}{suffix}"))?;
    let id = pipe.server_pid()?;
    let process = process(id)?;
    if !system(token(process.0)?.0)?
        || image(process.0)?
            .canonicalize()?
            .to_string_lossy()
            .to_lowercase()
            != expected.canonicalize()?.to_string_lossy().to_lowercase()
    {
        return denied();
    }
    unsafe {
        let manager = OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT);
        if manager.is_null() {
            return Err(error());
        }
        let service = OpenServiceW(manager, wide(name).as_ptr(), SERVICE_QUERY_STATUS);
        CloseServiceHandle(manager);
        if service.is_null() {
            return Err(error());
        }
        let mut status: SERVICE_STATUS_PROCESS = std::mem::zeroed();
        let mut needed = 0;
        let ok = QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            std::mem::size_of_val(&status) as u32,
            &mut needed,
        );
        CloseServiceHandle(service);
        if ok == 0 || status.dwCurrentState != SERVICE_RUNNING || status.dwProcessId != id {
            return denied();
        }
    }
    Ok(pipe)
}
