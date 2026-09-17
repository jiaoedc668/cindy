//! UAC-approved installation identity. No password, bearer token, or PID is
//! persisted. Each new Main process is checked against protected application
//! code and the originally approved Windows user, including after service restart.
use crate::{
    installation::{self, Installation},
    security,
    win::*,
};
use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
};

pub struct Approval {
    pub application: PathBuf,
    pub user_sid: String,
    pub executable: String,
    pub service: String,
}
impl Approval {
    pub fn for_client(pid: u32) -> Result<(Self, Handle)> {
        let source = std::env::current_exe()?.canonicalize()?;
        let development = installation::development_identity();
        let application = if let Some((application, _)) = &development {
            if !installation::is_local_application_path(application) {
                return denied();
            }
            application.clone()
        } else {
            let root = installation::package_root(&source)?;
            installation::validate_application_directory(&root)?;
            root
        };
        let (client, _) = security::authorize_client(pid, &application, None)?;
        let executable = if let Some((_, executable)) = development {
            executable.to_string_lossy().into_owned()
        } else {
            image(client.0)?
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(error)?
                .to_owned()
        };
        let user_sid = security::token_user_sid(token(client.0)?.0)?;
        Ok((
            Self {
                application,
                user_sid,
                executable,
                service: Installation::for_source(&source)?.name,
            },
            client,
        ))
    }
    fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "version": if cfg!(feature = "development") { 2 } else { 1 }, "application": self.application, "userSid": self.user_sid,
            "executable": self.executable, "service": self.service,
        }))
        .expect("serializable installation identity")
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        let value: serde_json::Value = serde_json::from_slice(bytes)?;
        let object = value.as_object().ok_or_else(error)?;
        let string = |key: &str| -> Result<String> {
            object
                .get(key)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty() && !s.contains('\0'))
                .map(String::from)
                .ok_or_else(error)
        };
        if object.len() != 5
            || value["version"] != if cfg!(feature = "development") { 2 } else { 1 }
        {
            return denied();
        }
        let approval = Self {
            application: PathBuf::from(string("application")?),
            user_sid: string("userSid")?,
            executable: string("executable")?,
            service: string("service")?,
        };
        if !installation::is_local_application_path(&approval.application)
            || !approval.user_sid.starts_with("S-1-")
        {
            return denied();
        }
        if let Some((application, executable)) = installation::development_identity() {
            if approval.application != application
                || PathBuf::from(&approval.executable) != executable
            {
                return denied();
            }
        } else if !["Cindy.exe", "CindyDev.exe"]
            .iter()
            .any(|name| approval.executable.eq_ignore_ascii_case(name))
        {
            return denied();
        }
        Ok(approval)
    }
    pub fn read() -> Result<Self> {
        let installation = Installation::current()?;
        let _guards =
            security::check_paths(vec![installation.directory.join(installation::APPROVAL)])?;
        let mut bytes = Vec::new();
        fs::File::open(installation.directory.join(installation::APPROVAL))?
            .take(8193)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 8192 {
            return denied();
        }
        let approval = Self::decode(&bytes)?;
        let source = approval
            .application
            .join("resources/tools/remote-desktop")
            .join(installation::HOST);
        if approval.service != installation.name
            || installation::approval_service_name(&source) != installation.name
        {
            return denied();
        }
        // The approved app drive may not be mounted yet at boot. The protected
        // record stores its canonical identity; live code/ACL checks happen on
        // connection, so startup neither accesses shares nor depends on Main.
        Ok(approval)
    }
    pub fn authorize(&self, pid: u32) -> Result<(Handle, u32, Vec<Handle>)> {
        let guards = if installation::development_identity().is_some() {
            Vec::new()
        } else {
            security::protect_application(&self.application)?
        };
        let (client, session) =
            security::authorize_client(pid, &self.application, Some(&self.user_sid))?;
        if !security::same_file(&image(client.0)?, &self.application.join(&self.executable)) {
            return denied();
        }
        Ok((client, session, guards))
    }
}

fn read_restore_record(directory: &std::path::Path) -> Result<Option<security::AclSnapshot>> {
    let restore = directory.join(installation::ACL_RESTORE);
    if !restore.exists() {
        return Ok(None);
    }
    security::check_paths(vec![restore.clone()])?;
    let mut bytes = Vec::new();
    fs::File::open(&restore)?
        .take(1_048_577)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1_048_576 {
        return denied();
    }
    Ok(Some(security::AclSnapshot::decode(&bytes)?))
}

fn write_protected_record(directory: &std::path::Path, name: &str, bytes: &[u8]) -> Result<()> {
    let record = directory.join(name);
    let temporary = directory.join(format!("{name}.new"));
    if temporary.exists() {
        security::check_paths(vec![temporary.clone()])?;
        fs::remove_file(&temporary)?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    security::secure_code(&temporary)?;
    if record.exists() {
        security::check_paths(vec![record.clone()])?;
        fs::remove_file(&record)?;
    }
    fs::rename(&temporary, record)?;
    Ok(())
}

pub fn install(pid: u32) -> Result<()> {
    security::require_elevated()?;
    security::prepare_elevated_identity_query();
    let (approval, _client) = Approval::for_client(pid)?;
    let source = std::env::current_exe()?.canonicalize()?;
    let target = Installation::for_source(&source)?;
    // Refuse missing/broken packages, unsigned Main, and live writers before
    // changing permissions. Reinstall must not wipe the first-install restore
    // record: capture skips already-protected paths and would otherwise persist
    // an empty snapshot.
    let snapshot = if installation::development_identity().is_none() {
        let paths = security::application_paths(&approval.application)?;
        let _ancestors = security::pin_ancestors(&approval.application)?;
        security::authenticate_application_code(&approval.application, &approval.executable)?;
        Some(security::AclSnapshot::capture(&paths)?)
    } else {
        None
    };
    let mut restore = snapshot
        .as_ref()
        .filter(|snapshot| !snapshot.paths.is_empty())
        .cloned()
        .map(security::AclRestoreGuard::new);
    let _application = if let Some(snapshot) = &snapshot {
        for (path, _) in &snapshot.paths {
            security::secure_code(path)?;
        }
        security::protect_application(&approval.application)?
    } else {
        Vec::new()
    };
    let base = installation::program_files()?.join("CindyRemoteDesktop");
    security::create_protected_directory(&base)?;
    security::create_protected_directory(&target.directory)?;
    let _target = security::pin_ancestors(&target.directory)?;
    // This removes/replaces the legacy SCM registration under the same name.
    // Stop must finish before any privileged binary is replaced.
    crate::service::uninstall()?;
    for name in [installation::HOST, installation::INPUT] {
        let destination = target.directory.join(name);
        if destination.exists() {
            security::check_paths(vec![destination.clone()])?;
        }
        security::copy_protected_payload(&source.with_file_name(name), &destination)?;
        security::secure_code(&destination)?;
    }
    if let Some(captured) = snapshot {
        let existing = read_restore_record(&target.directory)?;
        if !(existing.is_some() && captured.paths.is_empty()) {
            if let Some(combined) = security::AclSnapshot::combined(existing, captured) {
                write_protected_record(
                    &target.directory,
                    installation::ACL_RESTORE,
                    &combined.encode(),
                )?;
            }
        }
    }
    write_protected_record(
        &target.directory,
        installation::APPROVAL,
        &approval.encode(),
    )?;
    crate::service::install()?;
    if let Some(restore) = restore.as_mut() {
        restore.commit();
    }
    Ok(())
}

pub fn remove() -> Result<()> {
    let installation = Installation::current()?;
    crate::service::uninstall()?;
    if !installation.directory.exists() {
        return Ok(());
    }
    security::require_elevated()?;
    let ancestors = security::pin_ancestors(&installation.directory)?;
    security::check_paths(vec![installation.directory.clone()])?;
    let application = Approval::read().ok().map(|approval| approval.application);
    let snapshot = read_restore_record(&installation.directory)?;
    if let Some(snapshot) = &snapshot {
        for (path, descriptor) in &snapshot.paths {
            let allowed = match &application {
                Some(root) => security::path_is_within(path, root),
                None => installation::is_local_application_path(path),
            };
            if allowed && path.exists() {
                security::restore_descriptor(path, descriptor)?;
            }
        }
    }
    for name in [
        installation::APPROVAL,
        "authorization.new",
        "authorization.json.new",
        installation::ACL_RESTORE,
        "acl-restore.json.new",
        installation::INPUT,
        installation::HOST,
    ] {
        let path = installation.directory.join(name);
        if path.exists() {
            security::check_paths(vec![path.clone()])?;
            fs::remove_file(path)?;
        }
    }
    drop(ancestors);
    fs::remove_dir(&installation.directory)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[cfg(feature = "development")]
    fn development_approval_is_bound_to_the_compiled_checkout_and_runtime() {
        let (application, executable) = installation::development_identity().unwrap();
        let approval = Approval {
            application: application.clone(),
            executable: executable.to_string_lossy().into_owned(),
            user_sid: "S-1-5-21-100-200-300-1001".into(),
            service: installation::approval_service_name(&application),
        };
        assert!(Approval::decode(&approval.encode()).is_ok());
        let mut value: serde_json::Value = serde_json::from_slice(&approval.encode()).unwrap();
        value["version"] = 1.into();
        assert!(Approval::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        value["version"] = 2.into();
        value["application"] = "D:\\different-checkout".into();
        assert!(Approval::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        value["application"] = application.to_string_lossy().as_ref().into();
        value["executable"] = "D:\\other-electron.exe".into();
        assert!(Approval::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        assert_eq!(
            installation::approval_service_name(&application.join("cache-one")),
            installation::approval_service_name(&application.join("cache-two"))
        );
    }
    #[test]
    #[cfg(not(feature = "development"))]
    fn restart_identity_is_user_and_installation_not_a_process_id() {
        let approval = Approval {
            application: PathBuf::from(r"D:\Custom Apps\Cindy"),
            user_sid: "S-1-5-21-100-200-300-1001".into(),
            executable: "Cindy.exe".into(),
            service: "CindyRemoteDesktop-0123456789abcdef".into(),
        };
        let restored = Approval::decode(&approval.encode()).unwrap();
        assert_eq!(restored.application, approval.application);
        assert_eq!(restored.user_sid, approval.user_sid);
        assert_eq!(restored.executable, approval.executable);
        let mut value: serde_json::Value = serde_json::from_slice(&approval.encode()).unwrap();
        value["pid"] = 123.into();
        assert!(Approval::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        value.as_object_mut().unwrap().remove("pid");
        value["executable"] = "../Cindy.exe".into();
        assert!(Approval::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        value["executable"] = "Cindy.exe".into();
        value["version"] = 99.into();
        assert!(Approval::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        value["version"] = 1.into();
        value["application"] = r"\\server\share\Cindy".into();
        assert!(Approval::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}
