//! Local native-only credential handoff. Never expose this payload to JavaScript.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const PROVIDER_DLL: &str = "cindy_windows_unlock.dll";
pub const MAX_SECRET_BYTES: usize = 8192;

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct SavedCredential {
    pub user: String,
    pub domain: String,
    pub password: String,
    pub sid: String,
    pub revision: String,
}
impl SavedCredential {
    pub fn valid(&self) -> bool {
        !self.user.is_empty()
            && self.user.len() <= 512
            && self.domain.len() <= 512
            && !self.password.is_empty()
            && self.password.len() <= 2048
            && self.sid.starts_with("S-1-")
            && self.sid.len() <= 184
            && self.revision.len() == 32
            && self.revision.bytes().all(|v| v.is_ascii_hexdigit())
            && [&self.user, &self.domain, &self.password, &self.sid]
                .iter()
                .all(|v| !v.contains('\0'))
    }
}

/// Per-installation CLSID, so Dev and independent installed copies cannot replace
/// one another's registered logon component. Not a credential or authority token.
pub fn provider_id(service: &str) -> u128 {
    let hash = Sha256::digest(format!("cindy-windows-unlock-v1:{service}").as_bytes());
    u128::from_be_bytes(hash[..16].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credential_record_rejects_invalid_identity_and_embedded_nulls() {
        let mut record = SavedCredential {
            user: "test".into(),
            domain: "test".into(),
            password: "NOT-A-REAL-PASSWORD".into(),
            sid: "S-1-5-21-123".into(),
            revision: "1234567890abcdef1234567890abcdef".into(),
        };
        assert!(record.valid());
        record.password.push('\0');
        assert!(!record.valid());
        assert_ne!(provider_id("dev"), provider_id("installed"));
    }
}
