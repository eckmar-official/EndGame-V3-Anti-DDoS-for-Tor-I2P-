// rsbpk == rsbalance private key

use ed25519_dalek::VerifyingKey;
use crate::onionbalance::hs_v3::ext::ed_25519_exts_ref::publickey_from_esk;

// PrivateKey wrapper around ed25519 private key to handle both tor format or normal
#[derive(Clone)]
pub struct PrivateKey {
    pub is_priv_key_in_tor_format: bool,
    pub private_key: [u8; 32],
}

impl PrivateKey {
    pub fn new(esk: &[u8; 64], is_priv_key_in_tor_format: bool) -> Self {
        Self {
            is_priv_key_in_tor_format,
            private_key: ed25519_dalek::hazmat::ExpandedSecretKey::from_bytes(esk).scalar.to_bytes(),
        }
    }

    pub fn public(&self) -> anyhow::Result<VerifyingKey> {
        if self.is_priv_key_in_tor_format {
            let tmp = publickey_from_esk(&self.private_key);
            return Ok(VerifyingKey::from_bytes(&tmp)?);
        }
        Ok(VerifyingKey::from_bytes(&self.private_key)?)
    }
}
