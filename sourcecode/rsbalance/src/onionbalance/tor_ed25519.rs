use anyhow::{bail, ensure};

// LoadTorKeyFromDisk load a private identity key from little-t-tor.
pub fn load_tor_key_from_disk(key_bytes: &[u8]) -> anyhow::Result<[u8; 64]> {
    if !key_bytes.starts_with("== ed25519v1-secret: type0 ==".as_bytes()) {
        bail!("Tor key does not start with Tor header");
    }

    let expended_sk = &key_bytes[32..];

    // The rest should be 64 bytes (a,h):
    // 32 bytes for secret scalar 'a'
    // 32 bytes for PRF key 'h'

    ensure!(expended_sk.len() == 64, "Tor private key has the wrong length");

    Ok(expended_sk.try_into()?)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::VerifyingKey;
    use crate::onionbalance::hs_v3::ext::ed_25519_exts_ref;
    use crate::onionbalance::tor_ed25519::load_tor_key_from_disk;
    use crate::stem::descriptor::hidden_service::address_from_identity_key;

    #[test]
    fn test_load_key_from_disk() {
        let b = [
            0x3d, 0x3d, 0x20, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x76, 0x31, 0x2d, 0x73, 0x65, 0x63,
            0x72, 0x65, 0x74, 0x3a, 0x20, 0x74, 0x79, 0x70, 0x65, 0x30, 0x20, 0x3d, 0x3d, 0x00, 0x00, 0x00,
            0xf0, 0xf6, 0xf7, 0x6f, 0x47, 0x88, 0xcb, 0x8a, 0xb4, 0x02, 0x70, 0x37, 0x12, 0xba, 0x7c, 0xfa,
            0xad, 0xd5, 0xbf, 0xe0, 0xd9, 0x84, 0xee, 0xcf, 0xc9, 0x75, 0x55, 0x47, 0x9d, 0xc2, 0xc6, 0x6d,
            0x56, 0x56, 0x15, 0xb1, 0x42, 0xaf, 0x3b, 0xf6, 0x8b, 0x2e, 0xc9, 0x6f, 0x04, 0x18, 0x26, 0x99,
            0xac, 0xe3, 0xde, 0xed, 0x31, 0x9e, 0x49, 0x67, 0x7e, 0xfa, 0x9c, 0xd0, 0xd8, 0x0a, 0xd4, 0x29];
        let esk = load_tor_key_from_disk(&b).unwrap();
        let tmp = ed_25519_exts_ref::publickey_from_esk(&esk);
        let eid = VerifyingKey::from_bytes(&tmp).unwrap();
        let onion_address = address_from_identity_key(&eid);
        let expected = "gigtv62fezzvziinq4iuwifxvjymetmla2yoxf36j7h44zec6znxhbyd.onion";
        assert_eq!(expected, onion_address);
    }
}
