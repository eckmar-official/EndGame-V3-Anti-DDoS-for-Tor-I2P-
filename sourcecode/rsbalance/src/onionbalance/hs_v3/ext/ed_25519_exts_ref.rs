use crate::onionbalance::hs_v3::ext::slow_ed25519;

pub fn publickey_from_esk(h: &[u8]) -> [u8; 32] {
    let a = slow_ed25519::decode_int(&h[0..32]);
    let aa = slow_ed25519::scalarmult(&slow_ed25519::BB_CONST.clone(), &a);
    slow_ed25519::encode_point(&aa)
}
