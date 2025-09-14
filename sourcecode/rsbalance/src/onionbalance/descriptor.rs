use std::fmt::{Display, Formatter};
use anyhow::bail;
use crate::onionbalance::consensus::Consensus;
use crate::onionbalance::param;
use crate::onionbalance::param::INSTANCE_DESCRIPTOR_TOO_OLD;
use crate::rsbpk;
use crate::stem::descriptor::certificate::Ed25519CertificateV1;
use crate::stem::descriptor::hidden_service::{
    hidden_service_descriptor_v3_create, inner_layer_create, HiddenServiceDescriptorV3, IntroductionPointV3,
};
use chrono::{DateTime, Utc};
use cipher::generic_array::GenericArray;
use cipher::KeyIvInit;
use cipher::StreamCipher;
use rand::seq::SliceRandom;
use rand::thread_rng;
use rand::rngs::OsRng;
use sha3::Digest;
use sha3::Sha3_256;
use tor_llcrypto::cipher::aes::Aes256Ctr;
use ed25519_dalek::{SigningKey, VerifyingKey};
use crate::utils::fmt_first;

pub struct IntroductionPointSet {}

#[derive(Clone, Debug)]
pub struct IntroductionPointSetV3 {
    pub intro_points: Vec<Vec<IntroductionPointV3>>,
}

impl IntroductionPointSetV3 {
    pub fn new(intro_points: Vec<Vec<IntroductionPointV3>>) -> Self {
        Self { intro_points }
    }

    pub fn equals(&self, other: &IntroductionPointSetV3) -> bool {
        let mut a_intro_points = self.get_intro_points_flat();
        let mut b_intro_points = other.get_intro_points_flat();
        if a_intro_points.len() != b_intro_points.len() {
            return false;
        }
        a_intro_points.sort_by(|a, b| a.onion_key.cmp(&b.onion_key));
        b_intro_points.sort_by(|a, b| a.onion_key.cmp(&b.onion_key));
        a_intro_points
            .iter()
            .zip(b_intro_points.iter())
            .all(|(a, b)| a.equals(b))
    }

    // Flatten the .intro_points list of list into a single list and return it
    pub fn get_intro_points_flat(&self) -> Vec<IntroductionPointV3> {
        self.intro_points.iter().cloned().flatten().collect()
    }

    // Retrieve N introduction points from the set of IPs
    // Where more than `count` IPs are available, introduction points are
    // selected to try and achieve the greatest distribution of introduction
    // points across all of the available backend instances.
    // Return a list of IntroductionPoints.
    pub fn choose(&self, count: usize) -> Vec<IntroductionPointV3> {
        let mut chosen_ips = self.get_intro_points_flat();
        chosen_ips.shuffle(&mut thread_rng());
        chosen_ips.truncate(count);
        chosen_ips
    }

    pub fn len(&self) -> usize {
        self.intro_points.iter().map(|ip| ip.len()).sum()
    }
}

#[derive(Debug, PartialEq)]
pub enum DescriptorErr {
    ErrBadDescriptor,
}

impl Display for DescriptorErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

pub struct OBDescriptor {
    pub base: V3Descriptor,
    pub last_upload_ts: Option<DateTime<Utc>>,
    pub last_publish_attempt_ts: Option<DateTime<Utc>>,
    pub responsible_hsdirs: Option<Vec<String>>,
    pub consensus: Consensus,
    pub intro_set: IntroductionPointSetV3,
}

impl OBDescriptor {
    pub fn new(
        onion_address: &str,
        identity_priv_key: &rsbpk::PrivateKey,
        blinding_param: &[u8; 32],
        intro_points: Vec<IntroductionPointV3>,
        is_first_desc: bool,
        consensus: &Consensus,
    ) -> anyhow::Result<Self> {
        // Start generating descriptor
        let mut csprng = OsRng;
        let desc_signing_key = SigningKey::generate(&mut csprng);

        // Get the intro points for this descriptor and recertify them!
        let mut recertified_intro_points: Vec<IntroductionPointV3> = Vec::new();
        for ip in &intro_points {
            let rec = recertify_intro_point(ip, &desc_signing_key)?;
            recertified_intro_points.push(rec);
        }

        let rev_counter = get_revision_counter(consensus, identity_priv_key, is_first_desc);
        let v3_desc_inner_layer = inner_layer_create(Some(recertified_intro_points));
        let mut v3_desc = hidden_service_descriptor_v3_create(
            blinding_param,
            identity_priv_key,
            desc_signing_key,
            &v3_desc_inner_layer,
            rev_counter,
        )?;
        let intro_points = v3_desc_inner_layer.introduction_points.clone();

        // TODO stem should probably initialize it itself so that it has balance
        // between descriptor creation (where this is not inted) and descriptor
        // parsing (where this is inited)
        v3_desc.inner_layer = v3_desc_inner_layer;

        // Check max size is within range
        if v3_desc.string().len() > param::MAX_DESCRIPTOR_SIZE {
            bail!("Created descriptor is too big ({} intros). Consider relaxing number of instances or intro points per instance (see N_INTROS_PER_INSTANCE)", v3_desc.string().len());
        }

        let desc = Self {
            base: V3Descriptor {
                onion_address: onion_address.to_owned(),
                v3_desc,
                intro_set: IntroductionPointSetV3::new(Vec::new()),
            },
            consensus: consensus.clone(),
            // Timestamp of the last attempt to assemble this descriptor
            last_publish_attempt_ts: None,
            // Timestamp we last uploaded this descriptor
            last_upload_ts: None,
            // Set of responsible HSDirs for last time we uploaded this descriptor
            responsible_hsdirs: None,
            // Start generating descriptor
            intro_set: IntroductionPointSetV3::new(vec![intro_points]),
        };

        Ok(desc)
    }

    pub fn set_last_publish_attempt_ts(&mut self, last_publish_attempt_ts: DateTime<Utc>) {
        self.last_publish_attempt_ts = Some(last_publish_attempt_ts);
    }

    pub fn set_last_upload_ts(&mut self, last_upload_ts: DateTime<Utc>) {
        self.last_upload_ts = Some(last_upload_ts);
    }

    pub fn set_responsible_hsdirs(&mut self, responsible_hsdirs: Vec<String>) {
        self.responsible_hsdirs = Some(responsible_hsdirs);
    }
}

fn get_revision_counter(consensus: &Consensus, identity_priv_key: &rsbpk::PrivateKey, is_first_desc: bool) -> i64 {
    let now = Utc::now().timestamp();

    // TODO: Mention that this is done with the private key instead of the blinded priv key
    // this means that this won't cooperate with normal tor
    let privkey_bytes = &identity_priv_key.private_key;

    let srv_start: u64 = match is_first_desc {
        true  => consensus.get_start_time_of_previous_srv_run(),
        false => consensus.get_start_time_of_current_srv_run(),
    };

    let (ope_result, seconds_since_srv_start) = get_revision_counter_det(privkey_bytes, now, srv_start);
    debug!("Rev counter for {} descriptor (SRV secs {seconds_since_srv_start}, OPE {ope_result})", fmt_first(is_first_desc));
    ope_result
}

// Recertify an HSv3 intro point certificate using the new descriptor signing
// key so that it can be accepted as part of a new descriptor.
// "Recertifying" means taking the certified key and signing it with a new
// key.
// Return the new certificate.
fn recertify_intro_point(intro_point: &IntroductionPointV3, descriptor_signing_key: &SigningKey) -> anyhow::Result<IntroductionPointV3> {
    let mut intro_point = intro_point.clone();
    let original_auth_key_cert = intro_point.auth_key_cert;
    let original_enc_key_cert = intro_point.enc_key_cert;

    // We have already removed all the intros with legacy keys. Make sure that
    // no legacy intros sneaks up on us, because they would result in
    // unparseable descriptors if we don't recertify them (and we won't).
    // assert(not intro_point.legacy_key_cert)

    // Get all the certs we need to recertify
    // [we need to use the _replace method of named tuples because there is no
    // setter for those attributes due to the way stem sets those fields. If we
    // attempt to normally replace the attributes we get the following
    // exception: AttributeError: can't set attribute]
    intro_point.auth_key_cert = recertify_ed_certificate(original_auth_key_cert, descriptor_signing_key)?;
    intro_point.enc_key_cert = recertify_ed_certificate(original_enc_key_cert, descriptor_signing_key)?;
    intro_point.auth_key_cert_raw = intro_point.auth_key_cert.to_base64();
    intro_point.enc_key_cert_raw = intro_point.enc_key_cert.to_base64();
    let recertified_intro_point = intro_point;

    Ok(recertified_intro_point)
}

fn get_revision_counter_det(privkey_bytes: &[u8; 32], now: i64, srv_start: u64) -> (i64, i64) {
    let mut hasher = Sha3_256::new();
    hasher.update(b"rev-counter-generation");
    hasher.update(&privkey_bytes);
    let cipher_key: [u8; 32] = hasher.finalize().into();

    let mut seconds_since_srv_start = now - srv_start as i64;
    // This must be strictly positive
    seconds_since_srv_start += 1;

    let iv = GenericArray::from([0u8; 16]);
    let key = GenericArray::from_slice(cipher_key.as_slice());
    let mut cipher = Aes256Ctr::new(&key, &iv);

    let mut ope_result = 0i64;
    for _ in 0..seconds_since_srv_start {
        let mut data = GenericArray::from([0u8; 2]);
        cipher.apply_keystream(&mut data);
        ope_result += (data[0] as i64) + 256 * (data[1] as i64) + 1
    }

    (ope_result, seconds_since_srv_start)
}

fn recertify_ed_certificate(ed_cert: Ed25519CertificateV1, descriptor_signing_key: &SigningKey) -> anyhow::Result<Ed25519CertificateV1> {
    let extensions = vec![Ed25519Extension::new(
        HAS_SIGNING_KEY,
        0,
        descriptor_signing_key.verifying_key().as_bytes(),
    )?];
    Ed25519CertificateV1::new(
        ed_cert.typ,
        Some(ed_cert.expiration),
        ed_cert.key_type,
        ed_cert.key,
        extensions,
        Some(descriptor_signing_key),
        None,
    )
}

#[derive(Clone)]
pub struct ReceivedDescriptor {
    pub base: V3Descriptor,
    received_ts: Option<DateTime<Utc>>,
}

impl ReceivedDescriptor {
    pub fn new(desc_text: &str, onion_address: &str) -> Result<Self, DescriptorErr> {
        let mut v3_desc = match HiddenServiceDescriptorV3::new(desc_text.to_owned()) {
            Ok(v) => v,
            Err(err) => {
                warn!("Descriptor is corrupted ({err}).");
                return Err(DescriptorErr::ErrBadDescriptor);
            }
        };
        if let Err(err) = v3_desc.decrypt(onion_address) {
            error!("failed to decrypt v3Desc : {onion_address} : {desc_text} : {err}");
            return Err(DescriptorErr::ErrBadDescriptor);
        }
        debug!("Successfully decrypted descriptor for {onion_address}!");

        Ok(Self {
            base: V3Descriptor {
                onion_address: onion_address.to_owned(),
                intro_set: IntroductionPointSetV3::new(vec![v3_desc.inner_layer.introduction_points.clone()]),
                v3_desc,
            },
            received_ts: Some(Utc::now()),
        })
    }

    pub fn is_old(&self) -> bool {
        let Some(received_ts) = self.received_ts else { return true; };
        let received_age = Utc::now().signed_duration_since(received_ts);
        received_age.num_seconds() > INSTANCE_DESCRIPTOR_TOO_OLD
    }
}

#[derive(Clone)]
pub struct V3Descriptor {
    pub onion_address: String,
    pub v3_desc: HiddenServiceDescriptorV3,
    pub intro_set: IntroductionPointSetV3,
}

impl V3Descriptor {
    pub fn get_intro_points(&self) -> Vec<IntroductionPointV3> {
        self.intro_set.get_intro_points_flat()
    }

    pub fn get_blinded_key(&self) -> anyhow::Result<VerifyingKey> {
        self.v3_desc.signing_cert.signing_key()
    }
}

#[derive(Clone, Debug)]
pub struct Ed25519Extension {
    pub typ: u8,
    flags: Vec<String>,
    flag_int: u8,
    pub data: Vec<u8>,
}

pub const HAS_SIGNING_KEY: u8 = 4;

impl Ed25519Extension {
    pub fn new(ext_type: u8, flag_val: u8, data: &[u8]) -> anyhow::Result<Self> {
        let mut out = Self {
            typ: ext_type,
            flags: Vec::new(),
            flag_int: flag_val,
            data: data.to_owned(),
        };
        let mut flag_val = flag_val;
        if flag_val > 0 && flag_val % 2 == 1 {
            out.flags.push("AFFECTS_VALIDATION".to_owned());
            flag_val -= 1;
        }
        if flag_val > 0 {
            out.flags.push("UNKNOWN".to_owned());
        }
        if ext_type == HAS_SIGNING_KEY && out.data.len() != 32 {
            bail!("Ed25519 HAS_SIGNING_KEY extension must be 32 bytes, but was {}.", out.data.len())
        }
        Ok(out)
    }

    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend((self.data.len() as u16).to_be_bytes());
        out.push(self.typ);
        out.push(self.flag_int);
        out.extend(&self.data);
        out
    }
}

#[cfg(test)]
mod tests {
    use crate::onionbalance::descriptor::{get_revision_counter_det, recertify_ed_certificate};
    use crate::stem::descriptor::certificate::Ed25519CertificateV1;
    use base64::{engine::general_purpose, Engine as _};
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_recertify() {
        let signing_key_pem = r#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIOcEHVwEY9iXpRtgQ9V3gfRPxWnVLueY911dGZDmLsE5
-----END PRIVATE KEY-----"#;
        let cert_in = r#"-----BEGIN ED25519 CERT-----
AQkABvnyAeKc+JWLUCqeZ0PeYQMLB/s1x78MnHbaVJEJRydNiS4MAQAgBABcfN7F
QCPKVVMMIsn/OMg/XEQjOhfiqBB7DDU36l7dRyLU9kxujPUIBRUN229MYnIZE7iC
Bbtp5EM7G8R6GeX63anXSwcgldZJMa3hTq4QqhJf92nIOWakmAh9N++z+wo=
-----END ED25519 CERT-----"#;
        let expected = r#"-----BEGIN ED25519 CERT-----
AQkABvnyAeKc+JWLUCqeZ0PeYQMLB/s1x78MnHbaVJEJRydNiS4MAQAgBADpdmL5
jB9FTH/efQdCjogJa4F2/Xh9qJNiWmKWQYHdFB0b6xL7WctQFkBPWX0E+wyBjN+s
kcA5N/9MA4vWHYTeR2NI10q48FfC/A3iXu1W9f+vaVhYGr2rsgWmqt86Ngc=
-----END ED25519 CERT-----"#;

        let descriptor_signing_key = SigningKey::from_pkcs8_pem(signing_key_pem).unwrap();
        let ed_cert = Ed25519CertificateV1::from_base64(cert_in).unwrap();
        let mut kp = SigningKey::from_bytes(&descriptor_signing_key.to_bytes().try_into().unwrap());
        let out = recertify_ed_certificate(ed_cert, &mut kp).unwrap();
        assert_eq!(expected, out.to_base64());
    }

    #[test]
    fn test_get_revision_counter_det() {
        let pk: [u8; 32] = general_purpose::STANDARD.decode("5FPpKghcg2LnAuG8eO1n/+EwYKePXbxl1kFPp+iKbb8=").unwrap().try_into().unwrap();
        let now = 1645956370i64;
        let srv_start = 1645833600u64;
        let expected = 4033953644i64;
        let expected_sss = 122771i64;
        let (ope_result, sss) = get_revision_counter_det(&pk, now, srv_start);
        assert_eq!(expected_sss, sss);
        assert_eq!(expected, ope_result);
    }
}
