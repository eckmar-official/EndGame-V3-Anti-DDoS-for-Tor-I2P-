use anyhow::{bail, ensure, Context};
use crate::onionbalance::descriptor::{Ed25519Extension, HAS_SIGNING_KEY};
use crate::rsbpk;
use crate::stem::descriptor::certificate::{split_by_length, Ed25519CertificateV1, HS_V3DESC_SIGNING};
use crate::stem::util;
use base64::{engine::general_purpose, Engine as _};
use cipher::generic_array::GenericArray;
use cipher::StreamCipher;
use cipher::{KeyIvInit, StreamCipherCoreWrapper};
use ed25519_dalek::{Signer, VerifyingKey};
use rand::random;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha3::Digest;
use sha3::{
    digest::{ExtendableOutput, XofReader},
    Sha3_256, Shake256,
};
use tor_llcrypto::cipher::aes::Aes256Ctr;
use ed25519_dalek::SigningKey;
use x509_parser::nom::AsBytes;
use tor_llcrypto::pk::curve25519;

const END_ED25519_CERT: &str = "-----END ED25519 CERT-----";
const BEGIN_MESSAGE: &str = "-----BEGIN MESSAGE-----";
const END_MESSAGE: &str = "-----END MESSAGE-----";

pub fn identity_key_from_address(onion_address: &str) -> anyhow::Result<VerifyingKey> {
    let onion_address = onion_address.trim_end_matches(".onion");
    let decoded_address = base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &onion_address.to_uppercase()).context("base32 decode failed")?;
    let pub_key = &decoded_address[..32];
    let expected_checksum = &decoded_address[32..34];
    let version = &decoded_address[34..35];
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pub_key);
    hasher.update(version);
    let checksum_tmp: [u8; 32] = hasher.finalize().into();
    let checksum = &checksum_tmp[..2];
    if expected_checksum != checksum {
        bail!("Bad checksum (expected {expected_checksum:?} but was {checksum:?})");
    }
    Ok(VerifyingKey::from_bytes(&pub_key.try_into()?)?)
}

pub fn address_from_identity_key(eid: &VerifyingKey) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(eid.as_bytes());
    hasher.update(3_u8.to_be_bytes());
    let checksum: [u8; 32] = hasher.finalize().into();
    let mut v = Vec::<u8>::new();
    v.extend(eid.as_bytes());
    v.extend(&checksum[..2]);
    v.extend(3_u8.to_be_bytes());
    let addr = base32::encode(base32::Alphabet::Rfc4648 { padding: true }, v.as_bytes()).to_lowercase();
    format!("{addr}.onion")
}

#[derive(Clone, Debug)]
pub struct LinkSpecifier {
    typ: u8,
    value: Vec<u8>,
}

impl LinkSpecifier {
    fn pack(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.typ);
        out.push(self.value.len() as u8);
        out.extend(self.value.clone());
        out
    }

    fn parse(content: &str) -> anyhow::Result<Vec<Self>> {
        let decoded = general_purpose::STANDARD.decode(&content).expect(format!("Unable to base64 decode introduction point ({content})").as_str());
        let content = decoded;
        let mut link_specifiers = Vec::new();
        let count = &content[0];
        let mut content = content[1..].to_vec();
        for _ in 0..*count {
            let (link_specifier, content1) = LinkSpecifier::pop(&content)?;
            content = content1;
            link_specifiers.push(link_specifier);
        }
        ensure!(content.is_empty(), "Introduction point had excessive data ({content:?})");
        Ok(link_specifiers)
    }

    fn pop(packed: &[u8]) -> anyhow::Result<(Self, Vec<u8>)> {
        let packed = packed;
        let (typ, packed) = (packed[0], &packed[1..]);
        let (value_size, packed) = (&packed[0], &packed[1..]);
        let value_size = *value_size as usize;
        ensure!(value_size <= packed.len(), "Link specifier should have {value_size} bytes, but only had {} remaining", packed.len());
        let (value, packed) = (&packed[..value_size], &packed[value_size..]);
        match typ {
            0 => return Ok((LinkByIPv4::unpack(value)?.base, packed.to_vec())),
            1 => return Ok((LinkByIPv6::unpack(value)?.base, packed.to_vec())),
            2 => return Ok((LinkByFingerprint::new(value)?.base, packed.to_vec())),
            3 => return Ok((LinkByEd25519::new(value)?.base, packed.to_vec())),
            _ => {},
        }
        Ok((Self { typ, value: value.to_vec() }, packed.to_vec()))
    }
}

struct LinkByIPv4 {
    base: LinkSpecifier,
    #[allow(unused)]
    address: String,
    #[allow(unused)]
    port: u16,
}

impl LinkByIPv4 {
    fn new(address: String, port: u16) -> anyhow::Result<Self> {
        let mut value = Vec::new();
        value.extend(pack_ipv4_address(&address)?);
        value.extend(port.to_be_bytes());
        let base = LinkSpecifier { typ: 0, value };
        Ok(Self { base, address, port })
    }

    fn unpack(value: &[u8]) -> anyhow::Result<Self> {
        ensure!(value.len() == 6, "IPv4 link specifiers should be six bytes, but was {} instead: {value:?}", value.len());
        let addr: [u8; 4] = value[..4].try_into()?;
        let port_raw = &value[4..];
        let port = u16::from_be_bytes(port_raw.try_into()?);
        Ok(LinkByIPv4::new(unpack_ipv4_address(addr), port)?)
    }
}

struct LinkByIPv6 {
    base: LinkSpecifier,
    #[allow(unused)]
    address: String,
    #[allow(unused)]
    port: u16,
}

impl LinkByIPv6 {
    fn new(address: String, port: u16) -> anyhow::Result<Self> {
        let mut value = Vec::new();
        value.extend(pack_ipv6_address(&address)?);
        value.extend(port.to_be_bytes());
        let base = LinkSpecifier { typ: 1, value };
        Ok(Self { base, address, port })
    }

    fn unpack(value: &[u8]) -> anyhow::Result<Self> {
        ensure!(value.len() == 18, "IPv6 link specifiers should be eighteen bytes, but was {} instead: {value:?}", value.len());
        let addr: [u8; 16] = value[..16].try_into()?;
        let port_raw = &value[16..];
        let port = u16::from_be_bytes(port_raw.try_into()?);
        Ok(LinkByIPv6::new(unpack_ipv6_address(addr)?, port)?)
    }
}

struct LinkByFingerprint {
    base: LinkSpecifier,
}

impl LinkByFingerprint {
    fn new(value: &[u8]) -> anyhow::Result<Self> {
        ensure!(value.len() == 20, "Fingerprint link specifiers should be twenty bytes, but was {} instead: {value:?}", value.len());
        let base = LinkSpecifier { typ: 2, value: value.to_owned() };
        Ok(Self { base })
    }
}

struct LinkByEd25519 {
    base: LinkSpecifier,
}

impl LinkByEd25519 {
    fn new(value: &[u8]) -> anyhow::Result<Self> {
        ensure!(value.len() == 32, "Ed25519 link specifiers should be thirty two bytes, but was {} instead: {value:?}", value.len());
        let base = LinkSpecifier { typ: 3, value: value.to_owned() };
        Ok(Self { base })
    }
}

fn unpack_ipv4_address(value: [u8; 4]) -> String {
    value.iter().map(u8::to_string).collect::<Vec<_>>().join(".")
}

fn unpack_ipv6_address(value: [u8; 16]) -> anyhow::Result<String> {
    let mut strs = Vec::new();
    for i in 0..8 {
        strs.push(format!(
            "{:04x}",
            u16::from_be_bytes(value[i * 2..(i + 1) * 2].try_into()?)
        ));
    }
    Ok(strs.join(":"))
}

fn pack_ipv4_address(address: &str) -> anyhow::Result<[u8; 4]> {
    let mut out: [u8; 4] = [0; 4];
    for (idx, part) in address.split(".").enumerate() {
        out[idx] = part.parse::<u8>()?;
    }
    Ok(out)
}

fn pack_ipv6_address(address: &str) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    for part in address.split(":") {
        out.extend(hex::decode(part)?);
    }
    Ok(out)
}

#[derive(Default, Clone, Debug)]
pub struct IntroductionPointV3 {
    pub link_specifiers: Vec<LinkSpecifier>,
    pub onion_key: String,
    pub enc_key: String,
    pub auth_key_cert_raw: String,
    pub enc_key_cert_raw: String,
    pub auth_key_cert: Ed25519CertificateV1,
    pub enc_key_cert: Ed25519CertificateV1,
    //pub LegacyKeyRaw: any,
}

impl IntroductionPointV3 {
    pub(crate) fn equals(&self, other: &IntroductionPointV3) -> bool {
        self.encode() == other.encode()
    }

    fn encode(&self) -> String {
        let mut lines = Vec::new();
        let link_count = self.link_specifiers.len() as u8;
        let link_specifiers: Vec<_> = std::iter::once(link_count)
            .chain(self.link_specifiers.iter().flat_map(|ls| ls.pack()))
            .collect();
        lines.push(format!("introduction-point {}", general_purpose::STANDARD.encode(link_specifiers)));
        lines.push(format!("onion-key ntor {}", self.onion_key));
        lines.push(format!("auth-key\n{}", self.auth_key_cert_raw));
        if self.enc_key != "" {
            lines.push(format!("enc-key ntor {}", self.enc_key));
        }
        lines.push(format!("enc-key-cert\n{}", self.enc_key_cert_raw));
        lines.join("\n")
    }

    fn parse(content: &str) -> anyhow::Result<Self> {
        ensure!(content.starts_with("introduction-point "), "invalid content");
        let mut ip = Self { ..Default::default() };
        let mut auth_key_cert_content = String::new();
        let mut enc_key_cert_content = String::new();
        let lines = content.split("\n");
        let mut start_auth_key = false;
        let mut start_enc_key_cert = false;
        for line in lines {
            if line == "auth-key" {
                start_auth_key = true;
            } else if line == "enc-key-cert" {
                start_enc_key_cert = true;
            } else if start_auth_key {
                auth_key_cert_content = format!("{}{}\n", auth_key_cert_content, line);
                if line == END_ED25519_CERT {
                    start_auth_key = false;
                    auth_key_cert_content = auth_key_cert_content.trim().to_owned();
                }
            } else if start_enc_key_cert {
                enc_key_cert_content = format!("{}{}\n", enc_key_cert_content, line);
                if line == END_ED25519_CERT {
                    start_enc_key_cert = false;
                    enc_key_cert_content = enc_key_cert_content.trim().to_owned();
                }
            } else if let Some(stripped_line) = line.strip_prefix("introduction-point ") {
                ip.link_specifiers = LinkSpecifier::parse(stripped_line)?;
            } else if let Some(stripped_line) = line.strip_prefix("onion-key ntor ") {
                ip.onion_key = stripped_line.to_owned();
            } else if let Some(stripped_line) = line.strip_prefix("enc-key ntor ") {
                ip.enc_key = stripped_line.to_owned();
            }
        }
        ip.auth_key_cert_raw = auth_key_cert_content.to_owned();
        ip.enc_key_cert_raw = enc_key_cert_content.to_owned();
        ip.auth_key_cert = Ed25519CertificateV1::from_base64(&auth_key_cert_content)?;
        ip.enc_key_cert = Ed25519CertificateV1::from_base64(&enc_key_cert_content)?;
        Ok(ip)
    }
}

#[derive(Default, Clone, Debug)]
pub struct OuterLayer {
    encrypted: String,
    raw_content: String,
}

impl OuterLayer {
    fn new(content: String) -> Self {
        Self {
            encrypted: OuterLayer::parse(&content),
            raw_content: content,
        }
    }

    fn encrypt(
        &self,
        revision_counter: i64,
        subcredential: [u8; 32],
        blinded_key: VerifyingKey,
    ) -> anyhow::Result<String> {
        // Spec mandated padding: "Before encryption the plaintext is padded with
        // NUL bytes to the nearest multiple of 10k bytes."
        let mut content = self.get_bytes();
        content = format!("{content}{}", "\x00".repeat(content.len() % 10000));
        // encrypt back into a hidden service descriptor's 'superencrypted' field
        encrypt_layer(
            content.as_bytes().to_vec(),
            b"hsdir-superencrypted-data",
            revision_counter,
            subcredential,
            blinded_key.to_bytes(),
        )
    }

    fn get_bytes(&self) -> String {
        self.raw_content.clone()
    }

    fn parse(content: &str) -> String {
        content
            .split_once("encrypted\n")
            .and_then(|(_, after_start)| {
                after_start.find(END_MESSAGE).map(|idx| {
                    &after_start[..idx + END_MESSAGE.len()]
                })
            })
            .map(|between| between.replace(['\r', '\x00'], "").trim().to_owned())
            .unwrap_or_default()
    }
}

#[derive(Default, Clone, Debug)]
pub struct InnerLayer {
    #[allow(unused)]
    outer_layer: OuterLayer,
    pub introduction_points: Vec<IntroductionPointV3>,
    raw_contents: String,
}

impl InnerLayer {
    pub fn new(content: &str, outer_layer: OuterLayer) -> Self {
        let raw_contents = content.to_owned();
        let unparsed_introduction_points = raw_contents.find("\nintroduction-point ")
            .map(|idx| content[idx + 1..].to_owned())
            .unwrap_or_default();
        let introduction_points = parse_v3_introduction_points(&unparsed_introduction_points);
        Self { outer_layer, raw_contents, introduction_points }
    }

    fn encrypt(&self, revision_counter: i64, subcredential: [u8; 32], blinded_key: [u8; 32]) -> anyhow::Result<String> {
        // encrypt back into an outer layer's 'encrypted' field
        encrypt_layer(
            self.get_bytes(),
            b"hsdir-encrypted-data",
            revision_counter,
            subcredential,
            blinded_key,
        )
    }

    fn get_bytes(&self) -> Vec<u8> {
        self.raw_contents.as_bytes().to_vec()
    }
}

fn parse_v3_introduction_points(content: &str) -> Vec<IntroductionPointV3> {
    let delim = "introduction-point ";
    content
        .split(delim)
        .skip(1)
        .filter_map(|e| {
            IntroductionPointV3::parse(&format!("{delim}{e}"))
                .map_err(|err| error!("introductionPointV3Parse {err}"))
                .ok()
        })
        .collect()
}

fn encrypt_layer(
    plaintext: Vec<u8>,
    constant: &[u8],
    revision_counter: i64,
    subcredential: [u8; 32],
    blinded_key: [u8; 32],
) -> anyhow::Result<String> {
    let salt = random::<[u8; 16]>();
    encrypt_layer_det(plaintext, constant, revision_counter, subcredential, blinded_key, salt)
}

fn encrypt_layer_det(
    plaintext: Vec<u8>,
    constant: &[u8],
    revision_counter: i64,
    subcredential: [u8; 32],
    blinded_key: [u8; 32],
    salt: [u8; 16],
) -> anyhow::Result<String> {
    let (mut ciphr, mac_prefix) = layer_cipher(constant, revision_counter, subcredential, blinded_key, salt)?;
    let mut cipher_text = plaintext;
    ciphr.apply_keystream(&mut cipher_text);

    let mut to_enc = Vec::new();
    to_enc.extend(salt.as_bytes());
    to_enc.extend(cipher_text.as_bytes());

    let mut hasher = Sha3_256::new();
    hasher.update(mac_prefix);
    hasher.update(cipher_text);
    let tmp: [u8; 32] = hasher.finalize().into();

    to_enc.extend(tmp);

    let encoded = general_purpose::STANDARD.encode(to_enc);
    let joined = split_by_length(&encoded, 64).join("\n");
    Ok(format!("{BEGIN_MESSAGE}\n{joined}\n{END_MESSAGE}"))
}

fn outer_layer_decrypt(
    encrypted: &str,
    revision_counter: i64,
    subcredential: [u8; 32],
    blinded_key: [u8; 32],
) -> anyhow::Result<OuterLayer> {
    let plaintext = decrypt_layer(
        encrypted,
        b"hsdir-superencrypted-data",
        revision_counter,
        subcredential,
        blinded_key,
    )?;
    Ok(OuterLayer::new(plaintext))
}

fn inner_layer_decrypt(
    outer_layer: OuterLayer,
    revision_counter: i64,
    subcredential: [u8; 32],
    blinded_key: [u8; 32],
) -> anyhow::Result<InnerLayer> {
    let plaintext = decrypt_layer(
        &outer_layer.encrypted,
        b"hsdir-encrypted-data",
        revision_counter,
        subcredential,
        blinded_key,
    )?;
    Ok(InnerLayer::new(&plaintext, outer_layer))
}

fn decrypt_layer(
    encrypted_block: &str,
    constant: &[u8],
    revision_counter: i64,
    subcredential: [u8; 32],
    blinded_key: [u8; 32],
) -> anyhow::Result<String> {
    let mut encrypted_block = encrypted_block;
    if encrypted_block.starts_with(BEGIN_MESSAGE) && encrypted_block.ends_with(END_MESSAGE) {
        encrypted_block = encrypted_block.trim_start_matches(BEGIN_MESSAGE);
        encrypted_block = encrypted_block.trim_end_matches(END_MESSAGE);
    }
    let encrypted_block = encrypted_block.replace("\n", "");
    let encrypted = general_purpose::STANDARD.decode(&encrypted_block).expect("Unable to decode encrypted block as base64");
    ensure!(encrypted.len() >= SALT_LEN + MAC_LEN, "Encrypted block malformed (only {} bytes)", &encrypted.len());
    let salt: [u8; 16] = encrypted[..SALT_LEN].try_into()?;
    let ciphertext = &encrypted[SALT_LEN..encrypted.len() - MAC_LEN];
    let expected_mac = &encrypted[encrypted.len() - MAC_LEN..];
    let (mut ciphr, mac_prefix) = layer_cipher(constant, revision_counter, subcredential, blinded_key, salt)?;

    let mut actual_mac = Vec::<u8>::new();
    actual_mac.extend(mac_prefix.clone());
    actual_mac.extend(ciphertext.as_bytes());

    let mut hasher = Sha3_256::new();
    hasher.update(&actual_mac);
    let actual_mac: [u8; 32] = hasher.finalize().into();
    ensure!(expected_mac == actual_mac, "Malformed mac (expected {expected_mac:?}, but was {actual_mac:?})");

    let mut plaintext = ciphertext.to_vec();
    ciphr.apply_keystream(&mut plaintext);
    Ok(std::str::from_utf8(plaintext.as_bytes())?.to_owned())
}

const S_KEY_LEN: usize = 32;
const S_IV_LEN: usize = 16;
const SALT_LEN: usize = 16;
const MAC_LEN: usize = 32;

fn layer_cipher(
    constant: &[u8],
    revision_counter: i64,
    subcredential: [u8; 32],
    blinded_key: [u8; 32],
    salt: [u8; 16],
) -> anyhow::Result<(StreamCipherCoreWrapper<ctr::CtrCore<aes::Aes256, ctr::flavors::Ctr128BE>>, Vec<u8>)> {
    use sha3::digest::Update;

    let data1: [u8; 8] = revision_counter.to_be_bytes();
    let mut data: Vec<u8> = Vec::new();
    data.extend(blinded_key);
    data.extend(subcredential);
    data.extend(data1);
    data.extend(salt);
    data.extend(constant);
    let mut hasher = Shake256::default();
    hasher.update(&data);
    let mut reader = hasher.finalize_xof();
    let mut keys = [0u8; S_KEY_LEN + S_IV_LEN + MAC_LEN];
    reader.read(&mut keys);

    let secret_key = &keys[..S_KEY_LEN];
    let secret_iv = &keys[S_KEY_LEN..S_KEY_LEN + S_IV_LEN];
    let mac_key = &keys[S_KEY_LEN + S_IV_LEN..];

    let iv = GenericArray::from_slice(&secret_iv);
    let key = GenericArray::from_slice(&secret_key);
    let cipher = Aes256Ctr::new(&key, &iv);

    let data2: [u8; 8] = mac_key.len().to_be_bytes().try_into()?;
    let data3: [u8; 8] = salt.len().to_be_bytes().try_into()?;
    let mut mac_prefix: Vec<u8> = Vec::new();
    mac_prefix.extend(data2);
    mac_prefix.extend(mac_key);
    mac_prefix.extend(data3);
    mac_prefix.extend(salt);
    Ok((cipher, mac_prefix))
}

fn inner_layer_content(introduction_points: Option<Vec<IntroductionPointV3>>) -> String {
    let mut suffix = String::new();
    if let Some(introduction_points) = introduction_points {
        let mut ips = Vec::new();
        for ip in introduction_points {
            ips.push(ip.encode());
        }
        suffix = format!("\n{}", ips.join("\n"));
    }
    format!("create2-formats 2{suffix}")
}

pub fn inner_layer_create(introduction_points: Option<Vec<IntroductionPointV3>>) -> InnerLayer {
    InnerLayer::new(
        &inner_layer_content(introduction_points),
        OuterLayer { ..Default::default() },
    )
}

#[derive(Default, Clone)]
pub struct Descriptor {
    hs_descriptor_version: i64,
    descriptor_lifetime: i64,
    descriptor_signing_key_cert: String,
    revision_counter: i64,
    superencrypted: String,
    signature: String,
}

impl Descriptor {
    fn from_str(content: &str) -> anyhow::Result<Self> {
        desc_from_str(&content)
    }
}

fn desc_from_str(content: &str) -> anyhow::Result<Descriptor> {
    let mut d = Descriptor { ..Default::default() };
    let content = content.replace("\r", "");
    let lines = content.split("\n");
    let mut start_cert = false;
    let mut start_superencrypted = false;
    for (idx, line) in lines.enumerate() {
        if idx == 0 {
            d.hs_descriptor_version = line.strip_prefix("hs-descriptor ").context("missing prefix")?.parse()?;
        } else if idx == 1 {
            d.descriptor_lifetime = line.strip_prefix("descriptor-lifetime ").context("missing prefix")?.parse()?;
        } else if line == "descriptor-signing-key-cert" {
            start_cert = true;
        } else if line == "superencrypted" {
            start_superencrypted = true;
        } else if let Some(stripped_line) = line.strip_prefix("revision-counter ") {
            d.revision_counter = stripped_line.parse()?;
        } else if let Some(stripped_line) = line.strip_prefix("signature ") {
            d.signature = stripped_line.to_owned();
        } else if start_cert {
            d.descriptor_signing_key_cert.push_str(line);
            d.descriptor_signing_key_cert.push_str("\n");
            if line == END_ED25519_CERT {
                start_cert = false;
                d.descriptor_signing_key_cert = d.descriptor_signing_key_cert.trim().to_owned();
            }
        } else if start_superencrypted {
            d.superencrypted.push_str(line);
            d.superencrypted.push_str("\n");
            if line == END_MESSAGE {
                start_superencrypted = false;
                d.superencrypted = d.superencrypted.trim().to_owned();
            }
        }
    }
    Ok(d)
}

#[derive(Default, Clone)]
pub struct BaseHiddenServiceDescriptor {
    base: Descriptor,
}

#[derive(Default, Clone)]
pub struct HiddenServiceDescriptorV3 {
    base: BaseHiddenServiceDescriptor,
    pub signing_cert: Ed25519CertificateV1,
    pub inner_layer: InnerLayer,
}

impl HiddenServiceDescriptorV3 {
    pub fn new(raw_contents: String) -> anyhow::Result<Self> {
        let descriptor = Descriptor::from_str(&raw_contents).context("failed to parse descriptor from string")?;
        let signing_cert = Ed25519CertificateV1::from_base64(&descriptor.descriptor_signing_key_cert).context("failed to get certificate")?;
        let base = BaseHiddenServiceDescriptor { base: descriptor };
        let inner_layer = InnerLayer { raw_contents, ..Default::default() };
        Ok(Self { base, signing_cert, inner_layer })
    }

    pub fn string(&self) -> String {
        let descriptor_lifetime = &self.base.base.descriptor_lifetime;
        let descriptor_signing_key_cert = &self.base.base.descriptor_signing_key_cert;
        let revision_counter = &self.base.base.revision_counter;
        let superencrypted = &self.base.base.superencrypted;
        let signature = &self.base.base.signature;
        format!("\
        hs-descriptor 3\n\
        descriptor-lifetime {descriptor_lifetime}\n\
        descriptor-signing-key-cert\n\
        {descriptor_signing_key_cert}\n\
        revision-counter {revision_counter}\n\
        superencrypted\n\
        {superencrypted}\n\
        signature {signature}")
    }

    pub fn decrypt(&mut self, onion_address: &str) -> anyhow::Result<()> {
        let descriptor_signing_key_cert = &self.base.base.descriptor_signing_key_cert;
        let cert = Ed25519CertificateV1::from_base64(&descriptor_signing_key_cert).context("failed to get certificate")?;
        let blinded_key = cert.signing_key().context("No signing key is present")?;
        let identity_public_key = identity_key_from_address(onion_address)?;
        let subcredential = subcredential(identity_public_key, &blinded_key);
        let outer_layer = outer_layer_decrypt(
            &self.base.base.superencrypted,
            self.base.base.revision_counter,
            subcredential,
            blinded_key.to_bytes(),
        )?;
        self.inner_layer = inner_layer_decrypt(
            outer_layer,
            self.base.base.revision_counter,
            subcredential,
            blinded_key.to_bytes(),
        )?;
        Ok(())
    }
}

fn blinded_pub_key(
    identity_key: &rsbpk::PrivateKey,
    blinding_nonce: &[u8; 32],
) -> anyhow::Result<VerifyingKey> {
    util::blinded_pubkey(identity_key.public()?, blinding_nonce)
}

const SIG_PREFIX_HS_V3: &str = "Tor onion service descriptor sig v3";

fn hidden_service_descriptor_v3_content(
    blinding_nonce: &[u8; 32],
    identity_key: &rsbpk::PrivateKey,
    desc_signing_key: SigningKey,
    inner_layer: &InnerLayer,
    rev_counter: i64,
) -> anyhow::Result<String> {
    let blinded_key = blinded_pub_key(identity_key, blinding_nonce)?;
    let pubk = identity_key.public()?;
    let subcredential = subcredential(pubk, &blinded_key);
    let outer_layer = outer_layer_create(inner_layer, rev_counter, subcredential, blinded_key.to_bytes())?;
    let signing_cert = get_signing_cert(blinded_key, &desc_signing_key, identity_key, blinding_nonce)?;
    let signing_cert_b64 = signing_cert.to_base64();
    let superencrypted = outer_layer.encrypt(rev_counter, subcredential.clone(), blinded_key)?;

    let mut desc_content = "hs-descriptor 3\n".to_owned();
    desc_content.push_str(&format!("descriptor-lifetime {}\n", 180));
    desc_content.push_str("descriptor-signing-key-cert\n");
    desc_content.push_str(&format!("{signing_cert_b64}\n"));
    desc_content.push_str(&format!("revision-counter {rev_counter}\n"));
    desc_content.push_str("superencrypted\n");
    desc_content.push_str(&format!("{}\n", superencrypted));

    let sig_content = format!("{SIG_PREFIX_HS_V3}{desc_content}");
    let sig = desc_signing_key.sign(sig_content.as_bytes());
    let b64_signature = general_purpose::STANDARD.encode(sig.to_bytes());
    let signature = b64_signature.trim_end_matches("=");
    desc_content.push_str(&format!("signature {signature}"));
    Ok(desc_content)
}

fn get_signing_cert(
    blinded_key: VerifyingKey,
    desc_signing_key: &SigningKey,
    identity_key: &rsbpk::PrivateKey,
    blinding_nonce: &[u8; 32],
) -> anyhow::Result<Ed25519CertificateV1> {
    let extensions = vec![Ed25519Extension::new(HAS_SIGNING_KEY, 0, blinded_key.as_bytes())?];
    let mut signing_cert = Ed25519CertificateV1::new(HS_V3DESC_SIGNING, None, 1, desc_signing_key.verifying_key(), extensions, None, None)?;
    signing_cert.signature = Some(blinded_sign(signing_cert.pack(), identity_key, blinded_key, blinding_nonce));
    Ok(signing_cert)
}

fn blinded_sign(
    msg: Vec<u8>,
    identity_key: &rsbpk::PrivateKey,
    blinded_key: VerifyingKey,
    blinding_nonce: &[u8; 32],
) -> Vec<u8> {
    let identity_key_bytes = identity_key.private_key.to_vec();
    if identity_key.is_priv_key_in_tor_format {
        util::blinded_sign_with_tor_key(msg, identity_key_bytes, blinded_key, blinding_nonce)
    } else {
        util::blinded_sign(msg, identity_key_bytes, blinded_key, blinding_nonce)
    }
}

fn subcredential(identity_key: VerifyingKey, blinded_key: &VerifyingKey) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"credential");
    hasher.update(identity_key.as_bytes());
    let credential: [u8; 32] = hasher.finalize().into();
    let mut hasher = Sha3_256::new();
    hasher.update(b"subcredential");
    hasher.update(credential.as_bytes());
    hasher.update(blinded_key.as_bytes());
    hasher.finalize().into()
}

// AuthorizedClient Client authorized to use a v3 hidden service.
// id: base64 encoded client id
// iv: base64 encoded randomized initialization vector
// cookie: base64 encoded authentication cookie
struct AuthorizedClient {
    id: String,
    iv: String,
    cookie: String,
}

impl AuthorizedClient {
    fn new() -> Self {
        let id = general_purpose::STANDARD.encode(random::<[u8; 8]>())
            .trim_end_matches("=").to_owned();
        let iv = general_purpose::STANDARD.encode(random::<[u8; 16]>())
            .trim_end_matches("=").to_owned();
        let cookie = general_purpose::STANDARD.encode(random::<[u8; 16]>())
            .trim_end_matches("=").to_owned();
        Self { id, iv, cookie }
    }
}

fn outer_layer_create(
    inner_layer: &InnerLayer,
    revision_counter: i64,
    subcredential: [u8; 32],
    blinded_key: [u8; 32],
) -> anyhow::Result<OuterLayer> {
    Ok(OuterLayer::new(outer_layer_content(
        inner_layer,
        revision_counter,
        subcredential,
        blinded_key,
    )?))
}

fn outer_layer_content(
    inner_layer: &InnerLayer,
    revision_counter: i64,
    subcredential: [u8; 32],
    blinded_key: [u8; 32],
) -> anyhow::Result<String> {
    let mut authorized_clients = Vec::new();
    for _ in 0..16 {
        authorized_clients.push(AuthorizedClient::new());
    }

    let mut rng = ChaCha20Rng::from_entropy();
    let ephemeral_secret = curve25519::EphemeralSecret::random_from_rng(&mut rng);
    let ephemeral_pk = curve25519::PublicKey::from(&ephemeral_secret);
    let desc_auth_ephemeral_key = general_purpose::STANDARD.encode(ephemeral_pk.as_bytes());
    let encrypted_inner_layer = inner_layer.encrypt(revision_counter, subcredential, blinded_key)?;

    let mut v = vec!["desc-auth-type x25519".to_owned()];
    v.push(format!("desc-auth-ephemeral-key {desc_auth_ephemeral_key}"));
    for c in authorized_clients {
        v.push(format!("auth-client {} {} {}", c.id, c.iv, c.cookie));
    }
    v.push("encrypted".to_owned());
    v.push(encrypted_inner_layer);
    Ok(v.join("\n"))
}

pub fn hidden_service_descriptor_v3_create(
    blinding_nonce: &[u8; 32],
    identity_priv_key: &rsbpk::PrivateKey,
    desc_signing_key: SigningKey,
    v3_desc_inner_layer: &InnerLayer,
    rev_counter: i64,
) -> anyhow::Result<HiddenServiceDescriptorV3> {
    Ok(HiddenServiceDescriptorV3::new(hidden_service_descriptor_v3_content(
        blinding_nonce,
        identity_priv_key,
        desc_signing_key,
        v3_desc_inner_layer,
        rev_counter,
    )?)?)
}

#[cfg(test)]
mod tests {
    use crate::stem::descriptor::certificate::Ed25519CertificateV1;
    use crate::stem::descriptor::hidden_service::{address_from_identity_key, desc_from_str, encrypt_layer_det, identity_key_from_address, inner_layer_decrypt, outer_layer_decrypt, pack_ipv4_address, pack_ipv6_address, parse_v3_introduction_points, subcredential, unpack_ipv4_address, unpack_ipv6_address, HiddenServiceDescriptorV3, IntroductionPointV3, LinkSpecifier};
    use crate::stem::util;
    use base64::engine::general_purpose;
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    use x509_parser::nom::AsBytes;

    #[test]
    fn test_parse_link_specifier() {
        let raw = "BAAGwWx24QG7AhSMqkcLkFdYdCID4+tFlBcZ/Kn+7AMgGOC0nmuoMP3c+cpu+iejBmfnw82ySyQJQP+g76QA4cwBEiYEhsDwAQAAAADQ7QDh0A8Buw==";
        let link_specifiers = LinkSpecifier::parse(raw).unwrap();
        let link_count = link_specifiers.len() as u8;
        let mut res = vec![link_count];
        for ls in link_specifiers {
            res.extend(ls.pack());
        }
        assert_eq!(raw, general_purpose::STANDARD.encode(res));
    }

    #[test]
    fn test_parse_ipv4() {
        let raw_bytes: [u8; 4] = [193, 46, 108, 46];
        let unpacked = unpack_ipv4_address(raw_bytes);
        let packed = pack_ipv4_address(&unpacked).unwrap();
        assert_eq!("193.46.108.46", unpacked);
        assert_eq!(raw_bytes, packed);
    }

    #[test]
    fn test_parse_ipv6() {
        let raw = "JgSGwPABAAAAANDtAOHQDw==";
        let raw_bytes: [u8; 16] = general_purpose::STANDARD.decode(raw).unwrap().as_bytes().try_into().unwrap();
        let unpacked = unpack_ipv6_address(raw_bytes).unwrap();
        let packed = pack_ipv6_address(&unpacked).unwrap();
        assert_eq!("2604:86c0:f001:0000:0000:d0ed:00e1:d00f", unpacked);
        assert_eq!(raw, general_purpose::STANDARD.encode(packed));
    }

    #[test]
    fn test_blinded_pubkey() {
        let identity_key_pem = r#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKwDvypzMTFpOB36CEJyP5irq/p2by0tEXh8JoS6sgVS
-----END PRIVATE KEY-----"#;
        let identity_key = SigningKey::from_pkcs8_pem(identity_key_pem).unwrap();
        let vk = identity_key.verifying_key();
        let blinded_nonce_raw = "uocUS01oA1Kwd6cLcGUIGxslai4aPgG73yMw4hRqthM=";
        let expected = "HeNHEZUl3eemfEfLcj9tPekTGfQE6G6bB9SsMCzJtmM=";
        let blinded_nonce: [u8; 32] = general_purpose::STANDARD.decode(blinded_nonce_raw).unwrap().try_into().unwrap();
        let blinded_key = util::blinded_pubkey(vk, &blinded_nonce).unwrap();
        assert_eq!(expected, general_purpose::STANDARD.encode(blinded_key));
    }

    #[test]
    fn test_desc_from_str() {
        let raw_in = r#"hs-descriptor 3
descriptor-lifetime 180
descriptor-signing-key-cert
-----BEGIN ED25519 CERT-----
AQgABvm8AVAyGE0T3EcR+gvX/WJOzuz0fQ6ieP1YDwZ1MdErcRWSAQAgBADxr0YZ
lfzRxUfC4MZxe/EX/9lwpR9ytH9c9Yh4ubD8fGbGKhV4WscKAL1WJtziAoyHhd4k
GJXXI4s1kZoDua1/iiuO3NzhxgqFy11RZlNlEbs3EheCzIXV+flWSm3T8Q4=
-----END ED25519 CERT-----
revision-counter 1719909149
superencrypted
-----BEGIN MESSAGE-----
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
-----END MESSAGE-----
signature ROHwZMmdKtjxgfLswWWmqyA//hdLy9mPuinzg6cAxTjU/KvBe1EBeNIiSCQuyQrnL9zRAGipVBheyHsd8AHjCw
."#;
        let expected_cert = r#"-----BEGIN ED25519 CERT-----
AQgABvm8AVAyGE0T3EcR+gvX/WJOzuz0fQ6ieP1YDwZ1MdErcRWSAQAgBADxr0YZ
lfzRxUfC4MZxe/EX/9lwpR9ytH9c9Yh4ubD8fGbGKhV4WscKAL1WJtziAoyHhd4k
GJXXI4s1kZoDua1/iiuO3NzhxgqFy11RZlNlEbs3EheCzIXV+flWSm3T8Q4=
-----END ED25519 CERT-----"#;
        let expected_superencrypted = r#"-----BEGIN MESSAGE-----
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
-----END MESSAGE-----"#;
        let desc = desc_from_str(raw_in).unwrap();
        assert_eq!(3, desc.hs_descriptor_version);
        assert_eq!(180, desc.descriptor_lifetime);
        assert_eq!(expected_cert, desc.descriptor_signing_key_cert);
        assert_eq!(1719909149, desc.revision_counter);
        assert_eq!(expected_superencrypted, desc.superencrypted);
        assert_eq!(
            "ROHwZMmdKtjxgfLswWWmqyA//hdLy9mPuinzg6cAxTjU/KvBe1EBeNIiSCQuyQrnL9zRAGipVBheyHsd8AHjCw",
            desc.signature
        );
    }

    #[test]
    fn test_introduction_point_v3_parse() {
        let raw_intro_point_v3 = r#"introduction-point BAAGwWx24QG7AhSMqkcLkFdYdCID4+tFlBcZ/Kn+7AMgGOC0nmuoMP3c+cpu+iejBmfnw82ySyQJQP+g76QA4cwBEiYEhsDwAQAAAADQ7QDh0A8Buw==
onion-key ntor zlCXhJ+dpDZ1tnlbtOdmKQ1A1VofkDJE/4MXEkAsSAE=
auth-key
-----BEGIN ED25519 CERT-----
AQkABvn1AXC14ehaLDsBXqZGTwfWXnnNpMXOlRWlmvjreE9WDHn1AQAgBADmw/3J
vKJ7I31/f49CXA/d9PcdNOlbsGes5WBGpw3K9hJGDc9kAf/OgpuUml2BFShR0Csp
yfkXOwnOgJvbZ0TNYxz5lACK/cyD/ZBYrWkwM0cMXvcDdsuLoFkYgwtUVQo=
-----END ED25519 CERT-----
enc-key ntor hV0RpH0yCWR/MCgYbYiZiFyx2uIbNEdGJjGJuU67gCg=
enc-key-cert
-----BEGIN ED25519 CERT-----
AQsABvn1AT6y/SLVsEv3nUBYRrNQUjt0NR2239EizE4OhDOEJqVkAQAgBADmw/3J
vKJ7I31/f49CXA/d9PcdNOlbsGes5WBGpw3K9uSliFfsXwfHbAWmnC2W8ibfhvR7
eHhsBfj4xvSEOmlhNBX+J/IvtNzIy7U/Nsjv74w+Fc1UPXS3lok25/56gw4=
-----END ED25519 CERT-----"#;
        let ip = IntroductionPointV3::parse(raw_intro_point_v3).unwrap();
        let encoded = ip.encode();
        assert_eq!(raw_intro_point_v3, encoded);
    }

    #[test]
    fn test_sign() {
        let raw = r#"Tor onion service descriptor sig v3hs-descriptor 3
descriptor-lifetime 180
descriptor-signing-key-cert
-----BEGIN ED25519 CERT-----
AQgABvoeAQX8F6suhSA4e1nRxbWJg4gDjpHog6ArcfqgK8mVvmlhAQAgBAAd40cR
lSXd56Z8R8tyP2096RMZ9ATobpsH1KwwLMm2YwlT9YmafyWuqdRqlcSc31I3m0Gn
RkryWQsOclS1IcawpS1khXrtvKFjqprfgbykghlGZCj3/O29MRG95RjM2gk=
-----END ED25519 CERT-----
revision-counter 1924420826
superencrypted
-----BEGIN MESSAGE-----
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
7dAel8L06WYRQwgV7wjvLA==
-----END MESSAGE-----
"#;
        let key_pem = r#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKLpmltYP2oimD2jpYBVrigM0WyCYlNSqmINJr1d1NSv
-----END PRIVATE KEY-----"#;
        let descriptor_signing_key = SigningKey::from_pkcs8_pem(key_pem).unwrap();
        let expected = "6Fub0DA399AD4klrLBwcGy1BgyXr/6zNKuL8KJVSkPKxnSA50+xEk79QNZhtiUK+eYzZvr3XcbSbVbPZOvF6Ag";
        let sig = descriptor_signing_key.sign(raw.as_bytes());
        let res = general_purpose::STANDARD.encode(sig.to_vec());
        let res = res.trim_end_matches("=");
        assert_eq!(expected, res);
    }

    #[test]
    fn test_encrypt_layer() {
        let plaintext = r#"create2-formats 2
introduction-point BAAGlThAkiMpAhS/hhzpSj0jvkwZ1d91f+CgyLCK8AMgNzXf+kNIU48g7ud7y7nlxKROWuBVAkHSYs7h9cAUlvsBEiYHUwABIAF2AUYAAAAAAGkjKQ==
onion-key ntor YedoMGn7IN+3VAoilT+jRnABz+AgmQInHh7PHLBwC24=
auth-key
-----BEGIN ED25519 CERT-----
AQkABvouAXN8OvHQoq88nSwpHo+1CiRKCIRCqht4ogTSfJ6MXHO6AQAgBADpdmL5
jB9FTH/efQdCjogJa4F2/Xh9qJNiWmKWQYHdFCYd8lco4OQEbS7NwgJrcq6sV+ms
TWZkNicRGg8yJu6uvTTXEneihvXCyAn4kRRzSJ4hCONKi/tiJejW3NFfdA0=
-----END ED25519 CERT-----
enc-key ntor aWHswoiCAOTlD3+WWSKGxZ3XElBd6nZzi24oO7YrSH0=
enc-key-cert
-----BEGIN ED25519 CERT-----
AQsABvouAVlr1/Qx12bTxXNCRJQ2jXt8V+3uyNoTrfQ6/QswdshlAQAgBADpdmL5
jB9FTH/efQdCjogJa4F2/Xh9qJNiWmKWQYHdFBQyMdb7NgjKBdGOK+kevRmKPvoK
LPV9sVJQ/48XCeek1/rYc8jqOuMVFxsnLa3oxmfLPL9dlPCh1S/sEXGUpQI=
-----END ED25519 CERT-----
introduction-point AwAGLVZ8+CMpAhRgruojqFuDpAcxK1YKYEgqUBpriQMgyr1vqX1d4rSk9rpcXxtqNwiYpnY19xWWJfL5E3sxzAY=
onion-key ntor 7obm0nWaUCgF02QvZeA21rlN72s37zNBGsbGDbiCfiI=
auth-key
-----BEGIN ED25519 CERT-----
AQkABvouAZBY20E36Rb/fKCrIua9ZZ4dK3gD3KW1F/YOxvdBHQOoAQAgBADpdmL5
jB9FTH/efQdCjogJa4F2/Xh9qJNiWmKWQYHdFPyGK07f8FQtIvb8KA/0n1efaJLc
eOT9Md2YzFInGCK2EyaWh0V3oHzY9E42bH3oK1Quy2bsh52vZRD9ZytO9gs=
-----END ED25519 CERT-----
enc-key ntor kS9zhYTpIyRzwnF5v1rP1yJp09leeWteh0qLoS5AeRg=
enc-key-cert
-----BEGIN ED25519 CERT-----
AQsABvouAbprFSOzdg8+gGg/dcxnBrWL7qjqP0e6tDVXGiNpEx0jAQAgBADpdmL5
jB9FTH/efQdCjogJa4F2/Xh9qJNiWmKWQYHdFMV9kFU/67CPNNkPAPhG1naElKhb
f1l2zeC+G9aCHz+yt6YWl4XwLZX3/Zn8oVfsKqh7kZ0sVBk9MrZJ0uHLWQY=
-----END ED25519 CERT-----"#;
        let constant = b"hsdir-encrypted-data";
        let rev_counter = 3941516272i64;
        let subcred: [u8; 32] = general_purpose::STANDARD
            .decode("THfM+uAC89Iz6c2QKQkPKiLDTtyefDtly3XK2v6I4Bw=")
            .unwrap()
            .try_into()
            .unwrap();
        let blinded_key: [u8; 32] = general_purpose::STANDARD
            .decode("kF52SVmH3sjdhvAl+tUnkkL3CUmM8whsH/IVi7rPCGc=")
            .unwrap()
            .try_into()
            .unwrap();
        let salt: [u8; 16] = general_purpose::STANDARD.decode("k7tTh3kl++/nBCMDqutU7A==").unwrap().try_into().unwrap();
        let expected = r#"-----BEGIN MESSAGE-----
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
-----END MESSAGE-----"#;
        assert_eq!(
            expected,
            encrypt_layer_det(
                plaintext.as_bytes().to_vec(),
                constant,
                rev_counter,
                subcred,
                blinded_key,
                salt
            ).unwrap()
        )
    }

    #[test]
    fn test_outer_layer_decrypt() {
        let input = r#"hs-descriptor 3
descriptor-lifetime 180
descriptor-signing-key-cert
-----BEGIN ED25519 CERT-----
AQgABvnFAeCcUpUD6iALxxDA8uNbDKfwXd9jqkwhsjsT4c+domasAQAgBAAmDKQR
Mq6QlSuutBkP7pHoQ5TxZsg+UDMSCRJVlg4ADo0S4nsE/Xxl26g48b3mi0FHZXrN
WFZYeHCffGSLtSoe8Ygs39DNYBdmEQFlC4Z0h+6zDxgoC+2SDR3osfPnqQs=
-----END ED25519 CERT-----
revision-counter 2697567517
superencrypted
-----BEGIN MESSAGE-----
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
HSDmrKf1ui6SsCDDyx/CjQ==
-----END MESSAGE-----
signature 6HuMoXXT4TATNIUM6SBmf9tUqGbN1QUijuxEHbauFUX2PBJC6Pdsz76ofkD/WyOkg1n+YhTO14sAqVJ4LoUzAQ
.
"#;
        let desc = desc_from_str(input).unwrap();
        let cert_b64 = r#"-----BEGIN ED25519 CERT-----
AQgABvnFAeCcUpUD6iALxxDA8uNbDKfwXd9jqkwhsjsT4c+domasAQAgBAAmDKQR
Mq6QlSuutBkP7pHoQ5TxZsg+UDMSCRJVlg4ADo0S4nsE/Xxl26g48b3mi0FHZXrN
WFZYeHCffGSLtSoe8Ygs39DNYBdmEQFlC4Z0h+6zDxgoC+2SDR3osfPnqQs=
-----END ED25519 CERT-----"#;
        let cert = Ed25519CertificateV1::from_base64(cert_b64).unwrap();
        let content = r#"-----BEGIN MESSAGE-----
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
HSDmrKf1ui6SsCDDyx/CjQ==
-----END MESSAGE-----"#;

        let blinded_key = cert.signing_key().unwrap();
        let onion_address = "o5fke5yq63krmfy5nxqatnykru664qgohrvhzalielqavpo4sut6kvad";
        let identity_public_key = identity_key_from_address(onion_address).unwrap();
        let subcred = subcredential(identity_public_key, &blinded_key);

        let outer_layer = outer_layer_decrypt(content, desc.revision_counter, subcred, blinded_key.to_bytes()).unwrap();
        let inner_layer = inner_layer_decrypt(
            outer_layer.clone(),
            desc.revision_counter,
            subcred,
            blinded_key.to_bytes(),
        ).unwrap();

        assert_eq!("desc-auth-type", &outer_layer.raw_content[..14]);
        assert_eq!("create2-formats", &inner_layer.raw_contents[..15]);
    }

    #[test]
    fn test_parse_v3_introduction_points() {
        let content = r#"introduction-point BAAGwiSTfSMpAhTjC++XJJRDiXqgUeCmQxBnP/Y1SAMgC89MYeKtbLhpyTfEJZXVbWuh1KdLDXs8JKVXXYXOReEBEioDQAAATQ94mMoC//41eY0jKQ==
onion-key ntor n9wQohcG3A8i023782tpzJtPrdEL+kd+L+wx5eAdwFE=
auth-key
-----BEGIN ED25519 CERT-----
AQkAB1KSAb2BZFtJaxPBEL5uhIaVc5iV2+TAIMtGcA15uaOP+eNWAQAgBACAehOA
P90yGLFGVw+vlOFC82F1HNw47F81lJrUHPJEcolxEGLiKFCg6InFB+nDre/6pivW
JSvogFMocOxhsLrw6+2M38to6NLHWeiSaM/sKmHOMtFPl28X/FhPH79GvAw=
-----END ED25519 CERT-----
enc-key ntor zSi+lP5Zt6DvYjhDQfmNNj0SUiDqdUBMC9BHvDxMV1c=
enc-key-cert
-----BEGIN ED25519 CERT-----
AQsAB1KSAbluRsblFvffymIAi00xrkGy1Dot2GLBWKYOsz370MJdAQAgBACAehOA
P90yGLFGVw+vlOFC82F1HNw47F81lJrUHPJEcu2FiIFyZ4N2A95RxLoEls0FtwD7
v9LPXJgvectbQ7Y8uZCCd48f56m8L8BVSPr4dIs1b35/i6oVHo7h9kJkaQk=
-----END ED25519 CERT-----
introduction-point BAAGwqTFLQG7AhRJ0iiMNu14/wfBegsvVnPbwd8xZAMgqezCUrX5ChhgfjhlyRU/468OinWuAUucT+TOyUNh7AABEioBAjkCKdMAAAAAAAAAAAEBuw==
onion-key ntor ZH9fjkt7T29P08YbhJwhLH3Ln+cFnqlTWXPzBEcpWz4=
auth-key
-----BEGIN ED25519 CERT-----
AQkAB1KSAaJqY0dvDnJtJCsGkR/dcb9kTCJyqTbK3Emph8G8f2n4AQAgBACAehOA
P90yGLFGVw+vlOFC82F1HNw47F81lJrUHPJEcgBrLb5jsu2OYkkT2OKy2mTnMwST
Flb8bxQF8WX01dw1rTXArcyPf9GQmP9IHAMWl99OodAeIFE9UBV5sKMTnQo=
-----END ED25519 CERT-----
enc-key ntor cme47j+kAkAZTKk7b5vnDjbiHUxDFVBG9F0kbwwaWHQ=
enc-key-cert
-----BEGIN ED25519 CERT-----
AQsAB1KSAdQ1i6QEj8LFRT3nrInxUHjcGii22zWN3hMd9LjnkKtMAQAgBACAehOA
P90yGLFGVw+vlOFC82F1HNw47F81lJrUHPJEcr+b+SQdbn8dGEWuWL6m3Lo3Ze63
D6exGaSWKB8gbeEoDr905uPL6rZ5lE/OsxbBA9bNroJnvl0QZfdY+BXVKgc=
-----END ED25519 CERT-----
introduction-point BAAGublQeJm3AhTxHqP58A6V8ZJh2pPWZ5RMT5y1/AMg4g9V4wWyeXLebziOpmmn7da3VL8Zlt5iz6vp6nYeddsBEioCwgYhdkOHAAAAAAAAAAGGew==
onion-key ntor sZyHIL1iB8nQ1zKFj+uNkoTGxO9UtjhM7lmDoop1+k8=
auth-key
-----BEGIN ED25519 CERT-----
AQkAB1KSAXhNz+cpH78bSKjRyGCQbwBRxnrAnq/jzouVkyDPLUHUAQAgBACAehOA
P90yGLFGVw+vlOFC82F1HNw47F81lJrUHPJEcrLZv8BcwqgGhQtc4CwTXJWYrYki
Uvf1MS1pb7IaIsJ7GOGlV/nilIT8vJmYXGa3HEVW8kj2D9ypucYS2uP/+gA=
-----END ED25519 CERT-----
enc-key ntor gzMqRUrtnGpFW/FXvLC1Xmk/b+eaM8vqRRTavY8A9BI=
enc-key-cert
-----BEGIN ED25519 CERT-----
AQsAB1KSAe9DvJNkKbRLoJqJJH2SXTMP2WL3xpb6T+EP1HZdVdV8AQAgBACAehOA
P90yGLFGVw+vlOFC82F1HNw47F81lJrUHPJEclKk1Mmagmglu2rV5j+9r57SKqGM
oMprlUVaNeySBifC7nLxCyY63v9DJXCk3dtx0W9MnB+q4rqfX3cBCveR0Q4=
-----END ED25519 CERT-----"#;
        let pts = parse_v3_introduction_points(content);
        assert_eq!(3, pts.len());
        assert_eq!(4, pts[0].link_specifiers.len());
        assert_eq!(4, pts[1].link_specifiers.len());
        assert_eq!(4, pts[2].link_specifiers.len());
    }

    #[test]
    fn test_address_from_identity_key() {
        let orig_address = "o5fke5yq63krmfy5nxqatnykru664qgohrvhzalielqavpo4sut6kvad.onion";
        let pub_key = identity_key_from_address(orig_address).unwrap();
        let address = address_from_identity_key(&pub_key);
        assert_eq!(orig_address, address);
    }

    #[test]
    fn test_hidden_service_descriptor_v3_string() {
        let mut d = HiddenServiceDescriptorV3::default();
        d.base.base.descriptor_signing_key_cert = "some_signing_key_cert".to_owned();
        d.base.base.superencrypted = "some_superencrypted".to_owned();
        d.base.base.signature = "some_signature".to_owned();
        let result = d.string();
        let expected = "hs-descriptor 3\n\
        descriptor-lifetime 0\n\
        descriptor-signing-key-cert\n\
        some_signing_key_cert\n\
        revision-counter 0\n\
        superencrypted\n\
        some_superencrypted\n\
        signature some_signature";
        assert_eq!(expected, result);
    }
}
