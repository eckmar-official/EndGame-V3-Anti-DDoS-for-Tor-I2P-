use crate::onionbalance::descriptor::{Ed25519Extension, HAS_SIGNING_KEY};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, TimeZone, Utc};
use std::ops::Add;
use anyhow::{bail, ensure};
use ed25519_dalek::Signer;
use ed25519_dalek::VerifyingKey;
use ed25519_dalek::SigningKey;
use x509_parser::nom::AsBytes;

const LINK: u8 = 1;
const IDENTITY: u8 = 2;
const AUTHENTICATE: u8 = 3;
const ED25519_IDENTITY: u8 = 7;
pub const HS_V3DESC_SIGNING: u8 = 8;
const HS_V3INTRO_AUTH: u8 = 9;
const HS_V3NTOR_ENC: u8 = 11;

const ED25519_KEY_LENGTH: usize = 32;
const ED25519_HEADER_LENGTH: usize = 40;
const ED25519_SIGNATURE_LENGTH: usize = 64;

#[derive(Default, Clone, Debug)]
pub struct Ed25519Certificate {
    pub version: u8,
}

#[derive(Default, Clone, Debug)]
pub struct Ed25519CertificateV1 {
    pub base: Ed25519Certificate,
    pub typ: u8,
    pub expiration: DateTime<Utc>,
    pub key_type: u8,
    pub key: VerifyingKey,
    pub extensions: Vec<Ed25519Extension>,
    pub signature: Option<Vec<u8>>,
}

const DEFAULT_EXPIRATION_HOURS: i64 = 54; // HSv3 certificate expiration of tor

impl Ed25519CertificateV1 {
    pub fn new(
        cert_type: u8,
        expiration_in: Option<DateTime<Utc>>,
        key_type: u8,
        key: VerifyingKey,
        extensions: Vec<Ed25519Extension>,
        signing_key: Option<&SigningKey>,
        signature: Option<Vec<u8>>,
    ) -> anyhow::Result<Self> {
        match cert_type {
            HS_V3DESC_SIGNING | HS_V3INTRO_AUTH | HS_V3NTOR_ENC => {},
            LINK | IDENTITY | AUTHENTICATE => bail!("Ed25519 certificate cannot have a type of {}. This is reserved for CERTS cells.", cert_type),
            ED25519_IDENTITY => bail!("Ed25519 certificate cannot have a type of 7. This is reserved for RSA identity cross-certification."),
            0 => bail!("Certificate type is required"),
            _ => bail!("Ed25519 certificate type {} is unrecognized", cert_type),
        }
        let expiration = expiration_in.unwrap_or(Utc::now().add(chrono::Duration::seconds(DEFAULT_EXPIRATION_HOURS * 60 * 60)));
        let base = Ed25519Certificate { version: 1 };
        let typ = cert_type;
        let mut out = Self { base, typ, expiration, key_type, key, extensions, signature };
        /*
           // if caller provides both signing key *and* signature then ensure they match
           if self.signature and self.signature != calculated_sig:
             raise ValueError("Signature calculated from its key (%s) mismatches '%s'" % (calculated_sig, self.signature))
        */
        if let Some(signing_key) = signing_key {
            let calculated_sig = signing_key.sign(&out.pack());
            out.signature = Some(calculated_sig.to_bytes().to_vec());
        }
        Ok(out)
    }

    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.base.version);
        out.push(self.typ);
        let expiration = (self.expiration.timestamp() / 3600) as u32;
        out.extend(expiration.to_be_bytes());
        out.push(self.key_type);
        out.extend(self.key.to_bytes());
        out.push(self.extensions.len() as u8);
        for ext in &self.extensions {
            out.extend(ext.pack());
        }
        if let Some(signature) = &self.signature {
            out.extend(signature);
        }
        out
    }

    pub fn to_base64(&self) -> String {
        let b64 = split_by_length(&general_purpose::STANDARD.encode(self.pack()), 64).join("\n");
        format!("-----BEGIN ED25519 CERT-----\n{b64}\n-----END ED25519 CERT-----")
    }

    pub fn unpack(content: &[u8]) -> anyhow::Result<Self> {
        ensure!(content.len() >= ED25519_HEADER_LENGTH + ED25519_SIGNATURE_LENGTH, "Ed25519 certificate was {} bytes, but should be at least {}", content.len(), ED25519_HEADER_LENGTH + ED25519_SIGNATURE_LENGTH);
        let (header, signature) = (
            &content[..content.len() - ED25519_SIGNATURE_LENGTH],
            &content[content.len() - ED25519_SIGNATURE_LENGTH..],
        );
        let (version, header) = (header[0], &header[1..]);
        ensure!(version == 1, "Ed25519 certificate is version {version}. Parser presently only supports version 1.");
        let (cert_type, header) = (header[0], &header[1..]);
        let (expiration_hours_raw, header) = (&header[..4], &header[4..]);
        let expiration_hours = u32::from_be_bytes(expiration_hours_raw.try_into()?) as i64;
        let (key_type, header) = (header[0], &header[1..]);
        let (key, header) = (&header[..ED25519_KEY_LENGTH], &header[ED25519_KEY_LENGTH..]);
        let (extension_count, extension_data) = (&header[0], &header[1..]);
        let mut extension_data = extension_data.to_vec();
        let mut extensions = Vec::new();
        for _ in 0..*extension_count {
            let (extension, extension_data1) = ed25519_extension_pop(&extension_data)?;
            extension_data = extension_data1;
            extensions.push(extension);
        }
        ensure!(extension_data.is_empty(), "Ed25519 certificate had {} bytes of unused extension data", extension_data.len());
        let expiration = Utc.timestamp_opt(expiration_hours * 3600, 0).unwrap();

        let pub_key = VerifyingKey::from_bytes(key.try_into()?)?;
        Ed25519CertificateV1::new(
            cert_type,
            Some(expiration),
            key_type,
            pub_key,
            extensions,
            None,
            Some(signature.to_vec()),
        )
    }

    pub fn from_base64(content: &str) -> anyhow::Result<Self> {
        let mut content = content.to_owned();
        const BEGIN_CERT: &str = "-----BEGIN ED25519 CERT-----\n";
        const END_CERT: &str = "\n-----END ED25519 CERT-----";
        content = crate::utils::strip_prefix(&content, BEGIN_CERT);
        content = crate::utils::strip_suffix(&content, END_CERT);
        content = content.replace('\n', "");
        let by = general_purpose::STANDARD.decode(content)?;
        Ed25519CertificateV1::unpack(&by)
    }

    pub fn signing_key(&self) -> anyhow::Result<VerifyingKey> {
        for ext in &self.extensions {
            if ext.typ == HAS_SIGNING_KEY {
                return Ok(VerifyingKey::from_bytes(ext.data.as_bytes().try_into()?)?);
            }
        }
        bail!("signing key not found")
    }
}

pub fn split_by_length(msg: &str, size: usize) -> Vec<String> {
    msg.chars()
        .collect::<Vec<_>>()
        .chunks(size)
        .map(|chunk| chunk.iter().collect())
        .collect()
}

fn ed25519_extension_pop(content: &[u8]) -> anyhow::Result<(Ed25519Extension, Vec<u8>)> {
    ensure!(content.len() >= 4, "Ed25519 extension is missing header fields");
    let (data_size_raw, content) = (&content[..2], &content[2..]);
    let data_size = u16::from_be_bytes(data_size_raw.try_into()?) as usize;
    let (ext_type, content) = (&content[0], &content[1..]);
    let (flags, content) = (&content[0], &content[1..]);
    let (data, content) = (&content[..data_size], &content[data_size..]);
    ensure!(data.len() == data_size, "Ed25519 extension is truncated. It should have {data_size} bytes of data but there's only {}.", data.len());
    Ok((Ed25519Extension::new(*ext_type, *flags, data)?, content.to_vec()))
}

#[cfg(test)]
mod tests {
    use crate::stem::descriptor::certificate::{ed25519_extension_pop, split_by_length, Ed25519CertificateV1};
    use base64::{engine::general_purpose, Engine as _};

    #[test]
    fn to_base64() {
        let cert_raw = r#"-----BEGIN ED25519 CERT-----
AQkABvnvASpbRl8c5Iwx+KYXIGHMA+66ZN88TppVrRqrwyZkv45UAQAgBABcfN7F
QCPKVVMMIsn/OMg/XEQjOhfiqBB7DDU36l7dR+vl8qUr8ApIEPse2nAPmz8EscmY
25grvptE/1o0mS1ynpEPmeFrGbUCVyWsntwLyn77bscvNdG8Mozov3bGFQU=
-----END ED25519 CERT-----"#;
        let cert = Ed25519CertificateV1::from_base64(cert_raw).unwrap();
        let new_cert = cert.to_base64();
        assert_eq!(cert_raw, new_cert);
    }

    #[test]
    fn test_ed25519_certificate_v1_pack() {
        let raw = "AQgABvnxAVx83sVAI8pVUwwiyf84yD9cRCM6F+KoEHsMNTfqXt1HAQAgBAB0tYzO/dvRZRujduw/KKmyulEhsEvjhVbhZ4ALCYkMgBpLO+hsNQqVdbTWvm5FrMZcyuCP4451WdpYlgOlsG8Mu3goFEM8B2KWQdzVpI69oq61geN5yzwnhO7zH/o1qwo=";
        let by1 = general_purpose::STANDARD.decode(raw).unwrap();
        let cert = Ed25519CertificateV1::unpack(&by1).unwrap();
        let by2 = cert.pack();
        assert_eq!(by1, by2);
    }

    #[test]
    fn test_ed25519_extension_pack() {
        let raw = "ACAEAHS1jM7929FlG6N27D8oqbK6USGwS+OFVuFngAsJiQyA";
        let by1 = general_purpose::STANDARD.decode(raw).unwrap();
        let (ext, _) = ed25519_extension_pop(&by1).unwrap();
        let by2 = ext.pack();
        assert_eq!(by1, by2);
    }

    #[test]
    fn test_split_by_length() {
        let msg = "1234567890123";
        let result = split_by_length(msg, 5);
        let expected = vec!["12345", "67890", "123"];
        assert_eq!(expected, result);
    }
}
