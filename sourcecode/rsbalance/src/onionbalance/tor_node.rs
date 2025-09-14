use std::error::Error;
use std::fmt::{Display, Formatter};
use crate::onionbalance::consensus;
use crate::onionbalance::consensus::Consensus;
use crate::onionbalance::controller::MicroDescriptor;
use base64::{engine::general_purpose, Engine as _};
use sha3::Digest;
use sha3::Sha3_256;
use tor_netdoc::doc::netstatus::RouterStatus;
use tor_netdoc::doc::netstatus::{MdConsensusRouterStatus, RelayFlags};

#[derive(Clone)]
pub struct TorNode {
    microdescriptor: MicroDescriptor,
    pub routerstatus: MdConsensusRouterStatus,
}

impl TorNode {
    pub fn new(microdescriptor: MicroDescriptor, routerstatus: MdConsensusRouterStatus) -> Self {
        let tor_node = Self { microdescriptor, routerstatus };
        debug!("Initializing node with fpr {}", tor_node.get_hex_fingerprint());
        tor_node
    }
}

#[derive(Debug)]
pub enum TorNodeErr {
    ErrNoHSDir,
    ErrNoEd25519Identity,
}

impl Display for TorNodeErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for TorNodeErr {}

impl TorNode {
    pub fn get_hsdir_index(
        &self,
        srv: &Vec<u8>,
        period_num: u64,
        consensus: &Consensus,
    ) -> Result<[u8; 32], TorNodeErr> {
        // See if this node can be an HSDir (it needs to be supported both in
        // protover and in flags)
        if !self.routerstatus.flags().contains(RelayFlags::HSDIR) {
            return Err(TorNodeErr::ErrNoHSDir);
        }

        // See if ed25519 identity is supported for this node
        let Some(ed25519_value) = self.microdescriptor.identifiers.get("ed25519") else {
            return Err(TorNodeErr::ErrNoEd25519Identity);
        };

        // In stem the ed25519 identity is a base64 string and we need to add
        // the missing padding so that the python base64 module can successfully
        // decode it.
        // TODO: Abstract this into its own function...
        let mut ed25519_node_identity_b64 = ed25519_value.clone();
        let padding = (4 - ed25519_node_identity_b64.len() % 4) % 4;
        ed25519_node_identity_b64 += &"=".repeat(padding);
        let Ok(ed25519_node_identity) = general_purpose::STANDARD.decode(ed25519_node_identity_b64) else {
            return Err(TorNodeErr::ErrNoEd25519Identity);
        };
        let period_num_int8: [u8; 8] = period_num.to_be_bytes();
        let period_length = consensus.get_time_period_length();
        let period_length_int8: [u8; 8] = period_length.to_be_bytes();
        let mut hash_body = Vec::<u8>::new();
        hash_body.extend(b"node-idx");
        hash_body.extend(ed25519_node_identity);
        hash_body.extend(srv);
        hash_body.extend(period_num_int8);
        hash_body.extend(period_length_int8);
        let mut hasher = Sha3_256::new();
        hasher.update(hash_body);
        let hsdir_index: [u8; 32] = hasher.finalize().into();
        Ok(hsdir_index)
    }

    pub fn get_hex_fingerprint(&self) -> consensus::Fingerprint {
        let identity = &self.routerstatus.rsa_identity().to_string();
        crate::utils::strip_prefix(identity,"$").to_uppercase()
    }
}
