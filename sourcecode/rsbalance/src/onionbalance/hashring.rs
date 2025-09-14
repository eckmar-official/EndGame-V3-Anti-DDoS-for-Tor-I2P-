use crate::onionbalance::consensus::Consensus;
use crate::onionbalance::param::{HSDIR_N_REPLICAS};
use crate::onionbalance::tor_node::TorNode;
use base64::{engine::general_purpose, Engine as _};
use sha3::Digest;
use sha3::Sha3_256;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::time::UNIX_EPOCH;
use ed25519_dalek::VerifyingKey;
use crate::utils::fmt_first;

pub fn get_srv_and_time_period(is_first_desc: bool, consensus: &Consensus) -> (Vec<u8>, u64) {
    let valid_after = consensus
        .arti_consensus
        .as_ref()
        .expect("to have a consensus")
        .peek_lifetime()
        .valid_after()
        .duration_since(UNIX_EPOCH)
        .expect("Clock may have gone backwards")
        .as_secs();
    let current_tp = consensus.get_time_period_num(valid_after);
    let previous_tp = current_tp - 1;
    let next_tp = current_tp + 1;
    let time_between = time_between_tp_and_srv(valid_after, consensus);
    let (tp, srv, case) = match (is_first_desc, time_between) {
        (true, true) => {
            let tp = previous_tp;
            let srv = consensus.get_previous_srv(tp);
            (tp, srv, 1)
        },
        (true, false) => {
            let tp = current_tp;
            let srv = consensus.get_previous_srv(tp);
            (tp, srv, 2)
        },
        (false, true) => {
            let tp = current_tp;
            let srv = consensus.get_current_srv(tp);
            (tp, srv, 3)
        },
        (false, false) => {
            let tp = next_tp;
            let srv = consensus.get_current_srv(tp);
            (tp, srv, 4)
        },
    };
    let srv_b64 = general_purpose::STANDARD.encode(&srv);
    debug!("For valid_after {valid_after} we got SRV {srv_b64} and TP {tp} (case: #{case})");
    (srv, tp)
}

fn time_between_tp_and_srv(valid_after: u64, consensus: &Consensus) -> bool {
    let srv_start_time = consensus.get_start_time_of_current_srv_run();
    let tp_start_time = consensus.get_start_time_of_next_time_period(srv_start_time);
    if valid_after >= srv_start_time && valid_after < tp_start_time {
        debug!("We are between SRV and TP");
        return false;
    }
    debug!("We are between TP and SRV (valid_after: {valid_after}, srv_start_time: {srv_start_time} -> tp_start_time: {tp_start_time})");
    true
}

#[derive(Debug)]
pub enum HashRingErr {
    ErrEmptyHashRing,
    WrongNumber,
}

impl Display for HashRingErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for HashRingErr {}

// Return a list with the responsible HSDirs for a service with 'blinded_pubkey'.
// The returned list is a list of fingerprints.
pub fn get_responsible_hsdirs(
    blinded_pubkey: VerifyingKey,
    is_first_desc: bool,
    consensus: &Consensus,
) -> Result<Vec<String>, HashRingErr> {
    let hsdir_spread_store = consensus
        .arti_consensus
        .as_ref()
        .and_then(|consensus| consensus.consensus.params().get("hsdir_spread_store"))
        .map(|&value| value as usize)
        .unwrap_or(4);

    let mut responsible_hsdirs = Vec::new();

    // dictionary { <node hsdir index> : Node , .... }
    let node_hash_ring = get_hash_ring_for_descriptor(is_first_desc, consensus);
    if node_hash_ring.is_empty() {
        return Err(HashRingErr::ErrEmptyHashRing);
    }

    let mut sorted_hash_ring_list: Vec<_> = node_hash_ring.keys().collect();
    sorted_hash_ring_list.sort_unstable();

    info!("Initialized hash ring of size {} (blinded key: {})", node_hash_ring.len(), general_purpose::STANDARD.encode(blinded_pubkey));

    for replica_num in 1..=HSDIR_N_REPLICAS {
        // The HSDirs that we are gonna store this replica in
        let mut replica_store_hsdirs: Vec<String> = Vec::new();

        let hidden_service_index = get_hidden_service_index(blinded_pubkey, replica_num, is_first_desc, consensus);

        // Find position of descriptor ID in the HSDir list
        let hs_index_hex = hex::encode(&hidden_service_index);
        let mut index = sorted_hash_ring_list.binary_search(&&hs_index_hex).unwrap_or_else(|idx| idx);
        info!("\t Tried with HS index {hs_index_hex} got position {index}");

        while replica_store_hsdirs.len() < hsdir_spread_store {
            let wrapped_index = index % sorted_hash_ring_list.len(); // Wrap around when we reach the end of the HSDir list
            index += 1;
            let hsdir_key = sorted_hash_ring_list[wrapped_index];
            let hsdir_node = node_hash_ring.get(hsdir_key).expect("hsdir_key to exists");
            let hsdir_node_fingerprint = hsdir_node.get_hex_fingerprint();

            // Check if we have already added this node to this
            // replica. This should never happen on the real network but
            // might happen in small testnets like chutney!
            if replica_store_hsdirs.contains(&hsdir_node_fingerprint) {
                debug!("Ignoring already added HSDir to this replica!");
                break;
            }

            debug!("{wrapped_index}: {hsdir_node_fingerprint}: {hsdir_key}");

            replica_store_hsdirs.push(hsdir_node_fingerprint);
        }

        responsible_hsdirs.extend(replica_store_hsdirs);
    }

    // Do a sanity check
    if responsible_hsdirs.len() != HSDIR_N_REPLICAS * hsdir_spread_store {
        panic!("Got the wrong number of responsible HSDirs: {}. Aborting", responsible_hsdirs.len())
    }

    Ok(responsible_hsdirs)
}

fn get_hidden_service_index(
    blinded_pubkey: VerifyingKey,
    replica_num: usize,
    is_first_desc: bool,
    consensus: &Consensus,
) -> [u8; 32] {
    let period_length = consensus.get_time_period_length();
    let replica_num_int8: [u8; 8] = replica_num.to_be_bytes();
    let period_length_int8: [u8; 8] = period_length.to_be_bytes();
    let (_, time_period_num) = get_srv_and_time_period(is_first_desc, consensus);
    info!("Getting HS index with TP#{time_period_num} for {} descriptor ({replica_num} replica) ", fmt_first(is_first_desc));
    let period_num_int8: [u8; 8] = time_period_num.to_be_bytes();
    let mut hash_body = Vec::<u8>::new();
    hash_body.extend(b"store-at-idx");
    hash_body.extend(blinded_pubkey.as_bytes());
    hash_body.extend(replica_num_int8);
    hash_body.extend(period_length_int8);
    hash_body.extend(period_num_int8);
    let mut hasher = Sha3_256::new();
    hasher.update(hash_body);
    let hs_index: [u8; 32] = hasher.finalize().into();
    hs_index
}

// Return a dictionary { <node hsdir index> : Node , .... }
fn get_hash_ring_for_descriptor(is_first_desc: bool, consensus: &Consensus) -> HashMap<String, TorNode> {
    let mut node_hash_ring = HashMap::<String, TorNode>::new();
    let (srv, time_period_num) = get_srv_and_time_period(is_first_desc, &consensus);
    info!("Using srv {} and TP#{time_period_num} ({} descriptor)", hex::encode(&srv), fmt_first(is_first_desc));
    for node in &consensus.nodes {
        let fingerprint = node.get_hex_fingerprint();
        let hsdir_index = match node.get_hsdir_index(&srv, time_period_num, consensus) {
            Ok(hsdir_index) => hsdir_index,
            Err(err) => {
                debug!("Could not find ed25519 for node {fingerprint} ({err})");
                continue;
            }
        };
        let index = hex::encode(&hsdir_index);
        debug!("{}: Node: {fingerprint},  index: {index}", fmt_first(is_first_desc));
        node_hash_ring.insert(index, node.clone());
    }
    node_hash_ring
}
