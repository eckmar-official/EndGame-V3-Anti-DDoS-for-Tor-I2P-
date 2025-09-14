use crate::onionbalance::controller::{Controller, MicroDescriptor};
use crate::onionbalance::tor_node::TorNode;
use base64::{engine::general_purpose, Engine as _};
use sha3::Digest;
use sha3::Sha3_256;
use std::collections::HashMap;
use std::ops::{Add, Sub};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use anyhow::{ensure, Context};
use ed25519_dalek::VerifyingKey;
use tokio::sync::Mutex;
use tor_checkable::Timebound;
use tor_netdoc::doc::netstatus::{MdConsensus, MdConsensusRouterStatus, UnvalidatedConsensus, RouterStatus};

#[derive(Clone)]
pub struct Consensus {
    pub nodes: Vec<TorNode>,
    controller: Arc<Mutex<Controller>>,
    pub arti_consensus: Option<UnvalidatedConsensus<MdConsensusRouterStatus>>,
}

impl Consensus {
    pub fn new(controller: Arc<Mutex<Controller>>) -> Self {
        Self {
            controller,
            nodes: Vec::new(),
            arti_consensus: None,
        }
    }

    pub async fn refresh(&mut self) {
        let md_consensus_str = self.controller.lock().await.get_md_consensus().await.unwrap_or_default();
        self.arti_consensus = match network_status_document_v3(&md_consensus_str).await {
            Ok(v) => Some(v),
            Err(_) => {
                error!("No valid consensus received. Waiting for one...");
                return;
            },
        };
        if !self.is_live() {
            info!("Loaded consensus is not live. Waiting for a live one.");
            return;
        }
        self.nodes = self.initialize_nodes().await.unwrap_or_default();
    }

    async fn initialize_nodes(&self) -> anyhow::Result<Vec<TorNode>> {
        let mut nodes = Vec::new();
        let microdescriptors_list = match self.controller.lock().await.get_microdescriptors().await {
            Ok(microdescriptors_list) => microdescriptors_list,
            Err(_) => {
                warn!("Can't get microdescriptors from Tor. Delaying...");
                return Ok(nodes);
            }
        };
        // Turn the mds into a dictionary indexed by the digest as an
        // optimization while matching them with routerstatuses.
        let microdescriptors_dict: HashMap<String, MicroDescriptor> = microdescriptors_list.into_iter().map(|md| (md.digest(), md)).collect();

        // Go through the routerstatuses and match them up with
        // microdescriptors, and create a Node object for each match. If there
        // is no match we don't register it as a node.
        for (fingerprint, relay_router_status) in self.get_router_statuses()? {
            let microdescriptor_digest = general_purpose::STANDARD.encode(relay_router_status.md_digest()).trim_end_matches("=").to_owned();
            debug!("Checking routerstatus with md digest {microdescriptor_digest}");
            if let Some(node_microdescriptor) = microdescriptors_dict.get(&microdescriptor_digest) {
                let node = TorNode::new(node_microdescriptor.clone(), relay_router_status);
                nodes.push(node);
            } else {
                debug!("Could not find microdesc for rs with fpr {fingerprint}");
                continue;
            }
        }
        Ok(nodes)
    }

    fn get_router_statuses(&self) -> anyhow::Result<HashMap<String, MdConsensusRouterStatus>> {
        ensure!(self.is_live(), "get_router_statuses and not live");
        let relays: &[MdConsensusRouterStatus] = self.arti_consensus.as_ref().context("no consensus")?.consensus.relays();
        let mut out = HashMap::new();
        for relay in relays {
            let fingerprint = relay.rsa_identity().to_string().strip_prefix("$").context("no $ prefix")?.to_uppercase();
            out.insert(fingerprint, relay.clone());
        }
        Ok(out)
    }

    pub fn is_live(&self) -> bool {
        let Some(consensus) = &self.arti_consensus else {
            return false;
        };
        let lifetime = consensus.peek_lifetime();
        let reasonably_live_time = 24 * 60 * 60;
        let now = SystemTime::now();
        let valid_after = lifetime.valid_after();
        let valid_until = lifetime.valid_until();
        let is_live: bool = now >= valid_after.sub(Duration::from_secs(reasonably_live_time)) &&
                            now <= valid_until.add(Duration::from_secs(reasonably_live_time));
        is_live
    }

    // get_time_period_num get time period number for this 'valid_after'.
    //
    // valid_after is a datetime (if not set, we get it ourselves)
    // time_period_length set to default value of 1440 minutes == 1 day
    pub fn get_time_period_num(&self, valid_after: u64) -> u64 {
        let time_period_length = self.get_time_period_length();
        let seconds_since_epoch = valid_after;
        let mut minutes_since_epoch = seconds_since_epoch / 60;
        // Calculate offset as specified in rend-spec-v3.txt [TIME-PERIODS]
        let time_period_rotation_offset = self.get_srv_phase_duration();
        // assert(minutes_since_epoch > time_period_rotation_offset)
        minutes_since_epoch -= time_period_rotation_offset;
        let time_period_num = minutes_since_epoch / time_period_length;
        time_period_num
    }

    pub fn get_time_period_length(&self) -> u64 {
        24 * 60
    }

    fn get_srv_phase_duration(&self) -> u64 {
        12 * 60
    }

    pub fn get_start_time_of_previous_srv_run(&self) -> u64 {
        let start_time_of_current_run = self.get_start_time_of_current_srv_run();
        start_time_of_current_run - 24 * 3600
    }

    pub fn get_start_time_of_current_srv_run(&self) -> u64 {
        let beginning_of_current_round = self
            .arti_consensus
            .as_ref()
            .expect("to have a consensus")
            .peek_lifetime()
            .valid_after()
            .duration_since(UNIX_EPOCH)
            .expect("Clock may have gone backwards")
            .as_secs();
        let voting_interval_secs = 60 * 60;
        let curr_round_slot = (beginning_of_current_round / voting_interval_secs) % 24;
        let time_elapsed_since_start_of_run = curr_round_slot * voting_interval_secs;
        debug!("Current SRV proto run: Start of current round: {beginning_of_current_round}. Time elapsed: {time_elapsed_since_start_of_run} ({voting_interval_secs})");
        beginning_of_current_round - time_elapsed_since_start_of_run
    }

    // Return the start time of the upcoming time period
    pub fn get_start_time_of_next_time_period(&self, valid_after: u64) -> u64 {
        // Get start time of next time period
        let time_period_length = self.get_time_period_length();
        let next_time_period_num = self.get_next_time_period_num(valid_after);
        let start_of_next_tp_in_mins = next_time_period_num * time_period_length;
        // Apply rotation offset as specified by prop224 section [TIME-PERIODS]
        let time_period_rotation_offset = self.get_srv_phase_duration();
        (start_of_next_tp_in_mins + time_period_rotation_offset) * 60
    }

    fn get_next_time_period_num(&self, valid_after: u64) -> u64 {
        self.get_time_period_num(valid_after) + 1
    }

    fn get_srv<F>(&self, time_period_num: u64, get_shared_rand: F) -> Vec<u8>
    where
        F: Fn(&Self) -> Vec<u8>,
    {
        let shared_rand = get_shared_rand(self);
        if !shared_rand.is_empty() {
            shared_rand
        } else if time_period_num != 0 {
            info!("SRV not found so falling back to disaster mode");
            self.get_disaster_srv(time_period_num).to_vec()
        } else {
            Vec::new()
        }
    }

    pub fn get_previous_srv(&self, time_period_num: u64) -> Vec<u8> {
        self.get_srv(time_period_num, Self::get_shared_rand_prev)
    }

    pub fn get_current_srv(&self, time_period_num: u64) -> Vec<u8> {
        self.get_srv(time_period_num, Self::get_shared_rand_cur)
    }

    pub fn get_blinding_param(&self, identity_pubkey: VerifyingKey, time_period_number: u64) -> [u8; 32] {
        get_blinding_param(identity_pubkey, time_period_number, self.get_time_period_length())
    }

    // Return disaster SRV for 'timePeriodNum'.
    fn get_disaster_srv(&self, time_period_num: u64) -> [u8; 32] {
        let time_period_length = self.get_time_period_length();
        let data = time_period_length.to_be_bytes();
        let data1 = time_period_num.to_be_bytes();
        let mut disaster_body = Vec::<u8>::new();
        disaster_body.extend(b"shared-random-disaster");
        disaster_body.extend(data);
        disaster_body.extend(data1);
        let mut hasher = Sha3_256::new();
        hasher.update(disaster_body);
        hasher.finalize().into()
    }

    pub fn get_shared_rand_cur(&self) -> Vec<u8> {
        self.arti_consensus.as_ref()
            .and_then(|arti_consensus| arti_consensus.consensus.header.shared_rand_cur.as_ref())
            .map(|shared_rand| shared_rand.value.as_ref().to_vec())
            .unwrap_or_default()
    }

    pub fn get_shared_rand_prev(&self) -> Vec<u8> {
        self.arti_consensus.as_ref()
            .and_then(|arti_consensus| arti_consensus.consensus.header.shared_rand_prev.as_ref())
            .map(|shared_rand| shared_rand.value.as_ref().to_vec())
            .unwrap_or_default()
    }
}

async fn network_status_document_v3(md_consensus_str: &str) -> anyhow::Result<UnvalidatedConsensus<MdConsensusRouterStatus>> {
    let md_consensus_str = md_consensus_str.replace("\r", "");
    let (_, _, consensus) = MdConsensus::parse(&md_consensus_str)?;
    let consensus = consensus.check_valid_now()?;
    Ok(consensus)
}

pub type Fingerprint = String;

// Calculate the HSv3 blinding parameter as specified in rend-spec-v3.txt section A.2:
//
// h = H(BLIND_STRING | A | s | B | N)
// BLIND_STRING = "Derive temporary signing key" | INT_1(0)
// N = "key-blind" | INT_8(period-number) | INT_8(period_length)
// B = "(1511[...]2202, 4631[...]5960)"
//
// Use the time period number in 'time_period_number'.
pub fn get_blinding_param(
    identity_pubkey: VerifyingKey,
    time_period_number: u64,
    period_length: u64,
) -> [u8; 32] {
    let ed25519_basepoint = format!(
        "({}{}, {}{})",
        "15112221349535400772501151409588531511",
        "454012693041857206046113283949847762202",
        "463168356949264781694283940034751631413",
        "07993866256225615783033603165251855960"
    );
    let blind_string = b"Derive temporary signing key\x00";
    let data1 = time_period_number.to_be_bytes();
    let data2 = period_length.to_be_bytes();
    let mut n = Vec::<u8>::new();
    n.extend(b"key-blind");
    n.extend(data1);
    n.extend(data2);
    let mut to_enc = Vec::<u8>::new();
    to_enc.extend(blind_string);
    to_enc.extend(identity_pubkey.as_bytes());
    to_enc.extend(ed25519_basepoint.as_bytes());
    to_enc.extend(n);
    let mut hasher = Sha3_256::new();
    hasher.update(to_enc);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use crate::onionbalance::consensus::get_blinding_param;
    use base64::{engine::general_purpose, Engine as _};
    use ed25519_dalek::VerifyingKey;

    #[test]
    fn test_get_blinding_param() {
        let pk = general_purpose::STANDARD.decode("uDrHFYt+kWkB4vCkoXKFXUTm6LxOihUvAkq70nAqgy4=").unwrap();
        let expected = general_purpose::STANDARD.decode("JCh98DUfWVZlOjOIzgXwMrVvn+27hg1dXTjMO520OYY=").unwrap();
        let actual = get_blinding_param(
            VerifyingKey::from_bytes(&pk.try_into().unwrap()).unwrap(),
            19408,
            24 * 60,
        );
        assert_eq!(expected, actual);
    }
}
