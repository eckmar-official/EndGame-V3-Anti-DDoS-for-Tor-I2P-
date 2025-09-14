use crate::onionbalance::config::ServiceConfig;
use crate::onionbalance::consensus::Consensus;
use crate::onionbalance::controller::{Controller, ControllerErr};
use crate::onionbalance::descriptor::{IntroductionPointSetV3, OBDescriptor};
use crate::onionbalance::hashring::{get_responsible_hsdirs, get_srv_and_time_period, HashRingErr};
use crate::onionbalance::hs_v3::ext::ed_25519_exts_ref;
use crate::onionbalance::instance::{Instance, InstanceErr};
use crate::onionbalance::param::FRONTEND_DESCRIPTOR_LIFETIME;
use crate::onionbalance::{param, tor_ed25519};
use crate::rsbpk;
use crate::stem::descriptor::hidden_service::{
    address_from_identity_key, HiddenServiceDescriptorV3, IntroductionPointV3,
};
use crate::stem::util;
use chrono::Utc;
use std::sync::Arc;
use anyhow::{bail, Context};
use ed25519_dalek::VerifyingKey;
use tokio::sync::Mutex;
use x509_parser::nom::AsBytes;
use crate::utils::fmt_first;

pub struct Service {
    controller: Arc<Mutex<Controller>>,
    pub instances: Vec<Instance>,
    identity_priv_key: rsbpk::PrivateKey,
    onion_address: String,
    first_descriptor: Option<OBDescriptor>,
    second_descriptor: Option<OBDescriptor>,
}

fn load_service_keys(service_config_data: &ServiceConfig, config_path: &str) -> anyhow::Result<(rsbpk::PrivateKey, String)> {
    // First of all let's load up the private key
    let key_file_name = &service_config_data.key;
    let p = std::path::PathBuf::from(config_path);
    let abs = std::fs::canonicalize(&p)?;
    let config_directory = abs.parent().context("no parent")?;
    let pp = config_directory.join(key_file_name);
    let pem_key_bytes = std::fs::read(&pp)?;
    if pem_key_bytes.starts_with("== ed25519v1-secret: type0 ==".as_bytes()) {
        let esk = tor_ed25519::load_tor_key_from_disk(&pem_key_bytes)?;
        let tmp = ed_25519_exts_ref::publickey_from_esk(&esk);
        let eid = VerifyingKey::from_bytes(&tmp)?;
        let onion_address = address_from_identity_key(&eid);
        warn!("Loaded onion {onion_address} from {key_file_name}");
        let priv_key = rsbpk::PrivateKey::new(&esk, true);
        return Ok((priv_key, onion_address));
    }

    let pem = x509_parser::pem::parse_x509_pem(pem_key_bytes.as_bytes())?;
    let sk = &pem.1.contents.as_bytes()[16..].try_into()?;
    let priv_key = rsbpk::PrivateKey::new(&sk, false);
    Ok((priv_key, String::new()))
}

fn load_instances(
    onion_address: &str,
    controller: Arc<Mutex<Controller>>,
    service_config_data: &ServiceConfig,
) -> anyhow::Result<Vec<Instance>> {
    let mut instances = Vec::new();
    for config_instance in &service_config_data.instances {
        let new_instance = Instance::new(controller.clone(), &config_instance.address);
        instances.push(new_instance)
    }

    // Some basic validation
    for instance in &instances {
        if instance.onion_address == onion_address {
            error!("Config file error. Did you configure your frontend ({onion_address}) as an instance?");
            bail!("BadServiceInit");
        }
    }
    Ok(instances)
}

pub enum ServiceErr {
    ErrNotEnoughIntros,
}

impl Service {
    pub fn new(
        controller: Arc<Mutex<Controller>>,
        service_config_data: &ServiceConfig,
        config_path: &str,
    ) -> anyhow::Result<Self> {
        // Load private key and onion address from config
        // (the onion_address also includes the ".onion")
        let (identity_priv_key, onion_address) = load_service_keys(service_config_data, config_path)?;

        // Now load up the instances
        let instances = load_instances(&onion_address, controller.clone(), service_config_data)?;

        Ok(Self {
            controller,
            instances,
            identity_priv_key,
            onion_address,
            first_descriptor: None, // First descriptor for this service (the one we uploaded last)
            second_descriptor: None, // Second descriptor for this service (the one we uploaded last)
        })
    }

    pub async fn publish_descriptors(&mut self, force_publish: bool, consensus: &Consensus) {
        self.publish_descriptor(true, force_publish, consensus).await;
        self.publish_descriptor(false, force_publish, consensus).await;
    }

    // HasOnionAddress Return True if this service has this onion address
    pub fn has_onion_address(&self, onion_address: &str) -> bool {
        // Strip the ".onion" part of the address if it exists since some
        // subsystems don't use it (e.g. Tor sometimes omits it from control
        // port responses)
        let my_onion_address = self.onion_address.trim_end_matches(".onion");
        let their_onion_address = onion_address.trim_end_matches(".onion");
        my_onion_address == their_onion_address
    }

    pub async fn publish_descriptor(&mut self, is_first_desc: bool, force_publish: bool, consensus: &Consensus) {
        if !self.should_publish_descriptor_now(is_first_desc, &consensus, force_publish) {
            info!("No reason to publish {} descriptor for {}", fmt_first(is_first_desc), self.onion_address);
            return;
        }

        let intro_points = match self.get_intros_for_desc() {
            Err(ServiceErr::ErrNotEnoughIntros) => return,
            Ok(res) => res,
        };

        let (_, time_period_number) = get_srv_and_time_period(is_first_desc, &consensus);
        let identity_pubkey_bytes = match self.get_identity_pubkey_bytes() {
            Ok(v) => v,
            Err(err) => {
                error!("{err}");
                return;
            }
        };
        let blinding_param = consensus.get_blinding_param(identity_pubkey_bytes, time_period_number);
        let mut desc = match OBDescriptor::new(
            &self.onion_address,
            &self.identity_priv_key,
            &blinding_param,
            intro_points,
            is_first_desc,
            &consensus,
        ) {
            Ok(desc) => desc,
            Err(err) => {
                error!("{err}");
                return;
            },
        };

        let v3_desc_len = desc.base.v3_desc.string().len();
        let intro_set_len = desc.intro_set.len();
        info!(
            "Service {} created {} descriptor ({intro_set_len} intro points) (blinding param: {}) (size: {v3_desc_len} bytes). About to publish:",
            self.onion_address,
            fmt_first(is_first_desc),
            hex::encode(blinding_param)
        );

        // When we do a v3 HSPOST on the control port, Tor decodes the
        // descriptor and extracts the blinded pubkey to be used when uploading
        // the descriptor. So let's do the same to compute the responsible
        // HSDirs:
        let blinded_key = match desc.base.get_blinded_key() {
            Ok(v) => v,
            Err(err) => {
                error!("{err}");
                return
            },
        };

        // Calculate responsible HSDirs for our service
        let responsible_hsdirs = match get_responsible_hsdirs(blinded_key, is_first_desc, &consensus) {
            Ok(responsible_hsdirs) => responsible_hsdirs,
            Err(HashRingErr::ErrEmptyHashRing) => {
                warn!("Can't publish desc with no hash ring. Delaying...");
                return;
            },
            Err(err) => {
                error!("{err}");
                return;
            },
        };

        desc.set_last_publish_attempt_ts(Utc::now());

        info!("Uploading {} descriptor for {} to {responsible_hsdirs:?}", fmt_first(is_first_desc), self.onion_address);

        // Upload descriptor
        if let Err(err) = self.upload_descriptor(self.controller.clone(), &desc, &responsible_hsdirs).await {
            error!("{err}");
            return
        }

        // It would be better to set last_upload_ts when an upload succeeds and
        // not when an upload is just attempted. Unfortunately the HS_DESC #
        // UPLOADED event does not provide information about the service and
        // so it can't be used to determine when descriptor upload succeeds
        desc.set_last_upload_ts(Utc::now());
        desc.set_responsible_hsdirs(responsible_hsdirs);

        // Set the descriptor
        match is_first_desc {
            true  => self.first_descriptor  = Some(desc),
            false => self.second_descriptor = Some(desc),
        }
    }

    async fn upload_descriptor(
        &self,
        controller: Arc<Mutex<Controller>>,
        ob_desc: &OBDescriptor,
        hsdirs: &Vec<String>,
    ) -> anyhow::Result<()> {
        if let Err(ControllerErr::SocketClosedErr) = common_upload_descriptor(controller.clone(), &ob_desc.base.v3_desc, hsdirs, &ob_desc.base.onion_address).await {
            bail!("Error uploading descriptor for service {}.onion. Control port socket is closed.", &ob_desc.base.onion_address);
        }
        Ok(())
    }

    fn get_identity_pubkey_bytes(&self) -> anyhow::Result<VerifyingKey> {
        self.identity_priv_key.public()
    }

    fn get_intros_for_desc(&self) -> Result<Vec<IntroductionPointV3>, ServiceErr> {
        let all_intros = self.get_all_intros_for_publish();

        // Get number of instances that contributed to final intro point list
        let n_instances = all_intros.intro_points.len();
        let n_intros_wanted = n_instances * param::N_INTROS_PER_INSTANCE;

        let final_intros = all_intros.choose(n_intros_wanted);
        if final_intros.is_empty() {
            info!("Got no usable intro points from our instances. Delaying descriptor push...");
            return Err(ServiceErr::ErrNotEnoughIntros);
        }

        info!("We got {} intros from {n_instances} instances. We want {n_intros_wanted} intros ourselves (got: {})",
            all_intros.get_intro_points_flat().len(), final_intros.len());
        Ok(final_intros)
    }

    fn get_all_intros_for_publish(&self) -> IntroductionPointSetV3 {
        let mut all_intros = Vec::new();
        for inst in &self.instances {
            match inst.get_intros_for_publish() {
                Ok(instance_intros) => all_intros.push(instance_intros),
                Err(err) => match err {
                    InstanceErr::ErrInstanceHasNoDescriptor => info!("Entirely missing a descriptor for instance {}. Continuing anyway if possible", inst.onion_address),
                    InstanceErr::ErrInstanceIsOffline => info!("Instance {} is offline. Ignoring its intro points...", inst.onion_address),
                },
            }
        }
        IntroductionPointSetV3::new(all_intros)
    }

    fn should_publish_descriptor_now(&self, is_first_desc: bool, consensus: &Consensus, force_publish: bool) -> bool {
        // If descriptor not yet uploaded, do it now!
        if is_first_desc && self.first_descriptor.is_none() {
            return true;
        }
        if !is_first_desc && self.second_descriptor.is_none() {
            return true;
        }
        self.intro_set_modified(is_first_desc)
            || self.descriptor_has_expired(is_first_desc)
            || self.hsdir_set_changed(is_first_desc, consensus)
            || force_publish
    }

    // Check if the descriptor has expired (hasn't been uploaded recently).
    // If 'is_first_desc' is set then check the first descriptor of the
    // service, otherwise the second.
    fn descriptor_has_expired(&self, is_first_desc: bool) -> bool {
        let Some(ob_desc) = self.get_descriptor(is_first_desc) else {
            return true;
        };
        let Some(last_upload_ts) = ob_desc.last_upload_ts else {
            return true;
        };
        let descriptor_age = Utc::now().signed_duration_since(last_upload_ts).num_seconds();
        if descriptor_age > self.get_descriptor_lifetime() {
            info!("\t Our {} descriptor has expired ({descriptor_age} seconds old). Uploading new one.", fmt_first(is_first_desc));
            return true;
        }
        info!("\t Our {} descriptor is still fresh ({descriptor_age} seconds old).", fmt_first(is_first_desc));
        false
    }

    // HsdirSetChanged return True if the HSDir has changed between the last upload of this
    // descriptor and the current state of things
    fn hsdir_set_changed(&self, is_first_desc: bool, consensus: &Consensus) -> bool {
        // Derive blinding parameter
        let (_, time_period_number) = get_srv_and_time_period(is_first_desc, &consensus);
        let identity_pubkey_bytes = match self.get_identity_pubkey_bytes() {
            Ok(v) => v,
            Err(err) => {
                error!("{err}");
                return true;
            }
        };
        let blinded_param = consensus.get_blinding_param(identity_pubkey_bytes, time_period_number);

        // Get blinded key
        let blinded_key = match util::blinded_pubkey(identity_pubkey_bytes, &blinded_param) {
            Ok(v) => v,
            Err(err) => {
                error!("{err}");
                return true;
            }
        };

        let mut responsible_hsdirs = match get_responsible_hsdirs(blinded_key, is_first_desc, consensus) {
            Ok(responsible_hsdirs) => responsible_hsdirs,
            Err(HashRingErr::ErrEmptyHashRing) => return false,
            Err(_) => return false,
        };

        let Some(ob_desc) = self.get_descriptor(is_first_desc) else {
            return true;
        };

        let mut previous_responsible_hsdirs: Vec<String> = ob_desc.responsible_hsdirs.clone().unwrap_or_default();

        responsible_hsdirs.sort();
        previous_responsible_hsdirs.sort();
        if responsible_hsdirs.len() != previous_responsible_hsdirs.len() {
            info!("\t HSDir set changed ({responsible_hsdirs:?} vs {previous_responsible_hsdirs:?})");
            return true;
        }

        let mut changed = false;
        for (i, el) in responsible_hsdirs.iter().enumerate() {
            if &previous_responsible_hsdirs[i] != el {
                changed = true;
            }
        }
        if changed {
            info!("\t HSDir set changed ({responsible_hsdirs:?} vs {previous_responsible_hsdirs:?})");
            return true;
        }

        info!("\t HSDir set remained the same");
        false
    }

    fn get_descriptor_lifetime(&self) -> i64 {
        FRONTEND_DESCRIPTOR_LIFETIME
    }

    // Check if the introduction point set has changed since last publish.
    fn intro_set_modified(&self, is_first_desc: bool) -> bool {
        let last_upload_ts = self.get_descriptor(is_first_desc).as_ref().and_then(|desc| desc.last_upload_ts);
        let Some(last_upload_ts) = last_upload_ts else {
            info!("\t Descriptor never published before. Do it now!");
            return true;
        };
        for inst in &self.instances {
            let Some(intro_set_modified_timestamp) = inst.intro_set_modified_timestamp else {
                info!("\t Still dont have a descriptor for this instance");
                continue;
            };
            if intro_set_modified_timestamp > last_upload_ts {
                info!("\t Intro set modified");
                return true;
            }
        }
        info!("\t Intro set not modified");
        false
    }

    fn get_descriptor(&self, is_first_desc: bool) -> &Option<OBDescriptor> {
        match is_first_desc {
            true  => &self.first_descriptor,
            false => &self.second_descriptor,
        }
    }
}

// Upload descriptor via the Tor control port
//
// If no HSDirs are specified, Tor will upload to what it thinks are the
// responsible directories
//
// If 'v3_onion_address' is set, this is a v3 HSPOST request, and the address
// needs to be embedded in the request.
async fn common_upload_descriptor(
    controller: Arc<Mutex<Controller>>,
    signed_descriptor: &HiddenServiceDescriptorV3,
    hsdirs: &Vec<String>,
    v3_onion_address: &str,
) -> Result<(), ControllerErr> {
    debug!("Beginning service descriptor upload.");
    // Provide server fingerprints to control command if HSDirs are specified.
    let mut server_args = hsdirs.iter()
        .map(|hsdir| format!("SERVER={hsdir}"))
        .collect::<Vec<_>>()
        .join(" ");
    if v3_onion_address != "" {
        let hs_address = v3_onion_address.replace(".onion", "");
        server_args += &format!(" HSADDRESS={hs_address}");
    }
    let signed_descriptor_str = signed_descriptor.string();
    let msg = format!("+HSPOST {server_args}\n{signed_descriptor_str}\r\n.\r\n");
    let res = controller.lock().await.msg(msg.as_bytes()).await?;
    if !res.is_ok() {
        error!("HSPOST returned unexpected response code: {} {}", res.code(), res.inner());
    }
    Ok(())
}