use crate::onionbalance::config::{ConfigData, ServiceConfig};
use crate::onionbalance::consensus::Consensus;
use crate::onionbalance::controller::{Controller, ControllerErr, Message};
use crate::onionbalance::instance::Instance;
use crate::onionbalance::service::Service;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::mpsc::{Sender, UnboundedSender};
use tokio::sync::Mutex;
use tokio::time;
use tokio::time::Duration;

pub struct OnionBalance {
    pub controller: Arc<Mutex<Controller>>,
    pub consensus: Consensus,
    services: Vec<Service>,
}

pub struct InitSubsystemsParams {
    pub config_path: String,
    pub ip: String,
    pub port: u16,
    pub tor_password: String,
    pub desc_event_tx: UnboundedSender<Message>,
    pub desc_content_event_tx: UnboundedSender<Message>,
    pub status_event_tx: UnboundedSender<Message>,
    pub re_connect_tx: Sender<()>,
}

fn initialize_services_from_config_data(
    controller: Arc<Mutex<Controller>>,
    config_services: Vec<ServiceConfig>,
    config_path: &str,
) -> anyhow::Result<Vec<Service>> {
    let mut services = Vec::new();
    for service_conf in config_services {
        services.push(Service::new(controller.clone(), &service_conf, config_path)?);
    }
    Ok(services)
}

fn load_config_data(config_path: &str) -> anyhow::Result<ConfigData> {
    info!("Loaded the config file '{config_path}'.");
    let s = std::fs::read_to_string(config_path)?;
    let out: ConfigData = serde_yaml::from_str(&s)?;
    debug!("Onionbalance config data: {out:?}");
    Ok(out)
}

impl OnionBalance {
    pub async fn new(args: InitSubsystemsParams) -> anyhow::Result<Self> {
        let config_data = load_config_data(&args.config_path)?;

        let controller = Arc::new(Mutex::new(
            Controller::new(
                &args.ip,
                args.port,
                &args.tor_password,
                args.desc_event_tx,
                args.desc_content_event_tx,
                args.status_event_tx,
                args.re_connect_tx,
            ).await?,
        ));
        let mut consensus = Consensus::new(controller.clone());
        consensus.refresh().await;

        let services = initialize_services_from_config_data(
            controller.clone(),
            config_data.services,
            &args.config_path,
        )?;

        controller.lock().await.set_events().await?;

        warn!("Onionbalance initialized (tor version: {})!", controller.lock().await.get_version().await?);
        warn!("{}", "=".repeat(80));

        Ok(Self { controller, consensus, services })
    }

    pub async fn fetch_instance_descriptors(&mut self) {
        info!("[*] fetch_instance_descriptors() called [*]");

        // TODO: Don't do this here. Instead do it on a specialized function
        self.controller.lock().await.mark_tor_as_active().await;

        if !self.consensus.is_live() {
            warn!("No live consensus. Waiting before fetching descriptors...");
            return;
        }

        let ctrl = self.controller.clone();
        let all_instances = self.get_all_instances();

        helper_fetch_all_instance_descriptors(ctrl, all_instances).await;
    }

    pub fn get_all_instances(&mut self) -> Vec<&mut Instance> {
        self.services.iter_mut().flat_map(|service| service.instances.iter_mut()).collect()
    }

    pub async fn publish_all_descriptors(&mut self, force_publish: bool) {
        info!("[*] publish_all_descriptors() called [*]");

        if !self.consensus.is_live() {
            info!("No live consensus. Waiting before publishing descriptors...");
            return;
        }

        for service in self.services.iter_mut() {
            service.publish_descriptors(force_publish, &self.consensus).await;
        }
    }

    pub fn address_is_instance(&self, onion_address: &str) -> bool {
        self.services.iter().any(|svc|
            svc.instances.iter().any(|inst|
                inst.has_onion_address(onion_address)
            )
        )
    }

    pub fn address_is_frontend(&self, onion_address: &str) -> bool {
        self.services.iter().any(|svc| svc.has_onion_address(onion_address))
    }
}

async fn helper_fetch_all_instance_descriptors(ctrl: Arc<Mutex<Controller>>, instances: Vec<&mut Instance>) {
    info!("Initiating fetch of descriptors for all service instances.");
    // Clear Tor descriptor cache before making fetches by sending
    // the NEWNYM signal
    if let Err(ControllerErr::SocketClosedErr) = ctrl.lock().await.signal("NEWNYM").await {
        error!("Failed to send NEWNYM signal, socket is closed.");
        return
    }
    time::sleep(Duration::from_secs(5)).await; // Sleep to allow Tor time to build new circuits

    let mut unique_addresses = HashSet::new();
    for inst in instances {
        if unique_addresses.insert(&inst.onion_address) {
            if let Err(ControllerErr::SocketClosedErr) = inst.fetch_descriptor().await {
                error!("Failed to fetch descriptor, socket is closed");
                return;
            }
        }
    }
}
