use crate::onionbalance::onionbalance::{InitSubsystemsParams, OnionBalance};
use crate::onionbalance::param;
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender, UnboundedReceiver};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::{join, select, time};
use tokio::sync::mpsc::error::TrySendError;
use crate::{Args, Commands};
use crate::onionbalance::controller::Message;

pub async fn generate_config() -> anyhow::Result<()> {
    /*
        Enter path to store generated config
        Number of services (frontends) to create (default: 1):
        Enter path to master service private key (i.e. path to 'hs_ed25519_secret_key') (Leave empty to generate a key)
        Number of instance services to create (default: 2) (min: 1, max: 8)
        Provide a tag name to group these instances [node]

        Wrote master service config file '/Users/n0tr1v/Documents/onionbalance/config/config.yaml'
        Done! Successfully generated Onionbalance config
        Now please edit 'config/config.yaml' with a text editor to add/remove/edit your backend instances
    */
    let config_path = std::path::Path::new("config.yaml");
    if config_path.exists() {
        error!("config file {config_path:?} already exists");
        return Ok(());
    }

    // let mut csprng = rand_core::OsRng {};
    // let kp = tor_llcrypto::pk::ed25519::Keypair::generate(&mut csprng);
    // let id = tor_llcrypto::pk::ed25519::Ed25519Identity::from_bytes(kp.public.as_bytes()).unwrap();
    // let onion_address = crate::stem::descriptor::hidden_service::address_from_identity_key(id);
    // let master_key_file_name = format!("{}.key", onion_address.trim_end_matches(".onion"));
    // println!("test {}", master_key_file_name);
    // EncodePrivateKey::to_pkcs8_pem(&kp.secret.as_bytes(), pkcs8::LineEnding::default()).unwrap();
    // fs::write(master_key_file_name, "").unwrap();

    println!("Generate config file");
    let conf = crate::onionbalance::config::ConfigData {
        services: vec![crate::onionbalance::config::ServiceConfig {
            key: "my key".to_owned(),
            instances: vec![crate::onionbalance::config::InstanceConfig {
                address: "<Enter the instance onion address here>".to_owned(),
            }],
        }],
    };
    fs::write(config_path, serde_yaml::to_string(&conf)?)?;
    Ok(())
}

pub async fn main(args: Args) -> anyhow::Result<()> {
    match args.command {
        Some(Commands::GenerateConfig) => return generate_config().await,
        _ => {},
    }

    let quick = args.quick;
    let config_path = args.config;
    let ip = args.ip;
    let port = args.port;
    let tor_password = args.tor_password;

    let (desc_event_tx, desc_event_rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
    let (desc_content_event_tx, desc_content_event_rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
    let (status_event_tx, status_event_rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
    let (re_connect_tx, re_connect_rx) = tokio::sync::mpsc::channel::<()>(1);
    let (refresh_consensus_tx, refresh_consensus_rx) = tokio::sync::mpsc::channel::<()>(1);

    let args = InitSubsystemsParams {
        config_path,
        ip,
        port,
        tor_password,
        desc_event_tx,
        desc_content_event_tx,
        status_event_tx,
        re_connect_tx,
    };
    let ob_inst = Arc::new(Mutex::new(OnionBalance::new(args).await?));

    let h1 = handle_re_connect(ob_inst.clone(), re_connect_rx);
    let h2 = handle_new_desc_event_wrapper(ob_inst.clone(), desc_event_rx);
    let h3 = handle_new_desc_content_event_wrapper(ob_inst.clone(), desc_content_event_rx);
    let h4 = handle_new_status_event_wrapper(status_event_rx, refresh_consensus_tx);
    let h5 = fetch_descriptors_thread(ob_inst.clone());
    let h6 = publish_descriptors_thread(ob_inst.clone());
    let h7 = refresh_consensus_thread(ob_inst.clone(), refresh_consensus_rx);

    let initial_delay = if quick { 0 } else { param::INITIAL_CALLBACK_DELAY };
    time::sleep(Duration::from_secs(initial_delay)).await;
    perform_fetch_publish_descriptors(&ob_inst, false).await;

    let _ = join!(h1, h2, h3, h4, h5, h6, h7);
    Ok(())
}

fn handle_re_connect(ob_inst: Arc<Mutex<OnionBalance>>, mut rx: Receiver<()>) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(_) = rx.recv().await {
            ob_inst.lock().await.controller.lock().await.re_connect().await;
            perform_fetch_publish_descriptors(&ob_inst, true).await;
        }
        error!("handle_re_connect leaving");
    })
}

fn handle_new_desc_event_wrapper(ob_inst: Arc<Mutex<OnionBalance>>, mut rx: UnboundedReceiver<Message>) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(status_event) = rx.recv().await {
            let keywords = status_event.keywords();
            let words: Vec<&str> = keywords.split(" ").collect();
            let action = words[1];
            let hs_address = words[2];
            let hs_dir = words[4];
            match action {
                "RECEIVED" => continue,  // We already log in HS_DESC_CONTENT so no need to do it here too
                "UPLOADED" => debug!("Successfully uploaded descriptor for {hs_address} to {hs_dir}"),
                "REQUESTED" => debug!("Requested descriptor for {hs_address} from {hs_dir}..."),
                "FAILED" => {
                    let reason = words.get(6).unwrap_or(&"REASON NULL").trim();
                    if ob_inst.lock().await.address_is_instance(hs_address) {
                        info!("Descriptor fetch failed for instance {hs_address} from {hs_dir} ({reason})");
                    } else if ob_inst.lock().await.address_is_frontend(hs_address) {
                        warn!("Descriptor upload failed for frontend {hs_address} to {hs_dir} ({reason})");
                    } else {
                        warn!("Descriptor action failed for unknown service {hs_address} to {hs_dir} ({reason})");
                    }
                },
                _ => {},
            }
        }
        error!("handle_new_desc_event_wrapper leaving");
    })
}

fn handle_new_desc_content_event_wrapper(ob_inst: Arc<Mutex<OnionBalance>>, mut rx: UnboundedReceiver<Message>) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(status_event) = rx.recv().await {
            let keywords = status_event.keywords();
            let mut words = keywords.split(" ");
            let descriptor_text = status_event.inner();
            let Some(hs_address) = words.nth(1) else { continue; };
            //DescId := words[1];
            //HsDir := words[2];
            ob_inst.lock().await.get_all_instances().iter_mut()
                .filter(|inst| inst.onion_address == hs_address)
                .for_each(|inst| {
                    if let Err(err) = inst.register_descriptor(&descriptor_text, hs_address) {
                        error!("{err}");
                    }
                });
        }
        error!("handle_new_desc_content_event_wrapper leaving");
    })
}

fn handle_new_status_event_wrapper(mut rx: UnboundedReceiver<Message>, refresh_consensus_tx: Sender<()>) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(status_event) = rx.recv().await {
            let keywords = status_event.keywords();
            let mut words = keywords.split(" ");
            let Some(action) = words.nth(2) else { continue; };
            if action == "CONSENSUS_ARRIVED" {
                info!("Received new consensus!");
                match refresh_consensus_tx.try_send(()) {
                    Ok(_) => {},
                    Err(TrySendError::<()>::Full(_)) => {},
                    Err(TrySendError::<()>::Closed(_)) => panic!("receiver should not be closed"),
                }
            }
        }
        error!("handle_new_status_event_wrapper leaving");
    })
}

fn fetch_descriptors_thread(ob_inst: Arc<Mutex<OnionBalance>>) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            time::sleep(Duration::from_secs(param::FETCH_DESCRIPTOR_FREQUENCY)).await;
            ob_inst.lock().await.fetch_instance_descriptors().await;
        }
    })
}

fn publish_descriptors_thread(ob_inst: Arc<Mutex<OnionBalance>>) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            time::sleep(Duration::from_secs(param::PUBLISH_DESCRIPTOR_CHECK_FREQUENCY)).await;
            ob_inst.lock().await.publish_all_descriptors(false).await;
        }
    })
}

fn refresh_consensus_thread(ob_inst: Arc<Mutex<OnionBalance>>, mut rx: Receiver<()>) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            select! {
                _ = time::sleep(Duration::from_secs(param::REFRESH_CONSENSUS_FREQUENCY)) => {},
                _ = rx.recv() => {},
            }
            perform_consensus_refresh(&ob_inst).await;
        }
    })
}

async fn perform_consensus_refresh(ob_inst: &Arc<Mutex<OnionBalance>>) {
    ob_inst.lock().await.consensus.refresh().await;
    // Call all callbacks in case we just got a live consensus
    perform_fetch_publish_descriptors(ob_inst, false).await;
}

async fn perform_fetch_publish_descriptors(ob_inst: &Arc<Mutex<OnionBalance>>, force_publish: bool) {
    ob_inst.lock().await.fetch_instance_descriptors().await;
    time::sleep(Duration::from_secs(5)).await;
    ob_inst.lock().await.publish_all_descriptors(force_publish).await;
}