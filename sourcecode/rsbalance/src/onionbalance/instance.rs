use crate::onionbalance::controller::{Controller, ControllerErr};
use crate::onionbalance::descriptor::ReceivedDescriptor;
use crate::stem::descriptor::hidden_service::IntroductionPointV3;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use anyhow::ensure;
use tokio::sync::Mutex;
use crate::onionbalance::descriptor;

#[derive(Clone)]
pub struct Instance {
    controller: Arc<Mutex<Controller>>,
    pub onion_address: String,
    descriptor: Option<ReceivedDescriptor>,
    pub intro_set_modified_timestamp: Option<DateTime<Utc>>,
}

pub enum InstanceErr {
    ErrInstanceHasNoDescriptor,
    ErrInstanceIsOffline,
}

impl Instance {
    pub fn new(controller: Arc<Mutex<Controller>>, onion_address: &str) -> Self {
        let onion_address = onion_address.replace(".onion", "");

        // Onion address does not contain the '.onion'.
        warn!("Loaded instance {}", onion_address);

        Self {
            controller,
            onion_address,
            descriptor: None,
            intro_set_modified_timestamp: None,
        }
    }

    // FetchDescriptor try fetch a fresh descriptor for this service instance from the HSDirs
    pub async fn fetch_descriptor(&self) -> Result<(), ControllerErr> {
        debug!("Trying to fetch a descriptor for instance {}.onion.", self.onion_address);
        self.controller.lock().await.get_hidden_service_descriptor(&self.onion_address, false).await
    }

    // HasOnionAddress Return True if this instance has this onion address
    pub fn has_onion_address(&self, onion_address: &str) -> bool {
        // Strip the ".onion" part of the address if it exists since some
        // subsystems don't use it (e.g. Tor sometimes omits it from control
        // port responses)
        let my_onion_address = self.onion_address.trim_end_matches(".onion");
        let their_onion_address = onion_address.trim_end_matches(".onion");
        my_onion_address == their_onion_address
    }

    pub fn get_intros_for_publish(&self) -> Result<Vec<IntroductionPointV3>, InstanceErr> {
        let descriptor = self.descriptor.as_ref().ok_or(InstanceErr::ErrInstanceHasNoDescriptor)?;
        if descriptor.is_old() {
            Err(InstanceErr::ErrInstanceIsOffline)
        } else {
            Ok(descriptor.base.get_intro_points())
        }
    }

    // We received a descriptor (with 'descriptor_text') for 'onion_address'.
    // Register it to this instance.
    pub fn register_descriptor(&mut self, descriptor_text: &str, onion_address: &str) -> anyhow::Result<()> {
        let my_onion_address = &self.onion_address;
        info!("Found instance {my_onion_address} for this new descriptor!");

        ensure!(onion_address == my_onion_address, "onion_address != self.onion_address");

        // Parse descriptor. If it parsed correctly, we know that this
        // descriptor is truly for this instance (since the onion address
        // matches)
        let new_descriptor = match ReceivedDescriptor::new(descriptor_text, onion_address) {
            Ok(v) => v,
            Err(descriptor::DescriptorErr::ErrBadDescriptor) => {
                warn!("Received bad descriptor for {my_onion_address}. Ignoring.");
                return Ok(());
            }
        };

        // Before replacing the current descriptor with this one, check if the
        // introduction point set changed:

        // If this is the first descriptor for this instance, the intro point set changed
        let Some(descriptor) = &self.descriptor else {
            info!("This is the first time we see a descriptor for instance {my_onion_address}!");
            self.intro_set_modified_timestamp = Some(Utc::now());
            self.descriptor = Some(new_descriptor);
            return Ok(());
        };

        ensure!(new_descriptor.base.intro_set.len() > 0, "new_descriptor.base.intro_set.len() == 0");

        // We already have a descriptor but this is a new one. Check the intro points!
        if !new_descriptor.base.intro_set.equals(&descriptor.base.intro_set) {
            info!("We got a new descriptor for instance {my_onion_address} and the intro set changed!");
            self.intro_set_modified_timestamp = Some(Utc::now());
        } else {
            info!("We got a new descriptor for instance {my_onion_address} but the intro set did not change.");
        }
        self.descriptor = Some(new_descriptor);
        Ok(())
    }
}
