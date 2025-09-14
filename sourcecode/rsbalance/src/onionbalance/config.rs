use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct InstanceConfig {
    pub address: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub key: String,
    pub instances: Vec<InstanceConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigData {
    pub services: Vec<ServiceConfig>,
}
