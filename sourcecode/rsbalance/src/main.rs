use crate::onionbalance::manager;
use clap::{Parser, Subcommand};
use log4rs::append::console::ConsoleAppender;
use log::{warn, LevelFilter};
use log4rs::encode::pattern::PatternEncoder;

#[macro_use]
extern crate lazy_static;

pub mod onionbalance;
pub mod rsbpk;
pub mod stem;
mod utils;

#[macro_use]
extern crate log;
extern crate core;

// Based on "onionbalance" sha: c2b50f7f2de7fe4d1b596cfa61393f27715508ea

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[arg(short, long, default_value_t = String::from("127.0.0.1"), env = "OB_IP", help = "Tor control IP address")]
    ip: String,
    #[arg(short, long, default_value_t = 9051, env = "OB_PORT", help = "Tor control port")]
    port: u16,
    #[arg(long, default_value_t = String::from(""), env = "OB_TOR_PASSWORD", help = "Tor control password", hide_env_values = true)]
    tor_password: String,
    #[arg(long, default_value_t = String::from("config.yaml"), env = "OB_CONFIG", help = "Config file location")]
    config: String,
    #[arg(short, long, env = "OB_QUICK", default_value_t = true, help = "Quickly deploy a new descriptor (no 5min wait)")]
    quick: bool,
    #[arg(long, default_value_t = String::from("info"), env = "OB_VERBOSITY", help = "Minimum verbosity level for logging. Available in ascending order: trace, debug, info, warn, error, off). The default is info.")]
    verbosity: String,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(about = "generate a config.yaml file")]
    GenerateConfig,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    init_logger(&args.verbosity).unwrap();
    tokio::spawn(ctrl_c_handler());
    warn!("Initializing onionbalance (version: {})...", "0.0.0");
    if let Err(err) = manager::main(args).await {
        error!("{err}")
    }
}

async fn ctrl_c_handler() -> anyhow::Result<()> {
    tokio::signal::ctrl_c().await?;
    println!("Bye!");
    std::process::exit(0);
}

fn init_logger(verbosity: &str) -> anyhow::Result<()> {
    let level = match verbosity {
        "off" => LevelFilter::Off,
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Info,
    };
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{d(%Y-%m-%d %H:%M:%S)} {l} - {m}{n}")))
        .build();
    let config = log4rs::config::Config::builder()
        .appender(log4rs::config::Appender::builder().build("stdout", Box::new(stdout)))
        .build(log4rs::config::Root::builder().appender("stdout").build(level))?;
    log4rs::init_config(config)?;
    Ok(())
}