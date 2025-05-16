use crate::config::{Config, OidcConfig};
use crate::oidc::Oidc;
use clap::Parser;
use clap::builder::Styles;
use clap::builder::styling::AnsiColor;
use snafu::Report;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use tokio::time::Instant;
use tracing::{error, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod config;
mod oidc;
mod web;
mod web_handler;

// noinspection DuplicatedCode
const CLAP_STYLE: Styles = Styles::styled()
    .header(AnsiColor::Red.on_default().bold())
    .usage(AnsiColor::Red.on_default().bold())
    .literal(AnsiColor::Blue.on_default().bold())
    .placeholder(AnsiColor::Green.on_default());

/// Invite users to KITCTF keycloak
#[derive(Parser, Debug)]
#[command(version, about, long_about = None, styles = CLAP_STYLE)]
#[command(propagate_version = true)]
struct CliArgs {
    /// Path to the config file
    config_path: PathBuf,
}

#[tokio::main]
async fn main() {
    // Maybe: https://fasterthanli.me/articles/request-coalescing-in-async-rust#a-bit-of-tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = CliArgs::parse();

    let config = match std::fs::read_to_string(&args.config_path) {
        Ok(content) => content,
        Err(e) => {
            error!(
                path = %args.config_path.display(),
                error = %Report::from_error(e),
                "Error reading config file"
            );
            std::process::exit(1);
        }
    };
    let config: Config = match toml::from_str(&config) {
        Ok(config) => config,
        Err(e) => {
            error!(
                path = %args.config_path.display(),
                error = %Report::from_error(e),
                "Error parsing config file"
            );
            std::process::exit(1);
        }
    };

    let mut current_backoff = Duration::from_secs(1);
    let shutdown_requested = Arc::new(AtomicBool::new(false));
    register_termination_handler(&shutdown_requested);

    let oidc = loop {
        if shutdown_requested.load(Ordering::Acquire) {
            error!("Shutdown requested, exiting");
            return;
        }
        match Oidc::build_new(config.oidc.clone(), &config.secrets).await {
            Ok(oidc) => break oidc,
            Err(e) => {
                error!(
                    error = %Report::from_error(e),
                    "Error building OIDC client"
                );
                backoff(&mut current_backoff, &shutdown_requested);
                continue;
            }
        };
    };

    web::start_server(config, oidc).await;
}

pub fn backoff(current_backoff: &mut Duration, shutdown_requested: &Arc<AtomicBool>) {
    warn!(backoff = ?current_backoff, "Backing off");
    // We need to be responsive to stop requests (CTRL+C), so we can't just sleep for
    // the full duration
    let target = Instant::now() + *current_backoff;
    while Instant::now() < target && !shutdown_requested.load(Ordering::Acquire) {
        thread::sleep(Duration::from_millis(100));
    }
    *current_backoff *= 2;
    *current_backoff = (*current_backoff).min(Duration::from_secs(60));
}

fn register_termination_handler(stop_requested: &Arc<AtomicBool>) {
    let stop_requested_clone = stop_requested.clone();
    let ctrlc_result = ctrlc::set_handler(move || {
        stop_requested_clone.store(true, Ordering::Release);
    });

    if let Err(e) = ctrlc_result {
        warn!(
            error = ?e,
            "Could not register termination handler, program behaviour on SIGINT/SIGTERM is undefined"
        );
    }
}
