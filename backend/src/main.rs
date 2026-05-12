use crate::config::{Config, OidcConfig};
use crate::oidc::Oidc;
use clap::Parser;
use clap::builder::Styles;
use clap::builder::styling::AnsiColor;
use snafu::Report;
use std::path::PathBuf;
use std::time::Duration;
use tokio::signal::unix::{SignalKind, signal};
use tokio::{join, select, signal};
use tokio_util::sync::CancellationToken;
use tracing::{error, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod config;
mod endpoints;
mod error;
mod oidc;
mod server;

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
    let shutdown_requested = CancellationToken::new();

    let oidc = loop {
        if shutdown_requested.is_cancelled() {
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
                backoff(&mut current_backoff, shutdown_requested.clone()).await;
                continue;
            }
        };
    };

    let (res, _) = join!(
        server::start_server(config, oidc),
        shutdown_signal(shutdown_requested.clone())
    );
    res.unwrap();
}

pub async fn backoff(current_backoff: &mut Duration, shutdown_requested: CancellationToken) {
    warn!(backoff = ?current_backoff, "Backing off");
    let waiting = tokio::time::sleep(*current_backoff);
    let cancelling = shutdown_requested.cancelled();

    select! {
        _ = waiting => {},
        _ = cancelling => {},
    }
    *current_backoff *= 2;
    *current_backoff = (*current_backoff).min(Duration::from_secs(60));
}

async fn shutdown_signal(token: CancellationToken) {
    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let interrupt = signal::ctrl_c();
    select! {
        _ = sigterm.recv() => warn!("Received SIGTERM"),
        _ = interrupt => warn!("Received SIGINT")
    }
    token.cancel();
}
