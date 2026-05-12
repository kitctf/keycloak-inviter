use crate::config::{Config, OidcConfig};
use crate::oidc::Oidc;
use clap::Parser;
use clap::builder::Styles;
use clap::builder::styling::AnsiColor;
use rootcause::Report;
use rootcause::prelude::ResultExt;
use std::path::PathBuf;
use std::time::Duration;
use tokio::signal::unix::{SignalKind, signal};
use tokio::{select, signal};
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

    if let Err(e) = main_impl().await {
        error!("{e}")
    }
}

async fn main_impl() -> Result<(), Report> {
    let args = CliArgs::parse();

    let config = std::fs::read_to_string(&args.config_path)
        .context("failed to read config file")
        .attach(format!("path: {}", args.config_path.display()))?;
    let config: Config = toml::from_str(&config)
        .context("failed to parse config file")
        .attach(format!("path: {}", args.config_path.display()))?;

    let mut current_backoff = Duration::from_secs(1);
    let shutdown_requested = CancellationToken::new();

    let oidc = loop {
        if shutdown_requested.is_cancelled() {
            error!("Shutdown requested, exiting");
            return Ok(());
        }
        let oidc = Oidc::build_new(config.oidc.clone(), &config.secrets);
        match oidc.await.context("failed to build OIDC client") {
            Ok(oidc) => break oidc,
            Err(e) => {
                error!(
                    error = %e,
                    "Error building OIDC client"
                );
                backoff(&mut current_backoff, shutdown_requested.clone()).await;
                continue;
            }
        };
    };

    let res = select!(
        it = server::start_server(config, oidc) => { it },
        _ = shutdown_signal(shutdown_requested.clone()) => { Ok(()) }
    );
    res.context("failed to run server")
        .map_err(Report::into_dynamic)
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
