use crate::config::{Config, OidcConfig};
use crate::oidc::Oidc;
use clap::Parser;
use clap::builder::Styles;
use clap::builder::styling::AnsiColor;
use snafu::Report;
use std::path::PathBuf;
use tracing::error;
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

    let oidc = match Oidc::build_new(config.oidc.clone(), &config.secrets).await {
        Ok(oidc) => oidc,
        Err(e) => {
            error!(
                error = %Report::from_error(e),
                "Error building OIDC client"
            );
            std::process::exit(1);
        }
    };

    web::start_server(config, oidc).await;
}
