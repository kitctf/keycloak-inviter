use crate::oidc::Oidc;
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod oidc;
mod web;
mod web_handler;

#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub client_id: String,
    pub client_secret: String,
    pub issuer_url: String,
    pub redirect_url: String,
    pub introspect_url: String,
    pub scopes: Vec<String>,
}

#[derive(Clone)]
pub struct KeycloakConfig {
    pub keycloak_url: String,
    pub keycloak_user: String,
    pub keycloak_password: String,
    pub keycloak_realm: String,
}

impl KeycloakConfig {
    pub fn from_env() -> Self {
        Self {
            keycloak_url: get_env("KEYCLOAK_URL"),
            keycloak_user: get_env("KEYCLOAK_USER"),
            keycloak_password: get_env("KEYCLOAK_PASSWORD"),
            keycloak_realm: get_env_def("KEYCLOAK_REALM", "kitctf"),
        }
    }
}

#[derive(Clone)]
pub struct ServiceConfig {
    frontend_url: String,
    listen_address: String,
}

impl ServiceConfig {
    pub fn from_env() -> Self {
        Self {
            frontend_url: get_env("FRONTEND_URL"),
            listen_address: get_env_def("LISTEN_ADDRESS", "0.0.0.0:3000"),
        }
    }
}

#[derive(Clone)]
pub struct WebhookConfig {
    pub url: Option<String>,
}

impl WebhookConfig {
    pub fn from_env() -> Self {
        if let Ok(val) = std::env::var("WEBHOOK_URL") {
            return Self { url: Some(val) };
        }

        info!("No `WEBHOOK_URL` provided, skipping webhook");
        Self { url: None }
    }
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

    let oidc_config = OidcConfig {
        client_id: get_env("CLIENT_ID"),
        client_secret: get_env("CLIENT_SECRET"),
        issuer_url: get_env_def("ISSUER_URL", "https://sso.kitctf.de/realms/kitctf"),
        redirect_url: get_env("REDIRECT_URL"),
        introspect_url: get_env_def(
            "INTROSPECT_URL",
            "https://sso.kitctf.de/realms/kitctf/protocol/openid-connect/token/introspect",
        ),
        scopes: vec!["openid".to_string(), "profile".to_string()],
    };

    let oidc = Oidc::build_new(oidc_config.clone()).await.unwrap();
    let service_config = ServiceConfig::from_env();
    let webhook_config = WebhookConfig::from_env();

    web::start_server(
        service_config,
        webhook_config,
        oidc_config,
        oidc,
        KeycloakConfig::from_env(),
    )
    .await;
}

fn get_env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("Expected {} env var", key))
}

fn get_env_def(key: &str, default: &str) -> String {
    match std::env::var(key) {
        Ok(val) => val,
        Err(_) => {
            info!("Using default value for {}: `{}`", key, default);
            default.to_string()
        }
    }
}
