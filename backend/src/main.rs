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

#[tokio::main]
async fn main() {
    // Maybe: https://fasterthanli.me/articles/request-coalescing-in-async-rust#a-bit-of-tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = OidcConfig {
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

    let oidc = Oidc::build_new(config.clone()).await.unwrap();
    let frontend_url = get_env("FRONTEND_URL");
    let listen_address = get_env_def("LISTEN_ADDRESS", "0.0.0.0:3000");

    web::start_server(
        frontend_url,
        listen_address,
        config,
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
