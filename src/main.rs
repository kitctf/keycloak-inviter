use crate::oidc::Oidc;
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
            keycloak_url: std::env::var("KEYCLOAK_URL").expect("Expected 'KEYCLOAK_URL' env var"),
            keycloak_user: std::env::var("KEYCLOAK_USER")
                .expect("Expected 'KEYCLOAK_USER' env var"),
            keycloak_password: std::env::var("KEYCLOAK_PASSWORD")
                .expect("Expected 'KEYCLOAK_PASSWORD' env var"),
            keycloak_realm: std::env::var("KEYCLOAK_REALM")
                .unwrap_or_else(|_| "kitctf".to_string()),
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
        client_id: std::env::var("CLIENT_ID").expect("Expected 'CLIENT_ID' env var"),
        client_secret: std::env::var("CLIENT_SECRET").expect("Expected 'CLIENT_SECRET' env var"),
        issuer_url: "https://sso.kitctf.de/realms/kitctf".to_string(),
        redirect_url: std::env::var("REDIRECT_URL").expect("Expected 'REDIRECT_URL' env var"),
        introspect_url:
            "https://sso.kitctf.de/realms/kitctf/protocol/openid-connect/token/introspect"
                .to_string(),
        scopes: vec!["openid".to_string(), "profile".to_string()],
    };

    let oidc = Oidc::build_new(config.clone()).await.unwrap();

    web::start_server(config, oidc, KeycloakConfig::from_env()).await;
}
