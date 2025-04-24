use serde::{Deserialize, Deserializer};
use tracing::info;

#[derive(Debug, Clone, Deserialize)]
pub struct OidcConfig {
    pub client_id: String,
    pub issuer_url: String,
    pub redirect_url: String,
    pub introspect_url: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KeycloakConfig {
    pub url: String,
    pub realm: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceConfig {
    pub frontend_url: String,
    pub listen_address: String,
}

#[derive(Clone)]
pub struct Secrets {
    pub client_secret: String,
    pub keycloak_password: String,
    pub keycloak_user: String,
    pub webhook_url: Option<String>,
}

impl Secrets {
    fn from_env() -> Self {
        let webhook_url = match std::env::var("WEBHOOK_URL") {
            Ok(val) => Some(val),
            Err(_) => {
                info!("No `WEBHOOK_URL` provided, skipping webhook");
                None
            }
        };

        Self {
            client_secret: get_env("CLIENT_SECRET"),
            keycloak_password: get_env("KEYCLOAK_PASSWORD"),
            keycloak_user: get_env("KEYCLOAK_USER"),
            webhook_url,
        }
    }
}

impl<'de> Deserialize<'de> for Secrets {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Secrets::from_env())
    }
}

#[derive(Clone, Deserialize)]
pub struct Config {
    pub oidc: OidcConfig,
    pub keycloak: KeycloakConfig,
    pub service: ServiceConfig,
    pub secrets: Secrets,
}

fn get_env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("Expected {} env var", key))
}
