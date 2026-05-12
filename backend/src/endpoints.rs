use crate::config::{Config, Secrets};
use crate::error::WebError;
use keycloak::{KeycloakAdmin, KeycloakServiceAccountAdminTokenRetriever};
use reqwest::Client;
use serde_json::json;
use snafu::Report;
use tracing::warn;

pub mod auth;
pub mod invite;
pub mod self_register;

async fn get_keycloak_admin(
    config: &Config,
    client: Client,
) -> Result<KeycloakAdmin<KeycloakServiceAccountAdminTokenRetriever>, WebError> {
    let token_retriever = KeycloakServiceAccountAdminTokenRetriever::create_with_custom_realm(
        &config.oidc.client_id,
        &config.secrets.client_secret,
        &config.keycloak.realm,
        client.clone(),
    );

    Ok(KeycloakAdmin::new(
        &config.keycloak.url,
        token_retriever,
        client,
    ))
}

async fn send_user_added_to_mattermost(author: String, text: String, secrets: &Secrets) -> bool {
    let url = match &secrets.webhook_url {
        Some(url) => url,
        None => return false,
    };
    let response = Client::new()
        .post(url)
        .json(&json!({
            "text": text,
            "username": author,
            "icon_emoji": "woah"
        }))
        .send()
        .await;
    let response = match response {
        Err(e) => {
            warn!(error = %Report::from_error(&e), "Failed to send webhook");
            return false;
        }
        Ok(e) => e,
    };
    let status = response.status();
    if !status.is_success() {
        let response = response.text().await.unwrap_or("N/A".to_string());
        warn!(status = %status, response = %response, "Failed to send webhook");
        return false;
    }
    true
}
