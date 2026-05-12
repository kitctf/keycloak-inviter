use crate::config::{Config, Secrets};
use crate::error::WebError;
use keycloak::{KeycloakAdmin, KeycloakServiceAccountAdminTokenRetriever};
use reqwest::Client;
use rootcause::option_ext::OptionExt;
use rootcause::prelude::ResultExt;
use rootcause::{Report, report};
use serde_json::json;

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

async fn send_user_added_to_mattermost(
    author: &str,
    text: String,
    secrets: &Secrets,
) -> Result<(), Report> {
    let url = secrets
        .webhook_url
        .as_ref()
        .context("No webhook URL given in config")?;
    let response = Client::new()
        .post(url)
        .json(&json!({
            "text": text,
            "username": author,
            "icon_emoji": "woah"
        }))
        .send()
        .await
        .context("Failed to send webhook")?;

    let status = response.status();
    if !status.is_success() {
        let response = response.text().await.unwrap_or("N/A".to_string());
        return Err(report!("Failed to send webhook")
            .attach(status)
            .attach(format!("Message: {response}")));
    }
    Ok(())
}
