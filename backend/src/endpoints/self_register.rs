use crate::config::Secrets;
use crate::error::{PrintRootcauseChain, WebError};
use crate::server::AppState;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use keycloak::types::UserRepresentation;
use reqwest::Client;
use rootcause::prelude::ResultExt;
use rootcause::report;
use serde::Deserialize;
use tracing::{info, warn};

pub async fn register_user(
    State(state): State<AppState>,
    Json(payload): Json<RegisterPayload>,
) -> Result<(), WebError> {
    let Some(config) = &state.config.register else {
        return Err(report!("Register is not enabled")
            .attach(StatusCode::BAD_REQUEST)
            .into());
    };

    let supplied_token = &payload.token;
    let token = match config.tokens.get(supplied_token) {
        Some(token) => token,
        None => {
            return Err(report!("Invalid magic token")
                .attach(StatusCode::BAD_REQUEST)
                .attach(PrintRootcauseChain::info())
                .attach(format!("Token: {}", supplied_token))
                .attach(format!("Email: {}", payload.email))
                .attach(format!("User: {}", payload.username))
                .into());
        }
    };

    info!(
        token = %supplied_token,
        email = payload.email,
        username = payload.username,
        "Received valid token"
    );

    let admin = super::get_keycloak_admin(&state.config, Client::new()).await?;
    let response = admin
        .realm_users_post(
            &state.config.keycloak.realm,
            UserRepresentation {
                username: Some(payload.username.clone()),
                email: Some(payload.email.clone()),
                attributes: Some(token.attributes.clone()),
                enabled: Some(true),
                ..Default::default()
            },
        )
        .await
        .context("failed to add user to keycloak")?;
    let response = response.into_response();

    if !response.status().is_success() {
        return Err(report!("Failed to register user")
            .attach(response.status())
            .attach(format!("Token: {}", supplied_token))
            .attach(format!("Email: {}", payload.email))
            .attach(format!("User: {}", payload.username))
            .attach(format!(
                "Message: {}",
                response.text().await.unwrap_or("N/A".to_string())
            ))
            .into());
    }

    hooks_self_registered(payload.clone(), &state.config.secrets).await;

    let created_user = admin
        .realm_users_get(
            &state.config.keycloak.realm,   // realm
            None,                           // brief_representation
            None,                           // created_after
            None,                           // created_before
            None,                           // email
            None,                           // email_verified
            None,                           // enabled
            None,                           // exact
            None,                           // first
            None,                           // first_name
            None,                           // idp_alias
            None,                           // idp_user_id
            None,                           // last_name
            None,                           // max
            None,                           // q
            None,                           // search
            Some(payload.username.clone()), // username
        )
        .await
        .context("failed to retrieve created user from keycloak")?
        .into_iter()
        .next()
        .unwrap()
        .id
        .expect("UserId is missing")
        .to_string();

    info!(
        token = %supplied_token,
        email = payload.email,
        username = payload.username,
        "Registered user"
    );

    let response = admin
        .realm_users_with_user_id_send_verify_email_put(
            &state.config.keycloak.realm,
            &created_user,
            None,
            None,
            None,
        )
        .await
        .context("failed to send verify email")?;
    let response = response.into_response();

    if !response.status().is_success() {
        return Err(report!("Failed to send verify mail")
            .attach(response.status())
            .attach(format!("Token: {}", supplied_token))
            .attach(format!("Email: {}", payload.email))
            .attach(format!("User: {}", payload.username))
            .attach(format!(
                "Message: {}",
                response.text().await.unwrap_or("N/A".to_string())
            ))
            .into());
    }

    info!(
        token = %supplied_token,
        email = payload.email,
        username = payload.username,
        "Sent verify mail"
    );

    let response = admin
        .realm_organizations_with_org_id_members_post(
            &state.config.keycloak.realm,
            "1d6d8ce1-3dac-4642-b8fe-204649ffe82f",
            created_user,
        )
        .await
        .context("failed to add org membership")?;

    let response = response.into_response();
    if !response.status().is_success() {
        return Err(report!("Failed to add user to organization")
            .attach(response.status())
            .attach(format!("Token: {}", supplied_token))
            .attach(format!("Email: {}", payload.email))
            .attach(format!("User: {}", payload.username))
            .attach(format!(
                "Message: {}",
                response.text().await.unwrap_or("N/A".to_string())
            ))
            .into());
    }

    Ok(())
}

async fn hooks_self_registered(target: RegisterPayload, secrets: &Secrets) {
    let text = format!(
        "{} ({}) just self-registered",
        target.username, target.email
    );

    match super::send_user_added_to_mattermost("Keycloak Inviter", text, secrets).await {
        Err(e) => {
            warn!(error=%e, "Failed to send self-registration to mattermost")
        }
        Ok(..) => {
            info!(
                email = target.email,
                "Self-Registration successfully sent to mattermost"
            );
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterPayload {
    email: String,
    token: String,
    username: String,
}
