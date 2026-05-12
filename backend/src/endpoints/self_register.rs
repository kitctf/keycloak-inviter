use crate::config::Secrets;
use crate::error::{KeycloakSnafu, WebError};
use crate::server::AppState;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use keycloak::types::UserRepresentation;
use reqwest::Client;
use serde::Deserialize;
use snafu::{ResultExt, location};
use tracing::info;

pub async fn register_user(
    State(state): State<AppState>,
    Json(payload): Json<RegisterPayload>,
) -> Result<(), WebError> {
    let Some(config) = &state.config.register else {
        return Err(WebError::Anything {
            status: StatusCode::BAD_REQUEST,
            message: "Register is not enabled".to_string(),
            location: location!(),
        });
    };

    let supplied_token = &payload.token;
    let token = match config.tokens.get(supplied_token) {
        Some(token) => token,
        None => {
            info!(
                token = supplied_token,
                email = payload.email,
                username = payload.username,
                "User submitted invalid token"
            );
            return Err(WebError::Anything {
                status: StatusCode::BAD_REQUEST,
                message: "Invalid token".to_string(),
                location: location!(),
            });
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
        .context(KeycloakSnafu)?;
    let response = response.into_response();

    if !response.status().is_success() {
        return Err(WebError::Anything {
            status: response.status(),
            message: format!(
                "Failed to register user: {}",
                response.text().await.unwrap_or("N/A".to_string())
            ),
            location: location!(),
        });
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
        .context(KeycloakSnafu)?
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
        .context(KeycloakSnafu)?;
    let response = response.into_response();

    if !response.status().is_success() {
        return Err(WebError::Anything {
            status: response.status(),
            message: format!(
                "Failed to send verify mail: {}",
                response.text().await.unwrap_or("N/A".to_string())
            ),
            location: location!(),
        });
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
        .context(KeycloakSnafu)?;

    let response = response.into_response();

    if !response.status().is_success() {
        return Err(WebError::Anything {
            status: response.status(),
            message: format!(
                "Failed to add user to organization: {}",
                response.text().await.unwrap_or("N/A".to_string())
            ),
            location: location!(),
        });
    }

    Ok(())
}

async fn hooks_self_registered(target: RegisterPayload, secrets: &Secrets) {
    let text = format!(
        "{} ({}) just self-registered",
        target.username, target.email
    );

    let status =
        super::send_user_added_to_mattermost(String::from("Keycloak Inviter"), text, secrets).await;

    if status {
        info!(status = %status, email = target.email, "Webhook sent successfully");
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterPayload {
    email: String,
    token: String,
    username: String,
}
