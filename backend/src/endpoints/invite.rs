use crate::config::Secrets;
use crate::error::{PrintRootcauseChain, WebError};
use crate::server::{AppState, AuthedUser};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use keycloak::types::TypeMap;
use reqwest::Client;
use rootcause::prelude::ResultExt;
use rootcause::report;
use serde::Deserialize;
use tracing::{info, warn};

pub async fn invite_user(
    State(AppState { config, .. }): State<AppState>,
    Extension(authed_user): Extension<AuthedUser>,
    Json(payload): Json<InvitePayload>,
) -> Result<(), WebError> {
    info!(
        triggering_sub = %authed_user.sub,
        triggering_name = %authed_user.user_name,
        target_email = %payload.email,
        target_first_name = %payload.first_name.as_deref().unwrap_or("N/A"),
        target_last_name = %payload.last_name.as_deref().unwrap_or("N/A"),
        "Inviting user"
    );

    if !authed_user.can_invite {
        return Err(report!("You have no permission to invite a user")
            .attach(StatusCode::UNAUTHORIZED)
            .attach(PrintRootcauseChain::info())
            .attach(format!("user: {}", authed_user.sub))
            .attach(format!("user name: {}", authed_user.user_name))
            .attach(format!("target_email: {}", payload.email))
            .into());
    }

    hooks_invited_user(authed_user.clone(), payload.clone(), &config.secrets).await;

    let admin = super::get_keycloak_admin(&config, Client::new()).await?;

    let mut type_map = TypeMap::new();
    type_map.insert("email".to_string(), payload.email.clone());
    if let Some(first_name) = payload.first_name.clone() {
        type_map.insert("firstName".to_string(), first_name);
    };
    if let Some(last_name) = payload.last_name.clone() {
        type_map.insert("lastName".to_string(), last_name);
    }

    let result = admin
        .realm_organizations_with_org_id_members_invite_user_post(
            &config.keycloak.realm,
            "1d6d8ce1-3dac-4642-b8fe-204649ffe82f",
            type_map,
        )
        .await
        .context("keycloak invite failed")
        .attach(format!("Email: {}", payload.email))
        .attach(format!("First name: {:?}", payload.first_name))
        .attach(format!("Last name: {:?}", payload.last_name))?;

    let result = result.into_response();
    if !result.status().is_success() {
        return Err(report!("failed to invite user")
            .attach(format!("Email: {}", payload.email))
            .attach(format!("First name: {:?}", payload.first_name))
            .attach(format!("Last name: {:?}", payload.last_name))
            .attach(result.status())
            .attach(format!(
                "Message: {}",
                result.text().await.unwrap_or("N/A".to_string())
            ))
            .into());
    }

    info!(
        triggering_sub = %authed_user.sub,
        triggering_name = %authed_user.user_name,
        target_email = %payload.email,
        target_first_name = %payload.first_name.as_deref().unwrap_or("N/A"),
        target_last_name = %payload.last_name.as_deref().unwrap_or("N/A"),
        "Invited user"
    );

    Ok(())
}

async fn hooks_invited_user(triggering: AuthedUser, target: InvitePayload, secrets: &Secrets) {
    let mut text = format!("Invited user {}", target.email);
    let names = target
        .first_name
        .iter()
        .chain(target.last_name.iter())
        .map(String::as_str)
        .collect::<Vec<_>>();
    if !names.is_empty() {
        text += " (";
        text += &names.join(" ");
        text += ")";
    }

    match super::send_user_added_to_mattermost(&triggering.user_name, text, secrets).await {
        Err(e) => {
            warn!(error=%e, "Failed to send invite to mattermost")
        }
        Ok(..) => {
            info!(
                email = target.email,
                "Invite successfully sent to mattermost"
            );
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitePayload {
    email: String,
    first_name: Option<String>,
    last_name: Option<String>,
}
