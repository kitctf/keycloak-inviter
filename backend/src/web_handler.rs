use crate::config::{Config, Secrets};
use crate::oidc::{OidcError, OidcFlowId};
use crate::web::{AppState, AuthedUser};
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Extension, Json};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, Expiration, SameSite};
use keycloak::types::{TypeMap, UserRepresentation};
use keycloak::{KeycloakAdmin, KeycloakAdminToken, KeycloakError};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use snafu::{Location, Report, ResultExt, Snafu, location};
use tracing::{info, warn};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum WebError {
    #[snafu(display("Error {message} at {location}"))]
    Anything {
        status: StatusCode,
        message: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Oidc error at {location}"))]
    Oidc {
        source: OidcError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Keycloak error at {location}"))]
    Keycloak {
        source: KeycloakError,
        #[snafu(implicit)]
        location: Location,
    },
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        let status = match &self {
            WebError::Anything { status, .. } => *status,
            WebError::Oidc { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            WebError::Keycloak { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let msg = Report::from_error(&self).to_string();
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            info!(status = %status, error = %msg, "Internal server error");
        }

        (status, Json(json!({"message": msg}))).into_response()
    }
}

pub async fn login_redirect(
    State(state): State<AppState>,
    cookies: CookieJar,
) -> Result<(CookieJar, Redirect), WebError> {
    let oidc_auth_redirect = state.oidc.get_oidc_auth_redirect().await;
    let cookies = cookies.add(
        Cookie::build(("oidc_flow_id", oidc_auth_redirect.flow_id.to_string()))
            .http_only(true)
            .secure(true)
            .expires(Expiration::Session)
            .same_site(SameSite::Lax)
            .build(),
    );

    Ok((cookies, Redirect::temporary(&oidc_auth_redirect.url)))
}

pub async fn login_oidc_callback(
    State(state): State<AppState>,
    cookies: CookieJar,
    Query(oidc_callback_payload): Query<OidcCallbackPayload>,
) -> Result<(CookieJar, Redirect), WebError> {
    let flow_id = match cookies.get("oidc_flow_id") {
        Some(flow_id) => flow_id,
        None => {
            warn!("Received oidc login callback without oidc flow id cookie");
            return Err(WebError::Anything {
                status: StatusCode::UNAUTHORIZED,
                message: "Missing oidc flow id cookie".to_string(),
                location: location!(),
            });
        }
    };
    let flow_id = OidcFlowId::from_string(flow_id.value().to_string());

    info!(flow_id = %flow_id, "Handling OIDC callback");

    let res = state
        .oidc
        .handle_oidc_callback(
            flow_id.clone(),
            &oidc_callback_payload.code,
            &oidc_callback_payload.state,
        )
        .await;

    let user = match res {
        Ok(user) => user,
        Err(e) => {
            info!(flow_id = %flow_id, error = %Report::from_error(&e), "OIDC login failed");
            return Err(WebError::Oidc {
                location: location!(),
                source: e,
            });
        }
    };

    info!(
        flow_id = flow_id.to_string(),
        user = %user.id,
        user_name = %user.name,
        "OIDC login successful"
    );

    Ok((
        cookies.remove("oidc_flow_id").add(
            Cookie::build(("access_token", user.access_token))
                .http_only(true)
                .secure(true)
                .expires(Expiration::Session)
                .same_site(SameSite::Lax)
                .path("/")
                .build(),
        ),
        Redirect::temporary(&state.config.service.frontend_url),
    ))
}

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

    hooks_invited_user(authed_user.clone(), payload.clone(), &config.secrets).await;

    let admin = get_keycloak_admin(&config, Client::new()).await?;

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
        .context(KeycloakSnafu)?;

    let result = result.into_response();
    if !result.status().is_success() {
        return Err(WebError::Anything {
            status: result.status(),
            message: format!(
                "Failed to invite user: {}",
                result.text().await.unwrap_or("N/A".to_string())
            ),
            location: location!(),
        });
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

async fn get_keycloak_admin(config: &Config, client: Client) -> Result<KeycloakAdmin, WebError> {
    let token = KeycloakAdminToken::acquire_custom_realm(
        &config.keycloak.url,
        &config.secrets.keycloak_user,
        &config.secrets.keycloak_password,
        &config.keycloak.realm,
        "admin-cli",
        "password",
        &client,
    )
    .await
    .context(KeycloakSnafu)?;

    Ok(KeycloakAdmin::new(&config.keycloak.url, token, client))
}

async fn send_user_webhook(webhook_author: String, text: String, secrets: &Secrets) -> bool {
    let url = match &secrets.webhook_url {
        Some(url) => url,
        None => return false,
    };
    let response = Client::new()
        .post(url)
        .json(&json!({
            "text": text,
            "username": webhook_author,
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

    let status = send_user_webhook(triggering.user_name, text, secrets).await;

    if status {
        info!(status = %status, email = target.email, "Webhook sent successfully");
    }
}

async fn hooks_self_registered(target: RegisterPayload, secrets: &Secrets) {
    let text = format!(
        "{} ({}) just self-registered",
        target.username, target.email
    );

    let status = send_user_webhook(String::from("Keycloak Inviter"), text, secrets).await;

    if status {
        info!(status = %status, email = target.email, "Webhook sent successfully");
    }
}

pub async fn about_me(
    Extension(authed_user): Extension<AuthedUser>,
) -> Result<Json<AboutMeResponse>, WebError> {
    Ok(Json(AboutMeResponse {
        sub: authed_user.sub,
        user_name: authed_user.user_name,
    }))
}

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

    let admin = get_keycloak_admin(&state.config, Client::new()).await?;
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
            &state.config.keycloak.realm,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(payload.username.clone()),
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

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitePayload {
    email: String,
    first_name: Option<String>,
    last_name: Option<String>,
}

#[derive(Deserialize)]
pub struct OidcCallbackPayload {
    state: String,
    code: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AboutMeResponse {
    sub: String,
    user_name: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterPayload {
    email: String,
    token: String,
    username: String,
}
