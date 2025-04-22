use crate::oidc::{OidcError, OidcFlowId};
use crate::web::AppState;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Form, Json};
use axum_extra::extract::cookie::{Cookie, Expiration, SameSite};
use axum_extra::extract::CookieJar;
use keycloak::types::TypeMap;
use keycloak::{KeycloakAdmin, KeycloakAdminToken, KeycloakError};
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::json;
use snafu::{location, Location, Report, ResultExt, Snafu};
use std::error::Error;
use tracing::{info, warn};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum WebError {
    #[snafu(display("Error {message} at {location}"))]
    AnythingErr {
        status: StatusCode,
        message: String,
        source: Box<dyn Error + Sync + Send>,
        #[snafu(implicit)]
        location: Location,
    },
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
        let (status, msg) = match self {
            WebError::AnythingErr {
                status, message, ..
            } => (status, message),
            WebError::Anything {
                status, message, ..
            } => (status, message),
            WebError::Oidc { source, .. } => {
                let status = StatusCode::INTERNAL_SERVER_ERROR;
                let message = format!("OIDC error: {}", source);
                (status, message)
            }
            WebError::Keycloak { source, .. } => {
                let status = StatusCode::INTERNAL_SERVER_ERROR;
                let message = format!("Keycloak error: {}", source);
                (status, message)
            }
        };

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
) -> Result<CookieJar, WebError> {
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
            return Err(WebError::AnythingErr {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: "OIDC login failed".to_string(),
                location: location!(),
                source: Box::new(e),
            });
        }
    };

    info!(
        flow_id = flow_id.to_string(),
        user = %user.id,
        user_name = %user.name,
        "OIDC login successful"
    );

    Ok(cookies.remove("oidc_flow_id").add(
        Cookie::build(("access_token", user.access_token))
            .http_only(true)
            .secure(true)
            .expires(Expiration::Session)
            .same_site(SameSite::Lax)
            .path("/")
            .build(),
    ))
}

pub async fn invite_user(
    State(state): State<AppState>,
    Form(payload): Form<InvitePayload>,
) -> Result<(), WebError> {
    let client = reqwest::Client::new();
    let token = KeycloakAdminToken::acquire_custom_realm(
        &state.keycloak_config.keycloak_url,
        &state.keycloak_config.keycloak_user,
        &state.keycloak_config.keycloak_password,
        &state.keycloak_config.keycloak_realm,
        "admin-cli",
        "password",
        &client,
    )
    .await
    .context(KeycloakSnafu)?;

    let admin = KeycloakAdmin::new(&state.keycloak_config.keycloak_url, token, client);

    let mut type_map = TypeMap::new();
    type_map.insert("email".to_string(), payload.email);
    if let Some(first_name) = payload.first_name {
        type_map.insert("firstName".to_string(), first_name);
    };
    if let Some(last_name) = payload.last_name {
        type_map.insert("lastName".to_string(), last_name);
    }

    let result = admin
        .realm_organizations_with_org_id_members_invite_user_post(
            &state.keycloak_config.keycloak_realm,
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

    Ok(())
}

#[derive(Deserialize)]
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
