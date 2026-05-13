use crate::auth::{add_auth_cookies, delete_auth_cookies};
use crate::error::{PrintRootcauseChain, WebError};
use crate::oidc::OidcFlowId;
use crate::server::{AppState, AuthedUser};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Redirect;
use axum::{Extension, Json};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, Expiration, SameSite};
use rootcause::prelude::ResultExt;
use rootcause::report;
use serde::{Deserialize, Serialize};
use tracing::info;

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
            return Err(report!("Missing oidc flow cookie")
                .attach(StatusCode::UNAUTHORIZED)
                .attach(format!("code: {}", oidc_callback_payload.code))
                .attach(format!("state: {}", oidc_callback_payload.state))
                .attach(PrintRootcauseChain::warn())
                .into());
        }
    };
    let flow_id = OidcFlowId::from_string(flow_id.value().to_string());

    info!(flow_id = %flow_id, "Handling OIDC callback");

    let user = state
        .oidc
        .handle_oidc_callback(
            flow_id.clone(),
            &oidc_callback_payload.code,
            &oidc_callback_payload.state,
        )
        .await
        .context("OIDC login failed")
        .attach(PrintRootcauseChain::info())?;

    info!(
        flow_id = flow_id.to_string(),
        user = %user.id,
        user_name = %user.name,
        "OIDC login successful"
    );

    Ok((
        add_auth_cookies(cookies.remove("oidc_flow_id"), user.tokens),
        Redirect::temporary(&state.config.service.frontend_url),
    ))
}

pub async fn about_me(
    Extension(authed_user): Extension<AuthedUser>,
) -> Result<Json<AboutMeResponse>, WebError> {
    Ok(Json(AboutMeResponse {
        sub: authed_user.sub,
        user_name: authed_user.user_name,
        can_invite: authed_user.can_invite,
    }))
}

pub async fn logout(
    State(state): State<AppState>,
    cookies: CookieJar,
) -> Result<(CookieJar, Redirect), WebError> {
    Ok((
        delete_auth_cookies(cookies),
        Redirect::to(&state.config.service.frontend_url),
    ))
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
    can_invite: bool,
}
