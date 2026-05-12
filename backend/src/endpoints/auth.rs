use crate::error::WebError;
use crate::oidc::OidcFlowId;
use crate::server::{AppState, AuthedUser};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Redirect;
use axum::{Extension, Json};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, Expiration, SameSite};
use serde::{Deserialize, Serialize};
use snafu::{Report, location};
use tracing::{info, warn};

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

pub async fn about_me(
    Extension(authed_user): Extension<AuthedUser>,
) -> Result<Json<AboutMeResponse>, WebError> {
    Ok(Json(AboutMeResponse {
        sub: authed_user.sub,
        user_name: authed_user.user_name,
    }))
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
