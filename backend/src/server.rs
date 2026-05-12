use crate::config::Config;
use crate::endpoints::applications::get_available_applications;
use crate::endpoints::auth::{about_me, login_oidc_callback, login_redirect};
use crate::endpoints::invite::invite_user;
use crate::endpoints::self_register::register_user;
use crate::error::{PrintRootcauseChain, WebError};
use crate::oidc::Oidc;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Router, middleware};
use axum_extra::TypedHeader;
use axum_extra::headers::Cookie;
use oauth2::TokenIntrospectionResponse;
use openidconnect::core::CoreTokenIntrospectionResponse;
use rootcause::option_ext::OptionExt;
use rootcause::prelude::ResultExt;
use rootcause::{Report, report};
use std::net::SocketAddr;
use tokio::select;
use tokio::signal::unix::{SignalKind, signal};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{Instrument, Span, info, warn};

pub async fn start_server(config: Config, oidc: Oidc) -> Result<(), Report> {
    let state = AppState {
        config: config.clone(),
        oidc,
    };
    let authed = middleware::from_fn_with_state(
        state.clone(),
        |State(state): State<AppState>,
         TypedHeader(cookie): TypedHeader<Cookie>,
         request: Request,
         next: Next| async move {
            validate_access(&state, cookie, request, next)
                .await
                .unwrap_or_else(|e| e.into_response())
        },
    );

    let app = Router::new()
        .route("/login", get(login_redirect))
        .route("/login/callback", get(login_oidc_callback))
        .route("/invite-user", post(invite_user).layer(authed.clone()))
        .route("/about-me", get(about_me).layer(authed.clone()))
        .route("/register", post(register_user))
        .route(
            "/applications",
            get(get_available_applications).layer(authed.clone()),
        )
        .layer(CorsLayer::very_permissive()) // TODO: Make nicer
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.service.listen_address)
        .await
        .context("failed to listen")?;
    info!(
        "listening on {}",
        listener.local_addr().context("failed to get local addr")?
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async { graceful_shutdown().await }.instrument(Span::current()))
    .await
    .context("server died")
    .map_err(Report::into_dynamic)
}

async fn validate_access(
    state: &AppState,
    cookie: Cookie,
    mut request: Request,
    next: Next,
) -> Result<Response, WebError> {
    let token = cookie
        .get("access_token")
        .context("Mising access token")
        .attach(StatusCode::UNAUTHORIZED)?;

    let res = verify_access_token(&state.oidc, token).await?;
    let client_id = res
        .client_id()
        .context("Client id missing")
        .attach(StatusCode::UNAUTHORIZED)?;
    if !res.active() || client_id.to_string() != state.config.oidc.client_id {
        info!(
            active = %res.active(),
            client_id = ?res.client_id(),
            "Discarded access attempt"
        );
        return Err(report!("Wrong client id or access token no longer active")
            .attach(StatusCode::UNAUTHORIZED)
            .attach(format!("Client id: {client_id:?}"))
            .attach(PrintRootcauseChain::info())
            .into());
    }

    let access_token_content: serde_json::Value = jsonwebtoken::dangerous::insecure_decode(token)
        .context("failed to parse resource access from access token")?
        .claims;
    let can_invite = can_invite(&access_token_content).unwrap_or(false);

    request.extensions_mut().insert(AuthedUser {
        user_name: res.username().unwrap_or("no username").to_string(),
        sub: res
            .sub()
            .expect("No subject in keycloak token response")
            .to_string(),
        access_token_content,
        can_invite,
    });

    Ok(next.run(request).await)
}

async fn verify_access_token(
    oidc: &Oidc,
    access_token: &str,
) -> Result<CoreTokenIntrospectionResponse, Report> {
    oidc.introspect(access_token.trim().to_string())
        .await
        .context("failed to introspect access token")
        .map_err(Report::into_dynamic)
}

fn can_invite(access_token_content: &serde_json::Value) -> Result<bool, Report> {
    Ok(access_token_content
        .get("roles")
        .context("no roles")?
        .as_array()
        .context("no roles arr")?
        .iter()
        .filter_map(|it| it.as_str())
        .any(|it| it == "can-invite"))
}

async fn graceful_shutdown() {
    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let interrupt = tokio::signal::ctrl_c();
    select! {
        _ = sigterm.recv() => warn!("Received SIGTERM"),
        _ = interrupt => warn!("Received SIGINT")
    }
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub oidc: Oidc,
}

#[derive(Debug, Clone)]
pub struct AuthedUser {
    pub user_name: String,
    pub sub: String,
    pub access_token_content: serde_json::Value,
    pub can_invite: bool,
}
