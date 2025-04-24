use crate::config::Config;
use crate::oidc::Oidc;
use crate::web_handler::{
    OidcSnafu, WebError, about_me, invite_user, login_oidc_callback, login_redirect, register_user,
};
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
use snafu::futures::TryFutureExt;
use snafu::location;
use std::net::SocketAddr;
use tokio::select;
use tokio::signal::unix::{SignalKind, signal};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{Instrument, Span, info, warn};

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub oidc: Oidc,
}

#[derive(Debug, Clone)]
pub struct AuthedUser {
    pub user_name: String,
    pub sub: String,
}

pub async fn start_server(config: Config, oidc: Oidc) {
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
        .layer(CorsLayer::very_permissive()) // TODO: Make nicer
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.service.listen_address)
        .await
        .unwrap();
    info!("listening on {}", listener.local_addr().unwrap());

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async { graceful_shutdown().await }.instrument(Span::current()))
    .await
    .unwrap()
}

async fn validate_access(
    state: &AppState,
    cookie: Cookie,
    mut request: Request,
    next: Next,
) -> Result<Response, WebError> {
    let Some(token) = cookie.get("access_token") else {
        return Err(WebError::Anything {
            status: StatusCode::UNAUTHORIZED,
            message: "Missing access token".to_string(),
            location: location!(),
        });
    };

    let res = verify_access_token(&state.oidc, token).await?;
    let Some(client_id) = res.client_id() else {
        return Err(WebError::Anything {
            status: StatusCode::UNAUTHORIZED,
            message: "Client id missing".to_string(),
            location: location!(),
        });
    };
    if !res.active() || client_id.to_string() != state.config.oidc.client_id {
        info!(
            active = %res.active(),
            client_id = ?res.client_id(),
            "Discarded access attempt"
        );
        return Err(WebError::Anything {
            status: StatusCode::UNAUTHORIZED,
            message: "Invalid access token".to_string(),
            location: location!(),
        });
    }

    request.extensions_mut().insert(AuthedUser {
        user_name: res.username().unwrap_or("no username").to_string(),
        sub: res
            .sub()
            .expect("No subject in keycloak token response")
            .to_string(),
    });

    Ok(next.run(request).await)
}

async fn verify_access_token(
    oidc: &Oidc,
    access_token: &str,
) -> Result<CoreTokenIntrospectionResponse, WebError> {
    let res = oidc
        .introspect(access_token.trim().to_string())
        .context(OidcSnafu)
        .await?;

    Ok(res)
}

async fn graceful_shutdown() {
    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let interrupt = tokio::signal::ctrl_c();
    select! {
        _ = sigterm.recv() => warn!("Received SIGTERM"),
        _ = interrupt => warn!("Received SIGINT")
    }
}
