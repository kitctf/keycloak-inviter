use crate::error::{PrintRootcauseChain, WebError};
use crate::oidc::{Oidc, OidcTokenBundle};
use crate::server::{AppState, AuthedUser};
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, Expiration, SameSite};
use axum_extra::headers::Cookie as RequestCookie;
use oauth2::{AccessToken, RefreshToken, TokenIntrospectionResponse};
use rootcause::option_ext::OptionExt;
use rootcause::prelude::ResultExt;
use rootcause::{Report, report};

pub fn add_auth_cookies(mut jar: CookieJar, tokens: OidcTokenBundle) -> CookieJar {
    jar = jar.add(build_auth_cookie(
        "access_token",
        tokens.access_token.into_secret(),
    ));
    if let Some(refresh_token) = tokens.refresh_token {
        jar = jar.add(build_auth_cookie(
            "refresh_token",
            refresh_token.into_secret(),
        ));
    }
    jar
}

fn build_auth_cookie(name: &'static str, value: String) -> Cookie<'static> {
    Cookie::build((name, value))
        .http_only(true)
        .secure(true)
        .expires(Expiration::Session)
        .same_site(SameSite::Lax)
        .path("/")
        .build()
}

pub fn delete_auth_cookies(jar: CookieJar) -> CookieJar {
    let mut access_token = build_auth_cookie("access_token", "".to_string());
    access_token.make_removal();
    let mut refresh_token = build_auth_cookie("refresh_token", "".to_string());
    refresh_token.make_removal();

    jar.add(access_token).add(refresh_token)
}

pub async fn validate_access(
    state: &AppState,
    cookie: RequestCookie,
    mut request: Request,
    next: Next,
) -> Result<Response, WebError> {
    let access_token = cookie
        .get("access_token")
        .context("Mising access token")
        .attach(StatusCode::UNAUTHORIZED)?;
    let access_token = AccessToken::new(access_token.to_string());
    let refresh_token = cookie
        .get("refresh_token")
        .map(|it| RefreshToken::new(it.to_string()));

    let tokens = verify_tokens(&state.oidc, access_token, refresh_token)
        .await
        .context("Wrong client id or access token no longer active")
        .attach(StatusCode::UNAUTHORIZED)
        .attach(PrintRootcauseChain::info())?;
    let access_token_content = tokens
        .access_token_content()
        .context("Failed to parse access token")
        .attach(StatusCode::UNAUTHORIZED)
        .attach(PrintRootcauseChain::warn())?;

    request.extensions_mut().insert(AuthedUser {
        user_name: tokens.username()?,
        sub: tokens.sub()?,
        access_token_content,
        can_invite: tokens.can_invite()?,
    });

    let response = next.run(request).await;
    let cookies = CookieJar::from_headers(response.headers());
    let cookies = add_auth_cookies(cookies, tokens);

    Ok((cookies, response).into_response())
}

pub async fn verify_tokens(
    oidc: &Oidc,
    access_token: AccessToken,
    refresh_token: Option<RefreshToken>,
) -> Result<OidcTokenBundle, Report> {
    let introspection_result = oidc
        .introspect(access_token.clone().into_secret())
        .await
        .context("failed to introspect access token")?;
    if introspection_result.active() {
        return Ok(OidcTokenBundle {
            access_token,
            refresh_token: None,
        });
    }
    let Some(refresh_token) = refresh_token else {
        return Err(report!("Refresh token missing and access token is invalid"));
    };
    let refreshed_tokens = oidc
        .refresh_tokens(refresh_token.into_secret())
        .await
        .context("failed to refresh access token")?;

    Ok(refreshed_tokens)
}
