use crate::OidcConfig;
use crate::config::Secrets;
use derive_more::Display;
use oauth2::basic::{BasicErrorResponseType, BasicRevocationErrorResponse};
use oauth2::{AccessToken, IntrospectionUrl, PkceCodeVerifier, StandardRevocableToken};
use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreClient, CoreGenderClaim,
    CoreIdTokenClaims, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm, CoreProviderMetadata,
    CoreTokenIntrospectionResponse, CoreTokenResponse,
};
use openidconnect::{
    AccessTokenHash, AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken,
    EmptyAdditionalClaims, EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl, Scope, StandardErrorResponse,
    TokenResponse,
};
use rootcause::option_ext::OptionExt;
use rootcause::prelude::ResultExt;
use rootcause::{Report, report};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::debug;

#[derive(Debug, Eq, PartialEq, Hash, Clone, Display)]
pub struct OidcFlowId(String);

impl OidcFlowId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    pub fn from_string(s: String) -> Self {
        Self(s)
    }
}

struct PendingAuthentication {
    time: Instant,
    pkce_code_verifier: PkceCodeVerifier,
    csrf_token: CsrfToken,
    nonce: Nonce,
}

#[derive(Debug, Clone)]
pub struct OidcAuthRedirect {
    pub flow_id: OidcFlowId,
    pub url: String,
}

#[derive(Clone)]
pub struct Oidc {
    http_client: reqwest::Client,
    oidc_config: OidcConfig,
    #[allow(clippy::type_complexity)]
    oidc_client: Client<
        EmptyAdditionalClaims,
        CoreAuthDisplay,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJsonWebKey,
        CoreAuthPrompt,
        StandardErrorResponse<BasicErrorResponseType>,
        CoreTokenResponse,
        CoreTokenIntrospectionResponse,
        StandardRevocableToken,
        BasicRevocationErrorResponse,
        EndpointSet,
        EndpointNotSet,
        EndpointSet,
        EndpointNotSet,
        EndpointMaybeSet,
        EndpointMaybeSet,
    >,
    pending_auths: Arc<Mutex<HashMap<OidcFlowId, PendingAuthentication>>>,
}

impl Oidc {
    pub async fn build_new(oidc_config: OidcConfig, secrets: &Secrets) -> Result<Self, Report> {
        let http_client = reqwest::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("Could not create http client")?;

        let provider_metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(oidc_config.issuer_url.clone())
                .context("Could not parse issuer URL")
                .attach(format!("issuer_url: {}", oidc_config.issuer_url))?,
            &http_client,
        )
        .await
        .context("Could not fetch provider metadata")?;

        let oidc_client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(oidc_config.client_id.clone()),
            Some(ClientSecret::new(secrets.client_secret.to_string())),
        )
        .set_introspection_url(
            IntrospectionUrl::new(oidc_config.introspect_url.to_string())
                .context("Could not parse introspection URL")
                .attach(format!("introspection_url: {}", oidc_config.introspect_url))?,
        )
        .set_redirect_uri(
            RedirectUrl::new(oidc_config.redirect_url.to_string())
                .context("Could not parse redirect URL")
                .attach(format!("redirect_url: {}", oidc_config.redirect_url))?,
        );

        let pending_auths: Arc<Mutex<HashMap<OidcFlowId, PendingAuthentication>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Periodically trim the pending authentications. If a user takes longer than 5 minutes on
        // shibboleth they can start again
        let pending_auths_clone = pending_auths.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let mut pending_auths = pending_auths_clone.lock().unwrap();

                debug!(
                    pending = pending_auths.len(),
                    "Trimming pending authentications"
                );

                let now = Instant::now();
                pending_auths
                    .retain(|_, auth| now.duration_since(auth.time) < Duration::from_secs(5 * 60));
                drop(pending_auths);
            }
        });

        Ok(Self {
            http_client,
            oidc_config,
            oidc_client,
            pending_auths,
        })
    }

    pub async fn get_oidc_auth_redirect(&self) -> OidcAuthRedirect {
        let flow_id = OidcFlowId::new();

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (auth_url, csrf_token, nonce) = self
            .oidc_client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scopes(
                self.oidc_config
                    .scopes
                    .iter()
                    .map(|s| Scope::new(s.clone())),
            )
            .set_pkce_challenge(pkce_challenge)
            .url();

        self.pending_auths.lock().unwrap().insert(
            flow_id.clone(),
            PendingAuthentication {
                time: Instant::now(),
                pkce_code_verifier: pkce_verifier,
                csrf_token,
                nonce,
            },
        );

        OidcAuthRedirect {
            flow_id,
            url: auth_url.to_string(),
        }
    }

    pub async fn handle_oidc_callback(
        &self,
        flow_id: OidcFlowId,
        auth_token: &str,
        state: &str,
    ) -> Result<OidcUser, Report> {
        let pending_auth = self
            .pending_auths
            .lock()
            .unwrap()
            .remove(&flow_id)
            .context("Unknown flow id")
            .attach(format!("flow_id: {flow_id}"))
            .attach("could not match callback to pending authentication")?;

        if pending_auth.csrf_token.secret() != state {
            return Err(report!("CSRF token mismatch")
                .attach(format!("expected: {}", pending_auth.csrf_token.secret()))
                .attach(format!("actual: {state}")));
        }

        let token_response = self
            .oidc_client
            .exchange_code(AuthorizationCode::new(auth_token.to_string()))
            .context("Unable to configure authentication token exchange")?
            .set_pkce_verifier(pending_auth.pkce_code_verifier)
            .request_async(&self.http_client)
            .await
            .context("Error during authentication token exchange request")?;

        // Extract the ID token claims after verifying its authenticity and nonce.
        let id_token = token_response
            .id_token()
            .context("Server returned no id token after token exchange")?;
        let claims: &CoreIdTokenClaims = id_token
            .claims(&self.oidc_client.id_token_verifier(), &pending_auth.nonce)
            .context("Error verifying claims")?;

        println!("Got id token claims {:#?}", claims);

        // Verify the access token hash to ensure that the access token hasn't been substituted for
        // another user's.
        if let Some(expected_access_token_hash) = claims.access_token_hash() {
            let actual_access_token_hash = AccessTokenHash::from_token(
                token_response.access_token(),
                id_token
                    .signing_alg()
                    .context("Error verifying signature")?,
                id_token
                    .signing_key(&self.oidc_client.id_token_verifier())
                    .context("Error verifying signature")?,
            )
            .context("Could not hash access token")?;

            if actual_access_token_hash != *expected_access_token_hash {
                return Err(
                    report!("Access token signature did not match expected".to_string())
                        .attach(format!("actual: {:?}", actual_access_token_hash))
                        .attach(format!("expected: {:?}", expected_access_token_hash))
                        .into(),
                );
            }
        }

        let id = claims.subject().to_string();
        let name = claims
            .preferred_username()
            .map(|name| name.as_str())
            .unwrap_or("<not provided>")
            .to_string();

        println!(
            "Got access token claims {:#?}",
            token_response.access_token()
        );

        let user = OidcUser {
            id,
            name,
            access_token: token_response.access_token().clone().into_secret(),
        };

        Ok(user)
    }

    pub async fn introspect(
        &self,
        access_token: String,
    ) -> Result<CoreTokenIntrospectionResponse, Report> {
        let access_token = AccessToken::new(access_token);
        let req = self.oidc_client.introspect(&access_token);
        Ok(req
            .request_async(&self.http_client)
            .await
            .context("Error during introspection request")?)
    }
}

#[derive(Debug, Clone)]
pub struct OidcUser {
    pub id: String,
    pub name: String,
    pub access_token: String,
}
