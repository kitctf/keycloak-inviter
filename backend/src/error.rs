use crate::oidc::OidcError;
use axum::Json;
use axum::response::{IntoResponse, Response};
use keycloak::KeycloakError;
use reqwest::StatusCode;
use serde_json::json;
use snafu::{Location, Report, Snafu};
use tracing::info;

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
            Self::Anything { status, .. } => *status,
            Self::Oidc { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Keycloak { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let msg = Report::from_error(&self).to_string();
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            info!(status = %status, error = %msg, "Internal server error");
        }

        (status, Json(json!({"message": msg}))).into_response()
    }
}
