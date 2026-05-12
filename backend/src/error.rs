use axum::response::{IntoResponse, Response};
use derive_more::Display;
use reqwest::StatusCode;
use rootcause::Report;
use tracing::Level;
use tracing::warn;

/// A marker to print the whole error chain in the system log
#[derive(Debug, Display, Clone)]
pub struct PrintRootcauseChain(pub Level);

impl PrintRootcauseChain {
    pub fn warn() -> Self {
        Self(Level::WARN)
    }

    pub fn info() -> Self {
        Self(Level::INFO)
    }
}

macro_rules! dyn_event {
    ($lvl:expr, $($arg:tt)+) => {
        match $lvl {
            tracing::Level::ERROR => tracing::error!($($arg)+),
            tracing::Level::WARN  => tracing::warn!($($arg)+),
            tracing::Level::INFO  => tracing::info!($($arg)+),
            tracing::Level::DEBUG => tracing::debug!($($arg)+),
            tracing::Level::TRACE => tracing::trace!($($arg)+),
        }
    };
}

pub struct WebError {
    report: Report,
}

impl<T: ?Sized> From<Report<T>> for WebError {
    fn from(report: Report<T>) -> Self {
        Self {
            report: report.into_dynamic(),
        }
    }
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        let status_code = self
            .report
            .iter_reports()
            .flat_map(|node| node.attachments().iter())
            .filter_map(|attachment| attachment.downcast_inner::<StatusCode>())
            .next();
        let error_message = format!("error: {}", self.report);

        let print_chain = self
            .report
            .iter_reports()
            .flat_map(|node| node.attachments().iter())
            .filter_map(|attachment| attachment.downcast_inner::<PrintRootcauseChain>())
            .next();

        if let Some(print_chain) = print_chain {
            dyn_event!(print_chain.0, error = %self.report, "Error bubbled up to user");
        }

        if let Some(status_code) = status_code {
            // Only give the main context for client errors
            if status_code.is_client_error() {
                let error_message = self.report.format_current_context().to_string();
                (*status_code, error_message).into_response()
            } else {
                (*status_code, error_message).into_response()
            }
        } else {
            warn!(%self.report, "error without status code during handling");
            (StatusCode::INTERNAL_SERVER_ERROR, error_message).into_response()
        }
    }
}
