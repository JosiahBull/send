//! Error types for the server.

use axum::{extract::multipart::MultipartError, response::IntoResponse};

/// A convienent wrapper over `Result`, specifically catering to a server error.
pub type ServerResult<T> = Result<T, ServerError>;

/// A kitchen-sink error type for the server.
#[derive(Debug, thiserror::Error)]
#[allow(
    clippy::missing_docs_in_private_items,
    reason = "Error type is self explanatory"
)]
pub enum ServerError {
    // Generic
    #[error("Upload not found")]
    NotFound,
    #[error("Bad request: {reason}")]
    BadRequest { reason: String },
    #[error("Internal server error: {0}")]
    Internal(String),



    // Auth
    #[error("Unauthorized")]
    Unauthorized,

    // Specific Validation or User Errors
    #[error("Expiry must be between {min:?} and {max:?}")]
    InvalidExpiry {
        min: std::time::Duration,
        max: std::time::Duration,
    },
    #[error("File too big")]
    FileTooBig,
    #[error("Invalid file name")]
    InvalidFileName,
    #[error("Exceeded maximum allowed size of integer")]
    OverflowError,

    // Wrapped errors
    #[error(transparent)]
    ParseError(#[from] std::num::ParseIntError),
    #[error(transparent)]
    ChonoOutOfRange(#[from] chrono::OutOfRangeError),
    #[error(transparent)]
    MutlipartError(#[from] MultipartError),
    #[error(transparent)]
    SqlxError(#[from] sqlx::Error),
    #[error(transparent)]
    TokioIoError(#[from] tokio::io::Error),
    #[error(transparent)]
    DatabaseError(#[from] database::DatabaseError),
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),
    #[error(transparent)]
    TokioTimeoutError(#[from] tokio::time::error::Elapsed),
    #[error(transparent)]
    TokioJoinError(#[from] tokio::task::JoinError),
}

impl ServerError {
    /// Get the name of a variant as a string, used for snapshots. Only used for testing.
    /// Should match name of the enum variant exactly, otherwise it's a bug.
    #[cfg(test)]
    const fn to_name(&self) -> &'static str {
        match &self {
            Self::NotFound => "NotFound",
            Self::Internal(_) => "Internal",
            Self::Unauthorized => "Unauthorized",
            Self::BadRequest { .. } => "BadRequest",
            Self::MutlipartError { .. } => "MultipartError",
            Self::ParseError(_) => "ParseError",
            Self::InvalidExpiry { .. } => "InvalidExpiry",
            Self::FileTooBig => "FileTooBig",
            Self::InvalidFileName => "InvalidFileName",
            Self::OverflowError => "OverflowError",
            Self::ChonoOutOfRange(_) => "ChronoOutOfRange",
            Self::SqlxError(_) => "SqlxError",
            Self::TokioIoError(_) => "TokioIoError",
            Self::DatabaseError(_) => "DatabaseError",
            Self::ReqwestError(_) => "ReqwestError",
            Self::TokioTimeoutError(_) => "TokioTimeoutError",
            Self::TokioJoinError(_) => "TokioJoinError",
        }
    }

    /// Get the appropriate [`axum::http::StatusCode`] to be returned to the user based on the error
    /// variant.
    const fn status_code(&self) -> axum::http::StatusCode {
        match self {
            Self::NotFound => axum::http::StatusCode::NOT_FOUND,
            Self::Internal(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::Unauthorized => axum::http::StatusCode::FORBIDDEN,
            Self::BadRequest { .. } => axum::http::StatusCode::BAD_REQUEST,
            Self::MutlipartError { .. } => axum::http::StatusCode::BAD_REQUEST,
            Self::ParseError(_) => axum::http::StatusCode::BAD_REQUEST,
            Self::InvalidExpiry { .. } => axum::http::StatusCode::BAD_REQUEST,
            Self::FileTooBig => axum::http::StatusCode::BAD_REQUEST,
            Self::InvalidFileName => axum::http::StatusCode::BAD_REQUEST,
            Self::OverflowError => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::ChonoOutOfRange(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::SqlxError(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::TokioIoError(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::DatabaseError(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::ReqwestError(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::TokioTimeoutError(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::TokioJoinError(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for ServerError {
    fn into_response(self) -> axum::http::Response<axum::body::Body> {
        let status_code = self.status_code();
        if status_code.as_u16() == 400 {
            tracing::debug!(error = ?self, "Bad request");
            axum::http::Response::builder()
                .status(self.status_code())
                .body(self.to_string().into())
                .expect("Failed to create response")
        } else if status_code.is_server_error() {
            tracing::error!(error = ?self, "Internal server error");
            axum::http::Response::builder()
                .status(self.status_code())
                .body("Internal server error".into())
                .expect("Failed to create response")
        } else {
            tracing::debug!(error = ?self, "Client error");
            axum::http::Response::builder()
                .status(self.status_code())
                .body(self.to_string().into())
                .expect("Failed to create response")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use insta::{assert_debug_snapshot, assert_snapshot};

    #[tokio::test]
    async fn snapshot_error_codes() {
        let errors = vec![
            ServerError::NotFound,
            ServerError::BadRequest {
                reason: "Invalid input".to_string(),
            },
            ServerError::Internal("Something went wrong".to_string()),
            ServerError::Unauthorized,
            ServerError::InvalidExpiry {
                min: std::time::Duration::from_secs(60), // 1 minute
                max: std::time::Duration::from_secs(60 * 60 * 24 * 30), // 1 month
            },
            ServerError::FileTooBig,
            ServerError::InvalidFileName,
            ServerError::ParseError("12d3".parse::<i32>().expect_err("testing here")),
            // ServerError::ChonoOutOfRange(chrono::OutOfRangeError),
            // ServerError::MutlipartError(MultipartError::Boundary),
            ServerError::SqlxError(sqlx::Error::RowNotFound),
            ServerError::TokioIoError(tokio::io::Error::new(
                tokio::io::ErrorKind::Other,
                "io error",
            )),
            // ServerError::DatabaseError(database::DatabaseError::ConnectionError("db error".to_string())),
            // ServerError::ReqwestError(reqwest::Error::new(reqwest::StatusCode::INTERNAL_SERVER_ERROR, "reqwest error")),
        ];

        for error in errors.into_iter() {
            let name = error.to_name();

            let status_code = error.status_code();
            assert_snapshot!(format!("{}_status_code", name), status_code);

            let response = error.into_response();
            assert_debug_snapshot!(format!("{}_response", name), response);

            // Extract body
            let body = response.into_body();
            let body  = axum::body::to_bytes(body, 100_000).await.expect("to be able to collect body into string");
            let body = String::from_utf8(body.to_vec()).expect("response body to be valid utf-8");

            assert_snapshot!(format!("{}_body", name), body);
        }
    }
}
