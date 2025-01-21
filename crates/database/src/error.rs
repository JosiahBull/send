//! Error types for the database.

/// A convienent wrapper over `Result`, specifically catering to a database error.
pub type DatabaseResult<T> = Result<T, DatabaseError>;

/// A 'kitchen sink' error type for the database.
#[allow(
    clippy::module_name_repetitions,
    reason = "It is conventional for error types to contain 'Error' at the end to provide context."
)]
#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("The value is too long")]
    ValueTooLong,
    #[error("Was not able to find the requested value")]
    NotFound,
    #[error("The found value is not URL safe: {0}")]
    UrlUnsafe(String),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    MigrateError(#[from] sqlx::migrate::MigrateError),
    #[error(transparent)]
    TryFromIntError(#[from] std::num::TryFromIntError),
}
