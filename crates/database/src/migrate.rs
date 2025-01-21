//! Database migration functions.

use crate::DatabaseError;

/// Run the migrations on the database.
///
/// # Examples
///
/// ```rust
/// use sqlx::SqlitePool;
///
/// # tokio_test::block_on(async {
/// let pool = SqlitePool::connect("sqlite::memory:").await?;
/// database::migrate(&pool).await?;
/// #   Ok::<_, Box<dyn std::error::Error>>(())
/// # }).unwrap();
/// ```
///
/// # Errors
///
/// If the migration fails, a [`DatabaseError::MigrateError`] will be returned, this typically
/// indicates a problem with the database connection or the transaction as written, and should only
/// occur if an outside force has interfered with the migration process or database tables.
pub async fn migrate<'a, S>(db_pool: S) -> Result<(), DatabaseError>
where
    S: sqlx::Acquire<'a>,
    <S::Connection as std::ops::Deref>::Target: sqlx::migrate::Migrate,
{
    sqlx::migrate!("./migrations")
        .run(db_pool)
        .await
        .map_err(DatabaseError::MigrateError)
}
