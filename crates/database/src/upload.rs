//! Represents a user uploaded file in the database. See [`Upload::builder`] for creating a new instance,
//! and [`Upload::insert`] for inserting it into the database.

use bon::bon;
use sqlx::types::{chrono, uuid};

use crate::DatabaseError;

/// Represents a user uploaded file in the database. See [`Upload::builder`] for creating a new instance,
/// and [`Upload::insert`] for inserting it into the database.
///
/// The `pub` implementations have been quite permissive to allow this to be easily used in the surrounding
/// crate, but care should be taken to ensure checks are observed when manually writing into the fields.
// XXX: to improve type safety, we could new the newtype pattern to enforce this invariant, of course.
// Though, it's obviously also enforced at the database level.
///
/// # Examples
///
/// Create a new upload and insert it into the database:
///
/// ```rust
/// # use sqlx::SqlitePool;
/// # use chrono::Utc;
/// # use database::{Upload, migrate};
/// # tokio_test::block_on(async {
///   let pool = SqlitePool::connect("sqlite::memory:").await?;
/// # migrate(&pool).await?;
///   let new_upload = Upload::builder()
///     .upload_key("12345678".to_string()).expect("upload_key too long")
///     .uploader_username("uploader_username".to_string()).expect("uploader_username too long")
///     .file_name("file_name".to_string()).expect("file_name too long")
///     .file_size(1024)
///     .now(Utc::now())
///     .expires_at(Utc::now() + chrono::Duration::days(30))
///     .build();
///   new_upload.insert(&pool).await?;
/// # assert_eq!(Upload::select_by_upload_key(&pool, "12345678").await?.unwrap(), new_upload);
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// # }).unwrap();
/// ```
#[derive(Debug, serde::Serialize, Clone, PartialEq, Eq, Hash, sqlx::Type)]
pub struct Upload {
    /// A unique identifier for the upload.
    pub id: uuid::Uuid,

    /// A 8 character long key that is used to identify the upload, must be URL safe.
    /// MAX length: 8
    pub upload_key: String,

    /// The username of the user who uploaded the file, derived from the token used
    /// to authenticate the upload.
    /// MAX length: 255
    pub uploader_username: String,

    /// The name of the file on disk, if it is still present in the cache on the server.
    pub file_name_on_disk: Option<uuid::Uuid>,
    /// The name of the file as it was uploaded, and will be set for the download filename.
    /// MAX length: 255
    pub file_name: String,
    /// The size of the file in bytes, stored as an i64 to be more friendly with the database.
    // XXX: Could be changed to a NonZero u64 to be more typesafe.
    pub file_size: i64,

    /// The time the upload was created.
    pub created_at: chrono::DateTime<sqlx::types::chrono::Utc>,
    /// The time the upload was last updated, typically equal to [`created_at`].
    pub updated_at: chrono::DateTime<sqlx::types::chrono::Utc>,
    /// The time the upload will expire and be deleted from the database.
    pub expires_at: chrono::DateTime<sqlx::types::chrono::Utc>,

    /// The time the upload was uploaded, if it has been uploaded.
    pub uploaded_at: Option<chrono::DateTime<sqlx::types::chrono::Utc>>,
    /// The time the upload was deleted, if it has been deleted.
    pub deleted_at: Option<chrono::DateTime<sqlx::types::chrono::Utc>>,
}

#[bon]
impl Upload {
    /// Creates a new `Upload` instance to be inserted into the database.
    ///
    /// Has full support for the `builder` syntax supported by the [`::bon`] crate.
    ///
    /// # Errors
    ///
    /// While building some keys can return errors. The following errors are possible:
    /// * [`DatabaseError::ValueTooLong`] - The value is too long.
    ///
    /// # Examples
    /// ```rust
    /// # use database::Upload;
    /// # use chrono::Utc;
    /// let now = Utc::now();
    /// let upload = Upload::builder()
    ///     .upload_key("12345678".to_string()).expect("upload_key too long")
    ///     .uploader_username("uploader_username".to_string()).expect("uploader_username too long")
    ///     .file_name("file_name".to_string()).expect("file_name too long")
    ///     .file_size(1024)
    ///     .now(now)
    ///     .expires_at(now + chrono::Duration::days(30))
    ///     .build();
    ///
    /// # assert_eq!(upload.upload_key, "12345678");
    /// # assert_eq!(upload.uploader_username, "uploader_username");
    /// # assert_eq!(upload.file_name, "file_name");
    /// # assert_eq!(upload.file_size, 1024);
    /// # assert_eq!(upload.created_at, now);
    /// # assert_eq!(upload.updated_at, now);
    /// # assert_eq!(upload.expires_at, now + chrono::Duration::days(30));
    /// # assert_eq!(upload.uploaded_at, None);
    /// # assert_eq!(upload.deleted_at, None);
    /// ```
    #[builder]
    pub fn new(
        #[builder(with = |x: impl Into<String>| -> Result<_, DatabaseError> {
            let x = x.into();
            if x.len() > 8 {
                return Err(DatabaseError::ValueTooLong);
            }

            // Do a very basic check to ensure the key is alphanumeric.
            if !x.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(DatabaseError::UrlUnsafe(x));
            }

            Ok(x)
        })]
        upload_key: String,

        #[builder(with = |x: impl Into<String>| -> Result<_, DatabaseError> {
            let x = x.into();
            if x.len() > 255 {
                return Err(DatabaseError::ValueTooLong);
            }
            Ok(x)
        })]
        uploader_username: String,

        #[builder(with = |x: impl Into<String>| -> Result<_, DatabaseError> {
            let x = x.into();
            if x.len() > 255 {
                return Err(DatabaseError::ValueTooLong);
            }
            Ok(x)
        })]
        file_name: String,
        file_size: i64,

        now: chrono::DateTime<chrono::Utc>,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),

            upload_key,

            uploader_username,

            file_name_on_disk: None,
            file_name,
            file_size,

            created_at: now,
            updated_at: now,
            expires_at,

            uploaded_at: None,
            deleted_at: None,
        }
    }
}

#[allow(
    clippy::multiple_inherent_impl,
    reason = "The other impl is #[bon] annotated."
)]
impl Upload {
    /// Selects an upload by its ID, returning `None` if it does not exist.
    ///
    /// # Examples
    /// ```rust
    /// # use sqlx::SqlitePool;
    /// # use database::{Upload, migrate};
    /// # use uuid::Uuid;
    /// # tokio_test::block_on(async {
    ///   let pool = SqlitePool::connect("sqlite::memory:").await?;
    ///   # migrate(&pool).await?;
    ///   # let new_upload = Upload::builder()
    ///   #   .upload_key("12345678".to_string()).expect("upload_key too long")
    ///   #   .uploader_username("uploader_username".to_string()).expect("uploader_username too long")
    ///   #   .file_name("file_name".to_string()).expect("file_name too long")
    ///   #   .file_size(1024)
    ///   #   .now(chrono::Utc::now())
    ///   #   .expires_at(chrono::Utc::now() + chrono::Duration::days(30))
    ///   #   .build();
    ///   # let id = new_upload.id;
    ///   # new_upload.insert(&pool).await?;
    ///   let upload = Upload::select_by_id(&pool, id).await?;
    ///   if let Some(upload) = upload {
    ///       println!("Found upload: {:?}", upload);
    ///   } else {
    ///       panic!("Upload not found");
    ///   }
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// # }).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// This function can return any error that [`sqlx::query_as`] can return.
    pub async fn select_by_id<'e, E>(
        executor: E,
        id: uuid::Uuid,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        let upload = sqlx::query_as!(
            Upload,
            r#"
            SELECT
                id as "id: uuid::Uuid",

                upload_key as "upload_key: String",

                uploader_username as "uploader_username: String",

                file_name_on_disk as "file_name_on_disk: uuid::Uuid",
                file_name as "file_name: String",
                file_size as "file_size: i64",

                created_at as "created_at: chrono::DateTime<chrono::Utc>",
                updated_at as "updated_at: chrono::DateTime<chrono::Utc>",
                expires_at as "expires_at: chrono::DateTime<chrono::Utc>",

                uploaded_at as "uploaded_at: chrono::DateTime<chrono::Utc>",
                deleted_at as "deleted_at: chrono::DateTime<chrono::Utc>"
            FROM uploads
            WHERE
                id = ?
            "#,
            id
        )
        .fetch_optional(executor)
        .await?;

        Ok(upload)
    }

    /// Selects an upload by its upload key, returning `None` if it does not exist.
    ///
    /// # Examples
    /// ```rust
    /// # use sqlx::SqlitePool;
    /// # use database::{Upload, migrate};
    /// # tokio_test::block_on(async {
    ///   let pool = SqlitePool::connect("sqlite::memory:").await?;
    ///   # migrate(&pool).await?;
    ///   # let new_upload = Upload::builder()
    ///   #   .upload_key("12345678".to_string()).expect("upload_key too long")
    ///   #   .uploader_username("uploader_username".to_string()).expect("uploader_username too long")
    ///   #   .file_name("file_name".to_string()).expect("file_name too long")
    ///   #   .file_size(1024)
    ///   #   .now(chrono::Utc::now())
    ///   #   .expires_at(chrono::Utc::now() + chrono::Duration::days(30))
    ///   #   .build();
    ///   # new_upload.insert(&pool).await?;
    ///   let upload = Upload::select_by_upload_key(&pool, "12345678").await?;
    ///   if let Some(upload) = upload {
    ///       println!("Found upload: {:?}", upload);
    ///   } else {
    ///       println!("Upload not found");
    ///   }
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// # }).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// This function can return any error that [`sqlx::query_as`] can return.
    pub async fn select_by_upload_key<'e, E, T>(
        executor: E,
        upload_key: T,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
        T: AsRef<str>,
    {
        let upload_key = upload_key.as_ref();

        let upload = sqlx::query_as!(
            Upload,
            r#"
            SELECT
                id as "id: uuid::Uuid",

                upload_key as "upload_key: String",

                uploader_username as "uploader_username: String",

                file_name_on_disk as "file_name_on_disk: uuid::Uuid",
                file_name as "file_name: String",
                file_size as "file_size: i64",

                created_at as "created_at: chrono::DateTime<chrono::Utc>",
                updated_at as "updated_at: chrono::DateTime<chrono::Utc>",
                expires_at as "expires_at: chrono::DateTime<chrono::Utc>",

                uploaded_at as "uploaded_at: chrono::DateTime<chrono::Utc>",
                deleted_at as "deleted_at: chrono::DateTime<chrono::Utc>"
            FROM uploads WHERE upload_key = ?;
            "#,
            upload_key
        )
        .fetch_optional(executor)
        .await?;

        Ok(upload)
    }

    /// Selects the next `limit` uploads that are expiring, starting from `offset`.
    /// This is useful for cleaning up the database.
    ///
    /// # Examples
    /// ```
    /// # use database::{Upload, migrate};
    /// # use sqlx::SqlitePool;
    /// # tokio_test::block_on(async {
    /// let pool = SqlitePool::connect("sqlite::memory:").await?;
    /// # migrate(&pool).await?;
    /// # let new_upload = Upload::builder()
    /// #   .upload_key("12345677".to_string()).expect("upload_key too long")
    /// #   .uploader_username("uploader_username".to_string()).expect("uploader_username too long")
    /// #   .file_name("file_name".to_string()).expect("file_name too long")
    /// #   .file_size(1024)
    /// #   .now(chrono::Utc::now())
    /// #   .expires_at(chrono::Utc::now() + chrono::Duration::days(30))
    /// #   .build();
    /// # new_upload.insert(&pool).await?;
    /// # let new_upload = Upload::builder()
    /// #   .upload_key("12345678".to_string()).expect("upload_key too long")
    /// #   .uploader_username("uploader_username".to_string()).expect("uploader_username too long")
    /// #   .file_name("file_name".to_string()).expect("file_name too long")
    /// #   .file_size(1024)
    /// #   .now(chrono::Utc::now())
    /// #   .expires_at(chrono::Utc::now() + chrono::Duration::seconds(5))
    /// #   .build();
    /// # new_upload.insert(&pool).await?;
    /// # let expiring_upload_id = new_upload.id;
    /// # tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    /// let now = chrono::Utc::now();
    /// let uploads = Upload::select_next_expiring(&pool, 0, 10, now).await?;
    /// assert_eq!(uploads.len(), 1);
    /// # assert_eq!(uploads[0].id, expiring_upload_id);
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// # }).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// This function will return an error if the query execution fails.
    ///
    /// # Panics
    ///
    /// This function will panic if the `offset` or `limit` values are out of bounds for conversion to `i64`.
    pub async fn select_next_expiring<'e, E>(
        executor: E,
        offset: i64,
        limit: i64,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        let uploads = sqlx::query_as!(
            Upload,
            r#"
            SELECT
                id as "id: uuid::Uuid",

                upload_key as "upload_key: String",

                uploader_username as "uploader_username: String",

                file_name_on_disk as "file_name_on_disk: uuid::Uuid",
                file_name as "file_name: String",
                file_size as "file_size: i64",

                created_at as "created_at: chrono::DateTime<chrono::Utc>",
                updated_at as "updated_at: chrono::DateTime<chrono::Utc>",
                expires_at as "expires_at: chrono::DateTime<chrono::Utc>",

                uploaded_at as "uploaded_at: chrono::DateTime<chrono::Utc>",
                deleted_at as "deleted_at: chrono::DateTime<chrono::Utc>"
            FROM uploads
            WHERE
                expires_at <= ?
                AND deleted_at IS NULL
            ORDER BY expires_at ASC
            LIMIT ? OFFSET ?;
            "#,
            now,
            limit,
            offset
        )
        .fetch_all(executor)
        .await?;

        Ok(uploads)
    }

    /// Selects an upload by its file name on disk, returning `None` if it does not exist.
    ///
    /// # Examples
    /// ```rust
    /// # use uuid::uuid;
    /// # use sqlx::SqlitePool;
    /// # use database::{Upload, migrate};
    /// # tokio_test::block_on(async {
    ///  let pool = SqlitePool::connect("sqlite::memory:").await?;
    /// # migrate(&pool).await?;
    /// # let mut new_upload = Upload::builder()
    /// #     .upload_key("12345678".to_string()).expect("upload_key too long")
    /// #     .uploader_username("uploader_username".to_string()).expect("uploader_username too long")
    /// #     .file_name("file_name".to_string()).expect("file_name too long")
    /// #     .file_size(1024)
    /// #     .now(chrono::Utc::now())
    /// #     .expires_at(chrono::Utc::now() + chrono::Duration::days(30))
    /// #     .build();
    /// # new_upload.insert(&pool).await?;
    /// # new_upload.file_name_on_disk = Some(uuid!("00000000-0000-0000-0000-000000000001"));
    /// # new_upload.update(&pool).await?;
    ///
    /// let upload = Upload::select_by_file_name_on_disk(&pool, uuid!("00000000-0000-0000-0000-000000000001")).await?;
    /// assert_eq!(upload.unwrap().file_name_on_disk, Some(uuid!("00000000-0000-0000-0000-000000000001")));
    ///
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// # }).unwrap();
    /// ```
    ///
    /// # Errors
    /// This function will return an error if the query execution fails.
    pub async fn select_by_file_name_on_disk<'e, E>(
        executor: E,
        file_name_on_disk: uuid::Uuid,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        let upload = sqlx::query_as!(
            Upload,
            r#"
            SELECT
                id as "id: uuid::Uuid",

                upload_key as "upload_key: String",

                uploader_username as "uploader_username: String",

                file_name_on_disk as "file_name_on_disk: uuid::Uuid",
                file_name as "file_name: String",
                file_size as "file_size: i64",

                created_at as "created_at: chrono::DateTime<chrono::Utc>",
                updated_at as "updated_at: chrono::DateTime<chrono::Utc>",
                expires_at as "expires_at: chrono::DateTime<chrono::Utc>",

                uploaded_at as "uploaded_at: chrono::DateTime<chrono::Utc>",
                deleted_at as "deleted_at: chrono::DateTime<chrono::Utc>"
            FROM uploads
            WHERE
                file_name_on_disk = ?
            "#,
            file_name_on_disk
        )
        .fetch_optional(executor)
        .await?;

        Ok(upload)
    }

    /// Inserts the upload into the database.
    ///
    /// # Examples
    /// ```rust
    /// # use sqlx::SqlitePool;
    /// # use chrono::Utc;
    /// # use database::{Upload, migrate};
    /// # tokio_test::block_on(async {
    ///   let pool = SqlitePool::connect("sqlite::memory:").await?;
    /// # migrate(&pool).await?;
    ///   let new_upload = Upload::builder()
    ///     .upload_key("12345678".to_string()).expect("upload_key too long")
    ///     .uploader_username("uploader_username".to_string()).expect("uploader_username too long")
    ///     .file_name("file_name".to_string()).expect("file_name too long")
    ///     .file_size(1024)
    ///     .now(Utc::now())
    ///     .expires_at(Utc::now() + chrono::Duration::days(30))
    ///     .build();
    ///   new_upload.insert(&pool).await?;
    /// # assert_eq!(Upload::select_by_upload_key(&pool, "12345678").await?.unwrap(), new_upload);
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// # }).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// This function can return any error that [`sqlx::query`] can return.
    pub async fn insert<'e, E>(&self, executor: E) -> Result<(), sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        sqlx::query!(
            r#"
            INSERT INTO uploads (id, upload_key, uploader_username, file_name_on_disk, file_name, file_size, created_at, updated_at, expires_at, uploaded_at, deleted_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            "#,
            self.id,

            self.upload_key,

            self.uploader_username,

            self.file_name_on_disk,
            self.file_name,
            self.file_size,

            self.created_at,
            self.updated_at,
            self.expires_at,

            self.uploaded_at,
            self.deleted_at,
        )
        .execute(executor)
        .await?;

        Ok(())
    }

    /// Updates the upload in the database.
    ///
    /// # Examples
    /// ```rust
    /// # use sqlx::SqlitePool;
    /// # use chrono::Utc;
    /// # use database::{Upload, migrate};
    /// # tokio_test::block_on(async {
    ///   let pool = SqlitePool::connect("sqlite::memory:").await?;
    /// # migrate(&pool).await?;
    ///   let mut new_upload = Upload::builder()
    ///     .upload_key("12345678".to_string()).expect("upload_key too long")
    ///     .uploader_username("uploader_username".to_string()).expect("uploader_username too long")
    ///     .file_name("file_name".to_string()).expect("file_name too long")
    ///     .file_size(1024)
    ///     .now(Utc::now())
    ///     .expires_at(Utc::now() + chrono::Duration::days(30))
    ///     .build();
    ///   new_upload.insert(&pool).await?;
    ///
    ///   // Update some fields
    ///   new_upload.file_size = 2048;
    ///   new_upload.updated_at = Utc::now();
    ///   new_upload.uploaded_at = Some(Utc::now());
    ///
    ///   new_upload.update(&pool).await?;
    /// # assert_eq!(Upload::select_by_upload_key(&pool, "12345678").await?.unwrap().file_size, 2048);
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// # }).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// This function can return any error that [`sqlx::query`] can return.
    pub async fn update<'e, E>(&self, executor: E) -> Result<(), sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        sqlx::query!(
            r#"
            UPDATE uploads
            SET upload_key = ?, uploader_username = ?, file_name_on_disk = ?, file_size = ?, updated_at = ?, uploaded_at = ?, deleted_at = ?
            WHERE
                id = ?
            "#,
            self.upload_key,
            self.uploader_username,
            self.file_name_on_disk,
            self.file_size,
            self.updated_at,
            self.uploaded_at,
            self.deleted_at,
            self.id
        )
        .execute(executor)
        .await?;

        Ok(())
    }
}
