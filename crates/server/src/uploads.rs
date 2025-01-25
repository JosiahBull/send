//! Abstracts the file upload/downloads, including check if uploads exist and ensuring we don't
//! overrun the storage allocated to the service.

use std::{
    num::NonZeroU64,
    path::PathBuf,
    sync::{atomic::AtomicU64, Arc},
};

use async_stream::stream;
use bon::bon;
use database::Upload;
use futures::{Stream, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::Instrument;

use crate::{
    error::{ServerError, ServerResult},
    unique_ids::UploadId,
};

/// An abstraction for managing the lifetime of file uploads.
#[derive(Debug)]
pub struct Uploads {
    /// A persistant link to the database, useful for persisting information about uploads.
    db_pool: sqlx::SqlitePool,
    /// The total size of all files on the disk right now.
    size_of_files_on_disk: Arc<AtomicU64>,
    /// The location of the cache directory on disk.
    cache_directory: PathBuf,
    /// The maximum size of a single upload.
    max_allowed_file_size: NonZeroU64,
    /// The total maximum size of all files on disk.
    max_allowed_cache_size: NonZeroU64,

    /// The minimum time an upload is allowed to live for.
    min_time_to_live: std::time::Duration,

    /// The maximum time an upload is allowed to live for.
    max_time_to_live: std::time::Duration,

    /// A handle to the bookkeeping task.
    #[allow(
        dead_code,
        reason = "This is a handle to the task, it is not used directly."
    )]
    bookkeeping_handle: tokio::task::JoinHandle<()>,
    /// A token to cancel the bookkeeping task.
    #[allow(
        dead_code,
        reason = "This is a token to cancel the task, it is not used directly."
    )]
    drop_guard: tokio_util::sync::DropGuard,
}

/// Performs bookkeeping tasks, such as cleaning up expired uploads.
#[tracing::instrument(skip(db_pool))]
async fn bookkeeping(
    db_pool: &sqlx::SqlitePool,
    cache_directory: &PathBuf,
    size_of_files_on_disk: Arc<AtomicU64>,
) -> ServerResult<()> {
    let now = chrono::Utc::now();
    let expiring_uploads = Upload::select_next_expiring(
        db_pool, 0,
        1000, // Clean up at most 1000 uploads at a time, should exceed any normal usage.
        now,
    )
    .await?;

    // Convert into array of futures.
    let mut futures = Vec::with_capacity(expiring_uploads.len());
    for upload in expiring_uploads {
        futures.push(async move {
            let file_name_on_disk = match upload.file_name_on_disk {
                Some(file_name_on_disk) => file_name_on_disk,
                None => return Ok::<_, ServerError>(upload),
            };

            let file_path = cache_directory.join(file_name_on_disk.to_string());

            if tokio::fs::metadata(&file_path).await.is_ok() {
                tokio::fs::remove_file(&file_path).await?;
            }

            Ok(upload)
        });
    }

    // Wait for all the futures to complete, into an array of results.
    let results = futures::future::join_all(futures).await;

    // Check if any of the results are errors.
    let mut errors = vec![];
    for result in results {
        match result {
            Ok(mut upload) => {
                upload.file_name_on_disk = None;
                upload.deleted_at = Some(now);
                size_of_files_on_disk.fetch_sub(
                    upload.file_size.into(),
                    std::sync::atomic::Ordering::Relaxed,
                );
                upload.update(db_pool).await?;
            }
            Err(err) => {
                errors.push(err);
            }
        }
    }

    if !errors.is_empty() {
        let first_five_errors = errors
            .iter()
            .take(5)
            .map(|err| err.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        tracing::error!(
            num_errors = errors.len(),
            errors = first_five_errors,
            "Failed to cleanup uploads"
        );
        // SAFETY: errors is not empty.
        return Err(errors.remove(0));
    }

    Ok(())
}

#[bon]
impl Uploads {
    /// Creates a new instance of the `Uploads` service.
    ///
    /// # Arguments
    ///
    /// * `db_pool` - A connection pool to the database.
    /// * `cache_directory` - The directory where files will be stored.
    ///
    /// # Returns
    ///
    /// A new instance of the `Uploads` service.
    ///
    /// # Errors
    ///
    /// This function will return an error if the cache directory cannot be read or if the size of
    /// the files in the cache directory cannot be calculated.
    ///
    /// # Example
    /// # TODO
    /// ```rust
    /// ```
    #[builder]
    #[tracing::instrument(skip(db_pool), err)]
    pub async fn new(
        /// A connection pool to the database.
        db_pool: sqlx::SqlitePool,
        /// The directory where files will be stored.
        cache_directory: PathBuf,
        /// The maximum size of a single upload.
        max_allowed_file_size: NonZeroU64,
        /// The total maximum size of all files on disk.
        max_allowed_cache_size: NonZeroU64,
        /// The minimum time an upload is allowed to live for.
        min_time_to_live: std::time::Duration,
        /// The maximum time an upload is allowed to live for.
        max_time_to_live: std::time::Duration,
        /// The interval with which to perform bookkeeping tasks.
        bookkeeping_interval: std::time::Duration,
    ) -> ServerResult<Self> {
        // Read the cache directory and calculate the size of the files in it.
        let mut size_of_files_on_disk = 0_u64;
        let mut entries = tokio::fs::read_dir(&cache_directory).await?;
        while let Some(entry) = entries.next_entry().await? {
            let metadata = entry.metadata().await?;
            size_of_files_on_disk = size_of_files_on_disk
                .checked_add(metadata.len())
                .ok_or(ServerError::OverflowError)?;
        }

        let size_of_files_on_disk = Arc::new(AtomicU64::new(size_of_files_on_disk));

        let cancel_token = tokio_util::sync::CancellationToken::new();
        let drop_guard = cancel_token.clone().drop_guard();

        // On startup we validate all files in the cache and check if they have an entry in the database, cleaning up uploads that do not.
        let mut entries = tokio::fs::read_dir(&cache_directory).await?;
        while let Some(entry) = entries.next_entry().await? {
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            let file_name = file_name.as_ref();
            let file_name =
                uuid::Uuid::parse_str(file_name).expect("Failed to parse file name as UUID");

            let upload = Upload::select_by_file_name_on_disk(&db_pool, file_name).await?;

            if upload.is_none() {
                tracing::warn!(file_name = %file_name, "Found orphaned file in cache directory, removing");
                tokio::fs::remove_file(entry.path()).await?;
            }
        }

        let bookkeeping_handle = tokio::spawn({
            let db_pool = db_pool.clone();
            let cache_directory = cache_directory.clone();
            let size_of_files_on_disk = Arc::clone(&size_of_files_on_disk);

            tracing::info!("Starting bookkeeping task");

            async move {
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(bookkeeping_interval) => {
                            let size_of_files_on_disk = Arc::clone(&size_of_files_on_disk);
                            async {
                                if let Err(err) = bookkeeping(&db_pool, &cache_directory, size_of_files_on_disk).await {
                                    tracing::error!(error = %err, "Failed to perform bookkeeping");
                                }
                            }.instrument(tracing::info_span!("bookkeeping")).await;
                        }
                        _ = cancel_token.cancelled() => {
                            break;
                        }
                    }
                }

                tracing::info!("Bookkeeping task stopped");
            }
        });

        Ok(Self {
            db_pool,
            size_of_files_on_disk,
            cache_directory,
            max_allowed_file_size,
            max_allowed_cache_size,
            min_time_to_live,
            max_time_to_live,
            bookkeeping_handle,
            drop_guard,
        })
    }

    /// Tries to perform a graceful shutdown of the `Uploads` service.
    #[tracing::instrument(skip(self))]
    pub async fn gracefully_shutdown(self) -> ServerResult<()> {
        let Self {
            db_pool: _,
            size_of_files_on_disk: _,
            cache_directory: _,
            max_allowed_file_size: _,
            max_allowed_cache_size: _,
            min_time_to_live: _,
            max_time_to_live: _,
            bookkeeping_handle,
            drop_guard,
        } = self;

        drop(drop_guard);

        /// The maximum time to wait for the bookkeeping task to finish.
        const SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

        tokio::time::timeout(SHUTDOWN_TIMEOUT, bookkeeping_handle).await??;

        Ok(())
    }

    /// Generates the key that this file will be available at, once uploaded.
    ///
    /// Also creates an entry in the database for this upload, to be followed by an 'upload' call later on.
    #[tracing::instrument(skip(self))]
    #[builder]
    pub async fn preflight_upload(
        &self,

        /// The username of the user uploading the file.
        uploader_username: String,

        /// The name of the file.
        file_name: String,

        /// The size of the file.
        file_size: NonZeroU64,

        /// How long the file should be stored for.
        expiry: std::time::Duration,
    ) -> ServerResult<UploadId> {
        let upload_id = UploadId::generate::<8>();

        if file_size > self.max_allowed_file_size {
            return Err(ServerError::FileTooBig);
        }

        if file_name.is_empty() || file_name.len() > 254 {
            return Err(ServerError::InvalidFileName);
        }

        if expiry < self.min_time_to_live || expiry > self.max_time_to_live {
            return Err(ServerError::InvalidExpiry {
                min: self.min_time_to_live,
                max: self.max_time_to_live,
            });
        }

        let upload = Upload::builder()
            .uploader_username(uploader_username)?
            .upload_key(upload_id.clone())?
            .file_name(file_name)?
            .file_size(file_size)
            .now(chrono::Utc::now())
            .expires_at(
                chrono::Utc::now()
                    .checked_add_signed(chrono::Duration::from_std(expiry)?)
                    .ok_or(ServerError::OverflowError)?,
            )
            .build();
        upload.insert(&self.db_pool).await?;

        Ok(upload_id)
    }

    /// Uploads a file to the given key.
    #[tracing::instrument(skip(self, upload_stream), fields(
        upload_id = %key,
        size_of_files_on_disk = %self.size_of_files_on_disk.load(std::sync::atomic::Ordering::Relaxed),
        max_allowed_cache_size = %self.max_allowed_cache_size,
        upload_size = upload_size,
    ), err)]
    pub async fn upload<T>(
        &self,
        key: UploadId,
        upload_size: NonZeroU64,
        upload_stream: T,
    ) -> ServerResult<()>
    where
        T: Stream<Item = ServerResult<axum::body::Bytes>> + Unpin + Send,
    {
        // Do some basic checks based on the reported maximum file size.
        // NOTE: we check the ACTUAL size of the bytes being written to the disk too, in case of malicious clients.
        if upload_size > self.max_allowed_file_size {
            return Err(ServerError::FileTooBig);
        }
        if self
            .size_of_files_on_disk
            .load(std::sync::atomic::Ordering::Relaxed)
            .saturating_add(upload_size.into())
            > self.max_allowed_cache_size.into()
        {
            return Err(ServerError::FileTooBig);
        }

        let mut upload = Upload::select_by_upload_key(&self.db_pool, key)
            .await?
            .ok_or(ServerError::NotFound)?;

        if upload.expires_at < chrono::Utc::now()
            || upload
                .created_at
                .checked_add_signed(chrono::Duration::seconds(60 * 5))
                .expect("Failed to add 5 minutes to the creation time")
                < chrono::Utc::now()
            || upload.file_name_on_disk.is_some()
        {
            tracing::warn!(
                upload_id = %upload.upload_key,
                expires_at = %upload.expires_at,
                created_at = %upload.created_at,
                file_name_on_disk = ?upload.file_name_on_disk,
                "Upload expired or already uploaded"
            );
            return Err(ServerError::UploadExpired);
        }

        let file_name = uuid::Uuid::new_v4();
        upload.file_name_on_disk = Some(file_name);
        upload.update(&self.db_pool).await?;

        let file_path = self.cache_directory.join(file_name.to_string());
        let file = tokio::fs::File::create(&file_path).await?;

        /// Handles the stream of bytes being uploaded.
        async fn handle_stream<T>(
            mut file: tokio::fs::File,
            mut upload_stream: T,
            size_of_files_on_disk: Arc<AtomicU64>,
            max_allowed_cache_size: NonZeroU64,
            max_allowed_file_size: NonZeroU64,
        ) -> ServerResult<u64>
        where
            T: Stream<Item = ServerResult<axum::body::Bytes>> + Unpin,
        {
            let mut bytes_written_so_far: u64 = 0;
            while let Some(chunk) = upload_stream.next().await {
                let chunk = chunk?;

                // Ensure we haven't exceeded max size for an individual file.
                bytes_written_so_far = bytes_written_so_far
                    .checked_add(chunk.len() as u64)
                    .expect("Overflow error");
                if bytes_written_so_far > max_allowed_file_size.into() {
                    return Err(ServerError::FileTooBig);
                }

                // Ensure we haven't exceeded the total cache size.
                let size_of_files_on_disk = size_of_files_on_disk
                    .fetch_add(chunk.len() as u64, std::sync::atomic::Ordering::Relaxed);
                if size_of_files_on_disk
                    .checked_add(chunk.len() as u64)
                    .expect("Overflow error")
                    > max_allowed_cache_size.into()
                {
                    return Err(ServerError::FileTooBig);
                }

                file.write_all(&chunk).await?;
            }

            Ok(bytes_written_so_far)
        }

        match handle_stream(
            file,
            upload_stream,
            Arc::clone(&self.size_of_files_on_disk),
            self.max_allowed_cache_size,
            self.max_allowed_file_size,
        )
        .await
        {
            Ok(len) => {
                upload.file_size = NonZeroU64::new(len).ok_or(ServerError::BadRequest {
                    reason: "Uploaded file must have at least 1 byte.".to_string(),
                })?;
                upload.uploaded_at = Some(chrono::Utc::now());
                upload.update(&self.db_pool).await?;
            }
            Err(err) => {
                if let Err(e) = tokio::fs::remove_file(&file_path).await {
                    tracing::error!("Failed to remove file: {:?}", e);
                }
                upload.file_name_on_disk = None;
                upload.update(&self.db_pool).await?;
                return Err(err);
            }
        }

        Ok(())
    }

    /// Retrieves information about an upload by its key.
    ///
    /// # Arguments
    ///
    /// * `key` - The unique identifier for the upload.
    ///
    /// # Returns
    ///
    /// An `Upload` object containing information about the upload.
    ///
    /// # Errors
    ///
    /// Returns `ServerError::NotFound` if the upload does not exist or has expired.
    pub async fn info(&self, key: UploadId) -> ServerResult<Upload> {
        let upload = Upload::select_by_upload_key(&self.db_pool, key)
            .await?
            .ok_or(ServerError::NotFound)?;

        if upload.expires_at < chrono::Utc::now() {
            return Err(ServerError::NotFound);
        }

        Ok(upload)
    }

    /// Downloads the file at the given key.
    pub async fn download(
        &self,
        key: UploadId,
    ) -> ServerResult<(Upload, impl Stream<Item = ServerResult<Vec<u8>>>)> {
        let upload = self.info(key).await?;

        if upload.uploaded_at.is_none() {
            return Err(ServerError::NotFound);
        }

        let file_name_on_disk = match upload.file_name_on_disk {
            Some(file_name_on_disk) => file_name_on_disk,
            None => return Err(ServerError::NotFound),
        };

        let file_path = self.cache_directory.join(file_name_on_disk.to_string());

        let file = tokio::fs::File::open(&file_path).await?;

        let stream = stream! {
            let mut file = file;
            let mut buffer = [0; 4 * 1024]; // Configurable buffer size
            #[allow(clippy::indexing_slicing, reason = "file.read should return the number of bytes read")]
            loop {
                let bytes_read = file.read(&mut buffer).await?;
                if bytes_read == 0 {
                    break;
                }
                yield Ok(buffer[..bytes_read].to_vec());
            }
        };

        Ok((upload, stream))
    }
}
