//! Abstracts the file upload/downloads, including check if uploads exist and ensuring we don't
//! overrun the storage allocated to the service.

use std::{path::PathBuf, sync::atomic::AtomicU64};

use anyhow::Context;
use async_stream::stream;
use database::Upload;
use futures::{Stream, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::Instrument;

use crate::{
    error::{ServerError, ServerResult},
    unique_ids::UploadId,
};

/// The maximum size of a single upload.
const MAX_ALLOWED_FILE_SIZE: u64 = 1024 * 1024 * 1024 * 10; // 10 GB

/// The total maximum size of all files on disk.
const MAX_ALLOWED_CACHE_SIZE: u64 = 1024 * 1024 * 1024 * 100; // 200 GB

/// The interval with which to perform bookkeeping tasks.
const BOOKKEEPING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60); // 1 minute

/// An abstraction for managing the lifetime of file uploads.
#[derive(Debug)]
pub struct Uploads {
    /// A persistant link to the database, useful for persisting information about uploads.
    db_pool: sqlx::SqlitePool,
    /// The total size of all files on the disk right now.
    size_of_files_on_disk: AtomicU64,
    /// The location of the cache directory on disk.
    cache_directory: PathBuf,

    /// A handle to the bookkeeping task.
    bookkeeping_handle: tokio::task::JoinHandle<()>,
    /// A token to cancel the bookkeeping task.
    drop_guard: tokio_util::sync::DropGuard,
}

/// Performs bookkeeping tasks, such as cleaning up expired uploads.
#[tracing::instrument(skip(db_pool))]
async fn bookkeeping(db_pool: &sqlx::SqlitePool, cache_directory: &PathBuf) -> ServerResult<()> {
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
    pub async fn new(db_pool: sqlx::SqlitePool, cache_directory: PathBuf) -> ServerResult<Self> {
        // Read the cache directory and calculate the size of the files in it.
        let mut size_of_files_on_disk = 0_u64;
        let mut entries = tokio::fs::read_dir(&cache_directory).await?;
        while let Some(entry) = entries.next_entry().await? {
            let metadata = entry.metadata().await?;
            size_of_files_on_disk = size_of_files_on_disk
                .checked_add(metadata.len())
                .ok_or(ServerError::OverflowError)?;
        }

        let cancel_token = tokio_util::sync::CancellationToken::new();
        let drop_guard = cancel_token.clone().drop_guard();

        // On startup we validate all files in the cache and check if they have an entry in the database, cleaning up uploads that do not.
        let mut entries = tokio::fs::read_dir(&cache_directory).await?;
        while let Some(entry) = entries.next_entry().await? {
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            let file_name = file_name.as_ref();
            let file_name =
                uuid::Uuid::parse_str(file_name).context("Failed to parse file name")?;

            let upload = Upload::select_by_file_name_on_disk(&db_pool, file_name)
                .await
                .context("Failed to select upload by file name on disk")?;

            if upload.is_none() {
                tracing::warn!(file_name = %file_name, "Found orphaned file in cache directory, removing");
                tokio::fs::remove_file(entry.path()).await?;
            }
        }

        let bookkeeping_handle = tokio::spawn({
            let db_pool = db_pool.clone();
            let cache_directory = cache_directory.clone();

            tracing::info!("Starting bookkeeping task");

            async move {
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(BOOKKEEPING_INTERVAL) => {
                            async {
                                if let Err(err) = bookkeeping(&db_pool, &cache_directory).await {
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
            size_of_files_on_disk: AtomicU64::new(size_of_files_on_disk),
            cache_directory,
            bookkeeping_handle,
            drop_guard,
        })
    }

    /// Tries to perform a graceful shutdown of the `Uploads` service.
    #[tracing::instrument(skip(self))]
    pub async fn graceful_shutdown(self) -> ServerResult<()> {
        let Self {
            bookkeeping_handle,
            drop_guard,
            db_pool: _,
            size_of_files_on_disk: _,
            cache_directory: _,
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
    pub async fn preflight_upload(
        &self,
        uploader_username: String,
        file_name: String,
        file_size: i64,
        expiry: tokio::time::Duration,
    ) -> ServerResult<UploadId> {
        let upload_id = UploadId::generate::<8>();

        if file_size < 0 || file_size > MAX_ALLOWED_FILE_SIZE as i64 {
            return Err(ServerError::FileTooBig);
        }

        if file_name.is_empty() || file_name.len() > 254 {
            return Err(ServerError::InvalidFileName);
        }

        /// The minimum time a client is allowed to request their upload to live for.
        const MIN_EXPIRY: std::time::Duration = std::time::Duration::from_secs(60 * 5); // 5 minutes

        /// The maximum time a client is allowed to request their upload to live for.
        const MAX_EXPIRY: std::time::Duration = std::time::Duration::from_secs(60 * 60 * 24 * 7); // 1 week

        if expiry < MIN_EXPIRY || expiry > MAX_EXPIRY {
            return Err(ServerError::InvalidExpiry {
                min: MIN_EXPIRY,
                max: MAX_EXPIRY,
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
    pub async fn upload<T: Stream<Item = anyhow::Result<Vec<u8>>> + std::marker::Unpin>(
        &self,
        key: UploadId,
        mut upload_stream: T,
    ) -> anyhow::Result<()> {
        // TODO: improve error responses here.
        let mut upload = Upload::select_by_upload_key(&self.db_pool, key)
            .await?
            .context("Upload not found")?;

        if upload.file_name_on_disk.is_some() {
            return Err(anyhow::anyhow!("File already uploaded"));
        }

        if upload.expires_at < chrono::Utc::now()
            || upload
                .created_at
                .checked_add_signed(chrono::Duration::seconds(60 * 5))
                .expect("Failed to add 5 minutes to the creation time")
                < chrono::Utc::now()
        {
            return Err(anyhow::anyhow!("Upload expired"));
        }

        let file_name = uuid::Uuid::new_v4();
        upload.file_name_on_disk = Some(file_name);
        upload
            .update(&self.db_pool)
            .await
            .context("Failed to update upload")?;

        let file_path = self.cache_directory.join(file_name.to_string());

        let mut file = tokio::fs::File::create(&file_path)
            .await
            .context("Failed to create file")?;

        let size_of_files_on_disk = self
            .size_of_files_on_disk
            .load(std::sync::atomic::Ordering::Relaxed);
        let mut bytes_written_so_far = 0;

        macro_rules! cleanup_file {
            () => {
                // Try to cleanup the file if we can.
                let _ = tokio::fs::remove_file(&file_path).await;
                upload.file_name_on_disk = None;
                upload
                    .update(&self.db_pool)
                    .await
                    .context("Failed to update upload")?;
            };
        }
        while let Some(chunk) = upload_stream.next().await {
            match chunk {
                Ok(chunk) => {
                    bytes_written_so_far += chunk.len() as u64;
                    if bytes_written_so_far > MAX_ALLOWED_FILE_SIZE {
                        cleanup_file!();
                        return Err(anyhow::anyhow!("File too large"));
                    }
                    if bytes_written_so_far + size_of_files_on_disk > MAX_ALLOWED_CACHE_SIZE {
                        cleanup_file!();
                        return Err(anyhow::anyhow!("Cache too large"));
                    }
                    file.write_all(&chunk)
                        .await
                        .context("Failed to write to file")?;
                }
                Err(err) => {
                    cleanup_file!();
                    return Err(err);
                }
            }
        }

        let new_disk_size = self
            .size_of_files_on_disk
            .fetch_add(bytes_written_so_far, std::sync::atomic::Ordering::Relaxed);
        if new_disk_size > MAX_ALLOWED_CACHE_SIZE {
            cleanup_file!();
            return Err(anyhow::anyhow!("Cache too large"));
        }

        upload.file_size = bytes_written_so_far as i64;
        upload.uploaded_at = Some(chrono::Utc::now());
        upload
            .update(&self.db_pool)
            .await
            .context("Failed to update upload")?;

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
    ) -> ServerResult<(Upload, impl Stream<Item = anyhow::Result<Vec<u8>>>)> {
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
            let mut buffer = [0; 64 * 1024];
            loop {
                let bytes_read = file.read(&mut buffer).await
                    .context("Failed to read from file")?;
                if bytes_read == 0 {
                    break;
                }
                yield Ok(buffer.get(..bytes_read).unwrap_or(&[]).to_vec());
            }
        };

        Ok((upload, stream))
    }
}
