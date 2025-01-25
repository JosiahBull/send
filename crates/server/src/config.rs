//! Handles configuration for the server, typically pulling from structured environment variables.

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    num::{NonZeroU32, NonZeroU64},
    path::PathBuf,
};

use url::Url;

use crate::{ServerError, ServerResult};

/// The main configuration struct for the server.
#[derive(Debug)]
pub struct Config {
    /// Configuration for the server module.
    pub server: ServerConfig,
    // pub tracing: TracingConfig,
    /// Configuration for the database module.
    pub database: DatabaseConfig,
    /// Configuration for the uploads module.
    pub upload: UploadConfig,
    /// Configuration for the auth module.
    pub auth: AuthConfig,
    /// Configuration for rate limiting.
    pub rate_limit: RateLimitConfig,
}

impl Config {
    /// Constructs a `Config` instance by loading settings from a hashmap of environment variables.
    ///
    /// # Arguments
    /// * `env` - A HashMap of environment variables.
    ///
    /// # Errors
    /// Returns a `ServerError` if any required environment variable is missing or invalid.
    ///
    /// # Examples
    /// ```rust
    /// let config = Config::from_env().expect("Failed to load configuration");
    /// println!("Server is running on {}:{}", config.server.host, config.server.port);
    /// ```
    pub fn from_env(env: &HashMap<String, String>) -> ServerResult<Self> {
        Ok(Self {
            server: ServerConfig::from_env(env)?,
            // tracing: TracingConfig::from_env(env)?,
            database: DatabaseConfig::from_env(env)?,
            upload: UploadConfig::from_env(env)?,
            auth: AuthConfig::from_env(env)?,
            rate_limit: RateLimitConfig::from_env(env)?,
        })
    }
}

/// Configuration specific to the global server module.
#[derive(Debug)]
pub struct ServerConfig {
    /// The host to bind the server to.
    pub host: Ipv4Addr,
    /// The port to bind the server to.
    pub port: u16,
    /// The domain the server is hosted at.
    /// Should have a scheme and no trailing slash.
    pub domain: Url,
}

impl ServerConfig {
    /// Constructs a `ServerConfig` instance by loading `SERVER__HOST` and `SERVER__PORT` from a provided HashMap.
    ///
    /// # Arguments
    /// * `env` - A HashMap of environment variables.
    ///
    /// # Errors
    /// Returns a `ServerError` if any of the required environment variables are missing or invalid.
    ///
    /// # Examples
    /// ```rust
    /// let env = std::env::vars().collect::<HashMap<String, String>>();
    /// # let mut env = env;
    /// # env.insert("SERVER__HOST".to_string(), "127.0.0.1");
    /// # env.insert("SERVER__PORT".to_string(), "8080");
    /// # env.insert("SERVER__DOMAIN".to_string(), "http://localhost");
    /// # let env = env;
    /// println!("Server host: {}, port: {}, domain: {}", server_config.host, server_config.port, server_config.domain);
    /// # assert_eq!(server_config.host, std::net::Ipv4Addr::new(127, 0, 0, 1));
    /// # assert_eq!(server_config.port, 8080);
    /// # assert_eq!(server_config.domain, url::Url::parse("http://localhost").unwrap());
    /// ```
    pub fn from_env(env: &HashMap<String, String>) -> ServerResult<Self> {
        let host = env
            .get("SERVER__HOST")
            .and_then(|s| if s.is_empty() { None } else { Some(s) })
            .ok_or_else(|| ServerError::MissingEnvVar("SERVER__HOST"))?
            .parse::<Ipv4Addr>()
            .map_err(|e| {
                ServerError::InvalidEnvVar(
                    "SERVER__HOST",
                    env.get("SERVER__HOST")
                        .expect("already checked to be present")
                        .to_string(),
                    e.to_string(),
                )
            })?;

        let port = env
            .get("SERVER__PORT")
            .and_then(|s| if s.is_empty() { None } else { Some(s) })
            .ok_or_else(|| ServerError::MissingEnvVar("SERVER__PORT"))?
            .parse::<u16>()
            .map_err(|e| {
                ServerError::InvalidEnvVar(
                    "SERVER__PORT",
                    env.get("SERVER__PORT")
                        .expect("already checked to be present")
                        .to_string(),
                    e.to_string(),
                )
            })?;

        let domain = env
            .get("SERVER__DOMAIN")
            .and_then(|s| if s.is_empty() { None } else { Some(s) })
            .ok_or_else(|| ServerError::MissingEnvVar("SERVER__DOMAIN"))?
            .parse::<Url>()
            .map_err(|e| {
                ServerError::InvalidEnvVar(
                    "SERVER__DOMAIN",
                    env.get("SERVER__DOMAIN")
                        .expect("already checked to be present")
                        .to_string(),
                    e.to_string(),
                )
            })?;

        if domain.scheme().is_empty() {
            return Err(ServerError::InvalidEnvVar(
                "SERVER__DOMAIN",
                env.get("SERVER__DOMAIN")
                    .expect("already checked to be present")
                    .to_string(),
                "Invalid URL scheme".to_string(),
            ));
        }
        if domain.cannot_be_a_base() {
            return Err(ServerError::InvalidEnvVar(
                "SERVER__DOMAIN",
                env.get("SERVER__DOMAIN")
                    .expect("already checked to be present")
                    .to_string(),
                "Invalid URL".to_string(),
            ));
        }

        Ok(Self { host, port, domain })
    }
}

/// Configuration specific to the database module.
#[derive(Debug)]
pub struct DatabaseConfig {
    /// The URL to connect to the database.
    pub url: String,
}

impl DatabaseConfig {
    /// Constructs a `DatabaseConfig` instance by loading `DATABASE__URL` from the environment variables.
    ///
    /// # Arguments
    /// * `env` - A HashMap of environment variables.
    ///
    /// # Errors
    /// Returns a `ServerError` if the `DATABASE__URL` environment variable is missing.
    ///
    /// # Examples
    /// ```rust
    /// let env = std::env::vars().collect::<HashMap<String, String>>();
    /// # let mut env = env;
    /// # env.insert("DATABASE__URL".to_string(), "postgres://user:password@localhost/dbname");
    /// # let env = env;
    /// let database_config = DatabaseConfig::from_env(&env).expect("Failed to load database configuration");
    /// println!("Database URL: {}", database_config.url);
    /// # assert_eq!(database_config.url, "postgres://user:password@localhost/dbname");
    /// ```
    pub fn from_env(env: &HashMap<String, String>) -> ServerResult<Self> {
        let url = env
            .get("DATABASE__URL")
            .and_then(|s| if s.is_empty() { None } else { Some(s) })
            .ok_or_else(|| ServerError::MissingEnvVar("DATABASE__URL"))?
            .to_string();

        Ok(Self { url })
    }
}

/// Configuration specific to the uploads module.
#[derive(Debug)]
pub struct UploadConfig {
    /// The directory to store files in.
    pub cache_directory: PathBuf,
    /// The maximum size of the uploads directory before we reject new uploads.
    pub max_cache_size_bytes: NonZeroU64,
    /// The maximum size of any individual file before we reject it.
    pub max_file_size_bytes: NonZeroU64,
    /// How often to perform book keeping and cleanup expired files.
    pub book_keeping_interval: std::time::Duration,
    /// The minimum time a file must live in the cache.
    pub min_file_time_to_live: std::time::Duration,
    /// The maximum time a file may live in the cache before it is considered expired and summarily deleted.
    pub max_file_time_to_live: std::time::Duration,
}

impl UploadConfig {
    /// Constructs an `UploadConfig` instance by loading the following environment variables from the provided HashMap:
    ///
    /// - `UPLOAD__CACHE_DIRECTORY`
    /// - `UPLOAD__MAX_SIZE`
    /// - `UPLOAD__MAX_TIME`
    ///
    /// Max size must specify units: `B`, `KB`, `MB`, `GB`. For example, `10MB`.
    /// Max time must specify units: `s`, `m`, `h`, `d`. For example, `1h`.
    ///
    /// # Arguments
    /// * `env` - A HashMap of environment variables.
    ///
    /// # Errors
    /// Returns a `ServerError` if any of the required environment variables are missing or invalid.
    ///
    /// # Examples
    /// ```rust
    /// let env = std::env::vars().collect::<HashMap<String, String>>();
    /// # let mut env = env;
    /// # env.insert("UPLOAD__CACHE_DIRECTORY".to_string(), "/tmp/uploads");
    /// # env.insert("UPLOAD__MAX_CACHE_SIZE".to_string(), "10MB");
    /// # env.insert("UPLOAD__MAX_FILE_SIZE".to_string(), "1MB");
    /// # env.insert("UPLOAD__BOOK_KEEPING_INTERVAL".to_string(), "1h");
    /// # env.insert("UPLOAD__MAX_FILE_TIME_TO_LIVE".to_string(), "1h");
    /// # let env = env;
    /// let upload_config = UploadConfig::from_env(&env).expect("Failed to load upload configuration");
    /// println!(
    /// println!(
    ///     "Cache directory: {:?}, max cache size: {}, max file size: {}, book keeping interval: {:?}, max file time to live: {:?}",
    ///     upload_config.cache_directory,
    ///     upload_config.max_cache_size_bytes,
    ///     upload_config.max_file_size_bytes,
    ///     upload_config.book_keeping_interval,
    ///     upload_config.max_file_time_to_live
    /// );
    /// # assert_eq!(upload_config.cache_directory, std::path::PathBuf::from("/tmp/uploads"));
    /// # assert_eq!(upload_config.max_cache_size_bytes, 10 * 1024 * 1024);
    /// # assert_eq!(upload_config.max_file_size_bytes, 1 * 1024 * 1024);
    /// # assert_eq!(upload_config.book_keeping_interval, std::time::Duration::from_secs(60 * 60));
    /// # assert_eq!(upload_config.max_file_time_to_live, std::time::Duration::from_secs(60 * 60));
    /// ```
    pub fn from_env(env: &HashMap<String, String>) -> ServerResult<Self> {
        let cache_directory = env
            .get("UPLOAD__CACHE_DIRECTORY")
            .and_then(|s| if s.is_empty() { None } else { Some(s) })
            .ok_or_else(|| ServerError::MissingEnvVar("UPLOAD__CACHE_DIRECTORY"))?
            .parse::<PathBuf>()
            .map_err(|e| {
                ServerError::InvalidEnvVar(
                    "UPLOAD__CACHE_DIRECTORY",
                    env.get("UPLOAD__CACHE_DIRECTORY")
                        .expect("already checked to be present")
                        .to_string(),
                    e.to_string(),
                )
            })?;

        let max_cache_size_bytes = parse_size(
            env.get("UPLOAD__MAX_CACHE_SIZE")
                .and_then(|s| if s.is_empty() { None } else { Some(s) })
                .ok_or_else(|| ServerError::MissingEnvVar("UPLOAD__MAX_CACHE_SIZE"))?,
            "UPLOAD__MAX_CACHE_SIZE",
        )?;

        let max_file_size_bytes = parse_size(
            env.get("UPLOAD__MAX_FILE_SIZE")
                .and_then(|s| if s.is_empty() { None } else { Some(s) })
                .ok_or_else(|| ServerError::MissingEnvVar("UPLOAD__MAX_FILE_SIZE"))?,
            "UPLOAD__MAX_FILE_SIZE",
        )?;

        let book_keeping_interval = parse_time(
            env.get("UPLOAD__BOOK_KEEPING_INTERVAL")
                .and_then(|s| if s.is_empty() { None } else { Some(s) })
                .ok_or_else(|| ServerError::MissingEnvVar("UPLOAD__BOOK_KEEPING_INTERVAL"))?,
            "UPLOAD__BOOK_KEEPING_INTERVAL",
        )?;

        let min_file_time_to_live = parse_time(
            env.get("UPLOAD__MIN_FILE_TIME_TO_LIVE")
                .and_then(|s| if s.is_empty() { None } else { Some(s) })
                .ok_or_else(|| ServerError::MissingEnvVar("UPLOAD__MIN_FILE_TIME_TO_LIVE"))?,
            "UPLOAD__MIN_FILE_TIME_TO_LIVE",
        )?;

        let max_file_time_to_live = parse_time(
            env.get("UPLOAD__MAX_FILE_TIME_TO_LIVE")
                .and_then(|s| if s.is_empty() { None } else { Some(s) })
                .ok_or_else(|| ServerError::MissingEnvVar("UPLOAD__MAX_FILE_TIME_TO_LIVE"))?,
            "UPLOAD__MAX_FILE_TIME_TO_LIVE",
        )?;

        Ok(Self {
            cache_directory,
            max_cache_size_bytes,
            max_file_size_bytes,
            book_keeping_interval,
            min_file_time_to_live,
            max_file_time_to_live,
        })
    }
}

/// Configuration specifically for the auth module.
#[derive(Debug)]
pub struct AuthConfig {
    /// The maximum time a nonce may live before it is considered expired.
    pub nonce_max_time_to_live: std::time::Duration,
    /// The time to wait between refreshing keys, recommended to be no lower than 60 seconds.
    pub key_refresh_interval: std::time::Duration,
    /// The maximum number of keys a single user may have from a provided source, it's generally
    /// recommended to keep this number low to prevent abuse.
    pub max_number_of_keys_per_user: usize,
    /// If a key upstream is not available, this is the maximum time to continue allowing authentication with stale
    /// keys before rejecting all requests.
    pub max_time_allowed_since_refresh: std::time::Duration,
    /// Url + usernames to authentication keys used for validation.
    pub auth_keys: HashMap<Url, String>,
}

impl AuthConfig {
    /// Constructs an `AuthConfig` instance by loading the following environment variables from the provided HashMap:
    ///
    /// - `AUTH__NONCE_MAX_TIME_TO_LIVE`
    /// - `AUTH__KEY_REFRESH_INTERVAL`
    /// - `AUTH__MAX_NUMBER_OF_KEYS_PER_USER`
    /// - `AUTH__MAX_TIME_ALLOWED_SINCE_REFRESH`
    /// - `AUTH__AUTH_KEYS__*` (where `*` is a URL)
    ///
    /// The time values must specify units: `s`, `m`, `h`, `d`. For example, `1h`.
    ///
    /// # Arguments
    /// * `env` - A HashMap of environment variables.
    ///
    /// # Errors
    /// Returns a `ServerError` if any of the required environment variables are missing or invalid.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let env = std::env::vars().collect::<HashMap<String, String>>();
    /// # let mut env = env;
    /// # env.insert("AUTH__NONCE_MAX_TIME_TO_LIVE".to_string(), "100s");
    /// # env.insert("AUTH__KEY_REFRESH_INTERVAL".to_string(), "60s");
    /// # env.insert("AUTH__MAX_NUMBER_OF_KEYS_PER_USER".to_string(), "5");
    /// # env.insert("AUTH__MAX_TIME_ALLOWED_SINCE_REFRESH".to_string(), "1h");
    /// # env.insert("AUTH__AUTH_KEYS__http://example.com".to_string(), "key1");
    /// # let env = env;
    /// let auth_config = AuthConfig::from_env(&env).expect("Failed to load auth configuration");
    /// println!("Nonce max time-to-live: {:?}", auth_config.nonce_max_time_to_live);
    /// println!("Key refresh interval: {:?}", auth_config.key_refresh_interval);
    /// println!("Max number of keys per user: {}", auth_config.max_number_of_keys_per_user);
    /// println!("Max time allowed since refresh: {:?}", auth_config.max_time_allowed_since_refresh);
    /// println!("Auth keys: {:?}", auth_config.auth_keys);
    /// ```
    pub fn from_env(env: &HashMap<String, String>) -> ServerResult<Self> {
        let nonce_max_time_to_live = parse_time(
            env.get("AUTH__NONCE_MAX_TIME_TO_LIVE")
                .and_then(|s| if s.is_empty() { None } else { Some(s) })
                .ok_or_else(|| ServerError::MissingEnvVar("AUTH__NONCE_MAX_TIME_TO_LIVE"))?,
            "AUTH__NONCE_MAX_TIME_TO_LIVE",
        )?;

        let key_refresh_interval = parse_time(
            env.get("AUTH__KEY_REFRESH_INTERVAL")
                .and_then(|s| if s.is_empty() { None } else { Some(s) })
                .ok_or_else(|| ServerError::MissingEnvVar("AUTH__KEY_REFRESH_INTERVAL"))?,
            "AUTH__KEY_REFRESH_INTERVAL",
        )?;

        let max_number_of_keys_per_user = env
            .get("AUTH__MAX_NUMBER_OF_KEYS_PER_USER")
            .and_then(|s| if s.is_empty() { None } else { Some(s) })
            .ok_or_else(|| ServerError::MissingEnvVar("AUTH__MAX_NUMBER_OF_KEYS_PER_USER"))?
            .parse::<usize>()
            .map_err(|e| {
                ServerError::InvalidEnvVar(
                    "AUTH__MAX_NUMBER_OF_KEYS_PER_USER",
                    env.get("AUTH__MAX_NUMBER_OF_KEYS_PER_USER")
                        .expect("already checked to be present")
                        .to_string(),
                    e.to_string(),
                )
            })?;

        let max_time_allowed_since_refresh = parse_time(
            env.get("AUTH__MAX_TIME_ALLOWED_SINCE_REFRESH")
                .and_then(|s| if s.is_empty() { None } else { Some(s) })
                .ok_or_else(|| {
                    ServerError::MissingEnvVar("AUTH__MAX_TIME_ALLOWED_SINCE_REFRESH")
                })?,
            "AUTH__MAX_TIME_ALLOWED_SINCE_REFRESH",
        )?;

        let mut auth_keys = HashMap::new();
        let mut index = 0_usize;

        loop {
            if index > 10_000 {
                panic!("Too many AUTH__AUTH_KEYS__* entries");
            }

            let username_key = format!("AUTH__AUTH_KEYS__{}__USERNAME", index);
            let url_key = format!("AUTH__AUTH_KEYS__{}__URL", index);

            let username = match env.get(&username_key) {
                Some(username) => username,
                None => break,
            };

            let url = match env.get(&url_key) {
                Some(url) => Url::parse(url).map_err(|e| {
                    ServerError::InvalidEnvVar("AUTH__AUTH_KEYS__*", url.to_string(), e.to_string())
                })?,
                None => break,
            };

            auth_keys.insert(url, username.to_string());
            index = index.saturating_add(1);
        }

        // All of the keys should end in .keys and be valid URLs with a scheme and no trailing slash.
        if auth_keys
            .iter()
            .any(|(url, _)| !["http", "https"].contains(&url.scheme()))
        {
            let first_failed_key = auth_keys
                .iter()
                .find(|(url, _)| !["http", "https"].contains(&url.scheme()))
                .expect("already checked to be present");

            return Err(ServerError::InvalidEnvVar(
                "AUTH__AUTH_KEYS__*",
                format!("{:?}", first_failed_key),
                "Invalid URL".to_string(),
            ));
        }

        Ok(Self {
            nonce_max_time_to_live,
            key_refresh_interval,
            max_number_of_keys_per_user,
            max_time_allowed_since_refresh,
            auth_keys,
        })
    }
}

/// Configuration for rate limiting.
#[derive(Debug)]
pub struct RateLimitConfig {
    /// The size of the rate limit bucket.
    /// [`NonZeroU32`] is due to internal limitation on variable size in rate limiting library.
    pub bucket_size: NonZeroU32,
    /// The duration to wait before adding 1 request to the bucket.
    pub duration_between_refill: std::time::Duration,
}

impl RateLimitConfig {
    /// Configuration for rate limiting.
    ///
    /// This struct provides the configuration for rate limiting, including the
    /// bucket size and the duration between refills.
    ///
    /// # Methods
    ///
    /// - `from_env`: Constructs a `RateLimitConfig` from environment variables.
    ///
    /// # Environment Variables
    ///
    /// - `RATE_LIMIT__BUCKET_SIZE`: The size of the rate limit bucket.
    /// - `RATE_LIMIT__REFILL_INTERVAL`: The duration between refills of the rate limit bucket.
    ///
    /// # Errors
    ///
    /// This function will return a `ServerError::MissingEnvVar` if any of the required
    /// environment variables are missing or empty.
    ///
    /// # Examples
    /// ```
    /// let env = std::env::vars().collect::<HashMap<String, String>>();
    /// # let mut env = env;
    /// # env.insert("RATE_LIMIT__BUCKET_SIZE".to_string(), "100MB");
    /// # env.insert("RATE_LIMIT__REFILL_INTERVAL".to_string(), "1h");
    /// # let env = env;
    /// let rate_limit_config = RateLimitConfig::from_env(&env).expect("Failed to load rate limit configuration");
    /// println!("Bucket size: {}, Duration between refill: {:?}", rate_limit_config.bucket_size, rate_limit_config.duration_between_refill);
    /// # assert_eq!(rate_limit_config.bucket_size, 100 * 1024 * 1024);
    /// # assert_eq!(rate_limit_config.duration_between_refill, std::time::Duration::from_secs(60 * 60));
    /// ```
    pub fn from_env(env: &HashMap<String, String>) -> ServerResult<Self> {
        let bucket_size: NonZeroU32 = env
            .get("RATE_LIMIT__BUCKET_SIZE")
            .and_then(|s| if s.is_empty() { None } else { Some(s) })
            .ok_or_else(|| ServerError::MissingEnvVar("RATE_LIMIT__BUCKET_SIZE"))?
            .parse::<u32>()
            .map_err(|e| {
                ServerError::InvalidEnvVar(
                    "RATE_LIMIT__BUCKET_SIZE",
                    env.get("RATE_LIMIT__BUCKET_SIZE")
                        .expect("already checked to be present")
                        .to_string(),
                    e.to_string(),
                )
            })?
            .try_into()
            .map_err(|_| {
                ServerError::InvalidEnvVar(
                    "RATE_LIMIT__BUCKET_SIZE",
                    env.get("RATE_LIMIT__BUCKET_SIZE")
                        .expect("already checked to be present")
                        .to_string(),
                    "Size must be non-zero".to_string(),
                )
            })?;

        let duration_between_refill = parse_time(
            env.get("RATE_LIMIT__REFILL_INTERVAL")
                .and_then(|s| if s.is_empty() { None } else { Some(s) })
                .ok_or_else(|| ServerError::MissingEnvVar("RATE_LIMIT__REFILL_INTERVAL"))?,
            "RATE_LIMIT__REFILL_INTERVAL",
        )?;

        Ok(Self {
            bucket_size,
            duration_between_refill,
        })
    }
}

/// Parses a size string with units (e.g., `10MB`, `500KB`) into a size in bytes.
///
/// Supported units:
/// - `B` for bytes
/// - `KB` for kilobytes (1024 bytes)
/// - `MB` for megabytes (1024^2 bytes)
/// - `GB` for gigabytes (1024^3 bytes)
///
/// # Errors
/// Returns a `ServerError` if the string cannot be parsed or contains an unsupported unit.
///
/// # Examples
/// ```rust
/// let size = parse_size("10MB").expect("Failed to parse size");
/// assert_eq!(size, 10 * 1024 * 1024);
/// ```
fn parse_size(size_str: &str, variable_name: &'static str) -> ServerResult<NonZeroU64> {
    let (value, unit) = size_str.trim().split_at(
        size_str
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .ok_or_else(|| {
                ServerError::InvalidEnvVar(
                    variable_name,
                    size_str.to_string(),
                    "Invalid size string".to_string(),
                )
            })?,
    );
    let value: u64 = value.parse::<u64>().map_err(|e| {
        ServerError::InvalidEnvVar(variable_name, size_str.to_string(), e.to_string())
    })?;
    let parsed = match unit.to_uppercase().as_str() {
        "" | "B" => Ok(value),
        "K" | "KB" => Ok(value.checked_mul(1024).expect("Size overflow")),
        "M" | "MB" => Ok(value.checked_mul(1024 * 1024).expect("Size overflow")),
        "G" | "GB" => Ok(value
            .checked_mul(1024 * 1024 * 1024)
            .expect("Size overflow")),
        got => Err(ServerError::InvalidEnvVar(
            variable_name,
            size_str.to_string(),
            format!("Unsupported unit: {}", got),
        )),
    }?;

    NonZeroU64::new(parsed).map_or_else(
        || {
            Err(ServerError::InvalidEnvVar(
                variable_name,
                size_str.to_string(),
                "Size must be non-zero".to_string(),
            ))
        },
        Ok,
    )
}

/// Parses a time string with units (e.g., `1h`, `30m`, `300s`) into a Duration.
///
/// Supported units:
/// - `s` for seconds
/// - `m` for minutes (60 seconds)
/// - `h` for hours (3600 seconds)
/// - `d` for days (86400 seconds)
///
/// # Errors
/// Returns a `ServerError` if the string cannot be parsed or contains an unsupported unit.
///
/// # Examples
/// ```rust
/// let time = parse_time("1h").expect("Failed to parse time");
/// assert_eq!(time, 3600);
///
/// let time = parse_time("1H");
/// assert!(time.is_err());
/// assert_eq!(time.unwrap_err().to_string(), "Unsupported unit: H");
/// ```
fn parse_time(time_str: &str, variable_name: &'static str) -> ServerResult<std::time::Duration> {
    let (value, unit) = time_str
        .trim()
        .split_at(time_str.len().checked_sub(1).ok_or_else(|| {
            ServerError::InvalidEnvVar(
                variable_name,
                time_str.to_string(),
                "Length too short".to_string(),
            )
        })?);
    let value: u64 = value.parse::<u64>().map_err(|e| {
        ServerError::InvalidEnvVar(variable_name, time_str.to_string(), e.to_string())
    })?;
    let seconds = match unit.to_lowercase().as_str() {
        "s" => Ok(value),
        "m" => Ok(value.checked_mul(60).expect("Time overflow")),
        "h" => Ok(value.checked_mul(60 * 60).expect("Time overflow")),
        "d" => Ok(value.checked_mul(60 * 60 * 24).expect("Time overflow")),
        got => Err(ServerError::InvalidEnvVar(
            variable_name,
            time_str.to_string(),
            format!("Unsupported unit: {}", got),
        )),
    }?;

    Ok(std::time::Duration::from_secs(seconds))
}

#[cfg(test)]
mod test_server_config {
    use super::*;

    fn base_valid_env() -> HashMap<String, String> {
        let mut env = HashMap::new();
        env.insert("SERVER__HOST".to_string(), "127.0.0.1".to_string());
        env.insert("SERVER__PORT".to_string(), "8080".to_string());
        env.insert("SERVER__DOMAIN".to_string(), "http://owo.com".to_string());
        env
    }

    #[test]
    fn test_server_config_from_env() {
        let env = base_valid_env();
        let ServerConfig { host, port, domain } =
            ServerConfig::from_env(&env).expect("Failed to load ServerConfig");
        assert_eq!(host, Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(port, 8080);
        assert_eq!(
            domain,
            Url::parse("http://owo.com").expect("Failed to parse URL")
        );
    }

    #[test]
    fn test_invalid_server_host() {
        let mut env = base_valid_env();
        env.insert("SERVER__HOST".to_string(), "invalid_host".to_string());

        let err = ServerConfig::from_env(&env);

        assert!(err.is_err());
        assert_eq!(
            err.expect_err("Should fail due to invalid host").to_string(),
            "Invalid environment variable: SERVER__HOST: invalid_host, failed due to: invalid IPv4 address syntax"
        );
    }

    #[test]
    fn test_invalid_server_port() {
        let mut env = base_valid_env();
        env.insert("SERVER__PORT".to_string(), "invalid_port".to_string());

        let err = ServerConfig::from_env(&env);

        assert!(err.is_err());
        assert_eq!(
            err.expect_err("Should valid due to invalid port").to_string(),
            "Invalid environment variable: SERVER__PORT: invalid_port, failed due to: invalid digit found in string"
        );
    }
}

#[cfg(test)]
mod test_database_config {
    use super::*;

    fn base_valid_env() -> HashMap<String, String> {
        let mut env = HashMap::new();
        env.insert(
            "DATABASE__URL".to_string(),
            "postgres://user:password@localhost/dbname".to_string(),
        );
        env
    }

    #[test]
    fn test_database_config_from_env() {
        let env = base_valid_env();

        let DatabaseConfig { url } =
            DatabaseConfig::from_env(&env).expect("Failed to load DatabaseConfig");
        assert_eq!(url, "postgres://user:password@localhost/dbname");
    }
}

#[cfg(test)]
mod test_upload_config {
    use super::*;

    fn base_valid_env() -> HashMap<String, String> {
        let mut env = HashMap::new();
        env.insert(
            "UPLOAD__CACHE_DIRECTORY".to_string(),
            "/tmp/uploads".to_string(),
        );
        env.insert("UPLOAD__MAX_CACHE_SIZE".to_string(), "10MB".to_string());
        env.insert("UPLOAD__MAX_FILE_SIZE".to_string(), "1MB".to_string());
        env.insert(
            "UPLOAD__BOOK_KEEPING_INTERVAL".to_string(),
            "1h".to_string(),
        );
        env.insert(
            "UPLOAD__MIN_FILE_TIME_TO_LIVE".to_string(),
            "30m".to_string(),
        );
        env.insert(
            "UPLOAD__MAX_FILE_TIME_TO_LIVE".to_string(),
            "2h".to_string(),
        );
        env
    }

    #[test]
    fn test_upload_config_from_env() {
        let env = base_valid_env();
        let UploadConfig {
            cache_directory,
            max_cache_size_bytes,
            max_file_size_bytes,
            book_keeping_interval,
            min_file_time_to_live,
            max_file_time_to_live,
        } = UploadConfig::from_env(&env).expect("Failed to load UploadConfig");

        assert_eq!(cache_directory, PathBuf::from("/tmp/uploads"));
        assert_eq!(
            max_cache_size_bytes,
            NonZeroU64::new(10 * 1024 * 1024).expect("Failed to create NonZeroU64")
        );
        assert_eq!(
            min_file_time_to_live,
            std::time::Duration::from_secs(30 * 60)
        );
        assert_eq!(
            max_file_time_to_live,
            std::time::Duration::from_secs(2 * 60 * 60)
        );
        assert_eq!(
            book_keeping_interval,
            std::time::Duration::from_secs(60 * 60)
        );
        assert_eq!(
            max_file_size_bytes,
            NonZeroU64::new(1024 * 1024).expect("Failed to create NonZeroU64")
        );
    }

    #[test]
    fn test_upload_size_units() {
        let mut env = base_valid_env();
        env.insert("UPLOAD__MAX_CACHE_SIZE".to_string(), "1GB".to_string());
        let upload_config = UploadConfig::from_env(&env).expect("Failed to load UploadConfig");
        assert_eq!(
            upload_config.max_cache_size_bytes,
            NonZeroU64::new(1024 * 1024 * 1024).expect("Failed to create NonZeroU64")
        );

        env.insert("UPLOAD__MAX_CACHE_SIZE".to_string(), "500KB".to_string());
        let upload_config = UploadConfig::from_env(&env).expect("Failed to load UploadConfig");
        assert_eq!(
            upload_config.max_cache_size_bytes,
            NonZeroU64::new(500 * 1024).expect("Failed to create NonZeroU64")
        );
    }

    #[test]
    fn test_invalid_upload_size() {
        let mut env = base_valid_env();
        env.insert("UPLOAD__MAX_CACHE_SIZE".to_string(), "1.5GB".to_string());
        let err = UploadConfig::from_env(&env);

        assert!(err.is_err());
        assert_eq!(
            err.expect_err("Should fail due to float value").to_string(),
            "Invalid environment variable: UPLOAD__MAX_CACHE_SIZE: 1.5GB, failed due to: invalid digit found in string"
        );
    }
}

#[cfg(test)]
mod test_auth_config {
    use std::time::Duration;

    use super::*;

    #[allow(clippy::arithmetic_side_effects, reason = "tests can panic")]
    fn insert_auth_keys(env: &mut HashMap<String, String>, username: &str, url: &str) {
        // Find the max existing key using a binary search, in the search space 0 -> 100k
        let mut low = 0;
        let mut high = 100_000;

        // if the high key exists already - panic
        if env.contains_key(&format!("AUTH__AUTH_KEYS__{}__USERNAME", high - 1)) {
            panic!("Too many AUTH__AUTH_KEYS__* entries");
        }

        while low < high {
            let mid = low + (high - low) / 2;
            let key = format!("AUTH__AUTH_KEYS__{}__USERNAME", mid);
            if env.contains_key(&key) {
                low = mid + 1;
            } else {
                high = mid;
            }
        }

        let index = low;

        env.insert(
            format!("AUTH__AUTH_KEYS__{}__USERNAME", index),
            username.to_string(),
        );
        env.insert(format!("AUTH__AUTH_KEYS__{}__URL", index), url.to_string());
    }

    fn base_valid_env() -> HashMap<String, String> {
        let mut env = HashMap::new();
        env.insert(
            "AUTH__NONCE_MAX_TIME_TO_LIVE".to_string(),
            "100s".to_string(),
        );
        env.insert("AUTH__KEY_REFRESH_INTERVAL".to_string(), "60s".to_string());
        env.insert(
            "AUTH__MAX_NUMBER_OF_KEYS_PER_USER".to_string(),
            "5".to_string(),
        );
        env.insert(
            "AUTH__MAX_TIME_ALLOWED_SINCE_REFRESH".to_string(),
            "1h".to_string(),
        );
        insert_auth_keys(&mut env, "username0", "http://example.com/user0.keys");
        env
    }

    #[test]
    fn test_auth_config_from_env() {
        let env = base_valid_env();
        let AuthConfig {
            nonce_max_time_to_live,
            key_refresh_interval,
            max_number_of_keys_per_user,
            max_time_allowed_since_refresh,
            auth_keys,
        } = AuthConfig::from_env(&env).expect("Failed to load AuthConfig");

        assert_eq!(nonce_max_time_to_live, Duration::from_secs(100));
        assert_eq!(key_refresh_interval, Duration::from_secs(60));
        assert_eq!(max_number_of_keys_per_user, 5);
        assert_eq!(max_time_allowed_since_refresh, Duration::from_secs(60 * 60));
        assert_eq!(
            auth_keys,
            vec![(
                Url::parse("http://example.com/user0.keys").expect("Failed to parse URL"),
                "username0".to_string()
            )]
            .into_iter()
            .collect()
        );
    }

    #[test]
    fn test_invalid_auth_nonce_time() {
        let mut env = base_valid_env();
        env.insert(
            "AUTH__NONCE_MAX_TIME_TO_LIVE".to_string(),
            "1.5h".to_string(),
        );

        let err = AuthConfig::from_env(&env);

        assert!(err.is_err());
        assert_eq!(
            err.expect_err("Should fail due to float value").to_string(),
            "Invalid environment variable: AUTH__NONCE_MAX_TIME_TO_LIVE: 1.5h, failed due to: invalid digit found in string"
        );
    }

    #[test]
    fn test_auth_config_max_number_of_keys() {
        let mut env = base_valid_env();
        for i in 1..10_000 {
            // one already present
            insert_auth_keys(
                &mut env,
                &format!("username{}", i),
                &format!("http://example.com/user{}.keys", i),
            );
        }

        let config = AuthConfig::from_env(&env).expect("Failed to load AuthConfig");

        assert_eq!(config.auth_keys.len(), 10_000);
    }

    #[test]
    #[should_panic = "Too many AUTH__AUTH_KEYS__* entries"]
    fn test_auth_config_too_many_keys() {
        let mut env = base_valid_env();
        for i in 0..10_000 {
            // one already present
            insert_auth_keys(
                &mut env,
                &format!("username{}", i),
                &format!("http://example.com/user{}.keys", i),
            );
        }

        AuthConfig::from_env(&env).expect("Should panic due to too many keys");
    }

    #[test]
    fn test_that_auth_key_url_should_have_scheme() {
        let mut env = base_valid_env();
        insert_auth_keys(&mut env, "username1", "www.example.com/user1.keys");

        let err = AuthConfig::from_env(&env);

        assert!(err.is_err());
        assert_eq!(
            err.expect_err("Should fail due to missing scheme").to_string(),
            "Invalid environment variable: AUTH__AUTH_KEYS__*: www.example.com/user1.keys, failed due to: relative URL without a base"
        );
    }

    #[test]
    fn test_that_auth_key_url_must_not_be_base() {
        let mut env = base_valid_env();
        insert_auth_keys(&mut env, "username1", "file:///user1.keys");

        let err = AuthConfig::from_env(&env);

        assert!(err.is_err());
        assert_eq!(
            err.expect_err("Should fail due to base URL").to_string(),
            "Invalid environment variable: AUTH__AUTH_KEYS__*: (Url { scheme: \"file\", cannot_be_a_base: false, username: \"\", password: None, host: None, port: None, path: \"/user1.keys\", query: None, fragment: None }, \"username1\"), failed due to: Invalid URL"
        );
    }
}

#[cfg(test)]
mod test_rate_limit_config {
    use super::*;

    fn base_valid_env() -> HashMap<String, String> {
        let mut env = HashMap::new();
        env.insert("RATE_LIMIT__BUCKET_SIZE".to_string(), "100".to_string());
        env.insert("RATE_LIMIT__REFILL_INTERVAL".to_string(), "1h".to_string());
        env
    }

    #[test]
    fn test_rate_limit_config_from_env() {
        let env = base_valid_env();
        let RateLimitConfig {
            bucket_size,
            duration_between_refill,
        } = RateLimitConfig::from_env(&env).expect("Failed to load RateLimitConfig");

        assert_eq!(
            bucket_size,
            NonZeroU32::new(100).expect("Failed to create NonZeroU64")
        );
        assert_eq!(
            duration_between_refill,
            std::time::Duration::from_secs(60 * 60)
        );
    }

    #[test]
    fn test_invalid_rate_limit_bucket_size() {
        let mut env = base_valid_env();
        env.insert("RATE_LIMIT__BUCKET_SIZE".to_string(), "nan".to_string());

        let err = RateLimitConfig::from_env(&env);

        assert!(err.is_err());
        assert_eq!(
                err.expect_err("Should fail due to invalid bucket size").to_string(),
                "Invalid environment variable: RATE_LIMIT__BUCKET_SIZE: nan, failed due to: invalid digit found in string"
            );
    }

    #[test]
    fn test_invalid_rate_limit_duration_between_refill() {
        let mut env = base_valid_env();
        env.insert(
            "RATE_LIMIT__REFILL_INTERVAL".to_string(),
            "invalid_duration".to_string(),
        );

        let err = RateLimitConfig::from_env(&env);

        assert!(err.is_err());
        assert_eq!(
                err.expect_err("Should fail due to invalid duration").to_string(),
                "Invalid environment variable: RATE_LIMIT__REFILL_INTERVAL: invalid_duration, failed due to: invalid digit found in string"
            );
    }

    #[test]
    fn test_rate_limit_duration_units() {
        let mut env = base_valid_env();
        env.insert("RATE_LIMIT__REFILL_INTERVAL".to_string(), "30m".to_string());
        let rate_limit_config =
            RateLimitConfig::from_env(&env).expect("Failed to load RateLimitConfig");
        assert_eq!(
            rate_limit_config.duration_between_refill,
            std::time::Duration::from_secs(30 * 60)
        );

        env.insert("RATE_LIMIT__REFILL_INTERVAL".to_string(), "2h".to_string());
        let rate_limit_config =
            RateLimitConfig::from_env(&env).expect("Failed to load RateLimitConfig");
        assert_eq!(
            rate_limit_config.duration_between_refill,
            std::time::Duration::from_secs(2 * 60 * 60)
        );
    }
}
