//! Handles configuration for the server, typically pulling from structured environment variables.

use std::{collections::HashMap, net::Ipv4Addr, path::PathBuf};

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
                    e.into(),
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
                    e.into(),
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
                    e.into(),
                )
            })?;

        if domain.scheme().is_empty() {
            return Err(ServerError::InvalidEnvVar(
                "SERVER__DOMAIN",
                env.get("SERVER__DOMAIN")
                    .expect("already checked to be present")
                    .to_string(),
                anyhow::anyhow!("Invalid URL scheme"),
            ));
        }
        if domain.cannot_be_a_base() {
            return Err(ServerError::InvalidEnvVar(
                "SERVER__DOMAIN",
                env.get("SERVER__DOMAIN")
                    .expect("already checked to be present")
                    .to_string(),
                anyhow::anyhow!("Invalid URL"),
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
    pub max_size: u64,
    /// The maximum time a file may live in the cache before it is considered expired and summarily deleted.
    pub max_time: std::time::Duration,
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
    /// # env.insert("UPLOAD__MAX_SIZE".to_string(), "10MB");
    /// # env.insert("UPLOAD__MAX_TIME".to_string(), "1h");
    /// # let env = env;
    /// let upload_config = UploadConfig::from_env(&env).expect("Failed to load upload configuration");
    /// println!(
    ///     "Cache directory: {:?}, Max size: {}, Max time: {}",
    ///     upload_config.cache_directory,
    ///     upload_config.max_size,
    ///     upload_config.max_time
    /// );
    /// # assert_eq!(upload_config.cache_directory, std::path::PathBuf::from("/tmp/uploads"));
    /// # assert_eq!(upload_config.max_size, 10 * 1024 * 1024);
    /// # assert_eq!(upload_config.max_time, std::time::Duration::from_secs(60 * 60));
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
                    e.into(),
                )
            })?;

        let max_size = parse_size(
            env.get("UPLOAD__MAX_SIZE")
                .and_then(|s| if s.is_empty() { None } else { Some(s) })
                .ok_or_else(|| ServerError::MissingEnvVar("UPLOAD__MAX_SIZE"))?,
        )?;

        let max_time = parse_time(
            env.get("UPLOAD__MAX_TIME")
                .and_then(|s| if s.is_empty() { None } else { Some(s) })
                .ok_or_else(|| ServerError::MissingEnvVar("UPLOAD__MAX_TIME"))?,
        )?;

        Ok(Self {
            cache_directory,
            max_size,
            max_time,
        })
    }
}

/// Configuration specifically for the auth module.
#[derive(Debug)]
pub struct AuthConfig {
    /// The maximum time a nonce may live before it is considered expired.
    pub nonce_max_time_to_live: std::time::Duration,
    /// Url + usernames to authentication keys used for validation.
    pub auth_keys: HashMap<Url, String>,
}

impl AuthConfig {
    /// Constructs an `AuthConfig` instance by loading `AUTH__NONCE_MAX_TIME_TO_LIVE` from the environment variables.
    ///
    /// The time must specify units: `s`, `m`, `h`, `d`. For example, `1h`.
    ///
    /// # Arguments
    /// * `env` - A HashMap of environment variables.
    ///
    /// # Errors
    /// Returns a `ServerError` if the `AUTH__NONCE_MAX_TIME_TO_LIVE` environment variable is missing or invalid.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let env = std::env::vars().collect::<HashMap<String, String>>();
    /// # let mut env = env;
    /// # env.insert("AUTH__NONCE_MAX_TIME_TO_LIVE".to_string(), "100s");
    /// # let env = env;
    /// let auth_config = AuthConfig::from_env(&env).expect("Failed to load auth configuration");
    /// println!("Nonce max time-to-live: {:?}", auth_config.nonce_max_time_to_live);
    /// ```
    pub fn from_env(env: &HashMap<String, String>) -> ServerResult<Self> {
        let nonce_max_time_to_live = parse_time(
            env.get("AUTH__NONCE_MAX_TIME_TO_LIVE")
                .and_then(|s| if s.is_empty() { None } else { Some(s) })
                .ok_or_else(|| ServerError::MissingEnvVar("AUTH__NONCE_MAX_TIME_TO_LIVE"))?,
        )?;

        let auth_keys: HashMap<Url, String> = env
            .iter()
            .filter(|(k, _)| k.starts_with("AUTH__AUTH_KEYS__"))
            .map(|(k, v)| {
                let url = k
                    .trim_start_matches("AUTH__AUTH_KEYS__")
                    .split("__")
                    .next()
                    .expect("Failed to parse URL");
                let url = Url::parse(url).expect("Failed to parse URL");
                (url, v.to_string())
            })
            .collect();

        // All of the keys should end in .keys and be valid URLs with a scheme and no trailing slash.
        if auth_keys.iter().any(|(url, _)| {
            url.scheme().is_empty() || url.cannot_be_a_base() || !url.path().is_empty()
        }) {
            let first_failed_key = auth_keys
                .iter()
                .find(|(url, _)| {
                    url.scheme().is_empty() || url.cannot_be_a_base() || !url.path().is_empty()
                })
                .expect("already checked to be present");

            return Err(ServerError::InvalidEnvVar(
                "AUTH__AUTH_KEYS__*",
                format!("{:?}", first_failed_key),
                anyhow::anyhow!("Invalid URL"),
            ));
        }

        Ok(Self {
            nonce_max_time_to_live,
            auth_keys,
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
fn parse_size(size_str: &str) -> ServerResult<u64> {
    let (value, unit) = size_str
        .trim()
        .split_at(size_str.len().checked_sub(2).ok_or_else(|| {
            ServerError::InvalidEnvVar(
                "UPLOAD__MAX_SIZE",
                size_str.to_string(),
                anyhow::anyhow!("Invalid size string"),
            )
        })?);
    let value: u64 = value.parse::<u64>().map_err(|e| {
        ServerError::InvalidEnvVar("UPLOAD__MAX_SIZE", size_str.to_string(), e.into())
    })?;
    match unit.to_uppercase().as_str() {
        "B" => Ok(value),
        "KB" => Ok(value.checked_mul(1024).expect("Size overflow")),
        "MB" => Ok(value.checked_mul(1024 * 1024).expect("Size overflow")),
        "GB" => Ok(value
            .checked_mul(1024 * 1024 * 1024)
            .expect("Size overflow")),
        got => Err(ServerError::InvalidEnvVar(
            "UPLOAD__MAX_SIZE",
            size_str.to_string(),
            anyhow::anyhow!("Unsupported unit: {}", got),
        )),
    }
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
fn parse_time(time_str: &str) -> ServerResult<std::time::Duration> {
    let (value, unit) = time_str
        .trim()
        .split_at(time_str.len().checked_sub(1).ok_or_else(|| {
            ServerError::InvalidEnvVar(
                "UPLOAD__MAX_TIME",
                time_str.to_string(),
                anyhow::anyhow!("Length too short"),
            )
        })?);
    let value: u64 = value.parse::<u64>().map_err(|e| {
        ServerError::InvalidEnvVar("UPLOAD__MAX_TIME", time_str.to_string(), e.into())
    })?;
    let seconds = match unit.to_lowercase().as_str() {
        "s" => Ok(value),
        "m" => Ok(value.checked_mul(60).expect("Time overflow")),
        "h" => Ok(value.checked_mul(60 * 60).expect("Time overflow")),
        "d" => Ok(value.checked_mul(60 * 60 * 24).expect("Time overflow")),
        got => Err(ServerError::InvalidEnvVar(
            "UPLOAD__MAX_TIME",
            time_str.to_string(),
            anyhow::anyhow!("Unsupported unit: {}", got),
        )),
    }?;

    Ok(std::time::Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::time::Duration;

    use super::*;

    #[test]
    fn test_server_config_from_env() {
        let mut env = HashMap::new();
        env.insert("SERVER__HOST".to_string(), "127.0.0.1".to_string());
        env.insert("SERVER__PORT".to_string(), "8080".to_string());

        let server_config = ServerConfig::from_env(&env).expect("Failed to load ServerConfig");
        assert_eq!(server_config.host, Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(server_config.port, 8080);
    }

    #[test]
    fn test_invalid_server_host() {
        let mut env = HashMap::new();
        env.insert("SERVER__HOST".to_string(), "invalid_host".to_string());
        env.insert("SERVER__PORT".to_string(), "8080".to_string());

        let err = ServerConfig::from_env(&env);

        assert!(err.is_err());
        assert_eq!(
            err.expect_err("Should fail due to invalid host").to_string(),
            "Invalid environment variable: SERVER__HOST: invalid_host, failed due to: invalid IPv4 address syntax"
        );
    }

    #[test]
    fn test_invalid_server_port() {
        let mut env = HashMap::new();
        env.insert("SERVER__HOST".to_string(), "127.0.0.1".to_string());
        env.insert("SERVER__PORT".to_string(), "invalid_port".to_string());

        let err = ServerConfig::from_env(&env);

        assert!(err.is_err());
        assert_eq!(
            err.expect_err("Should valid due to invalid port").to_string(),
            "Invalid environment variable: SERVER__PORT: invalid_port, failed due to: invalid digit found in string"
        );
    }

    #[test]
    fn test_database_config_from_env() {
        let mut env = HashMap::new();
        env.insert(
            "DATABASE__URL".to_string(),
            "postgres://user:password@localhost/dbname".to_string(),
        );

        let database_config =
            DatabaseConfig::from_env(&env).expect("Failed to load DatabaseConfig");
        assert_eq!(
            database_config.url,
            "postgres://user:password@localhost/dbname"
        );
    }

    #[test]
    fn test_upload_config_from_env() {
        let mut env = HashMap::new();
        env.insert(
            "UPLOAD__CACHE_DIRECTORY".to_string(),
            "/tmp/uploads".to_string(),
        );
        env.insert("UPLOAD__MAX_SIZE".to_string(), "10MB".to_string());
        env.insert("UPLOAD__MAX_TIME".to_string(), "1h".to_string());

        let upload_config = UploadConfig::from_env(&env).expect("Failed to load UploadConfig");
        assert_eq!(upload_config.cache_directory, PathBuf::from("/tmp/uploads"));
        assert_eq!(upload_config.max_size, 10 * 1024 * 1024);
        assert_eq!(
            upload_config.max_time,
            std::time::Duration::from_secs(60 * 60)
        );
    }

    #[test]
    fn test_upload_size_units() {
        let mut env = HashMap::new();
        env.insert(
            "UPLOAD__CACHE_DIRECTORY".to_string(),
            "/tmp/uploads".to_string(),
        );
        env.insert("UPLOAD__MAX_TIME".to_string(), "1h".to_string());
        env.insert("UPLOAD__MAX_SIZE".to_string(), "1GB".to_string());
        let upload_config = UploadConfig::from_env(&env).expect("Failed to load UploadConfig");
        assert_eq!(upload_config.max_size, 1024 * 1024 * 1024);

        let mut env = HashMap::new();
        env.insert(
            "UPLOAD__CACHE_DIRECTORY".to_string(),
            "/tmp/uploads".to_string(),
        );
        env.insert("UPLOAD__MAX_TIME".to_string(), "1h".to_string());
        env.insert("UPLOAD__MAX_SIZE".to_string(), "500KB".to_string());
        let upload_config = UploadConfig::from_env(&env).expect("Failed to load UploadConfig");
        assert_eq!(upload_config.max_size, 500 * 1024);
    }

    #[test]
    fn test_invalid_upload_size() {
        let mut env = HashMap::new();
        env.insert(
            "UPLOAD__CACHE_DIRECTORY".to_string(),
            "/tmp/uploads".to_string(),
        );
        env.insert("UPLOAD__MAX_TIME".to_string(), "1h".to_string());
        env.insert("UPLOAD__MAX_SIZE".to_string(), "1.5GB".to_string());

        let err = UploadConfig::from_env(&env);

        assert!(err.is_err());
        assert_eq!(
            err.expect_err("Should fail due to float value").to_string(),
            "Invalid environment variable: UPLOAD__MAX_SIZE: 1.5GB, failed due to: invalid digit found in string"
        );
    }

    #[test]
    fn test_auth_config_from_env() {
        let mut env = HashMap::new();
        env.insert(
            "AUTH__NONCE_MAX_TIME_TO_LIVE".to_string(),
            "100s".to_string(),
        );
        let auth_config = AuthConfig::from_env(&env).expect("Failed to load AuthConfig");
        assert_eq!(auth_config.nonce_max_time_to_live, Duration::from_secs(100));

        let mut env = HashMap::new();
        env.insert("AUTH__NONCE_MAX_TIME_TO_LIVE".to_string(), "5m".to_string());
        let auth_config = AuthConfig::from_env(&env).expect("Failed to load AuthConfig");
        assert_eq!(auth_config.nonce_max_time_to_live, Duration::from_secs(300));

        let mut env = HashMap::new();
        env.insert("AUTH__NONCE_MAX_TIME_TO_LIVE".to_string(), "1h".to_string());
        let auth_config = AuthConfig::from_env(&env).expect("Failed to load AuthConfig");
        assert_eq!(
            auth_config.nonce_max_time_to_live,
            Duration::from_secs(3600)
        );

        let mut env = HashMap::new();
        env.insert("AUTH__NONCE_MAX_TIME_TO_LIVE".to_string(), "1d".to_string());
        let auth_config = AuthConfig::from_env(&env).expect("Failed to load AuthConfig");
        assert_eq!(
            auth_config.nonce_max_time_to_live,
            Duration::from_secs(86400)
        );
    }

    #[test]
    fn test_invalid_auth_nonce_time() {
        let mut env = HashMap::new();
        env.insert(
            "AUTH__NONCE_MAX_TIME_TO_LIVE".to_string(),
            "1.5h".to_string(),
        );

        let err = AuthConfig::from_env(&env);

        assert!(err.is_err());
        assert_eq!(
            err.expect_err("Should fail due to float value").to_string(),
            "Invalid environment variable: UPLOAD__MAX_TIME: 1.5h, failed due to: invalid digit found in string"
        );
    }
}
