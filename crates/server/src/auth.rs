//! Handles authentication by signing nonces with an ssh key.

// TODO: move this into it's own library which can be published to crates.io

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use axum_extra::headers::authorization::Credentials;
use base64::Engine;
use rand::RngCore;
use reqwest::Url;
use ssh_key::{public::KeyData, PublicKey, SshSig};
use tokio::sync::RwLock;
use tokio_util::sync::{CancellationToken, DropGuard};
use tracing::Instrument;

use crate::error::ServerError;

/// The length of the nonce in bytes.
const NONCE_LENGTH: usize = 32;
/// How long to keep a nonce active for in milliseconds, after which it will be expired and cannot be used to perform an upload.
const NONCE_TTL_MS: u64 = 1000 * 60 * 5; // 5 minutes
/// How often to refresh the keys from the sources in milliseconds.
const KEY_REFRESH_INTERVAL_MS: u64 = 1000 * 60 * 30; // 1 hour
/// The maximum time allowed since the keys were last refreshed in milliseconds, after which we will refuse to verify nonces.
const MAX_TIME_ALLOWED_SINCE_REFRESH: u64 = 1000 * 60 * 60 * 24; // 24 hours
/// The absolute maximum number of keys to hold at once.
const MAX_NUMBER_OF_KEYS: usize = 20; // Should more than cover the number of keys for a single user.

#[derive(Debug)]
pub struct AuthenticatedUpload {
    nonce: [u8; NONCE_LENGTH],
    signature: SshSig,
}

impl AuthenticatedUpload {
    pub fn nonce(&self) -> &[u8; NONCE_LENGTH] {
        &self.nonce
    }

    pub fn signature(&self) -> &SshSig {
        &self.signature
    }
}

impl Credentials for AuthenticatedUpload {
    const SCHEME: &'static str = "SshSig";

    #[tracing::instrument]
    fn decode(value: &axum::http::HeaderValue) -> Option<Self> {
        // Ensure the string starts with 'SshSig '.
        let value = value.to_str().ok()?;
        if !value.starts_with(Self::SCHEME) {
            tracing::warn!("Invalid scheme");
            return None;
        }

        // Split the string by space, grabbing the second part.
        let value = value.split_once(' ')?.1.to_string();

        // Parse the incoming string as base64
        let string = base64::engine::general_purpose::STANDARD
            .decode(value.as_bytes())
            .ok()?;

        #[allow(clippy::missing_docs_in_private_items, reason = "Internal type")]
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "snake_case", deny_unknown_fields)]
        struct Inner {
            nonce: String,
            signature: String,
        }

        let Inner { nonce, signature } = serde_json::from_slice::<Inner>(&string).ok()?;

        // Try parsing the nonce
        let nonce = base64::engine::general_purpose::STANDARD
            .decode(nonce.as_bytes())
            .ok()?;
        let nonce: [u8; NONCE_LENGTH] = nonce.try_into().ok()?;

        // Try parsing the signature
        // Split the string by space.
        let signature = signature.replace(
            "-----BEGIN SSH SIGNATURE-----",
            "-----BEGIN SSH SIGNATURE-----\n",
        );
        let signature = signature.replace(
            "-----END SSH SIGNATURE-----",
            "\n-----END SSH SIGNATURE-----",
        );

        // Get the index of these two newlines
        let [index_start, index_end] = {
            let mut indices = signature.match_indices("\n");
            let start = indices.next()?.0;
            let end = indices.next()?.0;
            [start, end]
        };

        // Insert a newline every 76 characters after the first newline but before the last newline.
        let mut signature = signature.chars().collect::<Vec<_>>();
        let mut i = index_start.checked_add(71).expect("Overflow occurred");
        while i < index_end {
            signature.insert(i, '\n');
            i = i.checked_add(71).expect("Overflow occurred");
        }
        let signature = signature.into_iter().collect::<String>();

        // Parse the string as a PEM encoded SSH signature.
        let signature = SshSig::from_pem(&signature).ok()?;

        Some(Self { nonce, signature })
    }

    #[tracing::instrument]
    fn encode(&self) -> axum::http::HeaderValue {
        unreachable!("Why are we encoding an AuthenticatedUpload?");
    }
}

/// Represents a user and the public key associated with them in fully denormalised form. Given more
/// users have more than one public key, normalising this could result in some benefits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct KeyDataInner {
    /// The public key.
    public_key: PublicKey,
    /// The username associated with the key.
    username: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeySource {
    pub url: Url,
    pub username: String,
}

/// Inner data structure for managing GitHub keys and nonces.
#[derive(Debug)]
struct GithubKeysInner {
    /// The verifying keys that are used to verify the nonces.
    keys: HashMap<KeyData, KeyDataInner>,

    /// When the keys were last requested from the sources.
    last_requested: chrono::DateTime<chrono::Utc>,

    /// The currently active nonces that can be used for a valid upload.
    active_nonces: HashMap<[u8; NONCE_LENGTH], tokio::time::Instant>,
}

pub struct GithubKeys {
    /// The inner data used by the Authenticator. This is a shared object to enable access by
    /// multiple requests and the spawned tokio tasks which manage the data at the same time.
    inner: Arc<RwLock<GithubKeysInner>>,

    /// A guard held so that if the [`GithubKeys`] object is uncermouniously dropped we will
    /// properly shutdown all handlers via a cancellation token.
    drop_guard: DropGuard,

    /// A reference to the tokio task spawned to handle expiring old nonces.
    handle_tokens: tokio::task::JoinHandle<()>,

    /// A reference to the tokio task spawned to handle refetching keys from the various providers
    /// on a regular interval.
    handle_keys: tokio::task::JoinHandle<()>,
}

impl GithubKeys {
    #[tracing::instrument(skip(sources_to_check), fields(
        sources_to_check = ?sources_to_check.iter().take(15).map(|source| source.url.as_str()).collect::<Vec<_>>(),
    ), level = "debug")]
    pub fn new(sources_to_check: Vec<KeySource>) -> Self {
        // Ensure sources_to_check is populated, are valid URLs, are unique, and end in .keys
        let sources_to_check: HashSet<KeySource> = sources_to_check.into_iter().collect();
        assert!(!sources_to_check.is_empty(), "No sources to check for keys");
        for source in &sources_to_check {
            assert!(
                source.url.as_str().ends_with(".keys"),
                "Source does not end in .keys: {}",
                source.url
            );
        }
        let sources_to_check: Vec<KeySource> = sources_to_check.into_iter().collect();

        let inner = GithubKeysInner {
            keys: HashMap::new(),
            last_requested: chrono::Utc::now(),
            active_nonces: HashMap::new(),
        };
        let inner = Arc::new(RwLock::new(inner));

        let cancel_token = CancellationToken::new();
        let drop_guard = cancel_token.clone().drop_guard();

        // Spawn the key refresh task.
        let handle_keys = tokio::spawn({
            let inner = Arc::clone(&inner);

            let client = reqwest::Client::builder()
                // .https_only(false) // For tests
                // Set some excessive timeouts.
                .connect_timeout(Duration::from_secs(30))
                .read_timeout(Duration::from_secs(30))
                .build()
                .expect("Failed to build reqwest::Client");

            let cancel_token = cancel_token.child_token();

            async move {
                loop {
                    tokio::select! {
                        _ = cancel_token.cancelled() => {
                            break;
                        }
                        _ = {
                            async {
                                let mut all_keys = HashMap::new();
                                for KeySource { url, username } in sources_to_check.clone().into_iter() {
                                    let response = client.get(url).send().await?;
                                    let keys = response.text().await?;
                                    let keys = keys.lines().filter_map(|key| {
                                        let key = key.trim();
                                        match PublicKey::from_openssh(key) {
                                            Ok(key) => Some(key),
                                            Err(e) => {
                                                tracing::warn!(err = (&e as &dyn std::error::Error),
                                                key = key,
                                                 "Failed to parse key");
                                                None
                                            }
                                        }
                                    });

                                    let keys = keys.map(|key| {
                                        let data = KeyData::from(&key);
                                        let inner = KeyDataInner {
                                            public_key: key,
                                            username: username.clone(),
                                        };
                                        (data, inner)
                                    });

                                    all_keys.extend(keys);
                                    tokio::time::sleep(Duration::from_secs(1)).await;
                                }

                                if all_keys.len() > MAX_NUMBER_OF_KEYS {
                                    return Err(ServerError::Internal(format!(
                                        "Too many keys fetched: {}",
                                        all_keys.len()
                                    )));
                                }

                                {
                                    let mut inner = inner.write().await;
                                    inner.keys = all_keys;
                                    inner.last_requested = chrono::Utc::now();
                                }

                                Ok(())
                            }.instrument(tracing::info_span!("Key refresh task"))
                        } => {}
                    }

                    tokio::select! {
                        _ = cancel_token.cancelled() => {
                            break;
                        }
                        _ = tokio::time::sleep(Duration::from_millis(KEY_REFRESH_INTERVAL_MS)) => {}
                    }
                }

                tracing::info!("Key refresh task cancelled");
            }
        });

        // Spawn the token expiration task.
        let handle_tokens = tokio::spawn({
            let inner = Arc::clone(&inner);

            let cancel_token = cancel_token.child_token();

            async move {
                loop {
                    tokio::select! {
                        _ = cancel_token.cancelled() => {
                            break;
                        }
                        mut inner = async {
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            inner.write().await
                        } => {
                            let now = tokio::time::Instant::now();
                            inner.active_nonces.retain(|_, instant| now.checked_duration_since(*instant).map_or(false, |d| d < Duration::from_millis(NONCE_TTL_MS)));

                            // If we can't refresh the keys, stop performing any sort of verification.
                            // XXX: use durations to compare here, not MS.
                            if chrono::Utc::now().signed_duration_since(inner.last_requested).num_milliseconds() as u64 > MAX_TIME_ALLOWED_SINCE_REFRESH {
                                tracing::error!(
                                    last_checked = inner.last_requested.to_rfc3339(),
                                    timeout = MAX_TIME_ALLOWED_SINCE_REFRESH,
                                    "Keys have not been refreshed in too long"
                                );
                                inner.active_nonces.clear();
                                inner.keys.clear();
                            }
                        }
                    }
                }

                tracing::info!("Token expiration task cancelled");
            }
        });

        Self {
            inner,
            drop_guard,
            handle_tokens,
            handle_keys,
        }
    }

    #[tracing::instrument(skip(self), ret(level = "trace"))]
    pub async fn gracefully_shutdown(self) -> anyhow::Result<()> {
        let Self {
            drop_guard,
            handle_keys,
            handle_tokens,
            ..
        } = self;
        drop(drop_guard);

        /// The maximum time to wait for a service to shutdown before we throw an error.
        const ABSOLUTE_TIMEOUT: Duration = Duration::from_secs(10);

        if let Err(e) = tokio::time::timeout(ABSOLUTE_TIMEOUT, handle_keys).await {
            tracing::error!(
                err = (&e as &dyn std::error::Error),
                "Failed to join key refresh task"
            );
            anyhow::bail!("Failed to join key refresh task");
        }
        if let Err(e) = tokio::time::timeout(ABSOLUTE_TIMEOUT, handle_tokens).await {
            tracing::error!(
                err = (&e as &dyn std::error::Error),
                "Failed to join token expiration task"
            );
            anyhow::bail!("Failed to join token expiration task");
        }

        Ok(())
    }

    #[tracing::instrument(skip(self), ret(level = "trace"))]
    pub async fn generate_nonce(&self) -> String {
        let data = {
            let mut rng = rand::thread_rng();
            let mut data = [0_u8; NONCE_LENGTH];
            rng.fill_bytes(&mut data);
            data
        };

        {
            let mut inner = self.inner.write().await;
            inner
                .active_nonces
                .insert(data, tokio::time::Instant::now());
        }

        base64::engine::general_purpose::STANDARD.encode(data)
    }

    #[tracing::instrument(skip(self), ret(level = "trace"))]
    pub async fn get_user(&self, nonce: &[u8; NONCE_LENGTH], signature: &SshSig) -> Option<String> {
        // Check if the nonce is active
        {
            let mut inner = self.inner.write().await;
            if let Some(instant) = inner.active_nonces.remove(nonce) {
                if instant.elapsed().as_millis() as u64 > NONCE_TTL_MS {
                    return None;
                }
            } else {
                return None;
            }
        }
        tracing::debug!("Nonce succesfully validated.");

        let key = {
            let requested_key = signature.public_key();
            let inner = self.inner.read().await;

            tracing::trace!(
                all_keys = ?inner.keys,
                requested_key = ?requested_key,
                "Trying to find key"
            );
            match inner.keys.get(requested_key).cloned() {
                Some(key) => key,
                None => return None,
            }
        };
        tracing::debug!("Associated key found.");

        key.public_key
            .verify("file", nonce, signature)
            .is_ok()
            .then_some(key.username)
    }
}

#[cfg_attr(test, mutants::skip)]
impl std::fmt::Debug for GithubKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            inner,
            drop_guard,
            handle_keys,
            handle_tokens,
        } = &self;
        f.debug_struct("GithubKeys")
            .field("inner", &inner)
            .field("drop_guard", &drop_guard)
            .field("handle_keys", &handle_keys)
            .field("handle_tokens", &handle_tokens)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use httpmock::MockServer;
    use itertools::Itertools;
    use ssh_key::{
        private::{Ed25519Keypair, KeypairData},
        HashAlg, PrivateKey,
    };
    use tracing_test::traced_test;

    use super::*;

    // TODO: test with variable config.

    #[traced_test]
    #[tokio::test]
    async fn graceful_shutdown() {
        let public_keys = [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICaveS9skud+9YZF51mC6gYNENuWeTXFhZdg6EBiPSgg",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHI/e24QlOg4YtW1RCMJ1gAClWvkEWCbmNlwfKNowD2T",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILarW3/lgpjM30FAgYLSd6i/2CE3tEZ44O7m2Q6ESzb9",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIECGkEQqSyVcTmklLfklDFEAidcSStbNxECjOXSK7in2",
        ]
        .join("\n");

        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/testuser.keys");
            then.status(200)
                .body(public_keys)
                .header("Content-Type", "text/plain");
        });

        let keys = GithubKeys::new(vec![KeySource {
            url: Url::parse(&server.url("/testuser.keys")).expect("The url to be parsable"),
            username: "testuser".to_string(),
        }]);

        // Wait 1 second
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Get the number of requests
        mock.assert_hits(1);

        // Wait another second
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Get the number of requests
        mock.assert_hits(1);

        // Ensure that the log messages do not exist yet
        assert!(!logs_contain("Key refresh task cancelled"));
        assert!(!logs_contain("Token expiration task cancelled"));

        // Ensure we can shutdown gracefully
        keys.gracefully_shutdown()
            .await
            .expect("to be able to gracefully shut down");

        // Wait for 1 second
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Ensure that the logs contain "Key refresh task cancelled" and "Token expiration task cancelled"
        assert!(logs_contain("Key refresh task cancelled"));
        assert!(logs_contain("Token expiration task cancelled"));
    }

    #[tokio::test]
    async fn test_nonces_are_unique() {
        const NUM_TO_GENERATE: usize = 100_000;

        let keys = GithubKeys::new(vec![KeySource {
            url: "https://doesnotexistlakjdlfkj.com/testuser.keys"
                .parse()
                .expect("The URL to be parseable."),
            username: "testuser".to_string(),
        }]);
        let mut nonces = Vec::with_capacity(NUM_TO_GENERATE);
        for _ in 0..nonces.len() {
            nonces.push(keys.generate_nonce().await);
        }

        let mut deduplicated_nonces = nonces.clone().into_iter().unique().collect_vec();

        nonces.sort();
        deduplicated_nonces.sort();

        assert_eq!(
            nonces, deduplicated_nonces,
            "Nonces are expected to always be unique."
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn get_user_exists() {
        let private_key = PrivateKey::new(
            KeypairData::Ed25519(Ed25519Keypair::from_seed(&[1; 32])),
            "a static test key",
        )
        .expect("to be a valid private key");
        let public_key = private_key.public_key().to_string();

        assert_eq!(
            public_key,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIqI4910CfGV/VLbLTy6XXLKZwm/HZQSG/N0iAG0D29c a static test key",
            "public key should match expected constant"
        );

        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/testuser.keys");
            then.status(200)
                .body(public_key)
                .header("Content-Type", "text/plain");
        });

        let keys = GithubKeys::new(vec![KeySource {
            url: Url::parse(&server.url("/testuser.keys")).expect("to be valid url"),
            username: "testuser".to_string(),
        }]);

        tokio::time::sleep(Duration::from_secs(1)).await;
        mock.assert_hits(1);
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Get a nonce
        let nonce = keys.generate_nonce().await;

        // Decode the nonce using base64
        // XXX: this API seems... odd. This bears further investigation and potentially a restructure.
        let nonce = base64::engine::general_purpose::STANDARD
            .decode(nonce.as_bytes())
            .expect("to be valid base64");

        // Generate a valid signature.
        let sig = private_key
            .sign("file", HashAlg::Sha256, &nonce)
            .expect("to be able to sign file");

        let user = keys
            .get_user(&nonce.try_into().expect("nonce to be 32 bytes line"), &sig)
            .await;

        assert_eq!(
            user,
            Some("testuser".to_string()),
            "Expected to get the correct test user."
        );
    }

    #[test]
    fn test_decode_credentials() {
        let header_value = axum::http::HeaderValue::from_static(
            "SshSig eyJub25jZSI6ImgvOC9jSldvaWdJZzlKYkdCSUZuWjhtWXJENjk0QlFHL0dSS09WS2p5ZTQ9Iiwic2lnbmF0dXJlIjoiLS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS1VMU5JVTBsSEFBQUFBUUFBQURNQUFBQUxjM05vTFdWa01qVTFNVGtBQUFBZ3RxdGJmK1dDbU16ZlFVQ0JndEozcUwvWUlUZTBSbmpnN3ViWkRvUkxOdjBBQUFBRVptbHNaUUFBQUFBQUFBQUdjMmhoTlRFeUFBQUFVd0FBQUF0emMyZ3RaV1F5TlRVeE9RQUFBRURyZ1JnOHRFc0xIQ3NtQmx1RGd6MUpLaFRGNitablpFa1RzQmdxYmZHQjMzM2VVMU4wVFZYUXhpV1dVeWV0cjlIL1hocmxEM0NlNk42K0xiUFJrYklJLS0tLS1FTkQgU1NIIFNJR05BVFVSRS0tLS0tIn0="
        );

        let credentials =
            AuthenticatedUpload::decode(&header_value).expect("credentials to be valid");

        assert_eq!(
            credentials.nonce(),
            &[
                135, 255, 63, 112, 149, 168, 138, 2, 32, 244, 150, 198, 4, 129, 103, 103, 201, 152,
                172, 62, 189, 224, 20, 6, 252, 100, 74, 57, 82, 163, 201, 238
            ],
            "Expected nonce to be correct."
        );

        assert_eq!(
            credentials.signature().to_string(),
            "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgtqtbf+WCmMzfQUCBgtJ3qL/YIT\ne0Rnjg7ubZDoRLNv0AAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx\nOQAAAEDrgRg8tEsLHCsmBluDgz1JKhTF6+ZnZEkTsBgqbfGB333eU1N0TVXQxiWWUyetr9\nH/XhrlD3Ce6N6+LbPRkbII\n-----END SSH SIGNATURE-----\n".to_string(),
            "Expected signature to be correct."
        );
    }

    #[tokio::test]
    #[should_panic = "internal error: entered unreachable code: Why are we encoding an AuthenticatedUpload?"]
    async fn test_encode_credentials() {
        let private_key = PrivateKey::new(
            KeypairData::Ed25519(Ed25519Keypair::from_seed(&[1; 32])),
            "a static test key",
        )
        .expect("private key to be valid");

        let signature = private_key
            .sign("file", HashAlg::Sha256, &[0; NONCE_LENGTH])
            .expect("able to sign nonce");

        let credentials = AuthenticatedUpload {
            nonce: [0; NONCE_LENGTH],
            signature,
        };

        credentials.encode();
    }

    #[test]
    #[should_panic = "No sources to check for keys"]
    fn test_starting_with_empty_sources_panics() {
        GithubKeys::new(Vec::new());
    }

    #[test]
    #[should_panic = "Source does not end in .keys: https://github.com/josiahbull"]
    fn test_that_invalid_urls_panic() {
        GithubKeys::new(vec![KeySource {
            url: "https://github.com/josiahbull"
                .parse()
                .expect("The url to be valid"),
            username: "josiahbull".to_string(),
        }]);
    }
}
