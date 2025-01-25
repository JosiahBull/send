#![allow(
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::impl_trait_in_params,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "This is an integration test."
)]

use std::io::Read;

use assert_cmd::cargo::CommandCargoExt;
use base64::Engine;
use httpmock::{Mock, MockExt, MockServer};
use rstest::{fixture, rstest};
use ssh_key::{
    private::{Ed25519Keypair, KeypairData},
    PrivateKey, PublicKey,
};

const COMMAND_NAME: &str = "server";

struct ServerInstance {
    process: Option<std::process::Child>,
    stderr_drainer: Option<std::thread::JoinHandle<String>>,
    stdout_drainer: Option<std::thread::JoinHandle<String>>,
    armed: bool,
}

impl ServerInstance {
    pub const fn new(
        process: std::process::Child,
        stderr_drainer: std::thread::JoinHandle<String>,
        stdout_drainer: std::thread::JoinHandle<String>,
    ) -> Self {
        Self {
            process: Some(process),
            stderr_drainer: Some(stderr_drainer),
            stdout_drainer: Some(stdout_drainer),
            armed: true,
        }
    }

    pub fn disarm(mut self) {
        self.armed = false;
        drop(self);
    }
}

impl std::ops::Deref for ServerInstance {
    type Target = std::process::Child;

    fn deref(&self) -> &Self::Target {
        self.process.as_ref().expect("To always be Some")
    }
}

impl Drop for ServerInstance {
    fn drop(&mut self) {
        let Self {
            process,
            armed,
            stderr_drainer,
            stdout_drainer,
        } = self;
        let mut process = process.take().expect("To always be Some");

        // SAFETY:
        // 1. We are sending a signal to a valid process id.
        // 2. We are sending a signal that the process is expected to handle.
        #[allow(unsafe_code, reason = "This is a test")]
        unsafe {
            libc::kill(process.id() as i32, libc::SIGINT);
        }

        let output = process.wait().unwrap();
        let stdout = stdout_drainer
            .take()
            .expect("To always be Some")
            .join()
            .unwrap();
        let stderr = stderr_drainer
            .take()
            .expect("To always be Some")
            .join()
            .unwrap();

        if !output.success() | *armed || stderr.contains("panic") || stderr.contains("panicked") {
            panic!(
                "Server exited with status: {}\nstdout:\n{}\nstderr:\n{}",
                output, stdout, stderr
            );
        }
    }
}

#[fixture]
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

#[fixture]
fn keys() -> (PrivateKey, PublicKey) {
    let private_key = PrivateKey::new(
        KeypairData::Ed25519(Ed25519Keypair::from_seed(&[2; 32])),
        "a static test key",
    )
    .expect("to be a valid private key");
    let public_key = private_key.public_key().to_owned();

    (private_key, public_key)
}

#[fixture]
fn mock_keys_server(keys: (PrivateKey, PublicKey)) -> (MockServer, usize, PrivateKey) {
    let (_, public_key) = keys;
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/testuser.keys");
        then.status(200)
            .body(public_key.to_string())
            .header("Content-Type", "text/plain");
    });
    let id = mock.id();

    (server, id, keys.0)
}

#[fixture]
fn temp_dir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[fixture]
async fn started_server(
    mock_keys_server: (MockServer, usize, PrivateKey),
    temp_dir: tempfile::TempDir,
    free_port: u16,
) -> (
    MockServer,
    usize,
    PrivateKey,
    tempfile::TempDir,
    u16,
    ServerInstance,
) {
    let mut cmd = std::process::Command::cargo_bin(COMMAND_NAME).unwrap();
    cmd.env_clear()
        // Rust directives
        .env("RUST_LOG", "DEBUG")
        // OTEL directives
        .env("OTEL_SERVICE_NAME", "backend")
        .env(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "http://telemetry.orb.local:4317",
        )
        .env("TRACE_SAMPLE_PROBABILITY", "1.0")
        // Server directives
        .env("SERVER__HOST", "127.0.0.1")
        .env("SERVER__PORT", free_port.to_string())
        .env("SERVER__DOMAIN", "http://127.0.0.1:3000")
        .env("DATABASE__URL", "sqlite::memory:")
        .env("UPLOAD__CACHE_DIRECTORY", temp_dir.path())
        .env("UPLOAD__MAX_CACHE_SIZE", "5M")
        .env("UPLOAD__MAX_FILE_SIZE", "1M")
        .env("UPLOAD__BOOK_KEEPING_INTERVAL", "5s")
        .env("UPLOAD__MIN_FILE_TIME_TO_LIVE", "5s")
        .env("UPLOAD__MAX_FILE_TIME_TO_LIVE", "1d")
        .env("AUTH__NONCE_MAX_TIME_TO_LIVE", "5s")
        .env("AUTH__KEY_REFRESH_INTERVAL", "1h")
        .env("AUTH__MAX_NUMBER_OF_KEYS_PER_USER", "20")
        .env("AUTH__MAX_TIME_ALLOWED_SINCE_REFRESH", "6h")
        .env("AUTH__AUTH_KEYS__0__USERNAME", "testuser")
        .env(
            "AUTH__AUTH_KEYS__0__URL",
            format!(
                "http://127.0.0.1:{}/testuser.keys",
                mock_keys_server.0.port()
            ),
        )
        .env("RATE_LIMIT__BUCKET_SIZE", "20")
        .env("RATE_LIMIT__REFILL_INTERVAL", "5s");

    // Spawn a thread to run the server.
    let mut handle = cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let stdout_handle = handle.stdout.take().unwrap();
    let stderr_handle = handle.stderr.take().unwrap();

    // Spawn a thread to read the server's stdout and stderr into Strings until they close, capping out
    // at 10MB of output each. Old output will be deleted to make room for new output. These threads will
    // exit when the streams close.
    let stdout_handle = std::thread::spawn(move || {
        let mut stdout = String::new();
        let mut buffer = [0; 1024];
        let mut reader = std::io::BufReader::new(stdout_handle);
        while let Ok(n) = reader.read(&mut buffer) {
            if n == 0 {
                break;
            }
            stdout.push_str(String::from_utf8_lossy(&buffer[..n]).as_ref());
            if stdout.len() > 10_000_000 {
                // remove the first 1_000_000 characters
                stdout = stdout.split_off(1_000_000);
            }
        }
        stdout
    });

    let stderr_handle = std::thread::spawn(move || {
        let mut stderr = String::new();
        let mut buffer = [0; 1024];
        let mut reader = std::io::BufReader::new(stderr_handle);
        while let Ok(n) = reader.read(&mut buffer) {
            if n == 0 {
                break;
            }
            stderr.push_str(String::from_utf8_lossy(&buffer[..n]).as_ref());
            if stderr.len() > 10_000_000 {
                // remove the first 1_000_000 characters
                stderr = stderr.split_off(1_000_000);
            }
        }
        stderr
    });

    let server_instance = ServerInstance::new(handle, stderr_handle, stdout_handle);

    // Wait for the server to start up by periodically pinging the /health endpoint.
    const MAX_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
    let start = std::time::Instant::now();
    loop {
        if let Ok(response) =
            reqwest::get(&format!("http://127.0.0.1:{}/api/health", free_port)).await
        {
            if response.status().is_success() {
                break;
            }
        }

        if start.elapsed() > MAX_TIMEOUT {
            panic!("Server did not start up in time.");
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    (
        mock_keys_server.0,
        mock_keys_server.1,
        mock_keys_server.2,
        temp_dir,
        free_port,
        server_instance,
    )
}

#[fixture]
#[awt]
async fn server_with_keys_initalised(
    #[future] started_server: (
        MockServer,
        usize,
        PrivateKey,
        tempfile::TempDir,
        u16,
        ServerInstance,
    ),
) -> (PrivateKey, tempfile::TempDir, u16, ServerInstance) {
    let (mock_server, mock_id, private_key, temp_dir, free_port, started_server) = started_server;
    let mock = Mock::new(mock_id, &mock_server);

    // Wait until the mockserver has been hit at least once
    const MAX_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
    let start = std::time::Instant::now();
    loop {
        if mock.hits() > 0 {
            break;
        }

        if start.elapsed() > MAX_TIMEOUT {
            panic!("Server did not start up in time.");
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

    (private_key, temp_dir, free_port, started_server)
}

fn sign_and_encode_nonce(nonce: &str, private_key: &PrivateKey) -> String {
    let nonce = base64::engine::general_purpose::STANDARD
        .decode(nonce.trim_matches('"'))
        .unwrap();
    let signature = private_key
        .sign("file", ssh_key::HashAlg::Sha256, &nonce)
        .unwrap();
    let signature = signature
        .to_pem(ssh_key::LineEnding::LF)
        .unwrap()
        .replace("\n", "");

    let json = serde_json::json!({
        "signature": signature,
        "nonce": base64::engine::general_purpose::STANDARD.encode(nonce),
    });

    base64::engine::general_purpose::STANDARD.encode(json.to_string())
}

fn sanitise_snapshot(snapshot: String) -> String {
    // Some parts of the html file are non-static because they contain timestamps, or custom URL components.
    // find http://127.0.0.1/([a-zA-Z0-9]{8})/file and replace the matching group with the string "DOWNLOAD_ID"
    let snapshot = regex::Regex::new(r"http://127\.0\.0\.1:3000/[a-zA-Z0-9-_=]{8}")
        .unwrap()
        .replace_all(&snapshot, "http://127.0.0.1:3000/DOWNLOAD_ID")
        .to_string();

    // We include some timestamps for uploadedAt and expiresAt, which must be replaced.
    // find: <span class="uploadedAt|expiresAt">([0-9]*?)< and replace it with 1_000_000_000
    let snapshot = regex::Regex::new(r#"<span class="(uploadedAt|expiresAt)">([0-9]*?)<"#)
        .unwrap()
        .replace_all(&snapshot, r#"<span class="$1">1_000_000_000<"#)
        .to_string();

    snapshot
}

/// Do a full test of the happy path to do a full upload and download.
#[rstest]
#[awt]
#[timeout(std::time::Duration::from_secs(30))]
#[tokio::test]
async fn test_successful_download_and_upload(
    #[future] server_with_keys_initalised: (PrivateKey, tempfile::TempDir, u16, ServerInstance),
) {
    let (private_key, temp_dir, free_port, started_server) = server_with_keys_initalised;

    // Get a nonce
    let response = reqwest::get(&format!("http://127.0.0.1:{}/api/v1/nonce", free_port))
        .await
        .unwrap();

    let binding = response.text().await.unwrap();
    let signed_nonce = sign_and_encode_nonce(&binding, &private_key);

    // Create a test file to upload
    let test_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(test_file.path(), "Hello, world 123!").unwrap();

    // Upload the file
    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/api/v1/upload", free_port))
        .header("Authorization", format!("SshSig {}", signed_nonce))
        .multipart(
            reqwest::multipart::Form::new()
                .text("file_name", "hello.txt")
                .text("file_size", "17")
                .text("expiry_secs", "5")
                .file("file", test_file.path())
                .await
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    let status = response.status();
    let body = response.text().await.unwrap();
    if !status.is_success() {
        panic!("Failed to upload file: {}", body);
    }

    let download = reqwest::get(&format!(
        "http://127.0.0.1:{}/{}",
        free_port,
        body.trim_matches('"')
    ))
    .await
    .unwrap();
    let download = download.text().await.unwrap();

    // Create a snapshot
    insta::assert_snapshot!(sanitise_snapshot(download));

    // There should be a single file in the cache directory, containing all of the data.
    let mut files = std::fs::read_dir(temp_dir.path()).unwrap();
    let file = files.next().unwrap().unwrap();
    let file = std::fs::read(file.path()).unwrap();
    let file = String::from_utf8(file).unwrap();
    insta::assert_snapshot!(file);

    // Download the actual file
    let download = reqwest::get(&format!(
        "http://127.0.0.1:{}/{}/file",
        free_port,
        body.trim_matches('"')
    ))
    .await
    .unwrap();

    let download = download.text().await.unwrap();
    insta::assert_snapshot!(download);

    // Wait for 5 + 5 + 1 second (5 seconds for the file to expire, 5 seconds for the book keeping interval, and 1 second for the server to process the expiry)
    tokio::time::sleep(std::time::Duration::from_secs(11)).await;

    // Ensure the file has been deleted.
    let files = std::fs::read_dir(temp_dir.path()).unwrap();
    assert!(files.count() == 0);

    // Ensure that anyone attempting to download the file now gets a 404
    let download = reqwest::get(&format!(
        "http://127.0.0.1:{}/{}/file",
        free_port,
        body.trim_matches('"')
    ))
    .await
    .unwrap();
    assert_eq!(download.status(), 404);
    insta::assert_snapshot!(download.text().await.unwrap());

    // Ensure that the download page now returns a 404
    let download = reqwest::get(&format!(
        "http://127.0.0.1:{}/{}",
        free_port,
        body.trim_matches('"')
    ))
    .await
    .unwrap();

    assert_eq!(download.status(), 404);
    insta::assert_snapshot!(download.text().await.unwrap());

    started_server.disarm();
}

#[rstest]
#[awt]
#[timeout(std::time::Duration::from_secs(30))]
#[tokio::test]
async fn test_that_nonces_expire(
    #[future] server_with_keys_initalised: (PrivateKey, tempfile::TempDir, u16, ServerInstance),
) {
    let (private_key, _, free_port, started_server) = server_with_keys_initalised;

    // Get a nonce
    let response = reqwest::get(&format!("http://127.0.0.1:{}/api/v1/nonce", free_port))
        .await
        .unwrap();

    let binding = response.text().await.unwrap();
    let signed_nonce = sign_and_encode_nonce(&binding, &private_key);

    // Wait for the nonce to expire
    tokio::time::sleep(std::time::Duration::from_secs(6)).await;

    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/api/v1/upload", free_port))
        .header("Authorization", format!("SshSig {}", signed_nonce))
        .multipart(
            reqwest::multipart::Form::new()
                .text("file_name", "hello.txt")
                .text("file_size", "17")
                .text("expiry_secs", "5")
                .file("file", tempfile::NamedTempFile::new().unwrap().path())
                .await
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    if response.status().as_u16() != 403 {
        panic!(
            "Expected a 403 response, got: {} with body: \n{}",
            response.status(),
            response.text().await.unwrap()
        );
    }
    insta::assert_snapshot!(response.text().await.unwrap());

    started_server.disarm();
}

#[rstest]
#[awt]
#[timeout(std::time::Duration::from_secs(30))]
#[tokio::test]
async fn test_that_large_files_get_rejected(
    #[future] server_with_keys_initalised: (PrivateKey, tempfile::TempDir, u16, ServerInstance),
) {
    let (private_key, _, free_port, started_server) = server_with_keys_initalised;

    // Create a large test file to upload
    let test_file = tempfile::NamedTempFile::new().unwrap();
    let large_content = vec![0_u8; 2 * 1024 * 1024]; // 2 MB file
    std::fs::write(test_file.path(), &large_content).unwrap();

    // Attempt to upload the large file
    // NOTE: the way hyper handles an early response from an upload is not perfect, and often
    // results in broken pipe errors on the clientside. I could not find a way to address this, so
    // adding retries makes this test much more reliable.
    const MAX_RETRIES: usize = 10;
    let mut num_retries = 0;
    let response = {
        loop {
            // Get a nonce
            let response = reqwest::get(&format!("http://127.0.0.1:{}/api/v1/nonce", free_port))
                .await
                .unwrap();

            let binding = response.text().await.unwrap();
            let signed_nonce = sign_and_encode_nonce(&binding, &private_key);

            let response = reqwest::Client::new()
                .post(format!("http://127.0.0.1:{}/api/v1/upload", free_port))
                .header("Authorization", format!("SshSig {}", signed_nonce))
                .multipart(
                    reqwest::multipart::Form::new()
                        .text("file_name", "large_file.txt")
                        // Lie about file size!
                        .text("file_size", "1")
                        .text("expiry_secs", "5")
                        .file("file", test_file.path())
                        .await
                        .unwrap(),
                )
                .send()
                .await;

            match response {
                Ok(response) => {
                    break response;
                }
                Err(e) => {
                    num_retries += 1;
                    eprintln!(
                        "Failed to upload file, retrying... Attempt: {}/{}",
                        num_retries, MAX_RETRIES
                    );
                    eprintln!("Got error: {}", e);
                    if num_retries >= MAX_RETRIES {
                        panic!("Failed to upload file after {} retries", MAX_RETRIES);
                    }
                }
            }
        }
    };

    let status = response.status();
    let body = response.text().await.unwrap();
    if status != 413 {
        panic!(
            "Expected a 413 response, got: {} with body: \n{}",
            status, body
        );
    }

    insta::assert_snapshot!(body);
    started_server.disarm();
}

#[rstest]
#[awt]
#[timeout(std::time::Duration::from_secs(30))]
#[tokio::test]
async fn test_that_many_files_cannot_exceed_max_size(
    #[future] server_with_keys_initalised: (PrivateKey, tempfile::TempDir, u16, ServerInstance),
) {
    let (private_key, _, free_port, started_server) = server_with_keys_initalised;

    let client = reqwest::Client::new();

    const FILE_SIZE: usize = 1024 * 1024; // 1 MB
    for i in 0..5 {
        // Get a nonce
        let response = reqwest::get(&format!("http://127.0.0.1:{}/api/v1/nonce", free_port))
            .await
            .unwrap();

        let binding = response.text().await.unwrap();
        let signed_nonce = sign_and_encode_nonce(&binding, &private_key);

        // Create a large test file to upload
        let test_file = tempfile::NamedTempFile::new().unwrap();

        let large_content = vec![0_u8; FILE_SIZE];
        std::fs::write(test_file.path(), &large_content).unwrap();

        // Attempt to upload the large file
        let response = client
            .post(format!("http://127.0.0.1:{}/api/v1/upload", free_port))
            .header("Authorization", format!("SshSig {}", signed_nonce))
            .multipart(
                reqwest::multipart::Form::new()
                    .text("file_name", "large_file.txt")
                    // Lie about file size
                    .text("file_size", "1")
                    .text("expiry_secs", "60")
                    .file("file", test_file.path())
                    .await
                    .unwrap(),
            )
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .unwrap();

        let status = response.status();
        let body = response.text().await.unwrap();
        if status != 200 {
            panic!("Failed to upload file [{i}/5]: {body}");
        }
    }

    // The next file - even if only 1 byte, should be rejected.
    // Get a nonce
    let response = reqwest::get(&format!("http://127.0.0.1:{}/api/v1/nonce", free_port))
        .await
        .unwrap();

    let binding = response.text().await.unwrap();
    let signed_nonce = sign_and_encode_nonce(&binding, &private_key);

    // Create a 1-byte file to upload.
    const SMALL_FILE_SIZE: usize = 1;
    let test_file = tempfile::NamedTempFile::new().unwrap();
    let content = vec![0_u8; SMALL_FILE_SIZE];
    std::fs::write(test_file.path(), &content).unwrap();

    // Attempt to upload the file
    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/api/v1/upload", free_port))
        .header("Authorization", format!("SshSig {}", signed_nonce))
        .multipart(
            reqwest::multipart::Form::new()
                .text("file_name", "small_file.txt")
                // Lie about file size
                .text("file_size", "1")
                .text("expiry_secs", "30")
                .file("file", test_file.path())
                .await
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    let status = response.status();
    let body = response.text().await.unwrap();
    if status != 413 {
        panic!(
            "Expected a 413 response, got: {} with body: \n{}",
            status, body
        );
    }
    insta::assert_snapshot!(body);

    started_server.disarm();
}

#[rstest]
#[awt]
#[timeout(std::time::Duration::from_secs(30))]
#[tokio::test]
async fn test_that_invalid_signing_key_fails(
    #[future] server_with_keys_initalised: (PrivateKey, tempfile::TempDir, u16, ServerInstance),
) {
    let (_, _, free_port, started_server) = server_with_keys_initalised;

    // Get a nonce
    let response = reqwest::get(&format!("http://127.0.0.1:{}/api/v1/nonce", free_port))
        .await
        .unwrap();

    let binding = response.text().await.unwrap();
    let signed_nonce = sign_and_encode_nonce(
        &binding,
        &PrivateKey::new(
            KeypairData::Ed25519(Ed25519Keypair::from_seed(&[1; 32])),
            "a static test key",
        )
        .unwrap(),
    );

    // Create a test file to upload
    let test_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(test_file.path(), "Hello, world 123!").unwrap();

    // Upload the file
    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/api/v1/upload", free_port))
        .header("Authorization", format!("SshSig {}", signed_nonce))
        .multipart(
            reqwest::multipart::Form::new()
                .text("file_name", "hello.txt")
                .text("file_size", "17")
                .text("expiry_secs", "5")
                .file("file", test_file.path())
                .await
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    let status = response.status();
    let body = response.text().await.unwrap();
    if status != 403 {
        panic!(
            "Expected a 403 response, got: {} with body: \n{}",
            status, body
        );
    }

    insta::assert_snapshot!(body);

    started_server.disarm();
}

#[rstest]
#[awt]
#[timeout(std::time::Duration::from_secs(30))]
#[tokio::test]
async fn test_that_missing_auth_fails(
    #[future] server_with_keys_initalised: (PrivateKey, tempfile::TempDir, u16, ServerInstance),
) {
    let (_, _, free_port, started_server) = server_with_keys_initalised;

    // Get a nonce
    let _ = reqwest::get(&format!("http://127.0.0.1:{}/api/v1/nonce", free_port))
        .await
        .unwrap();

    // Create a test file to upload
    let test_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(test_file.path(), "Hello, world 123!").unwrap();

    // Upload the file
    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/api/v1/upload", free_port))
        .multipart(
            reqwest::multipart::Form::new()
                .text("file_name", "hello.txt")
                .text("file_size", "17")
                .text("expiry_secs", "5")
                .file("file", test_file.path())
                .await
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    let status = response.status();
    let body = response.text().await.unwrap();
    if status != 400 {
        panic!(
            "Expected a 400 response, got: {} with body: \n{}",
            status, body
        );
    }

    insta::assert_snapshot!(body);

    started_server.disarm();
}

#[rstest]
#[awt]
#[timeout(std::time::Duration::from_secs(30))]
#[tokio::test]
async fn test_downloading_non_existent_file(
    #[future] server_with_keys_initalised: (PrivateKey, tempfile::TempDir, u16, ServerInstance),
) {
    let (_, _, free_port, started_server) = server_with_keys_initalised;

    // Attempt to download a non-existent file
    let response = reqwest::get(&format!("http://127.0.0.1:{}/non_existent_file", free_port))
        .await
        .unwrap();

    let status = response.status();
    let body = response.text().await.unwrap();
    if status != 400 {
        panic!(
            "Expected a 400 response, got: {} with body: \n{}",
            status, body
        );
    }
    insta::assert_snapshot!(body);

    // Attempt to download a non-existent file with a valid id

    // Try downloading the page
    let response = reqwest::get(&format!("http://127.0.0.1:{}/w33rwptc", free_port))
        .await
        .unwrap();

    let status = response.status();
    let body = response.text().await.unwrap();
    if status != 404 {
        panic!(
            "Expected a 404 response, got: {} with body: \n{}",
            status, body
        );
    }

    // Try downloading the file
    let response = reqwest::get(&format!("http://127.0.0.1:{}/w33rwptc/file", free_port))
        .await
        .unwrap();

    let status = response.status();
    let body = response.text().await.unwrap();
    if status != 404 {
        panic!(
            "Expected a 404 response, got: {} with body: \n{}",
            status, body
        );
    }

    started_server.disarm();
}

#[rstest]
#[awt]
#[timeout(std::time::Duration::from_secs(30))]
#[tokio::test]
async fn test_downloading_expired_file(
    #[future] server_with_keys_initalised: (PrivateKey, tempfile::TempDir, u16, ServerInstance),
) {
    let (private_key, temp_dir, free_port, started_server) = server_with_keys_initalised;

    // Get a nonce
    let response = reqwest::get(&format!("http://127.0.0.1:{}/api/v1/nonce", free_port))
        .await
        .unwrap();

    let binding = response.text().await.unwrap();
    let signed_nonce = sign_and_encode_nonce(&binding, &private_key);

    // Create a test file to upload
    let test_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(test_file.path(), "Hello, world 123!").unwrap();

    // Upload the file
    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/api/v1/upload", free_port))
        .header("Authorization", format!("SshSig {}", signed_nonce))
        .multipart(
            reqwest::multipart::Form::new()
                .text("file_name", "hello.txt")
                .text("file_size", "17")
                .text("expiry_secs", "5")
                .file("file", test_file.path())
                .await
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    let status = response.status();
    let body = response.text().await.unwrap();
    if !status.is_success() {
        panic!("Failed to upload file: {}", body);
    }

    // Ensure the file is a valid download
    let download = reqwest::get(&format!(
        "http://127.0.0.1:{}/{}",
        free_port,
        body.trim_matches('"')
    ))
    .await
    .unwrap();

    let download = download.text().await.unwrap();
    insta::assert_snapshot!(sanitise_snapshot(download));

    // Wait for 5 + 5 + 1 second (5 seconds for the file to expire, 5 seconds for the book keeping interval, and 1 second for the server to process the expiry)
    tokio::time::sleep(std::time::Duration::from_secs(11)).await;

    // Ensure the file has been deleted.
    let files = std::fs::read_dir(temp_dir.path()).unwrap();
    assert!(files.count() == 0);

    // Ensure that anyone attempting to download the file now gets a 404
    let download = reqwest::get(&format!(
        "http://127.0.0.1:{}/{}/file",
        free_port,
        body.trim_matches('"')
    ))
    .await
    .unwrap();

    assert_eq!(download.status(), 404);
    insta::assert_snapshot!(download.text().await.unwrap());

    started_server.disarm();
}

#[rstest]
#[awt]
#[timeout(std::time::Duration::from_secs(30))]
#[tokio::test]
async fn test_uploading_multiple_times(
    #[future] server_with_keys_initalised: (PrivateKey, tempfile::TempDir, u16, ServerInstance),
) {
    let (private_key, _, free_port, started_server) = server_with_keys_initalised;

    // Get a nonce
    let response = reqwest::get(&format!("http://127.0.0.1:{}/api/v1/nonce", free_port))
        .await
        .unwrap();

    let binding = response.text().await.unwrap();
    let signed_nonce = sign_and_encode_nonce(&binding, &private_key);

    // Create a test file to upload
    let test_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(test_file.path(), "Hello, world 123!").unwrap();

    // Upload the file
    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/api/v1/upload", free_port))
        .header("Authorization", format!("SshSig {}", signed_nonce))
        .multipart(
            reqwest::multipart::Form::new()
                .text("file_name", "hello.txt")
                .text("file_size", "17")
                .text("expiry_secs", "5")
                .file("file", test_file.path())
                .await
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    let status = response.status();
    let body = response.text().await.unwrap();
    if !status.is_success() {
        panic!("Failed to upload file: {}", body);
    }

    // Upload the file again
    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/api/v1/upload", free_port))
        .header("Authorization", format!("SshSig {}", signed_nonce))
        .multipart(
            reqwest::multipart::Form::new()
                .text("file_name", "hello.txt")
                .text("file_size", "17")
                .text("expiry_secs", "5")
                .file("file", test_file.path())
                .await
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    let status = response.status();
    let body = response.text().await.unwrap();
    if status != 403 {
        panic!(
            "Expected a 403 response, got: {} with body: \n{}",
            status, body
        );
    }

    insta::assert_snapshot!(body);

    started_server.disarm();
}

#[rstest]
#[awt]
#[timeout(std::time::Duration::from_secs(30))]
#[tokio::test]
async fn test_downloading_multiple_times(
    #[future] server_with_keys_initalised: (PrivateKey, tempfile::TempDir, u16, ServerInstance),
) {
    let (private_key, _, free_port, started_server) = server_with_keys_initalised;

    // Get a nonce
    let response = reqwest::get(&format!("http://127.0.0.1:{}/api/v1/nonce", free_port))
        .await
        .unwrap();

    let binding = response.text().await.unwrap();
    let signed_nonce = sign_and_encode_nonce(&binding, &private_key);

    // Create a test file to upload
    let test_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(test_file.path(), "Hello, world 123!").unwrap();

    // Upload the file
    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/api/v1/upload", free_port))
        .header("Authorization", format!("SshSig {}", signed_nonce))
        .multipart(
            reqwest::multipart::Form::new()
                .text("file_name", "hello.txt")
                .text("file_size", "17")
                .text("expiry_secs", "5")
                .file("file", test_file.path())
                .await
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    let status = response.status();
    let body = response.text().await.unwrap();
    if !status.is_success() {
        panic!("Failed to upload file: {}", body);
    }

    // Download the file multiple times
    for _ in 0..5 {
        let download = reqwest::get(&format!(
            "http://127.0.0.1:{}/{}",
            free_port,
            body.trim_matches('"')
        ))
        .await
        .unwrap();

        let download = download.text().await.unwrap();
        insta::assert_snapshot!(sanitise_snapshot(download));

        // Download the actual file
        let download = reqwest::get(&format!(
            "http://127.0.0.1:{}/{}/file",
            free_port,
            body.trim_matches('"')
        ))
        .await
        .unwrap();

        let status = download.status();
        let download = download.text().await.unwrap();
        if !status.is_success() {
            panic!("Failed to download file: {}", download);
        }

        insta::assert_snapshot!(download);
    }

    started_server.disarm();
}

#[rstest]
#[awt]
#[timeout(std::time::Duration::from_secs(30))]
#[tokio::test]
async fn test_uploading_file_with_zero_bytes_len(
    #[future] server_with_keys_initalised: (PrivateKey, tempfile::TempDir, u16, ServerInstance),
) {
    let (private_key, _, free_port, started_server) = server_with_keys_initalised;

    // Get a nonce
    let response = reqwest::get(&format!("http://127.0.0.1:{}/api/v1/nonce", free_port))
        .await
        .unwrap();

    let binding = response.text().await.unwrap();
    let signed_nonce = sign_and_encode_nonce(&binding, &private_key);

    // Create a test file to upload
    let test_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(test_file.path(), "").unwrap();

    // Upload the file
    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/api/v1/upload", free_port))
        .header("Authorization", format!("SshSig {}", signed_nonce))
        .multipart(
            reqwest::multipart::Form::new()
                .text("file_name", "hello.txt")
                .text("file_size", "1") // Claim to be uploading a 1 byte file
                .text("expiry_secs", "5")
                .file("file", test_file.path())
                .await
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    let status = response.status();
    let body = response.text().await.unwrap();

    if status != 400 {
        panic!(
            "Expected a 400 response, got: {} with body: \n{}",
            status, body
        );
    }

    insta::assert_snapshot!(body);

    started_server.disarm();
}

#[rstest]
#[awt]
#[timeout(std::time::Duration::from_secs(30))]
#[tokio::test]
async fn test_setting_expiry_too_high_fails(
    #[future] server_with_keys_initalised: (PrivateKey, tempfile::TempDir, u16, ServerInstance),
) {
    let (private_key, _, free_port, started_server) = server_with_keys_initalised;

    // Get a nonce
    let response = reqwest::get(&format!("http://127.0.0.1:{}/api/v1/nonce", free_port))
        .await
        .unwrap();

    let binding = response.text().await.unwrap();
    let signed_nonce = sign_and_encode_nonce(&binding, &private_key);

    // Create a test file to upload
    let test_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(test_file.path(), "Hello, world 123!").unwrap();

    // Upload the file
    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/api/v1/upload", free_port))
        .header("Authorization", format!("SshSig {}", signed_nonce))
        .multipart(
            reqwest::multipart::Form::new()
                .text("file_name", "hello.txt")
                .text("file_size", "17")
                .text("expiry_secs", ((60 * 60 * 24) + 1).to_string()) // 1 day + 1 second
                .file("file", test_file.path())
                .await
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    let status = response.status();
    let body = response.text().await.unwrap();

    if status != 400 {
        panic!(
            "Expected a 400 response, got: {} with body: \n{}",
            status, body
        );
    }

    insta::assert_snapshot!(body);

    started_server.disarm();
}

#[rstest]
#[awt]
#[timeout(std::time::Duration::from_secs(30))]
#[tokio::test]
async fn test_that_ratelimiting_works(
    #[future] server_with_keys_initalised: (PrivateKey, tempfile::TempDir, u16, ServerInstance),
) {
    let (_, _, free_port, started_server) = server_with_keys_initalised;

    // We should be able to make up to 20 requests, then the 21st should fail.
    for _ in 0..20 {
        // Get a nonce
        let response = reqwest::get(&format!("http://127.0.0.1:{}/api/v1/nonce", free_port))
            .await
            .unwrap();

        let status = response.status();
        let body = response.text().await.unwrap();
        if !status.is_success() {
            panic!("Failed to get nonce: {}", body);
        }
    }

    // 21st should fail
    let response = reqwest::get(&format!("http://127.0.0.1:{}/api/v1/nonce", free_port))
        .await
        .unwrap();

    let status = response.status();
    let retry_after_header = response.headers().get("retry-after").cloned();
    let body = response.text().await.unwrap();
    if status != 429 {
        panic!(
            "Expected a 429 response, got: {} with body: \n{}",
            status, body
        );
    }

    // Remove any digits from the response.
    let body = regex::Regex::new(r"\d+")
        .unwrap()
        .replace_all(&body, "REMOVED");

    insta::assert_snapshot!(body);

    // wait for the ratelimit to expire
    let retry_after_header = retry_after_header.unwrap();
    let retry_after_header = retry_after_header.to_str().unwrap();
    let retry_after_header = retry_after_header.parse::<u64>().unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(retry_after_header + 1)).await;

    // 7th should succeed
    let response = reqwest::get(&format!("http://127.0.0.1:{}/api/v1/nonce", free_port))
        .await
        .unwrap();

    let status = response.status();
    let body = response.text().await.unwrap();
    if !status.is_success() {
        panic!("Failed to get nonce: {}", body);
    }

    started_server.disarm();
}

/// In download.hbs we link to some static files hosted by someone else. these must always be live -
/// otherwise we want to fail the test suite so we know to update the files.
/// Simple regression test.
#[tokio::test]
async fn test_that_static_urls_resolve() {
    let links = vec![
        "https://cdn.jsdelivr.net/npm/simple-icons/icons/linkedin.svg",
        "https://cdn.jsdelivr.net/npm/simple-icons/icons/github.svg",
    ];

    let client = reqwest::Client::new();
    for link in links {
        let link: reqwest::Url = link.parse().unwrap();
        let response = client.get(link.clone()).send().await.unwrap();
        assert_eq!(response.status(), 200);

        // snapshot using insta
        let bytes = response.text().await.unwrap();
        insta::assert_snapshot!(
            format!(
                "{}-{}",
                link.host_str().unwrap(),
                link.path_segments().unwrap().last().unwrap()
            ),
            bytes
        );
    }
}
