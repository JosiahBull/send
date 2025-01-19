#![doc = include_str!("../README.md")]

mod auth;
mod build_info;
mod config;
mod error;
mod extractors;
mod template;
mod tracing_config;
mod unique_ids;
mod uploads;

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{self, State},
    response::{Html, IntoResponse},
    routing::{any, get, post},
    Json, Router,
};
use axum_extra::{headers, TypedHeader};
use axum_tracing_opentelemetry::middleware::{OtelAxumLayer, OtelInResponseLayer};
use error::{ServerError, ServerResult};
use futures::TryStreamExt;
use reqwest::{
    header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE, EXPIRES},
    Url,
};
use template::DownloadPageFields;
use tower_http::compression::CompressionLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use unique_ids::UploadId;

/// Global state shared for all requests.
#[derive(Debug, Clone)]
pub struct AppState {
    /// AUthentication service which relies on ssh keys.
    github_keys: Arc<auth::GithubKeys>,
    /// Upload manager for abstracing file uploads/downloads.
    uploads: Arc<uploads::Uploads>,
    /// A templating engine for server-side rendering.
    templates: Arc<template::Templates>,
    /// What url the service is being hosted at, e.g. `https://www.uploads.google.com/`. Should be a
    /// full URL including the `https`, `www` and a trailing slash.
    url_base: Url,
}

// Handlers
#[tracing::instrument(skip(state))]
#[axum::debug_handler]
async fn get_nonce(State(state): State<AppState>) -> axum::Json<String> {
    let nonce = state.github_keys.generate_nonce().await;
    axum::Json(nonce)
}

#[tracing::instrument(skip(state))]
#[axum::debug_handler]
async fn upload(
    State(state): State<AppState>,
    TypedHeader(headers::Authorization(token)): TypedHeader<
        headers::Authorization<auth::AuthenticatedUpload>,
    >,
    mut upload_fields: extractors::UploadFields,
) -> ServerResult<Json<UploadId>> {
    let username = match state
        .github_keys
        .get_user(token.nonce(), token.signature())
        .await
    {
        Some(username) => username,
        None => return Err(ServerError::Unauthorized),
    };

    let key = state
        .uploads
        .preflight_upload()
        .uploader_username(username)
        .file_name(upload_fields.file_name)
        .file_size(upload_fields.file_size as i64)
        .expiry(upload_fields.expiry)
        .call()
        .await?;

    let field = extractors::extract_field(&mut upload_fields.multipart, "file").await?;

    let s = field.into_stream().map_err(ServerError::from);

    state
        .uploads
        // XXX: don't have to clone here, or could make this into a cheap clone by making Key Copy via a byte slice.
        .upload(key.clone(), upload_fields.file_size, s)
        .await?;

    Ok(Json(key))
}

/// Begin the download process for a given file.
#[tracing::instrument(skip(state))]
#[axum::debug_handler]
async fn download_stream(
    State(state): State<AppState>,
    upload_id: extract::Path<UploadId>,
) -> ServerResult<impl IntoResponse> {
    let upload_id = upload_id.0;
    let (upload, stream) = state.uploads.download(upload_id).await?;

    let headers = [
        (CONTENT_TYPE, "application/octet-stream".to_string()),
        (CONTENT_LENGTH, upload.file_size.to_string()),
        (
            CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", upload.file_name),
        ),
        (
            CACHE_CONTROL,
            "no-store, no-cache, max-age=0, must-revalidate".to_string(),
        ),
        (EXPIRES, "0".to_string()),
    ];

    Ok((headers, Body::from_stream(stream)))
}

/// Get the HTML for a given download page.
async fn download_html(
    State(state): State<AppState>,
    extract::Path(upload_id): extract::Path<UploadId>,
) -> ServerResult<impl IntoResponse> {
    let upload = state.uploads.info(upload_id.clone()).await?;

    let download_url = state
        .url_base
        .join(&format!("{}/", upload_id))
        .expect("upload_id was not URL safe")
        .join("file")
        .expect("Failed to join URL");

    let fields = DownloadPageFields {
        file_name: upload.file_name.clone(),
        username_source_url: "https://www.github.com/josiahbull"
            .to_string()
            .parse()
            .expect("msg"), // TODO
        username: upload.uploader_username.clone(),
        download_url,
        upload_date: upload.created_at,
        expiry_date: upload.expires_at,
        file_size_bytes: (upload.file_size as u64)
            .try_into()
            .expect("to be non-zero"),
        base_url: state.url_base,
    };

    let html = state.templates.render_download_page(fields);

    let html = Html(html);
    let headers = [
        (CONTENT_TYPE, "text/html".to_string()),
        (CACHE_CONTROL, "private".to_string()),
        (
            CACHE_CONTROL,
            format!(
                "max-age={}",
                upload
                    .expires_at
                    .signed_duration_since(chrono::Utc::now())
                    .checked_sub(&chrono::Duration::seconds(10))
                    .unwrap_or_else(|| chrono::Duration::seconds(0))
                    .num_seconds()
                    .max(0)
            ),
        ),
        (EXPIRES, upload.expires_at.to_rfc2822()),
    ];
    Ok((headers, html))
}

/// Returns a 404 static HTML response.
async fn static_404() -> axum::http::Response<Body> {
    /// The static 404 response bytes.
    const RESPONSE_BYTES: &[u8] = include_bytes!("../static/404.html");

    // build a resposne from the bytes and headers, with 404 status.
    axum::http::Response::builder()
        .status(axum::http::StatusCode::NOT_FOUND)
        .header("Content-Type", "text/html")
        .header("Cache-Control", "public, max-age=1800, must-revalidate") // 30 minutes
        .body(RESPONSE_BYTES.into())
        .expect("Failed to create response")
}

/// Returns a static robots.txt response.
async fn static_robots_txt() -> axum::http::Response<Body> {
    /// The static robots.txt response bytes.
    const RESPONSE_BYTES: &str = "User-agent: *\nDisallow: /";

    // build a resposne from the bytes and headers.
    axum::http::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header("Content-Type", "text/plain")
        .header("Cache-Control", "public, max-age=604800, must-revalidate") // 1 week
        .header("Expires", "604800")
        .body(RESPONSE_BYTES.into())
        .expect("Failed to create response")
}

/// Constructs a static response at compile time from constant data. Useful for embedding static
/// files into the binary at compile time.
const fn build_response_for_static_file(
    data: &'static [u8],
    content_type: &'static str,
) -> impl IntoResponse {
    (
        [
            (axum::http::header::CONTENT_TYPE, content_type),
            (
                axum::http::header::CACHE_CONTROL,
                "public, max-age=604800, must-revalidate",
            ),
            (axum::http::header::EXPIRES, "604800"),
        ],
        data,
    )
}

pub fn router(app_state: AppState) -> Router {
    Router::new()
        // TODO: setup rate limiting.
        // TODO: setup logging.
        .nest("/api", {
            Router::new()
                .route("/health", get(|| async { "OK" }))
                .nest("/v1", {
                    Router::new()
                        .route("/nonce", get(get_nonce))
                        .route("/upload", post(upload))
                })
        })
        // Download Routes
        .route("/:upload_id", get(download_html))
        .route("/:upload_id/file", get(download_stream))
        // Homepage
        .route(
            "/",
            get(|| async {
                build_response_for_static_file(include_bytes!("../static/index.html"), "text/html")
            }),
        )
        // Static Resources
        .route("/robots.txt", get(static_robots_txt))
        .route(
            "/favicon.ico",
            get(|| async {
                build_response_for_static_file(
                    include_bytes!("../static/favicon.ico"),
                    "image/x-icon",
                )
            }),
        )
        // .route("/favicon-16x16.png", get(|| async { build_response_for_static_file(include_bytes!("../static/favicon-16x16.png"), "image/png") }))
        // .route("/favicon-32x32.png", get(|| async { build_response_for_static_file(include_bytes!("../static/favicon-32x32.png"), "image/png") }))
        // .route("/favicon-96x96.png", get(|| async { build_response_for_static_file(include_bytes!("../static/favicon-96x96.png"), "image/png") }))
        // .route("/favicon-192x192.png", get(|| async { build_response_for_static_file(include_bytes!("../static/favicon-192x192.png"), "image/png") }))
        // .route("/apple-touch-icon.png", get(|| async { build_response_for_static_file(include_bytes!("../static/apple-touch-icon.png"), "image/png") }))
        .route(
            "/styles.css",
            get(|| async {
                build_response_for_static_file(include_bytes!("../static/styles.css"), "text/css")
            }),
        )
        // Fallback handlers
        .route("/404", get(static_404))
        .fallback(
            // Redirect to /404
            any(|| async {
                axum::http::Response::builder()
                    .status(axum::http::StatusCode::FOUND)
                    .header(axum::http::header::LOCATION, "/404")
                    .body(Body::empty())
                    .expect("Failed to create response")
            }),
        )
        // State and middleware
        .with_state(app_state)
        // include trace context as header into the response
        // .layer(OtelInResponseLayer::default())
        // start OpenTelemetry trace on incoming request
        // as long as not filtered out!
        // .layer(OtelAxumLayer::default())
        // .layer(
        //     tower_otel_http_metrics::HTTPMetricsLayerBuilder::new()
        //         .with_meter(opentelemetry::global::meter(env!("CARGO_CRATE_NAME")))
        //         .build()
        //         .expect("Failed to build otel metrics layer"),
        // )
        .layer(
            CompressionLayer::new()
                .br(true)
                .gzip(true)
                .no_deflate()
                .no_zstd(),
        )
}

#[tokio::main]
async fn main() {
    let build_info = build_info::BuildInfo::get_buildinfo();
    println!("{}", build_info);

    // XXX: move this into a similar info module.
    let runtime = tokio::runtime::Handle::current();
    let num_threads = runtime.metrics().num_workers();
    println!("Number of threads: {}\n", num_threads);

    let env = std::env::vars().collect::<std::collections::HashMap<_, _>>();
    let config = config::Config::from_env(&env).expect("Failed to load config");

    println!("{:#?}", config);

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let db_pool = sqlx::SqlitePool::connect(&config.database.url)
        .await
        .unwrap_or_else(|_| panic!("Failed to connect to database at {}", &config.database.url));

    database::migrate(&db_pool)
        .await
        .expect("Failed to migrate database");

    let github_keys = {
        let sources_to_check = config
            .auth
            .auth_keys
            .clone()
            .into_iter()
            .map(|(url, username)| auth::KeySource { url, username })
            .collect();

        let auth = auth::GithubKeys::builder()
            .sources_to_check(sources_to_check)
            .key_refresh_interval(config.auth.key_refresh_interval)
            .max_number_of_keys(config.auth.max_number_of_keys_per_user)
            .max_time_allowed_since_refresh(config.auth.max_time_allowed_since_refresh)
            .nonce_time_to_live(config.auth.nonce_max_time_to_live)
            .build();

        Arc::new(auth)
    };

    let uploads = async {
        let uploads = uploads::Uploads::builder()
            .db_pool(db_pool.clone())
            .cache_directory(config.upload.cache_directory)
            .max_allowed_cache_size(config.upload.max_cache_size_bytes)
            .max_allowed_file_size(config.upload.max_file_size_bytes)
            .min_time_to_live(config.upload.min_file_time_to_live)
            .max_time_to_live(config.upload.max_file_time_to_live)
            .bookkeeping_interval(config.upload.book_keeping_interval)
            .build()
            .await
            .expect("Failed to create uploads manager");

        Arc::new(uploads)
    }
    .await;

    let templates = Arc::new(template::Templates::new());

    let app_state = AppState {
        github_keys,
        uploads,
        templates,
        url_base: config.server.domain,
    };

    let app = router(app_state.clone());

    let listener =
        tokio::net::TcpListener::bind(format!("{}:{}", config.server.host, config.server.port))
            .await
            .expect("Failed to bind to port");

    tracing::info!(
        "Listening on {}",
        listener.local_addr().expect("Failed to bind to port")
    );

    #[allow(clippy::redundant_pub_crate, reason = "false positive in macro")]
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("Failed to listen for SIGTERM");
            let mut sigint =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                    .expect("Failed to listen for SIGINT");

            tokio::select! {
                _ = sigint.recv() => {},
                _ = sigterm.recv() => {},
            }
        })
        .await
        .expect("Failed to start server");

    // Attempt to gracefully shutdown all subcomponents on the server.
    let AppState {
        github_keys,
        uploads,
        templates: _,
        url_base: _,
    } = app_state;

    // Both should have 1 strong reference left, so we can safely drop them here.
    tracing::info!("Getting strong ref to github_keys and uploads");
    let (github_keys, uploads) = {
        const MAX_TIME_TO_WAIT: std::time::Duration = std::time::Duration::from_secs(5);
        let now = std::time::Instant::now();
        loop {
            if Arc::strong_count(&github_keys) == 1 && Arc::strong_count(&uploads) == 1 {
                let github_keys =
                    Arc::try_unwrap(github_keys).expect("Failed to unwrap github_keys");
                let uploads = Arc::try_unwrap(uploads).expect("Failed to unwrap uploads");
                break (github_keys, uploads);
            }
            tracing::debug!("Waiting for github_keys and uploads to be dropped");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            if now.elapsed() > MAX_TIME_TO_WAIT {
                panic!("Failed to unwrap github_keys and uploads in time");
            }
        }
    };

    tracing::info!("Shutting down subcomponents");
    tokio::try_join!(
        github_keys.gracefully_shutdown(),
        uploads.gracefully_shutdown()
    )
    .expect("Failed to gracefully shutdown subcomponents");

    // Flush the database connection and close it gracefully.
    tracing::info!("Shutting down database connection");
    db_pool.close().await;

    // Count the number of active threads left on the tokio runtime.
    let runtime = tokio::runtime::Handle::current();
    let now = std::time::Instant::now();
    while runtime.metrics().num_alive_tasks() > 0 {
        tracing::debug!(
            num_tasks = runtime.metrics().num_alive_tasks(),
            time_elapsed = ?now.elapsed(),
            "Waiting for all tasks to finish");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if now.elapsed() > std::time::Duration::from_secs(5) {
            panic!("Failed to wait for all tasks to finish in time");
        }
    }

    tracing::info!("Server shutdown");
}
