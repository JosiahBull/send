#![doc = include_str!("../README.md")]

mod auth;
mod error;
mod template;
mod tracing_config;
mod unique_ids;
mod uploads;

use std::{path::PathBuf, sync::Arc};

use anyhow::Context;
use auth::KeySource;
use axum::{
    body::Body,
    extract::{self, State},
    response::{Html, IntoResponse},
    routing::{any, get, post},
    Json, Router,
};
use axum_extra::{headers, TypedHeader};
use error::{ServerError, ServerResult};
use reqwest::{
    header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE, EXPIRES},
    Url,
};
use template::DownloadPageFields;
use tower_http::compression::CompressionLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use unique_ids::UploadId;

use axum_tracing_opentelemetry::middleware::{OtelAxumLayer, OtelInResponseLayer};

/// Global state shared for all requests.
#[derive(Debug, Clone)]
pub struct AppState {
    /// Database used for persistence, typically sqlite.
    db_pool: sqlx::SqlitePool,
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
    mut multipart: extract::Multipart,
) -> ServerResult<Json<UploadId>> {
    let username = match state
        .github_keys
        .get_user(token.nonce(), token.signature())
        .await
    {
        Some(username) => username,
        None => return Err(ServerError::Unauthorized),
    };

    // Extract the fields from the first 3 parts of the multi part.
    let (file_name, file_size, expiry) = {
        let mut file_name = None;
        let mut file_size = None;
        let mut expiry_secs = None;

        for _ in 0..3 {
            let field = multipart
                .next_field()
                .await?
                .ok_or_else(|| ServerError::BadRequest {
                    reason: "Missing field".to_string(),
                })?;

            let name = field.name().ok_or_else(|| ServerError::BadRequest {
                reason: "Missing field name".to_string(),
            })?;

            match name {
                "file_name" => file_name = Some(field.text().await.map_err(ServerError::from)?),
                "file_size" => file_size = Some(field.text().await.map_err(ServerError::from)?),
                "expiry_secs" => expiry_secs = Some(field.text().await.map_err(ServerError::from)?),
                n => {
                    return Err(ServerError::BadRequest {
                        reason: format!("Unknown field: {}", n),
                    })
                }
            }
        }

        let file_name = file_name.ok_or_else(|| ServerError::BadRequest {
            reason: "Missing 'file_name' field".to_string(),
        })?;
        let file_size = file_size
            .ok_or_else(|| ServerError::BadRequest {
                reason: "Missing 'file_size' field".to_string(),
            })?
            .parse()?;
        let expiry_secs: u64 = expiry_secs
            .ok_or_else(|| ServerError::BadRequest {
                reason: "Missing 'expiry_secs' field".to_string(),
            })?
            .parse()?;

        let expiry = std::time::Duration::from_secs(expiry_secs);

        (file_name, file_size, expiry)
    };

    let key = state
        .uploads
        .preflight_upload(username, file_name, file_size, expiry)
        .await?;

    let mut field = {
        let field = match multipart.next_field().await? {
            Some(field) => field,
            None => {
                return Err(ServerError::BadRequest {
                    reason: "Missing 'file' field".to_string(),
                })
            }
        };

        if field.name().ok_or_else(|| ServerError::BadRequest {
            reason: "Missing 'file' field name".to_string(),
        })? != "file"
        {
            return Err(ServerError::BadRequest {
                reason: "Invalid 'file' field name".to_string(),
            });
        }

        field
    };

    let s = async_stream::stream! {
        while let Some(chunk) = field
            .chunk()
            .await
            .context("Failed to read chunk")?
        {
            yield Ok(chunk.to_vec()); // TODO: this should use bytes::Bytes throughout
        }
    };
    let s = Box::pin(s);

    state
        .uploads
        .upload(key.clone(), s) // XXX: don't have to clone here -> see recent article
        .await
        .context("Failed to upload file")
        .unwrap();

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
        .layer(OtelInResponseLayer::default())
        // start OpenTelemetry trace on incoming request
        // as long as not filtered out!
        .layer(OtelAxumLayer::default())
        .layer(
            tower_otel_http_metrics::HTTPMetricsLayerBuilder::new()
                .with_meter(opentelemetry::global::meter(env!("CARGO_CRATE_NAME")))
                .build()
                .expect("Failed to build otel metrics layer"),
        )
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
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let db_path = "/Users/josiahbull/Documents/send/test.db";

    let db_pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db_path))
        .await
        .unwrap();

    let github_keys = Arc::new(auth::GithubKeys::new(vec![KeySource {
        url: "https://github.com/josiahbull.keys".parse().unwrap(),
        username: "josiahbull".to_owned(),
    }]));

    let uploads = Arc::new(
        uploads::Uploads::new(db_pool.clone(), PathBuf::from("./cache"))
            .await
            .unwrap(),
    );

    let templates = Arc::new(template::Templates::new());

    let app_state = AppState {
        db_pool,
        github_keys,
        uploads,
        templates,
        url_base: Url::parse("http://127.0.0.1:3000/").unwrap(),
    };

    let app = router(app_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();

    tracing::info!("Listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.unwrap();
        })
        .await
        .unwrap();

    tracing::info!("Server shutdown");
}
