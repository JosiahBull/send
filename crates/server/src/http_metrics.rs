/// Tower middleware that records HTTP server metrics using OpenTelemetry 0.31.
///
/// Replaces `tower-otel-http-metrics` to avoid pinning an older OpenTelemetry version.
///
/// Records:
/// - `http.server.request.duration` (seconds)
/// - `http.server.request.body.size` (bytes)
/// - `http.server.response.body.size` (bytes)
/// - `http.server.active_requests` (gauge)
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

use axum::{extract::MatchedPath, http};
use http::{Request, Response, Version};
use opentelemetry::{
    KeyValue,
    metrics::{Histogram, Meter, UpDownCounter},
};
use tower::{Layer, Service};

/// Shared state holding all metric instruments.
#[derive(Clone)]
struct Instruments {
    /// Histogram for request duration in seconds.
    request_duration: Histogram<f64>,
    /// Histogram for request body size in bytes.
    request_body_size: Histogram<u64>,
    /// Histogram for response body size in bytes.
    response_body_size: Histogram<u64>,
    /// Gauge tracking the number of in-flight requests.
    active_requests: UpDownCounter<i64>,
}

impl Instruments {
    /// Create instruments from the given [`Meter`].
    fn new(meter: &Meter) -> Self {
        Self {
            request_duration: meter
                .f64_histogram("http.server.request.duration")
                .with_description("Duration of HTTP server requests.")
                .with_unit("s")
                .build(),
            request_body_size: meter
                .u64_histogram("http.server.request.body.size")
                .with_description("Size of HTTP server request bodies.")
                .with_unit("By")
                .build(),
            response_body_size: meter
                .u64_histogram("http.server.response.body.size")
                .with_description("Size of HTTP server response bodies.")
                .with_unit("By")
                .build(),
            active_requests: meter
                .i64_up_down_counter("http.server.active_requests")
                .with_description("Number of active HTTP server requests.")
                .with_unit("{request}")
                .build(),
        }
    }
}

/// Tower [`Layer`] that adds HTTP metrics collection.
#[derive(Clone)]
pub struct HttpMetricsLayer {
    /// Shared metric instruments.
    instruments: Instruments,
}

impl HttpMetricsLayer {
    /// Create a new layer that records HTTP metrics using the given [`Meter`].
    pub fn new(meter: &Meter) -> Self {
        Self {
            instruments: Instruments::new(meter),
        }
    }
}

impl<S> Layer<S> for HttpMetricsLayer {
    type Service = HttpMetricsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpMetricsService {
            inner,
            instruments: self.instruments.clone(),
        }
    }
}

/// Tower [`Service`] wrapper that records HTTP metrics.
#[derive(Clone)]
pub struct HttpMetricsService<S> {
    /// The wrapped inner service.
    inner: S,
    /// Shared metric instruments.
    instruments: Instruments,
}

/// Map an HTTP [`Version`] to the protocol version string used in OTel attributes.
const fn protocol_version(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "0.9",
        Version::HTTP_10 => "1.0",
        Version::HTTP_11 => "1.1",
        Version::HTTP_2 => "2.0",
        Version::HTTP_3 => "3.0",
        _ => "unknown",
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for HttpMetricsService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    ResBody: axum::body::HttpBody,
    ReqBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let start = Instant::now();
        let instruments = self.instruments.clone();

        let method = req.method().as_str().to_owned();
        let version = req.version();
        let scheme = req.uri().scheme_str().unwrap_or("http").to_owned();
        let route = req
            .extensions()
            .get::<MatchedPath>()
            .map(|p| p.as_str().to_owned());
        let req_body_size = req
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let active_attrs = vec![
            KeyValue::new("url.scheme", scheme.clone()),
            KeyValue::new("http.request.method", method.clone()),
        ];
        instruments.active_requests.add(1, &active_attrs);

        let mut inner = self.inner.clone();
        Box::pin(async move {
            let result = inner.call(req).await;
            instruments.active_requests.add(-1, &active_attrs);

            match &result {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let res_body_size = response.body().size_hint().exact();

                    let mut attrs = vec![
                        KeyValue::new("network.protocol.name", "http"),
                        KeyValue::new("network.protocol.version", protocol_version(version)),
                        KeyValue::new("url.scheme", scheme),
                        KeyValue::new("http.request.method", method),
                        KeyValue::new("http.response.status_code", i64::from(status)),
                    ];
                    if let Some(route) = route {
                        attrs.push(KeyValue::new("http.route", route));
                    }

                    instruments
                        .request_duration
                        .record(start.elapsed().as_secs_f64(), &attrs);

                    if let Some(size) = req_body_size {
                        instruments.request_body_size.record(size, &attrs);
                    }
                    if let Some(size) = res_body_size {
                        instruments.response_body_size.record(size, &attrs);
                    }
                }
                Err(_) => {
                    // On service error, still record duration so we don't lose the datapoint.
                    let attrs = vec![
                        KeyValue::new("network.protocol.name", "http"),
                        KeyValue::new("network.protocol.version", protocol_version(version)),
                        KeyValue::new("url.scheme", scheme),
                        KeyValue::new("http.request.method", method),
                    ];
                    instruments
                        .request_duration
                        .record(start.elapsed().as_secs_f64(), &attrs);
                }
            }

            result
        })
    }
}
