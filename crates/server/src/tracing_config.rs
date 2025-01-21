//! Tracing configuration, prometheus metrics, and other observaility configuration and testing is
//! handled here.

use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::{LogExporter, WithExportConfig};
use opentelemetry_sdk::logs::LoggerProvider;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Layer;

use crate::error::ServerResult;

/// Initialize the meter provider for metrics.
fn init_meter_provider(
) -> Result<opentelemetry_sdk::metrics::SdkMeterProvider, opentelemetry_sdk::metrics::MetricError> {
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_timeout(std::time::Duration::from_secs(10))
        .build()?;

    let reader = PeriodicReader::builder(exporter, opentelemetry_sdk::runtime::Tokio).build();

    let provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(opentelemetry_sdk::Resource::default())
        .with_resource(opentelemetry_sdk::Resource::new(vec![
            opentelemetry::KeyValue::new("service.name", env!("CARGO_PKG_NAME")),
        ]))
        .build();

    opentelemetry::global::set_meter_provider(provider.clone());

    Ok(provider)
}

/// Initialize the logger provider for logs.
fn init_logger_provider() -> ServerResult<opentelemetry_sdk::logs::LoggerProvider> {
    // Note Opentelemetry does not provide a global API to manage the logger provider.
    let exporter = LogExporter::builder().with_tonic().build()?;

    let provider = LoggerProvider::builder()
        .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
        .build();

    Ok(provider)
}

/// Initialize the tracing layer.
pub fn init_tracing() -> (opentelemetry_sdk::metrics::SdkMeterProvider, opentelemetry_sdk::trace::TracerProvider){
    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());

    // Metrics
    let meter_provider = init_meter_provider().expect("Failed to create meter provider");
    let opentelemetry_metrics_layer = tracing_opentelemetry::MetricsLayer::new(meter_provider.clone());

    // Tracing
    // Uses OTEL_EXPORTER_OTLP_TRACES_ENDPOINT
    // Assumes a GRPC endpoint (e.g port 4317)
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .build()
        .expect("Failed to create OTLP exporter");

    let tracer_provider = opentelemetry_sdk::trace::TracerProvider::builder()
        .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
        //.with_resource(opentelemetry_sdk::Resource::default())
        .build();

    // Explicitly set the tracer provider globally
    opentelemetry::global::set_tracer_provider(tracer_provider.clone());

    // Filter the tracing layer - we can add custom filters that only impact the tracing layer
    let tracing_level_filter = tracing_subscriber::filter::Targets::new()
        .with_target(env!("CARGO_PKG_NAME"), tracing::Level::TRACE)
        .with_target("sqlx", tracing::Level::TRACE)
        .with_target("tower_http", tracing::Level::TRACE)
        .with_target("hyper_util", tracing::Level::TRACE)
        .with_target("h2", tracing::Level::TRACE)
        // Note an optional feature flag crate sets this most important trace from tracing to info level
        .with_target("otel::tracing", tracing::Level::TRACE)
        .with_default(tracing::Level::TRACE);

    // turn our OTLP pipeline into a tracing layer
    let tracing_opentelemetry_layer = tracing_opentelemetry::layer()
        .with_tracer(tracer_provider.tracer(env!("CARGO_PKG_NAME")))
        .with_filter(tracing_level_filter);

    // Configure the stdout fmt layer
    let format = tracing_subscriber::fmt::format()
        .with_level(true)
        .with_target(true)
        .with_thread_ids(false)
        .with_thread_names(false)
        .compact();

    let fmt_layer = tracing_subscriber::fmt::layer().event_format(format);

    // Logs to OTEL
    // Note this won't have trace context because that's only known about by the tracing system
    // not the opentelemetry system. https://github.com/open-telemetry/opentelemetry-rust/issues/1378
    let log_provider = init_logger_provider().expect("Failed to create logger provider");
    // Add a tracing filter to filter events from crates used by opentelemetry-otlp.
    // The filter levels are set as follows:
    // - Allow `info` level and above by default.
    // - Restrict `hyper`, `tonic`, and `reqwest` to `error` level logs only.
    // This ensures events generated from these crates within the OTLP Exporter are not looped back,
    // thus preventing infinite event generation.
    // Note: This will also drop events from these crates used outside the OTLP Exporter.
    // For more details, see: https://github.com/open-telemetry/opentelemetry-rust/issues/761
    let otel_log_filter = tracing_subscriber::EnvFilter::new(format!(
        "info,backend=debug,{}=debug,sqlx=info",
        env!("CARGO_PKG_NAME")
    ))
    .add_directive("hyper=error".parse().expect("Failed to parse directive"))
    .add_directive("tonic=error".parse().expect("Failed to parse directive"))
    .add_directive("reqwest=error".parse().expect("Failed to parse directive"));

    let otel_log_layer =
        opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&log_provider)
            .with_filter(otel_log_filter);

    // Build the subscriber by combining layers
    let subscriber = tracing_subscriber::Registry::default()
        .with(
            console_subscriber::ConsoleLayer::builder()
                .with_default_env()
                .server_addr(([0, 0, 0, 0], 6669))
                .spawn(),
        )
        .with(otel_log_layer)
        .with(opentelemetry_metrics_layer)
        .with(tracing_opentelemetry_layer)
        .with(fmt_layer.with_filter(tracing_subscriber::EnvFilter::from_default_env()));

    // Set the subscriber as the global default
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");

    (meter_provider, tracer_provider)
}
