//! File-backed tracing initialization for `abyss-broker`.
//!
//! Logging behavior is selected by the static startup file. Platform path
//! adapters supply only the built-in location when no path is configured.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use tracing_subscriber::{
    Layer as _,
    filter::{LevelFilter, Targets},
    fmt,
    fmt::format::FmtSpan,
    fmt::writer::MakeWriterExt as _,
    layer::SubscriberExt as _,
    util::SubscriberInitExt as _,
};

use crate::{
    config::{DevtoolsConfig, LogLevel},
    platform::PlatformAdapter,
};

const ABYSS_TARGET_PREFIX: &str = "abyss_";
const LOG_FILE_NAME: &str = "abyss-broker.log";
const PERFORMANCE_TRACE_FILE_NAME: &str = "abyss-broker-trace.log";

/// Guard that keeps asynchronous log writers alive until process exit.
#[must_use]
pub struct TraceGuard {
    _stdout: tracing_appender::non_blocking::WorkerGuard,
    _log_file: tracing_appender::non_blocking::WorkerGuard,
    _performance_trace: Option<tracing_appender::non_blocking::WorkerGuard>,
}

/// Initializes tracing from the file-managed developer diagnostics settings.
///
/// # Errors
///
/// Returns an error when the log directory cannot be created or secured.
pub fn init(config: &DevtoolsConfig, platform: &dyn PlatformAdapter) -> io::Result<TraceGuard> {
    let log_dir = log_dir(config, platform);
    create_log_dir(&log_dir)?;
    let file_appender = tracing_appender::rolling::never(&log_dir, LOG_FILE_NAME);
    let (stdout_writer, stdout_guard) = tracing_appender::non_blocking(std::io::stdout());
    let (file_writer, log_file_guard) = tracing_appender::non_blocking(file_appender);
    let writer = stdout_writer
        .with_max_level(tracing::Level::INFO)
        .and(file_writer);
    let filter = broker_log_targets(config.log_level);
    let log_layer = fmt::layer()
        .with_ansi(false)
        .with_writer(writer)
        .with_filter(filter);

    let performance_trace_guard = if config.performance_trace {
        let trace_appender =
            tracing_appender::rolling::never(&log_dir, PERFORMANCE_TRACE_FILE_NAME);
        let (trace_writer, trace_guard) = tracing_appender::non_blocking(trace_appender);
        let trace_filter = abyss_targets(LogLevel::Trace);
        let trace_layer = fmt::layer()
            .with_ansi(false)
            .with_target(true)
            .with_span_events(FmtSpan::CLOSE)
            .with_writer(trace_writer)
            .with_filter(trace_filter);
        tracing_subscriber::registry()
            .with(log_layer)
            .with(trace_layer)
            .init();
        Some(trace_guard)
    } else {
        tracing_subscriber::registry().with(log_layer).init();
        None
    };

    tracing::info!(
        log_dir = %log_dir.display(),
        log_file = %log_file_path(config, platform).display(),
        log_level = ?config.log_level,
        performance_tracing_enabled = performance_trace_guard.is_some(),
        performance_trace_file = %performance_trace_file_path(config, platform).display(),
        "abyss-broker file logging initialized"
    );

    Ok(TraceGuard {
        _stdout: stdout_guard,
        _log_file: log_file_guard,
        _performance_trace: performance_trace_guard,
    })
}

/// Returns the current broker log path.
#[must_use]
pub fn log_file_path(config: &DevtoolsConfig, platform: &dyn PlatformAdapter) -> PathBuf {
    log_dir(config, platform).join(LOG_FILE_NAME)
}

/// Returns the optional performance trace path.
#[must_use]
pub fn performance_trace_file_path(
    config: &DevtoolsConfig,
    platform: &dyn PlatformAdapter,
) -> PathBuf {
    log_dir(config, platform).join(PERFORMANCE_TRACE_FILE_NAME)
}

fn log_dir(config: &DevtoolsConfig, platform: &dyn PlatformAdapter) -> PathBuf {
    config
        .log_location
        .clone()
        .unwrap_or_else(|| platform.abyss_home().join("logs"))
}

fn abyss_targets(level: LogLevel) -> Targets {
    let level = match level {
        LogLevel::Trace => LevelFilter::TRACE,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Error => LevelFilter::ERROR,
    };

    Targets::new().with_target(ABYSS_TARGET_PREFIX, level)
}

fn broker_log_targets(level: LogLevel) -> Targets {
    abyss_targets(level).with_default(LevelFilter::ERROR)
}

#[cfg(unix)]
fn create_log_dir(directory: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
}

#[cfg(target_os = "windows")]
fn create_log_dir(directory: &Path) -> io::Result<()> {
    fs::create_dir_all(directory)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    #[cfg(unix)]
    use super::create_log_dir;
    use super::{abyss_targets, broker_log_targets, log_file_path};
    use crate::{
        config::{DevtoolsConfig, LogLevel},
        platform::PlatformAdapter,
    };

    struct TestPlatformAdapter {
        home: PathBuf,
    }

    impl TestPlatformAdapter {
        const fn at(home: PathBuf) -> Self {
            Self { home }
        }
    }

    impl PlatformAdapter for TestPlatformAdapter {
        fn abyss_home(&self) -> PathBuf {
            self.home.clone()
        }
    }

    #[test]
    fn configured_log_location_overrides_platform_default() {
        let config = DevtoolsConfig {
            log_location: Some(PathBuf::from("/configured/logs")),
            ..DevtoolsConfig::default()
        };
        let platform = TestPlatformAdapter::at(PathBuf::from("/default/abyss"));

        assert_eq!(
            log_file_path(&config, &platform),
            PathBuf::from("/configured/logs/abyss-broker.log")
        );
    }

    #[test]
    fn absent_log_location_uses_platform_home() {
        let platform = TestPlatformAdapter::at(PathBuf::from("/default/abyss"));

        assert_eq!(
            log_file_path(&DevtoolsConfig::default(), &platform),
            PathBuf::from("/default/abyss/logs/abyss-broker.log")
        );
    }

    #[test]
    fn broker_log_filter_keeps_dependency_errors_visible() {
        let filter = broker_log_targets(LogLevel::Info);

        assert!(filter.would_enable("abyss_new_runtime::module", &tracing::Level::INFO));
        assert!(!filter.would_enable("abyss_new_runtime::module", &tracing::Level::DEBUG));
        assert!(filter.would_enable("external_dependency", &tracing::Level::ERROR));
        assert!(!filter.would_enable("external_dependency", &tracing::Level::WARN));
    }

    #[test]
    fn performance_trace_filter_remains_limited_to_abyss_targets() {
        let filter = abyss_targets(LogLevel::Trace);

        assert!(filter.would_enable("abyss_new_runtime::module", &tracing::Level::TRACE));
        assert!(!filter.would_enable("external_dependency", &tracing::Level::ERROR));
    }

    #[cfg(unix)]
    #[test]
    fn log_dir_is_owner_only_on_unix() {
        use std::{
            fs,
            os::unix::fs::PermissionsExt as _,
            time::{SystemTime, UNIX_EPOCH},
        };

        let directory = std::env::temp_dir().join(format!(
            "abyss-broker-log-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock should be after Unix epoch")
                .as_nanos()
        ));

        create_log_dir(&directory).expect("log directory should be created");
        let mode = fs::metadata(&directory)
            .expect("log directory metadata should be readable")
            .permissions()
            .mode()
            & 0o777;
        drop(fs::remove_dir_all(&directory));

        assert_eq!(mode, 0o700);
    }
}
