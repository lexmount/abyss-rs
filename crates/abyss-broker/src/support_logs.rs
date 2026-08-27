//! Broker-owned log retrieval for local support bundles.
//!
//! The broker exports only files that it owns. Host App and platform adapter
//! logs stay outside this boundary and are collected by their owning clients.

use std::{
    io::{self, SeekFrom},
    path::{Path, PathBuf},
};

use tokio::{
    fs::File,
    io::{AsyncReadExt as _, AsyncSeekExt as _},
};

use crate::{config::DevtoolsConfig, logging, platform::PlatformAdapter};

const DEFAULT_MAX_BYTES_PER_FILE: u64 = 10 * 1024 * 1024;
const MAX_BYTES_PER_FILE_LIMIT: u64 = 64 * 1024 * 1024;

/// Request body for broker-owned log retrieval.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerLogRequest {
    #[serde(default)]
    max_bytes_per_file: Option<u64>,
}

impl BrokerLogRequest {
    fn max_bytes_per_file(&self) -> Result<u64, BrokerLogRequestError> {
        let value = self
            .max_bytes_per_file
            .unwrap_or(DEFAULT_MAX_BYTES_PER_FILE);
        if value == 0 {
            return Err(BrokerLogRequestError::ZeroMaxBytesPerFile);
        }
        if value > MAX_BYTES_PER_FILE_LIMIT {
            return Err(BrokerLogRequestError::MaxBytesPerFileTooLarge {
                requested: value,
                limit: MAX_BYTES_PER_FILE_LIMIT,
            });
        }
        Ok(value)
    }
}

/// Validation errors for support log retrieval requests.
#[derive(Debug, thiserror::Error)]
pub enum BrokerLogRequestError {
    #[error("max_bytes_per_file must be greater than zero")]
    ZeroMaxBytesPerFile,
    #[error("max_bytes_per_file {requested} exceeds limit {limit}")]
    MaxBytesPerFileTooLarge { requested: u64, limit: u64 },
}

/// Response body returned to the Host App.
#[derive(Debug, serde::Serialize)]
pub struct BrokerLogResponse {
    files: Vec<BrokerLogFile>,
    errors: Vec<BrokerLogError>,
}

/// One broker-owned log file.
#[derive(Debug, serde::Serialize)]
pub struct BrokerLogFile {
    name: String,
    content: String,
    truncated: bool,
    original_size: u64,
}

/// Per-file collection error. A missing optional log should not fail the whole
/// support bundle flow.
#[derive(Debug, serde::Serialize)]
pub struct BrokerLogError {
    name: String,
    error: String,
}

/// Reads broker-owned log files with bounded tail reads.
pub struct BrokerLogCollector {
    sources: Vec<BrokerLogSource>,
}

struct BrokerLogSource {
    name: &'static str,
    path: PathBuf,
    required: bool,
}

impl BrokerLogCollector {
    /// Creates a collector for the installed broker logging layout.
    #[must_use]
    pub fn installed(config: &DevtoolsConfig, platform: &dyn PlatformAdapter) -> Self {
        let mut sources = vec![
            BrokerLogSource {
                name: "abyss-broker.log",
                path: logging::log_file_path(config, platform),
                required: true,
            },
            BrokerLogSource {
                name: "abyss-broker-trace.log",
                path: logging::performance_trace_file_path(config, platform),
                required: false,
            },
        ];
        sources.extend(
            platform
                .platform_support_log_files()
                .into_iter()
                .map(|file| BrokerLogSource {
                    name: file.name,
                    path: file.path,
                    required: false,
                }),
        );
        Self { sources }
    }

    #[cfg(test)]
    const fn from_sources(sources: Vec<BrokerLogSource>) -> Self {
        Self { sources }
    }

    /// Collects all configured broker logs. Individual file errors are reported
    /// in the response so the Host App can still create a partial bundle.
    ///
    /// # Errors
    ///
    /// Returns an error when request limits are invalid.
    pub async fn collect(
        &self,
        request: &BrokerLogRequest,
    ) -> Result<BrokerLogResponse, BrokerLogRequestError> {
        let max_bytes_per_file = request.max_bytes_per_file()?;
        let mut files = Vec::new();
        let mut errors = Vec::new();

        for source in &self.sources {
            match read_tail(&source.path, max_bytes_per_file).await {
                Ok(collected) => files.push(BrokerLogFile {
                    name: source.name.to_owned(),
                    content: String::from_utf8_lossy(&collected.bytes).into_owned(),
                    truncated: collected.truncated,
                    original_size: collected.original_size,
                }),
                Err(error) if error.kind() == io::ErrorKind::NotFound && !source.required => {}
                Err(error) => errors.push(BrokerLogError {
                    name: source.name.to_owned(),
                    error: error.to_string(),
                }),
            }
        }

        Ok(BrokerLogResponse { files, errors })
    }
}

struct TailBytes {
    bytes: Vec<u8>,
    truncated: bool,
    original_size: u64,
}

async fn read_tail(path: &Path, max_bytes: u64) -> io::Result<TailBytes> {
    let mut file = File::open(path).await?;
    let original_size = file.metadata().await?.len();
    let truncated = original_size > max_bytes;
    if truncated {
        file.seek(SeekFrom::Start(original_size.saturating_sub(max_bytes)))
            .await?;
    }

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).await?;
    let grew_past_limit = u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes;
    if grew_past_limit {
        let max_len = usize::try_from(max_bytes).unwrap_or(usize::MAX);
        let drop_count = bytes.len().saturating_sub(max_len);
        bytes.drain(..drop_count);
    }
    Ok(TailBytes {
        bytes,
        truncated: truncated || grew_past_limit,
        original_size,
    })
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use tokio::fs;

    use super::{BrokerLogCollector, BrokerLogRequest, BrokerLogSource};

    #[tokio::test]
    async fn collects_bounded_tail_from_required_log() {
        let directory = test_directory("tail").await;
        let log_path = directory.join("abyss-broker.log");
        fs::write(&log_path, "0123456789abcdef")
            .await
            .expect("test log should write");
        let collector = BrokerLogCollector::from_sources(vec![BrokerLogSource {
            name: "abyss-broker.log",
            path: log_path,
            required: true,
        }]);

        let response = collector
            .collect(&BrokerLogRequest {
                max_bytes_per_file: Some(6),
            })
            .await
            .expect("request should be valid");

        assert!(response.errors.is_empty());
        assert_eq!(response.files.len(), 1);
        assert_eq!(response.files[0].content, "abcdef");
        assert!(response.files[0].truncated);
        assert_eq!(response.files[0].original_size, 16);
        fs::remove_dir_all(directory)
            .await
            .expect("test directory should be removed");
    }

    #[tokio::test]
    async fn reports_missing_required_log_without_failing_response() {
        let directory = test_directory("missing").await;
        let collector = BrokerLogCollector::from_sources(vec![BrokerLogSource {
            name: "abyss-broker.log",
            path: directory.join("missing.log"),
            required: true,
        }]);

        let response = collector
            .collect(&BrokerLogRequest {
                max_bytes_per_file: Some(1024),
            })
            .await
            .expect("request should be valid");

        assert!(response.files.is_empty());
        assert_eq!(response.errors.len(), 1);
        assert_eq!(response.errors[0].name, "abyss-broker.log");
        fs::remove_dir_all(directory)
            .await
            .expect("test directory should be removed");
    }

    #[tokio::test]
    async fn skips_missing_optional_log() {
        let directory = test_directory("optional").await;
        let collector = BrokerLogCollector::from_sources(vec![BrokerLogSource {
            name: "abyss-broker-trace.log",
            path: directory.join("missing-trace.log"),
            required: false,
        }]);

        let response = collector
            .collect(&BrokerLogRequest {
                max_bytes_per_file: Some(1024),
            })
            .await
            .expect("request should be valid");

        assert!(response.files.is_empty());
        assert!(response.errors.is_empty());
        fs::remove_dir_all(directory)
            .await
            .expect("test directory should be removed");
    }

    #[tokio::test]
    async fn rejects_invalid_byte_limits() {
        let collector = BrokerLogCollector::from_sources(Vec::new());

        assert!(
            collector
                .collect(&BrokerLogRequest {
                    max_bytes_per_file: Some(0),
                })
                .await
                .is_err()
        );
    }

    async fn test_directory(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "abyss-broker-support-logs-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&directory)
            .await
            .expect("test directory should create");
        directory
    }
}
