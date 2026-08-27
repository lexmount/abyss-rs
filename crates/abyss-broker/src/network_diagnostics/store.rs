//! Diesel-backed persistence for broker-collected network observations.
//!
//! The generic `SQLite` connection capability lives in `abyss-storage`. This
//! module owns only the network-observation schema, its migrations, and the
//! conversion between technical Rust observations and durable rows.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use abyss_storage::{SqliteStore, StorageError};
use diesel::{Connection, ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use uuid::Uuid;

use crate::{
    network_diagnostics::{
        NetworkDirection, NetworkErrorCode, NetworkFailureClass, NetworkHop, NetworkObservation,
        NetworkOutcome, NetworkStage, NetworkTiming,
    },
    platform::PlatformAdapter,
};

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

const DEFAULT_DATABASE_DIRECTORY: &str = "data";
const DATABASE_FILE_NAME: &str = "abyss.sqlite3";
const MAX_PERSISTED_OBSERVATIONS: i64 = 10_000;

diesel::table! {
    network_observations (observation_id) {
        observation_id -> Text,
        flow_id -> Nullable<Text>,
        observed_at_unix_ms -> BigInt,
        ingress_source -> Text,
        destination_host -> Nullable<Text>,
        source_pid -> Nullable<BigInt>,
        source_process_name -> Nullable<Text>,
        source_executable_path -> Nullable<Text>,
        source_bundle_id -> Nullable<Text>,
        hop -> Text,
        direction -> Nullable<Text>,
        operation -> Nullable<Text>,
        stage -> Text,
        outcome -> Text,
        failure_class -> Nullable<Text>,
        technical_error_code -> Nullable<Text>,
        started_at_unix_ms -> BigInt,
        ended_at_unix_ms -> BigInt,
        elapsed_ms -> BigInt,
        http_status -> Nullable<Integer>,
        request_method -> Nullable<Text>,
        request_path -> Nullable<Text>,
        bytes_up -> BigInt,
        bytes_down -> BigInt,
        error -> Nullable<Text>,
    }
}

#[derive(diesel::Insertable)]
#[diesel(table_name = network_observations)]
struct NewNetworkObservationRow {
    observation_id: String,
    flow_id: Option<String>,
    observed_at_unix_ms: i64,
    ingress_source: String,
    destination_host: Option<String>,
    source_pid: Option<i64>,
    source_process_name: Option<String>,
    source_executable_path: Option<String>,
    source_bundle_id: Option<String>,
    hop: String,
    direction: Option<String>,
    operation: Option<String>,
    stage: String,
    outcome: String,
    failure_class: Option<String>,
    technical_error_code: Option<String>,
    started_at_unix_ms: i64,
    ended_at_unix_ms: i64,
    elapsed_ms: i64,
    http_status: Option<i32>,
    request_method: Option<String>,
    request_path: Option<String>,
    bytes_up: i64,
    bytes_down: i64,
    error: Option<String>,
}

#[derive(diesel::Queryable, diesel::Selectable)]
#[diesel(table_name = network_observations)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct NetworkObservationRow {
    observation_id: String,
    flow_id: Option<String>,
    observed_at_unix_ms: i64,
    ingress_source: String,
    destination_host: Option<String>,
    source_pid: Option<i64>,
    source_process_name: Option<String>,
    source_executable_path: Option<String>,
    source_bundle_id: Option<String>,
    hop: String,
    direction: Option<String>,
    operation: Option<String>,
    stage: String,
    outcome: String,
    failure_class: Option<String>,
    technical_error_code: Option<String>,
    started_at_unix_ms: i64,
    ended_at_unix_ms: i64,
    elapsed_ms: i64,
    http_status: Option<i32>,
    request_method: Option<String>,
    request_path: Option<String>,
    bytes_up: i64,
    bytes_down: i64,
    error: Option<String>,
}

/// Errors raised while converting or querying persisted observations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NetworkObservationStoreError {
    /// The shared `SQLite` capability failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// A durable row contains a value that cannot be represented as a current
    /// technical observation.
    #[error("invalid persisted network observation field {field}: {value}")]
    InvalidValue {
        /// Field containing the invalid value.
        field: &'static str,
        /// Invalid stored value.
        value: String,
    },
    /// A counter or timestamp exceeded `SQLite`'s signed integer range.
    #[error("network observation field {field} is outside SQLite integer range")]
    IntegerOutOfRange {
        /// Field that could not be converted.
        field: &'static str,
    },
}

/// Durable store for metadata-only network observations.
#[derive(Clone)]
pub struct NetworkObservationStore {
    database: Arc<SqliteStore>,
}

impl NetworkObservationStore {
    /// Opens the local database and applies all network-observation migrations.
    pub fn open<P>(path: P) -> Result<Self, NetworkObservationStoreError>
    where
        P: Into<PathBuf>,
    {
        let database = Arc::new(SqliteStore::open(path.into())?);
        database.with_connection_result(|connection| {
            connection.run_pending_migrations(MIGRATIONS).map(|_| ())
        })?;
        Ok(Self { database })
    }

    /// Persists one completed observation.
    pub fn insert(
        &self,
        observation: &NetworkObservation,
    ) -> Result<(), NetworkObservationStoreError> {
        let row = NewNetworkObservationRow::try_from(observation)?;
        self.database.with_connection(|connection| {
            connection.transaction::<_, diesel::result::Error, _>(|connection| {
                diesel::insert_into(network_observations::table)
                    .values(row)
                    .execute(connection)?;
                prune_observations(connection, MAX_PERSISTED_OBSERVATIONS).map(|_| ())
            })
        })?;
        Ok(())
    }

    /// Returns the newest observations first, bounded by the caller's limit.
    pub fn latest(
        &self,
        limit: usize,
    ) -> Result<Vec<NetworkObservation>, NetworkObservationStoreError> {
        let limit = i64::try_from(limit)
            .map_err(|_| NetworkObservationStoreError::IntegerOutOfRange { field: "limit" })?;
        let rows = self.database.with_connection(|connection| {
            network_observations::table
                .select(NetworkObservationRow::as_select())
                .order(network_observations::observed_at_unix_ms.desc())
                .limit(limit)
                .load::<NetworkObservationRow>(connection)
        })?;
        rows.into_iter().map(NetworkObservation::try_from).collect()
    }
}

fn prune_observations(
    connection: &mut diesel::SqliteConnection,
    retained_rows: i64,
) -> diesel::QueryResult<usize> {
    let retained_observations = diesel::alias!(network_observations as retained_observations);
    let retained_ids = retained_observations
        .select(retained_observations.field(network_observations::observation_id))
        .order((
            retained_observations
                .field(network_observations::observed_at_unix_ms)
                .desc(),
            retained_observations
                .field(network_observations::observation_id)
                .desc(),
        ))
        .limit(retained_rows);
    diesel::delete(network_observations::table)
        .filter(network_observations::observation_id.ne_all(retained_ids))
        .execute(connection)
}

/// Returns the platform-specific broker database path.
#[must_use]
pub fn database_path(platform: &dyn PlatformAdapter) -> PathBuf {
    database_path_from_home(platform.abyss_home().as_path())
}

fn database_path_from_home(home: &Path) -> PathBuf {
    home.join(DEFAULT_DATABASE_DIRECTORY)
        .join(DATABASE_FILE_NAME)
}

impl TryFrom<&NetworkObservation> for NewNetworkObservationRow {
    type Error = NetworkObservationStoreError;

    fn try_from(observation: &NetworkObservation) -> Result<Self, Self::Error> {
        Ok(Self {
            observation_id: observation.observation_id.to_string(),
            flow_id: observation.flow_id.map(|value| value.to_string()),
            observed_at_unix_ms: sqlite_integer(observation.observed_at_unix_ms, "observed_at")?,
            ingress_source: observation.ingress_source.clone(),
            destination_host: observation.destination_host.clone(),
            source_pid: observation
                .source_pid
                .map(|value| sqlite_integer(value.into(), "source_pid"))
                .transpose()?,
            source_process_name: observation.source_process_name.clone(),
            source_executable_path: observation.source_executable_path.clone(),
            source_bundle_id: observation.source_bundle_id.clone(),
            hop: observation.hop.as_str().to_owned(),
            direction: observation
                .direction
                .map(NetworkDirection::as_str)
                .map(str::to_owned),
            operation: observation
                .operation
                .map(abyss_mitm::FlowOperation::as_str)
                .map(str::to_owned),
            stage: observation.stage.as_str().to_owned(),
            outcome: observation.outcome.as_str().to_owned(),
            failure_class: observation
                .failure_class
                .map(NetworkFailureClass::as_str)
                .map(str::to_owned),
            technical_error_code: observation
                .technical_error_code
                .map(NetworkErrorCode::as_str)
                .map(str::to_owned),
            started_at_unix_ms: sqlite_integer(observation.timing.started_at, "started_at")?,
            ended_at_unix_ms: sqlite_integer(observation.timing.ended_at, "ended_at")?,
            elapsed_ms: sqlite_integer(observation.timing.elapsed_ms, "elapsed_ms")?,
            http_status: observation.http_status.map(i32::from),
            request_method: observation.request_method.clone(),
            request_path: observation.request_path.clone(),
            bytes_up: sqlite_integer(observation.bytes_up, "bytes_up")?,
            bytes_down: sqlite_integer(observation.bytes_down, "bytes_down")?,
            error: observation.error.clone(),
        })
    }
}

impl TryFrom<NetworkObservationRow> for NetworkObservation {
    type Error = NetworkObservationStoreError;

    fn try_from(row: NetworkObservationRow) -> Result<Self, Self::Error> {
        Ok(Self {
            observation_id: parse_uuid(&row.observation_id, "observation_id")?,
            flow_id: row
                .flow_id
                .as_deref()
                .map(|value| parse_uuid(value, "flow_id"))
                .transpose()?,
            observed_at_unix_ms: non_negative_integer(
                row.observed_at_unix_ms,
                "observed_at_unix_ms",
            )?,
            ingress_source: row.ingress_source,
            destination_host: row.destination_host,
            source_pid: row
                .source_pid
                .map(|value| non_negative_integer(value, "source_pid"))
                .transpose()?
                .map(|value| {
                    u32::try_from(value).map_err(|_| NetworkObservationStoreError::InvalidValue {
                        field: "source_pid",
                        value: value.to_string(),
                    })
                })
                .transpose()?,
            source_process_name: row.source_process_name,
            source_executable_path: row.source_executable_path,
            source_bundle_id: row.source_bundle_id,
            hop: parse_enum(&row.hop, "hop", NetworkHop::parse)?,
            direction: row
                .direction
                .as_deref()
                .map(|value| parse_enum(value, "direction", NetworkDirection::parse))
                .transpose()?,
            operation: row
                .operation
                .as_deref()
                .map(|value| parse_enum(value, "operation", abyss_mitm::FlowOperation::parse))
                .transpose()?,
            stage: parse_enum(&row.stage, "stage", NetworkStage::parse)?,
            outcome: parse_enum(&row.outcome, "outcome", NetworkOutcome::parse)?,
            failure_class: row
                .failure_class
                .as_deref()
                .map(|value| parse_enum(value, "failure_class", NetworkFailureClass::parse))
                .transpose()?,
            technical_error_code: row
                .technical_error_code
                .as_deref()
                .map(|value| parse_enum(value, "technical_error_code", NetworkErrorCode::parse))
                .transpose()?
                .or_else(|| {
                    NetworkErrorCode::from_observation(
                        parse_enum(&row.hop, "hop", NetworkHop::parse).ok()?,
                        parse_enum(&row.stage, "stage", NetworkStage::parse).ok()?,
                        parse_enum(&row.outcome, "outcome", NetworkOutcome::parse).ok()?,
                        row.failure_class
                            .as_deref()
                            .and_then(NetworkFailureClass::parse),
                        row.http_status.and_then(|value| u16::try_from(value).ok()),
                    )
                }),
            timing: NetworkTiming {
                started_at: non_negative_integer(row.started_at_unix_ms, "started_at_unix_ms")?,
                ended_at: non_negative_integer(row.ended_at_unix_ms, "ended_at_unix_ms")?,
                elapsed_ms: non_negative_integer(row.elapsed_ms, "elapsed_ms")?,
            },
            http_status: row
                .http_status
                .map(|value| {
                    u16::try_from(value).map_err(|_| NetworkObservationStoreError::InvalidValue {
                        field: "http_status",
                        value: value.to_string(),
                    })
                })
                .transpose()?,
            request_method: row.request_method,
            request_path: row.request_path,
            bytes_up: non_negative_integer(row.bytes_up, "bytes_up")?,
            bytes_down: non_negative_integer(row.bytes_down, "bytes_down")?,
            error: row.error,
        })
    }
}

fn sqlite_integer(value: u64, field: &'static str) -> Result<i64, NetworkObservationStoreError> {
    i64::try_from(value).map_err(|_| NetworkObservationStoreError::IntegerOutOfRange { field })
}

fn non_negative_integer(
    value: i64,
    field: &'static str,
) -> Result<u64, NetworkObservationStoreError> {
    u64::try_from(value).map_err(|_| NetworkObservationStoreError::InvalidValue {
        field,
        value: value.to_string(),
    })
}

fn parse_uuid(value: &str, field: &'static str) -> Result<Uuid, NetworkObservationStoreError> {
    Uuid::parse_str(value).map_err(|_| NetworkObservationStoreError::InvalidValue {
        field,
        value: value.to_owned(),
    })
}

fn parse_enum<T>(
    value: &str,
    field: &'static str,
    parser: fn(&str) -> Option<T>,
) -> Result<T, NetworkObservationStoreError> {
    parser(value).ok_or_else(|| NetworkObservationStoreError::InvalidValue {
        field,
        value: value.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use abyss_mitm::{FlowIngress, SourceProcess, TransparentFlowSource};

    #[test]
    fn persists_and_reads_back_technical_observations() {
        let store = NetworkObservationStore::open(":memory:")
            .expect("in-memory network observation store should open");
        let ingress = FlowIngress::transparent(TransparentFlowSource::Unattributed);
        let source = SourceProcess::new(
            Some(42),
            Some("claude".to_owned()),
            Some("/usr/local/bin/claude".to_owned()),
        )
        .with_application_id(Some("com.anthropic.claude-code".to_owned()));
        let error = abyss_mitm::TransparentFlowError::Io {
            operation: abyss_mitm::FlowOperation::ConnectProviderTcp,
            source: std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused"),
        };
        let observation = NetworkObservation::from_error(
            Some(Uuid::new_v4()),
            &ingress,
            Some("api.example.test"),
            Some(&source),
            100,
            140,
            &error,
        );

        store
            .insert(&observation)
            .expect("observation should be inserted");
        let loaded = store.latest(10).expect("observation should be queried");

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].observation_id, observation.observation_id);
        assert_eq!(loaded[0].flow_id, observation.flow_id);
        assert_eq!(loaded[0].hop, NetworkHop::AbyssToProvider);
        assert_eq!(loaded[0].direction, Some(NetworkDirection::AbyssToProvider));
        assert_eq!(
            loaded[0].operation,
            Some(abyss_mitm::FlowOperation::ConnectProviderTcp)
        );
        assert_eq!(loaded[0].failure_class, observation.failure_class);
        assert_eq!(
            loaded[0].technical_error_code,
            observation.technical_error_code
        );
        assert_eq!(loaded[0].error, observation.error);
        assert_eq!(loaded[0].source_pid, Some(42));
        assert_eq!(loaded[0].source_process_name.as_deref(), Some("claude"));
        assert_eq!(
            loaded[0].source_bundle_id.as_deref(),
            Some("com.anthropic.claude-code")
        );
    }

    #[test]
    fn latest_respects_limit_and_orders_newest_first() {
        let store = NetworkObservationStore::open(":memory:")
            .expect("in-memory network observation store should open");
        let ingress = FlowIngress::transparent(TransparentFlowSource::Unattributed);
        let error = abyss_mitm::TransparentFlowError::Io {
            operation: abyss_mitm::FlowOperation::ConnectProviderTcp,
            source: std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused"),
        };
        for timestamp in [100_u64, 300, 200] {
            let observation = NetworkObservation::from_error(
                None,
                &ingress,
                Some("api.example.test"),
                None,
                timestamp,
                timestamp,
                &error,
            );
            store
                .insert(&observation)
                .expect("observation should insert");
        }

        let loaded = store.latest(2).expect("observations should be queried");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].observed_at_unix_ms, 300);
        assert_eq!(loaded[1].observed_at_unix_ms, 200);
    }

    #[test]
    fn observations_survive_store_reopen() {
        let root = std::env::temp_dir().join(format!(
            "abyss-network-observation-reopen-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be after Unix epoch")
                .as_nanos()
        ));
        let path = root.join("abyss.sqlite3");
        let ingress = FlowIngress::transparent(TransparentFlowSource::Unattributed);
        let error = abyss_mitm::TransparentFlowError::MissingSni;
        let observation = NetworkObservation::from_error(
            None,
            &ingress,
            Some("api.example.test"),
            None,
            100,
            120,
            &error,
        );

        {
            let store = NetworkObservationStore::open(&path)
                .expect("file-backed network observation store should open");
            store
                .insert(&observation)
                .expect("observation should persist");
        }
        let reopened =
            NetworkObservationStore::open(&path).expect("network observation store should reopen");
        let loaded = reopened
            .latest(10)
            .expect("reopened store should query observations");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].observation_id, observation.observation_id);

        drop(std::fs::remove_dir_all(root));
    }

    #[test]
    fn prunes_old_observations_by_timestamp() {
        let store = NetworkObservationStore::open(":memory:")
            .expect("in-memory network observation store should open");
        let ingress = FlowIngress::transparent(TransparentFlowSource::Unattributed);
        let error = abyss_mitm::TransparentFlowError::MissingSni;

        for timestamp in [100_u64, 300, 200] {
            let observation = NetworkObservation::from_error(
                None,
                &ingress,
                Some("api.example.test"),
                None,
                timestamp,
                timestamp,
                &error,
            );
            store
                .insert(&observation)
                .expect("observation should insert");
        }

        store
            .database
            .with_connection(|connection| prune_observations(connection, 2).map(|_| ()))
            .expect("pruning should succeed");
        let loaded = store.latest(10).expect("observations should be queried");

        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].observed_at_unix_ms, 300);
        assert_eq!(loaded[1].observed_at_unix_ms, 200);
    }
}
