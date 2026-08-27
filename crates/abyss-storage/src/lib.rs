//! Reusable local `SQLite` storage primitives for Abyss endpoint components.
//!
//! This crate owns database connection setup and safe local-file handling, but
//! intentionally does not define any product table or network-diagnostics
//! model. Feature crates provide their own Diesel schema and migrations through
//! [`SqliteStore::with_connection`].

mod path_security;

use std::{
    fs,
    path::{Path, PathBuf},
};

use diesel::{Connection, connection::SimpleConnection, sqlite::SqliteConnection};
use parking_lot::Mutex;

use crate::path_security::StoragePathSecurity;

/// Errors produced while opening or using the local `SQLite` database.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StorageError {
    /// The database connection could not be established.
    #[error("failed to open SQLite database at {path}: {source}")]
    Connection {
        /// Database path used by the attempted connection.
        path: PathBuf,
        /// Underlying Diesel connection error.
        #[source]
        source: diesel::ConnectionError,
    },
    /// A database operation failed.
    #[error("SQLite database operation failed: {0}")]
    Operation(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// A database path could not be prepared.
    #[error("failed to prepare SQLite database directory {path}: {source}")]
    PrepareDirectory {
        /// Directory that was being prepared.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: std::io::Error,
    },
    /// A database file or directory could not be assigned owner-only permissions.
    #[error("failed to protect SQLite database path {path}: {source}")]
    ProtectPath {
        /// Path whose permissions were being changed.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: std::io::Error,
    },
}

/// A process-local, mutex-protected `SQLite` connection.
///
/// Diesel's `SQLite` connection is synchronous. The store centralizes that
/// detail behind a small closure API so feature crates can share one durable
/// connection without owning connection setup or filesystem policy.
pub struct SqliteStore {
    path: PathBuf,
    connection: Mutex<SqliteConnection>,
}

impl SqliteStore {
    /// Opens or creates a `SQLite` database and applies safe local defaults.
    ///
    /// The special `:memory:` path is supported for isolated tests. File-backed
    /// databases create their parent directory and use platform-appropriate
    /// owner-only protection.
    ///
    /// # Errors
    ///
    /// Returns an error when the database directory, permissions, connection,
    /// or `SQLite` pragmas cannot be prepared.
    pub fn open<P>(path: P) -> Result<Self, StorageError>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref().to_path_buf();
        let path_security = path_security::platform();
        if path.as_os_str() != ":memory:" {
            Self::prepare_parent(&path, path_security.as_ref())?;
        }
        let mut connection =
            SqliteConnection::establish(&path.to_string_lossy()).map_err(|source| {
                StorageError::Connection {
                    path: path.clone(),
                    source,
                }
            })?;
        connection
            .batch_execute(
                "PRAGMA foreign_keys = ON;
                 PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = NORMAL;
                 PRAGMA busy_timeout = 5000;",
            )
            .map_err(Self::operation_error)?;
        if path.as_os_str() != ":memory:" {
            Self::protect_file(&path, path_security.as_ref())?;
        }
        Ok(Self {
            path,
            connection: Mutex::new(connection),
        })
    }

    /// Returns the path used to open this database.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Runs a Diesel operation using the shared `SQLite` connection.
    ///
    /// The closure may return any error type that can safely cross the storage
    /// boundary. This allows feature crates to run Diesel migrations as well as
    /// regular queries without making this crate depend on their migration
    /// framework.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the operation returns an error.
    pub fn with_connection<T, E, F>(&self, operation: F) -> Result<T, StorageError>
    where
        E: std::error::Error + Send + Sync + 'static,
        F: FnOnce(&mut SqliteConnection) -> Result<T, E>,
    {
        let mut connection = self.connection.lock();
        operation(&mut connection).map_err(|error| StorageError::Operation(Box::new(error)))
    }

    /// Runs an operation whose error is already boxed as a cross-crate error.
    ///
    /// Diesel migration APIs intentionally use a boxed error type. This
    /// companion method lets callers run those APIs without coupling the
    /// reusable storage crate to a particular migration implementation.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the operation returns an error.
    pub fn with_connection_result<T, F>(&self, operation: F) -> Result<T, StorageError>
    where
        F: FnOnce(&mut SqliteConnection) -> Result<T, Box<dyn std::error::Error + Send + Sync>>,
    {
        let mut connection = self.connection.lock();
        operation(&mut connection).map_err(StorageError::Operation)
    }

    fn prepare_parent(
        path: &Path,
        path_security: &dyn StoragePathSecurity,
    ) -> Result<(), StorageError> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|source| StorageError::PrepareDirectory {
            path: parent.to_path_buf(),
            source,
        })?;
        protect_directory(parent, path_security)
    }

    fn protect_file(
        path: &Path,
        path_security: &dyn StoragePathSecurity,
    ) -> Result<(), StorageError> {
        path_security
            .protect_file(path)
            .map_err(|source| StorageError::ProtectPath {
                path: path.to_path_buf(),
                source,
            })
    }

    fn operation_error(error: diesel::result::Error) -> StorageError {
        StorageError::Operation(Box::new(error))
    }
}

fn protect_directory(
    path: &Path,
    path_security: &dyn StoragePathSecurity,
) -> Result<(), StorageError> {
    path_security
        .protect_directory(path)
        .map_err(|source| StorageError::ProtectPath {
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use diesel::{RunQueryDsl, sql_query};

    use super::*;

    #[test]
    fn opens_in_memory_database_and_runs_queries() {
        let store = SqliteStore::open(":memory:").expect("in-memory SQLite should open");
        store
            .with_connection(|connection| {
                sql_query("CREATE TABLE values_table (value TEXT NOT NULL)")
                    .execute(connection)
                    .map(|_| ())
            })
            .expect("SQLite query should succeed");
    }

    #[test]
    fn creates_parent_directory_for_file_database() {
        let root = std::env::temp_dir().join(format!(
            "abyss-storage-test-{}-{}",
            std::process::id(),
            uuid_like_suffix()
        ));
        let path = root.join("nested").join("abyss.sqlite3");
        let store = SqliteStore::open(&path).expect("file-backed SQLite should open");
        assert_eq!(store.path(), path.as_path());
        drop(store);
        drop(fs::remove_dir_all(root));
    }

    #[cfg(unix)]
    #[test]
    fn protects_existing_database_paths() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "abyss-storage-permissions-test-{}-{}",
            std::process::id(),
            uuid_like_suffix()
        ));
        let path = root.join("nested").join("abyss.sqlite3");
        {
            let _store = SqliteStore::open(&path).expect("file-backed SQLite should open");
        }

        fs::set_permissions(
            path.parent().expect("database has a parent"),
            fs::Permissions::from_mode(0o777),
        )
        .expect("database directory permissions should be writable");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666))
            .expect("database file permissions should be writable");
        let _store = SqliteStore::open(&path).expect("database should reopen");

        let directory_mode = fs::metadata(path.parent().expect("database has a parent"))
            .expect("database directory should exist")
            .permissions()
            .mode()
            & 0o777;
        let file_mode = fs::metadata(&path)
            .expect("database file should exist")
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(directory_mode, 0o700);
        assert_eq!(file_mode, 0o600);
        drop(fs::remove_dir_all(root));
    }

    fn uuid_like_suffix() -> u128 {
        use std::time::{SystemTime, UNIX_EPOCH};

        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after Unix epoch")
            .as_nanos()
    }
}
