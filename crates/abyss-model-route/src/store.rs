//! Durable per-principal snapshots. Inspection only borrows published memory.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use parking_lot::{Mutex, RwLock};
use serde_json::Value;

use crate::routing::{Load, Routes, Select};

pub enum Change {
    Import(Load),
    Select(Select),
    Clear,
}

pub struct Store {
    pub broker_pid: u32,
    directory: PathBuf,
    profiles: RwLock<HashMap<String, Arc<Routes>>>,
    writer: Mutex<()>,
}

impl Store {
    /// The service owner controls the directory and supplies all file names.
    pub fn open(directory: PathBuf, broker_pid: u32) -> Result<Self, &'static str> {
        let mut profiles = HashMap::new();
        for entry in fs::read_dir(&directory).map_err(|_| "Cannot open route state directory.")? {
            let path = entry.map_err(|_| "Cannot enumerate route state.")?.path();
            if path.extension().is_none_or(|ext| ext != "json") {
                continue;
            }
            let id = path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or("Invalid route owner.")?;
            let routes = Self::read(&path)?;
            profiles.insert(id.to_owned(), Arc::new(routes));
        }
        Ok(Self {
            broker_pid,
            directory,
            profiles: RwLock::new(profiles),
            writer: Mutex::new(()),
        })
    }

    fn read(path: &Path) -> Result<Routes, &'static str> {
        let file = fs::File::open(path).map_err(|_| "Cannot open saved model routes.")?;
        if file
            .metadata()
            .map_err(|_| "Cannot inspect saved model routes.")?
            .len()
            > u64::from(crate::rest::LIMIT)
        {
            return Err("Saved model routes exceed the size limit.");
        }
        serde_json::from_reader(file).map_err(|_| "Invalid saved model routes.")
    }

    pub fn get(&self, principal: &str) -> Option<Arc<Routes>> {
        self.profiles.read().get(principal).cloned()
    }

    /// Acknowledgement follows atomic persistence and in-memory publication.
    pub fn update(&self, principal: &str, change: Change) -> Result<Value, &'static str> {
        let _serial = self.writer.lock();
        let mut next = self.get(principal).as_deref().cloned().unwrap_or_default();
        let state = match change {
            Change::Import(load) => next.load(load)?,
            Change::Select(update) => next.select(update)?,
            Change::Clear => {
                next = Routes::default();
                next.snapshot()?
            }
        };
        let file = tempfile::NamedTempFile::new_in(&self.directory)
            .map_err(|_| "Cannot create route state.")?;
        serde_json::to_writer(file.as_file(), &next).map_err(|_| "Cannot write route state.")?;
        let saved = file
            .as_file()
            .metadata()
            .map_err(|_| "Cannot measure route state.")?;
        if saved.len() > u64::from(crate::rest::LIMIT) {
            return Err("Saved model routes exceed the size limit.");
        }
        file.as_file()
            .sync_all()
            .map_err(|_| "Cannot flush route state.")?;
        file.persist(self.directory.join(format!("{principal}.json")))
            .map_err(|_| "Cannot replace route state.")?;
        self.profiles
            .write()
            .insert(principal.to_owned(), Arc::new(next));
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejected_edits_and_clearing_another_owner_preserve_saved_state() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path().to_owned(), 1).unwrap();
        let load = serde_json::from_value(json!({
            "source":"fixture", "catalog":{
                "harness_providers":{"codex":["example"]},
                "providers":{"example":{"base_url":"https://example.org/v1","models":["a"],
                    "credentials":{"one":{"kind":"api_key","api_key":"fixture-only"}}}}
            }
        }))
        .unwrap();
        let imported = store.update("100", Change::Import(load)).unwrap();
        let invalid = serde_json::from_value(json!({"harness":"codex","selection":{
            "provider":"unknown","credential":"one","model":"a"
        }}))
        .unwrap();
        assert!(store.update("100", Change::Select(invalid)).is_err());
        assert_eq!(store.get("100").unwrap().snapshot().unwrap(), imported);
        assert!(store.get("101").is_none());

        let cleared = store.update("101", Change::Clear).unwrap();
        let restored = Store::open(directory.path().to_owned(), 2).unwrap();
        assert_eq!(restored.get("100").unwrap().snapshot().unwrap(), imported);
        assert_eq!(restored.get("101").unwrap().snapshot().unwrap(), cleared);
    }
}
