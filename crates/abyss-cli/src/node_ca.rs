//! Child-process Node trust configuration for the explicit proxy.
//!
//! Adds the Abyss CA while preserving inherited extra certificates. Bundles
//! are immutable and retained so detached children can start further processes.

use std::{
    fs,
    path::{Path, PathBuf},
};

use sha2::{Digest as _, Sha256};

use crate::{
    error::CliError,
    local_config::{LocalConfig, write_state_bytes},
    paths::CliPaths,
};

pub struct NodeCaBundle {
    path: PathBuf,
}

impl NodeCaBundle {
    pub fn from_paths(paths: &CliPaths) -> Result<Self, CliError> {
        let config = LocalConfig::load(&paths.config_file())?;
        let root = config
            .ca_path(&paths.config_file())?
            .join("abyss-root-ca.pem");
        let inherited = std::env::var_os("NODE_EXTRA_CA_CERTS").filter(|value| !value.is_empty());
        Self::prepare(
            &root,
            &paths.root().join("runtime/ca-bundles"),
            inherited.as_deref().map(Path::new),
        )
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn prepare(root: &Path, directory: &Path, inherited: Option<&Path>) -> Result<Self, CliError> {
        let root_contents = fs::read_to_string(root)
            .map_err(|source| CliError::filesystem("read Abyss root certificate", root, source))?;
        let Some(inherited) = inherited else {
            return Ok(Self {
                path: root.to_path_buf(),
            });
        };
        let previous = fs::read_to_string(inherited).map_err(|source| {
            CliError::filesystem("read inherited Node CA bundle", inherited, source)
        })?;
        if previous.contains(root_contents.trim()) {
            let path = fs::canonicalize(inherited).map_err(|source| {
                CliError::filesystem("resolve inherited Node CA bundle", inherited, source)
            })?;
            return Ok(Self { path });
        }
        let contents = format!("{}\n{}\n", previous.trim_end(), root_contents.trim());
        let digest = Sha256::digest(contents.as_bytes());
        let path = directory.join(format!("node-{digest:x}.pem"));
        if !path.exists() {
            write_state_bytes(contents.as_bytes(), &path)?;
        }
        Ok(Self { path })
    }
}

#[cfg(test)]
mod tests {
    use super::NodeCaBundle;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn inherited_trust_is_preserved_without_changing_the_original_file() {
        let root = std::env::temp_dir().join(format!(
            "abyss-node-ca-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let ca = root.join("abyss.pem");
        let previous = root.join("enterprise.pem");
        fs::write(&ca, "abyss certificate\n").unwrap();
        fs::write(&previous, "enterprise certificate\n").unwrap();
        let bundle = NodeCaBundle::prepare(&ca, &root, Some(&previous)).unwrap();
        assert_eq!(
            fs::read_to_string(bundle.path()).unwrap(),
            "enterprise certificate\nabyss certificate\n"
        );
        assert_eq!(
            fs::read_to_string(&previous).unwrap(),
            "enterprise certificate\n"
        );
        let repeated = NodeCaBundle::prepare(&ca, &root, Some(bundle.path())).unwrap();
        assert_eq!(repeated.path(), fs::canonicalize(bundle.path()).unwrap());
        assert_eq!(NodeCaBundle::prepare(&ca, &root, None).unwrap().path(), ca);
        assert!(NodeCaBundle::prepare(&ca, &root, Some(&root.join("missing.pem"))).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
