//! Linux persistence policy for CLI-owned CA material.

use std::{
    fs,
    io::{self, Write as _},
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::Path,
};

use abyss_mitm::CaMaterialPersistence;

use super::LinuxPlatformAdapter;

impl CaMaterialPersistence for LinuxPlatformAdapter {
    fn prepare_store(&self, directory: &Path, private_key: &Path) -> io::Result<()> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700).create(directory)?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        if private_key.exists() {
            fs::set_permissions(private_key, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    fn write_public(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        write_file(path, contents, 0o644)
    }

    fn write_private(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        write_file(path, contents, 0o600)
    }
}

fn write_file(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(mode);
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    file.set_permissions(fs::Permissions::from_mode(mode))
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt as _, time::SystemTime};

    use abyss_mitm::CaMaterialPersistence as _;

    use super::LinuxPlatformAdapter;

    #[test]
    fn ca_policy_protects_directory_and_private_key() {
        let root = std::env::temp_dir().join(format!(
            "abyss-cli-linux-ca-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("test clock should be valid")
                .as_nanos()
        ));
        let key = root.join("abyss-root-ca-key.pem");
        LinuxPlatformAdapter
            .prepare_store(&root, &key)
            .expect("CA store should prepare");
        LinuxPlatformAdapter
            .write_private(&key, b"private")
            .expect("private CA key should write");
        let public = root.join("abyss-root-ca.pem");
        LinuxPlatformAdapter
            .write_public(&public, b"public")
            .expect("public CA should write");

        assert_eq!(
            fs::metadata(&root)
                .expect("CA store metadata should read")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&key)
                .expect("CA key metadata should read")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&public)
                .expect("CA certificate metadata should read")
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        drop(fs::remove_dir_all(root));
    }
}
