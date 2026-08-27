#![cfg(target_os = "macos")]

use std::{env, path::PathBuf};

use abyss_mitm::{CaStore, TrustStoreScope};

#[test]
#[ignore = "modifies the current user's macOS Keychain trust store"]
fn current_user_trust_store_round_trip() {
    assert_eq!(
        env::var("ABYSS_MACOS_CA_BLACKBOX_APPLY").as_deref(),
        Ok("1"),
        "set ABYSS_MACOS_CA_BLACKBOX_APPLY=1 to run this Keychain-modifying test"
    );
    let ca_dir = env::var_os("ABYSS_MACOS_CA_BLACKBOX_CA_DIR")
        .map(PathBuf::from)
        .expect("ABYSS_MACOS_CA_BLACKBOX_CA_DIR should point at test CA material");

    let store = CaStore::at(ca_dir);
    let ca = store
        .load_required()
        .expect("black-box CA material should load");
    let _cleanup = Cleanup {
        store: store.clone(),
    };

    ca.uninstall(TrustStoreScope::CurrentUser)
        .expect("pre-test uninstall should be idempotent");
    assert!(
        !store
            .status(TrustStoreScope::CurrentUser)
            .expect("status should query current user Keychain")
            .trust
            .expect("loaded CA should include trust status")
            .installed,
        "test CA should start untrusted"
    );

    ca.install(TrustStoreScope::CurrentUser)
        .expect("CA should install into current user Keychain");
    assert!(
        store
            .status(TrustStoreScope::CurrentUser)
            .expect("status should query current user Keychain after install")
            .trust
            .expect("loaded CA should include trust status")
            .installed,
        "test CA should be trusted after install"
    );

    ca.uninstall(TrustStoreScope::CurrentUser)
        .expect("CA should uninstall from current user Keychain");
    assert!(
        !store
            .status(TrustStoreScope::CurrentUser)
            .expect("status should query current user Keychain after uninstall")
            .trust
            .expect("loaded CA should include trust status")
            .installed,
        "test CA should be untrusted after uninstall"
    );
}

struct Cleanup {
    store: CaStore,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let Ok(Some(ca)) = self.store.load() else {
            return;
        };
        drop(ca.uninstall(TrustStoreScope::CurrentUser));
    }
}
