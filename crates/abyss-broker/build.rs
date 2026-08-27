//! Builds platform-specific native bindings used by the endpoint broker.

use std::{env, path::PathBuf};

const CALLOUT_ABI_HEADER: &str = "include/abyss_callout_abi.h";
const GENERATED_BINDINGS: &str = "abyss_callout_abi.rs";

fn main() {
    match env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("windows") => generate_windows_bindings(),
        Ok("macos") => link_macos_process_library(),
        _ => {}
    }
}

fn generate_windows_bindings() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let header_path = manifest_dir.join(CALLOUT_ABI_HEADER);
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let generated_path = out_dir.join(GENERATED_BINDINGS);

    println!("cargo:rerun-if-changed={}", header_path.display());

    let bindings = bindgen::Builder::default()
        .header(header_path.display().to_string())
        .clang_arg("-DABYSS_CALLOUT_BINDGEN")
        .allowlist_type("ABYSS_CALLOUT_REDIRECT_CONTEXT")
        .allowlist_var("ABYSS_CALLOUT_.*_BINDGEN")
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("generate broker callout ABI bindings");

    bindings
        .write_to_file(generated_path)
        .expect("write broker callout ABI bindings");
}

fn link_macos_process_library() {
    println!("cargo:rustc-link-lib=proc");
}
