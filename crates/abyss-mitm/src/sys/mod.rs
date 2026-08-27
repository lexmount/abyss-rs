//! Native platform wrappers used by `abyss-mitm`.
//!
//! All direct OS FFI is kept under this module. Higher-level MITM and CA code
//! must call safe wrappers from here instead of importing native APIs directly.

#[cfg(windows)]
pub mod windows;
