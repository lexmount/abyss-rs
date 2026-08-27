//! Shared Rust wire contract for the Abyss broker plugin protocol.
//!
//! This crate contains payload types and protocol constants only. Broker
//! runtime behavior and SDK client behavior remain in their owning crates.

pub mod event;
pub mod message;

/// Maximum UTF-8 JSON payload accepted in one version 1 frame.
pub const MAX_JSON_FRAME_BYTES: u32 = 16 * 1024 * 1024;
