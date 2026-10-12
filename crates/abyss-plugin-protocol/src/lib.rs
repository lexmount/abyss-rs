//! Shared Rust wire contract for the Abyss broker plugin protocol.
//!
//! This crate contains payload types and protocol constants only. Broker
//! runtime behavior and SDK client behavior remain in their owning crates.

pub mod event;
pub mod message;

/// Maximum UTF-8 JSON payload accepted since protocol v2.
pub const MAX_JSON_FRAME_BYTES: u32 = 64 * 1024 * 1024;
