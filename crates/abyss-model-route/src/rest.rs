//! HTTP/1.1 management over a local OS-authenticated connection.

mod client;
mod server;

pub use client::Client;
pub use server::serve;

pub const LIMIT: u32 = 4 * 1024 * 1024;
pub const STATUS: &str = "/v1/model-route/status";
pub const STATE: &str = "/v1/model-route";
pub const CATALOG: &str = "/v1/model-route/catalog";
pub const SELECTION: &str = "/v1/model-route/selection";
pub const PROFILE: &str = "/v1/model-route/profile";
