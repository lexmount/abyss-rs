//! Common normalization from detected Harness and parsed protocol values.

mod headers;
mod identifier;
pub mod normalizer;

pub use headers::ExchangeHeaders;
pub use normalizer::*;
