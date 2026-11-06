//! Common normalization from detected Harness and parsed protocol values.

mod identifier;
pub mod normalizer;
mod passthrough;

pub use normalizer::*;
pub use passthrough::ExchangePassthrough;
