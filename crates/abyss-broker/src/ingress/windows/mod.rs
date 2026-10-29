//! Windows WFP ingress and redirect-context normalization.

mod redirected_tcp;
mod upstream;

pub use redirected_tcp::IngressEndpoint;
