//! Windows WFP ingress and redirect-context normalization.

mod redirect_records;
mod redirected_tcp;
mod upstream;

pub use redirected_tcp::IngressEndpoint;
