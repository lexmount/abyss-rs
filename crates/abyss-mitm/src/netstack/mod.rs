//! Async packet IO and stream ownership shared by ingress and outbound stacks.
//!
//! This layer owns transport plumbing only. TUN admission, `WireGuard` keys,
//! destination selection, and MITM policy belong to their respective callers.

mod device;
mod stream;

pub use device::PacketDevice;
pub use stream::OwnedStream;

#[cfg(test)]
mod tests;
