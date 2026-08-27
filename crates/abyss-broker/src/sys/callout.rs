//! Safe wrappers for the Windows callout-driver redirect-context ABI.

#![expect(
    unsafe_code,
    reason = "Reading the bindgen-generated C header and its address union requires unsafe code."
)]

use std::{
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::windows::io::AsSocket as _,
};

use thiserror::Error;
use tokio::net::TcpStream;

use crate::connection::OriginalDestination;

use super::winsock::{self, WinSockError};

use generated::{ABYSS_CALLOUT_MAX_APPLICATION_ID_BYTES_BINDGEN, ABYSS_CALLOUT_REDIRECT_CONTEXT};

/// Valid fixed header recovered from a socket redirected by the callout driver.
struct RedirectContext {
    inner: ABYSS_CALLOUT_REDIRECT_CONTEXT,
}

mod generated {
    #![expect(
        unsafe_code,
        reason = "bindgen emits unsafe zero-initialization for C unions."
    )]
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        clippy::multiple_unsafe_ops_per_block,
        clippy::undocumented_unsafe_blocks,
        clippy::unreadable_literal,
        clippy::upper_case_acronyms,
        reason = "bindgen preserves C ABI style and emits definitions used by the callout wrapper."
    )]

    include!(concat!(env!("OUT_DIR"), "/abyss_callout_abi.rs"));
}

impl RedirectContext {
    fn max_encoded_size() -> usize {
        size_of::<ABYSS_CALLOUT_REDIRECT_CONTEXT>()
            .checked_add(max_application_id_bytes())
            .expect("callout redirect context size should fit usize")
    }

    /// Decodes the current fixed header and its sole trailing field.
    fn decode(
        bytes: &[u8],
    ) -> Result<(OriginalDestination, Option<u32>, Option<String>), RedirectContextError> {
        let header_size = size_of::<ABYSS_CALLOUT_REDIRECT_CONTEXT>();
        if bytes.len() < header_size {
            return Err(RedirectContextError::HeaderTooShort {
                actual: bytes.len(),
                required: header_size,
            });
        }

        // SAFETY: The length check above proves that `bytes` contains a complete
        // generated header. The header consists only of integer fields and an
        // integer/byte-array union, so every initialized bit pattern is valid.
        // `read_unaligned` does not assume the byte buffer's alignment.
        let inner = unsafe {
            bytes
                .as_ptr()
                .cast::<ABYSS_CALLOUT_REDIRECT_CONTEXT>()
                .read_unaligned()
        };
        let context = Self::from_native(inner, bytes.len())?;
        let application_id_bytes = bytes
            .get(header_size..)
            .expect("validated redirect context contains its complete fixed header");
        let maximum_application_id_bytes = max_application_id_bytes();
        if application_id_bytes.len() > maximum_application_id_bytes {
            return Err(RedirectContextError::ApplicationIdTooLarge {
                actual: application_id_bytes.len(),
                maximum: maximum_application_id_bytes,
            });
        }
        let application_id = decode_application_id(application_id_bytes)?;

        Ok((
            context.original_destination(),
            context.process_id(),
            application_id,
        ))
    }

    /// Wraps a native header when its size and fixed fields match the current ABI.
    fn from_native(
        inner: ABYSS_CALLOUT_REDIRECT_CONTEXT,
        actual_size: usize,
    ) -> Result<Self, RedirectContextError> {
        let declared_size = usize::try_from(inner.Size)
            .map_err(|_| RedirectContextError::FieldDoesNotFitPlatform("Size"))?;
        if declared_size != actual_size {
            return Err(RedirectContextError::DeclaredSizeMismatch {
                declared: declared_size,
                actual: actual_size,
            });
        }
        if inner.Reserved != 0 {
            return Err(RedirectContextError::ReservedFieldNotZero);
        }
        if !is_supported_address_family(inner.AddressFamily) {
            return Err(RedirectContextError::UnsupportedAddressFamily(
                inner.AddressFamily,
            ));
        }

        Ok(Self { inner })
    }

    fn original_destination(&self) -> OriginalDestination {
        OriginalDestination {
            ip: self.address(),
            port: self.inner.OriginalPort,
        }
    }

    fn process_id(&self) -> Option<u32> {
        (self.inner.ProcessId != 0).then_some(self.inner.ProcessId)
    }

    fn address(&self) -> IpAddr {
        if self.inner.AddressFamily == winsock::AddressFamily::ipv4() {
            // SAFETY: `from_native` only constructs `RedirectContext` for
            // supported address families. The driver writes `Ipv4Address`
            // when `AddressFamily` is AF_INET.
            let raw_address = unsafe { self.inner.OriginalDestination.Ipv4Address };
            IpAddr::V4(Ipv4Addr::from(u32::from_be(raw_address)))
        } else {
            // SAFETY: `from_native` rejects every non-IPv4/non-IPv6 family.
            // Therefore the remaining valid case is AF_INET6, and the driver
            // writes `Ipv6Address` for that family.
            let raw_address = unsafe { self.inner.OriginalDestination.Ipv6Address };
            IpAddr::V6(Ipv6Addr::from(raw_address))
        }
    }
}

/// Queries the current redirect metadata attached to a redirected TCP stream.
///
/// # Errors
///
/// Returns `RedirectContextError` when `WSAIoctl` rejects the query or the
/// callout driver returns a context that does not match the current ABI.
pub fn query_redirect_metadata(
    stream: &TcpStream,
) -> Result<(OriginalDestination, Option<u32>, Option<String>), RedirectContextError> {
    let bytes = winsock::ioctl_output_buffer(
        stream.as_socket(),
        winsock::SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT_CODE,
        RedirectContext::max_encoded_size(),
    )?;

    RedirectContext::decode(&bytes)
}

/// Failure to query or validate the current callout-driver redirect context.
#[derive(Debug, Error)]
pub enum RedirectContextError {
    #[error("query Windows WFP redirect context: {0}")]
    Query(#[from] WinSockError),
    #[error("redirect context has {actual} bytes; the current ABI requires at least {required}")]
    HeaderTooShort { actual: usize, required: usize },
    #[error("redirect context declares {declared} bytes but WinSock returned {actual}")]
    DeclaredSizeMismatch { declared: usize, actual: usize },
    #[error("redirect context field `{0}` does not fit the current platform")]
    FieldDoesNotFitPlatform(&'static str),
    #[error("redirect context reserved field is not zero")]
    ReservedFieldNotZero,
    #[error("redirect context uses unsupported Windows address family {0}")]
    UnsupportedAddressFamily(u32),
    #[error("redirect context application ID is {actual} bytes; maximum is {maximum}")]
    ApplicationIdTooLarge { actual: usize, maximum: usize },
    #[error("redirect context application ID has an odd byte length")]
    ApplicationIdOddLength,
    #[error("redirect context application ID is not valid UTF-16LE")]
    ApplicationIdInvalidUtf16,
    #[error("redirect context application ID is empty")]
    ApplicationIdEmpty,
    #[error("redirect context application ID contains an embedded NUL")]
    ApplicationIdEmbeddedNul,
}

fn is_supported_address_family(address_family: u32) -> bool {
    address_family == winsock::AddressFamily::ipv4()
        || address_family == winsock::AddressFamily::ipv6()
}

fn max_application_id_bytes() -> usize {
    usize::try_from(ABYSS_CALLOUT_MAX_APPLICATION_ID_BYTES_BINDGEN)
        .expect("callout application ID limit should fit usize")
}

fn decode_application_id(bytes: &[u8]) -> Result<Option<String>, RedirectContextError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    if !bytes.len().is_multiple_of(2) {
        return Err(RedirectContextError::ApplicationIdOddLength);
    }

    let mut code_units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect::<Vec<_>>();
    while code_units.last() == Some(&0) {
        code_units.pop();
    }
    if code_units.is_empty() {
        return Err(RedirectContextError::ApplicationIdEmpty);
    }
    if code_units.contains(&0) {
        return Err(RedirectContextError::ApplicationIdEmbeddedNul);
    }

    String::from_utf16(&code_units)
        .map(Some)
        .map_err(|_| RedirectContextError::ApplicationIdInvalidUtf16)
}

#[cfg(test)]
mod tests {
    use std::{
        mem::{offset_of, size_of},
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
    };

    use super::{
        RedirectContext, RedirectContextError, generated::ABYSS_CALLOUT_REDIRECT_CONTEXT,
        max_application_id_bytes, winsock,
    };

    #[test]
    fn current_ipv4_context_decodes_all_platform_metadata() {
        let application_id = r"\device\harddiskvolume4\program files\openai\codex.exe";
        let bytes = current_context(
            winsock::AddressFamily::ipv4(),
            443,
            &Ipv4Addr::new(93, 184, 216, 34).octets(),
            17_042,
            Some(application_id),
        );

        let (destination, process_id, decoded_application_id) =
            RedirectContext::decode(&bytes).expect("current context should decode");

        assert_eq!(destination.ip, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(destination.port, 443);
        assert_eq!(process_id, Some(17_042));
        assert_eq!(decoded_application_id.as_deref(), Some(application_id));
    }

    #[test]
    fn current_ipv6_context_decodes_destination() {
        let address = Ipv6Addr::LOCALHOST;
        let bytes = current_context(
            winsock::AddressFamily::ipv6(),
            8443,
            &address.octets(),
            91,
            None,
        );

        let (destination, process_id, application_id) =
            RedirectContext::decode(&bytes).expect("current IPv6 context should decode");

        assert_eq!(destination.ip, IpAddr::V6(address));
        assert_eq!(destination.port, 8443);
        assert_eq!(process_id, Some(91));
        assert!(application_id.is_none());
    }

    #[test]
    fn current_context_can_report_no_source_metadata() {
        let bytes = current_context(
            winsock::AddressFamily::ipv4(),
            443,
            &[127, 0, 0, 1],
            0,
            None,
        );

        let (_destination, process_id, application_id) = RedirectContext::decode(&bytes)
            .expect("current context without source metadata should decode");

        assert!(process_id.is_none());
        assert!(application_id.is_none());
    }

    #[test]
    fn trailing_utf16_terminators_are_removed() {
        let bytes = current_context(
            winsock::AddressFamily::ipv4(),
            443,
            &[127, 0, 0, 1],
            91,
            Some("C:\\Program Files\\OpenAI\\codex.exe\0\0"),
        );

        let (_destination, _process_id, application_id) =
            RedirectContext::decode(&bytes).expect("terminated application ID should decode");

        assert_eq!(
            application_id.as_deref(),
            Some(r"C:\Program Files\OpenAI\codex.exe")
        );
    }

    #[test]
    fn invalid_fixed_header_is_rejected() {
        let header_size = size_of::<ABYSS_CALLOUT_REDIRECT_CONTEXT>();
        let short_size = header_size
            .checked_sub(1)
            .expect("redirect context header is nonempty");
        let mut short = vec![0_u8; short_size];
        write_u32(
            &mut short,
            offset_of!(ABYSS_CALLOUT_REDIRECT_CONTEXT, Size),
            u32::try_from(short_size).expect("fixture size fits u32"),
        );
        assert!(matches!(
            RedirectContext::decode(&short),
            Err(RedirectContextError::HeaderTooShort {
                actual,
                required
            }) if actual == short_size && required == header_size
        ));

        let mut reserved = current_context(
            winsock::AddressFamily::ipv4(),
            443,
            &[127, 0, 0, 1],
            91,
            None,
        );
        write_u16(
            &mut reserved,
            offset_of!(ABYSS_CALLOUT_REDIRECT_CONTEXT, Reserved),
            1,
        );
        assert!(matches!(
            RedirectContext::decode(&reserved),
            Err(RedirectContextError::ReservedFieldNotZero)
        ));

        let mut size_mismatch = current_context(
            winsock::AddressFamily::ipv4(),
            443,
            &[127, 0, 0, 1],
            91,
            None,
        );
        let invalid_declared_size = header_size
            .checked_add(1)
            .expect("fixture size should not overflow");
        write_u32(
            &mut size_mismatch,
            offset_of!(ABYSS_CALLOUT_REDIRECT_CONTEXT, Size),
            u32::try_from(invalid_declared_size).expect("fixture size fits u32"),
        );
        assert!(matches!(
            RedirectContext::decode(&size_mismatch),
            Err(RedirectContextError::DeclaredSizeMismatch { .. })
        ));

        let unsupported = current_context(0, 443, &[127, 0, 0, 1], 91, None);
        assert!(matches!(
            RedirectContext::decode(&unsupported),
            Err(RedirectContextError::UnsupportedAddressFamily(0))
        ));
    }

    #[test]
    fn application_id_validation_is_strict() {
        let oversized_length = max_application_id_bytes()
            .checked_add(2)
            .expect("fixture length should not overflow");
        let oversized_size = size_of::<ABYSS_CALLOUT_REDIRECT_CONTEXT>()
            .checked_add(oversized_length)
            .expect("fixture size should not overflow");
        let mut oversized = vec![0_u8; oversized_size];
        seed_header(
            &mut oversized,
            winsock::AddressFamily::ipv4(),
            443,
            &[127, 0, 0, 1],
            91,
        );
        assert!(matches!(
            RedirectContext::decode(&oversized),
            Err(RedirectContextError::ApplicationIdTooLarge { .. })
        ));

        let mut invalid_utf16 = current_context(
            winsock::AddressFamily::ipv4(),
            443,
            &[127, 0, 0, 1],
            91,
            Some("x"),
        );
        invalid_utf16[size_of::<ABYSS_CALLOUT_REDIRECT_CONTEXT>()..]
            .copy_from_slice(&0xd800_u16.to_le_bytes());
        assert!(matches!(
            RedirectContext::decode(&invalid_utf16),
            Err(RedirectContextError::ApplicationIdInvalidUtf16)
        ));

        let odd_context_size = size_of::<ABYSS_CALLOUT_REDIRECT_CONTEXT>()
            .checked_add(1)
            .expect("fixture size should not overflow");
        let mut odd_length = vec![0_u8; odd_context_size];
        seed_header(
            &mut odd_length,
            winsock::AddressFamily::ipv4(),
            443,
            &[127, 0, 0, 1],
            91,
        );
        assert!(matches!(
            RedirectContext::decode(&odd_length),
            Err(RedirectContextError::ApplicationIdOddLength)
        ));
    }

    #[test]
    fn generated_layout_matches_the_wrapper_contract() {
        assert_eq!(size_of::<ABYSS_CALLOUT_REDIRECT_CONTEXT>(), 32);
        assert_eq!(offset_of!(ABYSS_CALLOUT_REDIRECT_CONTEXT, Size), 0);
        assert_eq!(offset_of!(ABYSS_CALLOUT_REDIRECT_CONTEXT, AddressFamily), 4);
        assert_eq!(offset_of!(ABYSS_CALLOUT_REDIRECT_CONTEXT, OriginalPort), 8);
        assert_eq!(offset_of!(ABYSS_CALLOUT_REDIRECT_CONTEXT, Reserved), 10);
        assert_eq!(
            offset_of!(ABYSS_CALLOUT_REDIRECT_CONTEXT, OriginalDestination),
            12
        );
        assert_eq!(offset_of!(ABYSS_CALLOUT_REDIRECT_CONTEXT, ProcessId), 28);
        assert_eq!(max_application_id_bytes(), 4096);
        assert_eq!(RedirectContext::max_encoded_size(), 4128);
    }

    fn current_context(
        address_family: u32,
        port: u16,
        address: &[u8],
        process_id: u32,
        application_id: Option<&str>,
    ) -> Vec<u8> {
        let application_id = application_id.map_or_else(Vec::new, |value| {
            value
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>()
        });
        let header_size = size_of::<ABYSS_CALLOUT_REDIRECT_CONTEXT>();
        let context_size = header_size
            .checked_add(application_id.len())
            .expect("application fixture context size should not overflow");
        let mut bytes = vec![0_u8; context_size];
        seed_header(&mut bytes, address_family, port, address, process_id);
        bytes[header_size..].copy_from_slice(&application_id);
        bytes
    }

    fn seed_header(
        bytes: &mut [u8],
        address_family: u32,
        port: u16,
        address: &[u8],
        process_id: u32,
    ) {
        write_u32(
            bytes,
            offset_of!(ABYSS_CALLOUT_REDIRECT_CONTEXT, Size),
            u32::try_from(bytes.len()).expect("fixture size fits u32"),
        );
        write_u32(
            bytes,
            offset_of!(ABYSS_CALLOUT_REDIRECT_CONTEXT, AddressFamily),
            address_family,
        );
        write_u16(
            bytes,
            offset_of!(ABYSS_CALLOUT_REDIRECT_CONTEXT, OriginalPort),
            port,
        );
        let destination_offset = offset_of!(ABYSS_CALLOUT_REDIRECT_CONTEXT, OriginalDestination);
        bytes
            .get_mut(destination_offset..)
            .and_then(|remaining| remaining.get_mut(..address.len()))
            .expect("fixture address should fit context")
            .copy_from_slice(address);
        write_u32(
            bytes,
            offset_of!(ABYSS_CALLOUT_REDIRECT_CONTEXT, ProcessId),
            process_id,
        );
    }

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes
            .get_mut(offset..)
            .and_then(|remaining| remaining.get_mut(..2))
            .expect("u16 fixture field should fit context")
            .copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes
            .get_mut(offset..)
            .and_then(|remaining| remaining.get_mut(..4))
            .expect("u32 fixture field should fit context")
            .copy_from_slice(&value.to_le_bytes());
    }
}
