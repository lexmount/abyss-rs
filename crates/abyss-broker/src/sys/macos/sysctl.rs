//! Safe, read-only access to macOS sysctl values as uninterpreted bytes.
//!
//! Callers select the MIB, allocate the output and decode its contents. This
//! adapter only handles FFI buffer boundaries and native error propagation.

#![expect(
    unsafe_code,
    reason = "sysctl requires native pointers to checked input and output buffers."
)]

use std::{io, ptr};

/// Reads a sysctl value into `output`, returning the number of bytes written.
///
/// A successful length never exceeds `output.len()`. On error, the buffer may
/// contain partial output and must not be decoded as a complete value.
///
/// # Errors
///
/// Returns an error if the MIB is empty or too long, the native call fails
/// (including an insufficient output buffer), or its returned length is invalid.
pub fn sysctl_read(mib: &[i32], output: &mut [u8]) -> io::Result<usize> {
    if mib.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty sysctl MIB",
        ));
    }
    let mib_len = libc::c_uint::try_from(mib.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "sysctl MIB is too long"))?;
    let mut mib = mib.to_vec();
    let mut size = output.len();
    // SAFETY: mib owns mib_len initialized native integers. output is exclusively
    // borrowed and writable for size bytes. Both buffers and size remain valid
    // throughout the call; a null newp with zero newlen requests only a read.
    let result = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib_len,
            output.as_mut_ptr().cast(),
            &raw mut size,
            ptr::null_mut(),
            0,
        )
    };
    if result != 0_i32 {
        return Err(io::Error::last_os_error());
    }
    if size > output.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sysctl returned a length beyond the output buffer",
        ));
    }
    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::sysctl_read;

    #[test]
    fn reads_raw_bytes_and_returns_the_actual_length() {
        let mut output = [0_u8; 64];
        let size = sysctl_read(&[libc::CTL_KERN, libc::KERN_OSTYPE], &mut output).unwrap();
        assert_eq!(&output[..size], b"Darwin\0");
    }

    #[test]
    fn insufficient_output_preserves_the_native_error() {
        let error = sysctl_read(&[libc::CTL_KERN, libc::KERN_OSTYPE], &mut [0_u8; 1])
            .expect_err("a one-byte buffer cannot hold the OS type");
        assert_eq!(error.raw_os_error(), Some(libc::ENOMEM));
    }

    #[test]
    fn rejects_empty_mibs() {
        let error = sysctl_read(&[], &mut [0_u8; 64]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
}
