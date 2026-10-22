//! Validates native command-line buffer offsets before copying UTF-16 code units.

#![expect(
    unsafe_code,
    reason = "Native buffers require aligned storage and a typed header read."
)]

use std::{ffi::c_void, io, mem::size_of};
use windows::Win32::Foundation::UNICODE_STRING;

const CAPACITY: u32 = 0x0002_0000;

pub(super) struct CommandBuffer(Vec<usize>);

impl CommandBuffer {
    pub(super) fn new() -> Self {
        Self(vec![
            0;
            usize::try_from(CAPACITY)
                .expect("buffer capacity fits usize")
                .div_ceil(size_of::<usize>())
        ])
    }

    pub(super) const fn capacity() -> u32 {
        CAPACITY
    }

    pub(super) const fn as_mut_ptr(&mut self) -> *mut c_void {
        self.0.as_mut_ptr().cast()
    }

    pub(super) fn decode(&self, returned: u32) -> io::Result<Vec<u16>> {
        let returned = usize::try_from(returned).map_err(io::Error::other)?;
        let capacity = usize::try_from(CAPACITY).map_err(io::Error::other)?;
        if returned < size_of::<UNICODE_STRING>() || returned > capacity {
            return Err(invalid_buffer());
        }
        // SAFETY: The owned initialized usize allocation is aligned for the
        // pointer-containing UNICODE_STRING and contains its complete header.
        let header = unsafe { self.0.as_ptr().cast::<UNICODE_STRING>().read() };
        let length = usize::from(header.Length);
        let maximum = usize::from(header.MaximumLength);
        let offset = header
            .Buffer
            .0
            .addr()
            .checked_sub(self.0.as_ptr().addr())
            .ok_or_else(invalid_buffer)?;
        let end = offset.checked_add(length).ok_or_else(invalid_buffer)?;
        if length == 0
            || !length.is_multiple_of(2)
            || length > maximum
            || offset < size_of::<UNICODE_STRING>()
            || !offset.is_multiple_of(2)
            || end > returned
            || offset.checked_add(maximum).is_none_or(|end| end > capacity)
        {
            return Err(invalid_buffer());
        }
        // SAFETY: The allocation owns at least capacity initialized bytes. Only
        // the checked local slice is read; the native pointer is never dereferenced.
        let bytes = unsafe { std::slice::from_raw_parts(self.0.as_ptr().cast::<u8>(), capacity) };
        Ok(bytes[offset..end]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_ne_bytes(*pair))
            .collect())
    }
}

fn invalid_buffer() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid native command-line buffer",
    )
}

#[cfg(test)]
mod tests {
    use super::{CAPACITY, CommandBuffer, UNICODE_STRING, size_of};
    use windows::core::PWSTR;

    fn fixture(length: u16, maximum: u16, offset: usize) -> CommandBuffer {
        let mut buffer = CommandBuffer::new();
        let header = UNICODE_STRING {
            Length: length,
            MaximumLength: maximum,
            Buffer: PWSTR(
                buffer
                    .0
                    .as_mut_ptr()
                    .cast::<u16>()
                    .wrapping_byte_add(offset),
            ),
        };
        // SAFETY: The fixture allocation has sufficient size and alignment for
        // the header; its pointer field is deliberately validated by decode.
        unsafe { buffer.as_mut_ptr().cast::<UNICODE_STRING>().write(header) };
        buffer
    }

    #[test]
    fn rejects_truncated_headers_and_out_of_bounds_native_strings() {
        let header = size_of::<UNICODE_STRING>();
        for (length, maximum, offset, returned) in [
            (2, 2, header, 0),
            (2, 2, header, CAPACITY + 1),
            (0, 2, header, 32),
            (3, 4, header, 32),
            (4, 2, header, 32),
            (2, 2, 0, 32),
            (2, 2, header + 1, 32),
            (4, 4, 32, 32),
            (2, 2, usize::MAX, 32),
        ] {
            assert!(fixture(length, maximum, offset).decode(returned).is_err());
        }
    }

    #[test]
    fn copies_only_the_reported_command_without_following_external_pointers() {
        let mut buffer = fixture(4, 6, size_of::<UNICODE_STRING>());
        // SAFETY: This fixture writes three UTF-16 units immediately after the
        // aligned header, within the owned allocation.
        unsafe {
            std::ptr::copy_nonoverlapping(
                [65_u16, 66, 0].as_ptr(),
                buffer
                    .as_mut_ptr()
                    .cast::<u16>()
                    .wrapping_byte_add(size_of::<UNICODE_STRING>()),
                3,
            );
        }
        assert_eq!(buffer.decode(32).unwrap(), [65, 66]);
    }
}
