//! Bounded native process queries using one owned handle for image and command line.

#![expect(
    unsafe_code,
    reason = "Windows process queries use native handles and buffers."
)]

use std::{
    ffi::c_void,
    io,
    mem::{MaybeUninit, size_of},
    os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
};

use dlopen::wrapper::{Container, WrapperApi};
use dlopen_derive::WrapperApi;
use windows::{
    Win32::{
        Foundation::{HANDLE, NTSTATUS, UNICODE_STRING},
        System::Threading::{
            OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
            QueryFullProcessImageNameW,
        },
    },
    core::PWSTR,
};

// ProcessCommandLineInformation returns a local UNICODE_STRING followed by its
// UTF-16 contents. Resolve the native API at runtime and fail closed if absent.
const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;

#[derive(WrapperApi)]
struct ProcessApi {
    #[dlopen_name = "NtQueryInformationProcess"]
    query_information: unsafe extern "system" fn(
        process: HANDLE,
        information_class: u32,
        information: *mut c_void,
        information_length: u32,
        return_length: *mut u32,
    ) -> NTSTATUS,
}

const COMMAND_BUFFER_CAPACITY: usize = 0x0002_0000;

/// Private output storage for the `ProcessCommandLineInformation` query.
#[repr(transparent)]
struct CommandBuffer {
    // usize supplies UNICODE_STRING alignment. The heap allocation keeps its
    // embedded string pointer valid when this owner moves into assume_init.
    inner: Box<MaybeUninit<[usize; COMMAND_BUFFER_CAPACITY.div_ceil(size_of::<usize>())]>>,
}

impl CommandBuffer {
    fn maybeuninit() -> Self {
        Self {
            inner: Box::new_uninit(),
        }
    }

    fn capacity() -> u32 {
        u32::try_from(COMMAND_BUFFER_CAPACITY).expect("command buffer capacity fits ULONG")
    }

    fn as_raw_mut(&mut self) -> *mut c_void {
        self.inner.as_mut_ptr().cast()
    }

    /// Copies the initialized command line after validating the native layout.
    ///
    /// # Safety
    ///
    /// If `returned` is within the accepted header-to-capacity range, all fields
    /// of the `UNICODE_STRING` header must be initialized. Any string range that
    /// passes the bounds checks must contain initialized UTF-16 units. A successful
    /// `ProcessCommandLineInformation` query establishes these requirements; unused
    /// capacity and structure padding may remain uninitialized.
    unsafe fn assume_init(self, returned: u32) -> io::Result<Vec<u16>> {
        let returned = usize::try_from(returned).map_err(io::Error::other)?;
        if returned < size_of::<UNICODE_STRING>() || returned > COMMAND_BUFFER_CAPACITY {
            return Err(invalid_buffer());
        }
        let base = self.inner.as_ptr();
        // SAFETY: usize storage provides header alignment, the size check proves
        // the header fits, and the caller guarantees its fields are initialized.
        let header = unsafe { base.cast::<UNICODE_STRING>().read() };
        let length = usize::from(header.Length);
        let maximum = usize::from(header.MaximumLength);
        let offset = header
            .Buffer
            .0
            .addr()
            .checked_sub(base.addr())
            .ok_or_else(invalid_buffer)?;
        let end = offset.checked_add(length).ok_or_else(invalid_buffer)?;
        if length == 0
            || !length.is_multiple_of(size_of::<u16>())
            || length > maximum
            || offset < size_of::<UNICODE_STRING>()
            || !offset.is_multiple_of(size_of::<u16>())
            || end > returned
            || offset
                .checked_add(maximum)
                .is_none_or(|end| end > COMMAND_BUFFER_CAPACITY)
        {
            return Err(invalid_buffer());
        }
        let text = base.cast::<u16>().wrapping_byte_add(offset);
        // SAFETY: The checked range is aligned and within the owned allocation;
        // the caller guarantees these units are initialized. Only that range is
        // read, never padding, unused capacity, or the native pointer itself.
        let text = unsafe { std::slice::from_raw_parts(text, length.div_ceil(size_of::<u16>())) };
        Ok(text.to_vec())
    }
}

fn invalid_buffer() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid native command-line buffer",
    )
}

pub struct NativeProcess(OwnedHandle);

impl NativeProcess {
    pub(crate) fn open(pid: u32) -> io::Result<Self> {
        if pid == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid process id",
            ));
        }
        // SAFETY: Scalar arguments request only query access to the specified PID.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
            .map_err(io::Error::other)?;
        // SAFETY: Successful OpenProcess returns a new owned, non-null handle.
        Ok(Self(unsafe { OwnedHandle::from_raw_handle(handle.0) }))
    }

    pub(crate) fn executable(&self) -> io::Result<Vec<u16>> {
        let mut size = 0x8000_u32;
        let mut buffer = vec![0_u16; 0x8000];
        // SAFETY: The process handle is live; buffer and size are writable for
        // the entire call and size is the buffer capacity in UTF-16 units.
        unsafe {
            QueryFullProcessImageNameW(
                HANDLE(self.0.as_raw_handle()),
                PROCESS_NAME_FORMAT(0),
                PWSTR(buffer.as_mut_ptr()),
                &raw mut size,
            )
        }
        .map_err(io::Error::other)?;
        let size = usize::try_from(size).map_err(io::Error::other)?;
        if size == 0 || size > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid image path length",
            ));
        }
        buffer.truncate(size);
        Ok(buffer)
    }

    pub(crate) fn command_line(&self) -> io::Result<Vec<u16>> {
        // SAFETY: ntdll is the Windows system library, and ProcessApi declares the
        // exported function's system ABI. The local container keeps the library
        // loaded until this query finishes.
        let api = unsafe { Container::<ProcessApi>::load("ntdll.dll") }
            .map_err(|error| io::Error::new(io::ErrorKind::Unsupported, error))?;
        let mut buffer = CommandBuffer::maybeuninit();
        let mut returned = 0_u32;
        // SAFETY: The ABI matches NtQueryInformationProcess. The handle remains
        // owned and the aligned buffer has the advertised writable capacity.
        let status = unsafe {
            api.query_information(
                HANDLE(self.0.as_raw_handle()),
                PROCESS_COMMAND_LINE_INFORMATION,
                buffer.as_raw_mut(),
                CommandBuffer::capacity(),
                &raw mut returned,
            )
        };
        if status.0 < 0_i32 {
            return Err(io::Error::other(format!(
                "query process command line: {status:?}"
            )));
        }
        // SAFETY: The successful query initialized the header and its command-line
        // contents in buffer's stable allocation. assume_init checks their bounds.
        unsafe { buffer.assume_init(returned) }
    }
}

#[cfg(test)]
mod tests {
    use super::{COMMAND_BUFFER_CAPACITY, CommandBuffer, NativeProcess, UNICODE_STRING, size_of};
    use windows::core::PWSTR;

    fn fixture(length: u16, maximum: u16, offset: usize) -> CommandBuffer {
        let mut buffer = CommandBuffer::maybeuninit();
        let header = UNICODE_STRING {
            Length: length,
            MaximumLength: maximum,
            Buffer: PWSTR(buffer.as_raw_mut().cast::<u16>().wrapping_byte_add(offset)),
        };
        // SAFETY: The allocation has sufficient size and alignment for the header.
        // Only its fields are initialized; the string pointer is validated later.
        unsafe { buffer.as_raw_mut().cast::<UNICODE_STRING>().write(header) };
        buffer
    }

    #[test]
    fn rejects_invalid_output_sizes_before_reading_uninitialized_storage() {
        for returned in [
            0,
            u32::try_from(size_of::<UNICODE_STRING>() - 1).unwrap(),
            CommandBuffer::capacity() + 1,
        ] {
            let buffer = CommandBuffer::maybeuninit();
            // SAFETY: These sizes are outside the accepted header-to-capacity
            // range, so no initialized header or string is required.
            assert!(unsafe { buffer.assume_init(returned) }.is_err());
        }
    }

    #[test]
    fn rejects_out_of_bounds_native_strings() {
        let header = size_of::<UNICODE_STRING>();
        for (length, maximum, offset, returned) in [
            (0, 2, header, 32),
            (3, 4, header, 32),
            (4, 2, header, 32),
            (2, 2, 0, 32),
            (2, 2, header + 1, 32),
            (4, 4, 32, 32),
            (2, 2, usize::MAX, 32),
            (2, 4, COMMAND_BUFFER_CAPACITY - 2, CommandBuffer::capacity()),
        ] {
            let buffer = fixture(length, maximum, offset);
            // SAFETY: The header fields are initialized. Every fixture fails
            // bounds validation before any uninitialized string units are read.
            assert!(unsafe { buffer.assume_init(returned) }.is_err());
        }
    }

    #[test]
    fn copies_initialized_text_after_moving_buffer_ownership() {
        // Leave a gap after the header and all unused string capacity uninitialized.
        let offset = size_of::<UNICODE_STRING>() + 8;
        let mut buffer = fixture(4, 16, offset);
        let pointer = buffer.as_raw_mut();
        assert!(
            pointer
                .addr()
                .is_multiple_of(std::mem::align_of::<UNICODE_STRING>())
        );
        // SAFETY: This writes exactly two UTF-16 units to the aligned string
        // range inside the allocation; no terminator or spare capacity is written.
        unsafe {
            std::ptr::copy_nonoverlapping(
                [65_u16, 66].as_ptr(),
                pointer.cast::<u16>().wrapping_byte_add(offset),
                2,
            );
        }
        let mut moved = std::hint::black_box(buffer);
        assert_eq!(moved.as_raw_mut(), pointer);
        // SAFETY: The header and its reported string units are initialized. Moving
        // the owner preserves the allocation and the embedded string pointer.
        let text = unsafe { moved.assume_init(u32::try_from(offset + 4).unwrap()) }.unwrap();
        assert_eq!(text, [65, 66]);
    }

    #[test]
    fn copies_text_at_allocation_boundaries_and_maximum_utf16_length() {
        for (offset, length) in [
            (size_of::<UNICODE_STRING>(), 2_u16),
            (COMMAND_BUFFER_CAPACITY - 2, 2),
            (size_of::<UNICODE_STRING>(), u16::MAX - 1),
        ] {
            let text = vec![0xd800_u16; usize::from(length).div_ceil(size_of::<u16>())];
            let mut buffer = fixture(length, length, offset);
            // SAFETY: These fixtures place the entire text in an aligned range
            // within the allocation. No terminator or unused capacity is read.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    text.as_ptr(),
                    buffer.as_raw_mut().cast::<u16>().wrapping_byte_add(offset),
                    text.len(),
                );
            }
            let returned = u32::try_from(offset + usize::from(length)).unwrap();
            // SAFETY: Both the header and its complete reported text are initialized.
            assert_eq!(unsafe { buffer.assume_init(returned) }.unwrap(), text);
        }
    }

    #[test]
    fn native_queries_survive_repeated_concurrent_library_and_handle_drops() {
        let pid = std::process::id();
        let (expected_image, expected_command) = {
            let process = NativeProcess::open(pid).unwrap();
            (
                process.executable().unwrap(),
                process.command_line().unwrap(),
            )
        };

        std::thread::scope(|scope| {
            for _ in 0_u32..8 {
                scope.spawn(|| {
                    for _ in 0_u32..64 {
                        let (image, command) = {
                            let process = NativeProcess::open(pid).unwrap();
                            (
                                process.executable().unwrap(),
                                process.command_line().unwrap(),
                            )
                        };
                        // Neither result borrows the process handle, query buffer,
                        // or the local dlopen container, all of which are dropped.
                        assert_eq!(image, expected_image);
                        assert_eq!(command, expected_command);
                    }
                });
            }
        });
    }
}
