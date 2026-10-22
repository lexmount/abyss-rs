//! Bounded native process queries using one owned handle for image and command line.

#![expect(
    unsafe_code,
    reason = "Windows process queries use native handles and buffers."
)]

mod command_buffer;

use std::{
    ffi::c_void,
    io,
    os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
};

use windows::{
    Win32::{
        Foundation::{HANDLE, NTSTATUS},
        System::{
            LibraryLoader::{GetModuleHandleW, GetProcAddress},
            Threading::{
                OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
                QueryFullProcessImageNameW,
            },
        },
    },
    core::{PWSTR, s, w},
};

use command_buffer::CommandBuffer;

// ProcessCommandLineInformation returns a local UNICODE_STRING followed by its
// UTF-16 contents. Resolve the native API at runtime and fail closed if absent.
const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;
type QueryProcess = unsafe extern "system" fn(HANDLE, u32, *mut c_void, u32, *mut u32) -> NTSTATUS;

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
        let query = Self::query_function()?;
        let mut buffer = CommandBuffer::new();
        let mut returned = 0_u32;
        // SAFETY: The ABI matches NtQueryInformationProcess. The handle remains
        // owned and the aligned buffer has the advertised writable capacity.
        let status = unsafe {
            query(
                HANDLE(self.0.as_raw_handle()),
                PROCESS_COMMAND_LINE_INFORMATION,
                buffer.as_mut_ptr(),
                CommandBuffer::capacity(),
                &raw mut returned,
            )
        };
        if status.0 < 0_i32 {
            return Err(io::Error::other(format!(
                "query process command line: {status:?}"
            )));
        }
        buffer.decode(returned)
    }

    fn query_function() -> io::Result<QueryProcess> {
        // SAFETY: ntdll is a process-lifetime module; the name is NUL-terminated.
        let module = unsafe { GetModuleHandleW(w!("ntdll.dll")) }.map_err(io::Error::other)?;
        // SAFETY: The module remains loaded and the export name is NUL-terminated.
        let function = unsafe { GetProcAddress(module, s!("NtQueryInformationProcess")) }
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::Unsupported, "process query API unavailable")
            })?;
        // SAFETY: This export has the documented NtQueryInformationProcess ABI;
        // both values are system-ABI function pointers of the same size.
        Ok(unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, QueryProcess>(function)
        })
    }
}
