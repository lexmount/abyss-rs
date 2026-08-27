//! Safe process metadata wrappers around macOS `libproc`.

#![expect(
    unsafe_code,
    reason = "Calling proc_pidinfo and initializing its native output require unsafe code."
)]

use std::{
    ffi::OsString,
    io,
    mem::{MaybeUninit, size_of},
    os::unix::ffi::OsStringExt as _,
    path::PathBuf,
};

/// Reads the current working directory for a live macOS process.
///
/// `Ok(None)` means `libproc` returned a complete process record without a
/// current directory. Process exit, permission failures, and malformed native
/// output are returned as errors so the caller can choose its best-effort
/// policy without weakening this system boundary.
///
/// # Errors
///
/// Returns an I/O error when the PID cannot be represented by `libproc`, the
/// native call fails or returns a partial record, or the fixed-size path buffer
/// is not NUL terminated.
pub fn process_working_directory(pid: u32) -> io::Result<Option<PathBuf>> {
    let native_pid = libc::pid_t::try_from(pid)
        .map_err(|_| invalid_input(format!("process id {pid} does not fit pid_t")))?;
    if native_pid <= 0_i32 {
        return Err(invalid_input("process id must be positive"));
    }

    let expected_size = libc::c_int::try_from(size_of::<libc::proc_vnodepathinfo>())
        .map_err(|_| invalid_input("proc_vnodepathinfo size does not fit c_int"))?;
    let mut info = MaybeUninit::<libc::proc_vnodepathinfo>::zeroed();

    // SAFETY: `info` points to writable storage of exactly `expected_size`
    // bytes for the duration of the call. The PID and flavor use the types and
    // constants declared by libc for macOS. The value is only assumed
    // initialized after libproc reports that it filled the complete structure.
    let actual_size = unsafe {
        libc::proc_pidinfo(
            native_pid,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            info.as_mut_ptr().cast(),
            expected_size,
        )
    };
    if actual_size <= 0_i32 {
        return Err(io::Error::last_os_error());
    }
    if actual_size != expected_size {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("proc_pidinfo returned {actual_size} bytes, expected {expected_size}"),
        ));
    }

    // SAFETY: The exact-size check above establishes that libproc initialized
    // the complete `proc_vnodepathinfo` output structure.
    let info = unsafe { info.assume_init() };
    path_from_native_buffer(&info.pvi_cdir.vip_path)
}

fn path_from_native_buffer(buffer: &[[libc::c_char; 32]; 32]) -> io::Result<Option<PathBuf>> {
    let capacity = buffer
        .len()
        .checked_mul(buffer[0].len())
        .expect("native path buffer dimensions should fit usize");
    let mut path = Vec::with_capacity(capacity);
    let mut terminated = false;
    for byte in buffer.iter().flatten().copied() {
        if byte == 0 {
            terminated = true;
            break;
        }
        path.push(byte.cast_unsigned());
    }
    if !terminated {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proc_pidinfo working-directory path is not NUL terminated",
        ));
    }
    if path.is_empty() {
        return Ok(None);
    }
    Ok(Some(PathBuf::from(OsString::from_vec(path))))
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::{path_from_native_buffer, process_working_directory};

    #[test]
    fn reads_the_current_process_working_directory() {
        let expected = std::env::current_dir().expect("test cwd should be available");

        assert_eq!(
            process_working_directory(std::process::id())
                .expect("current process cwd lookup should succeed"),
            Some(expected)
        );
    }

    #[test]
    fn rejects_zero_process_id() {
        let error = process_working_directory(0).expect_err("PID zero should be rejected");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn native_path_buffer_requires_nul_termination() {
        let buffer = [[b'a'.cast_signed(); 32]; 32];

        let error =
            path_from_native_buffer(&buffer).expect_err("unterminated native path should fail");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn empty_native_path_is_unavailable() {
        let buffer = [[0; 32]; 32];

        assert_eq!(
            path_from_native_buffer(&buffer).expect("empty path should parse"),
            None
        );
    }
}
