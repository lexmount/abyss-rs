//! Bounded macOS argv reads for process entry attribution, with PID-version checks.
//! Native buffers are discarded after extracting the entry; environment and full
//! command lines are never returned to diagnostics or policy code.

#![expect(
    unsafe_code,
    reason = "Native sysctl and libproc reads require checked FFI output buffers."
)]

use std::{
    io,
    mem::{MaybeUninit, size_of},
    ptr,
};

// macOS ABI documented by Apple in bsd/sys/proc_info_private.h:
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info_private.h
const PROC_PIDUNIQIDENTIFIERINFO: libc::c_int = 17;
#[repr(C)]
struct ProcessIdentity {
    uuid: [u8; 16],
    unique_id: u64,
    parent_unique_id: u64,
    version: i32,
    original_parent_version: i32,
    reserved: [u64; 2],
}
const _: () = assert!(
    size_of::<ProcessIdentity>() == 56,
    "macOS process identity ABI must be 56 bytes"
);
const MAX_ARGUMENT_BYTES: usize = 0x0010_0000;

pub fn process_arguments(
    pid: u32,
    expected_version: Option<u32>,
) -> io::Result<Option<ProcessArguments>> {
    let pid = libc::pid_t::try_from(pid)
        .ok()
        .filter(|pid| *pid > 0_i32)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid process id"))?;
    let before = process_identity(pid)?;
    if expected_version.is_some_and(|version| version != before.version.cast_unsigned()) {
        return Ok(None);
    }
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut buffer = vec![0_u8; MAX_ARGUMENT_BYTES];
    let mut size = buffer.len();
    // SAFETY: mib contains three native integers; buffer is writable for size
    // bytes. No new value is supplied. Output is bounded by the allocated buffer.
    let result = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buffer.as_mut_ptr().cast(),
            &raw mut size,
            ptr::null_mut(),
            0,
        )
    };
    if result != 0_i32 {
        return Err(io::Error::last_os_error());
    }
    let bytes = buffer
        .get(..size)
        .ok_or_else(|| invalid_data("oversized process arguments"))?;
    let arguments = ProcessArguments::parse(bytes)?;
    let after = process_identity(pid)?;
    if before.unique_id != after.unique_id || before.version != after.version {
        return Ok(None);
    }
    Ok(Some(arguments))
}

fn process_identity(pid: libc::pid_t) -> io::Result<ProcessIdentity> {
    let mut record = MaybeUninit::<ProcessIdentity>::zeroed();
    let size = libc::c_int::try_from(size_of::<ProcessIdentity>())
        .map_err(|_| invalid_data("process identity size overflow"))?;
    // SAFETY: record is a correctly aligned repr(C) buffer of size bytes. It is
    // read only after libproc confirms that the complete ABI record was written.
    let read = unsafe {
        libc::proc_pidinfo(
            pid,
            PROC_PIDUNIQIDENTIFIERINFO,
            0,
            record.as_mut_ptr().cast(),
            size,
        )
    };
    if read <= 0_i32 {
        return Err(io::Error::last_os_error());
    }
    if read != size {
        return Err(invalid_data("partial process identity"));
    }
    // SAFETY: exact-size successful libproc output initialized the entire record.
    Ok(unsafe { record.assume_init() })
}

pub struct ProcessArguments {
    pub executable: String,
    pub argv: Vec<String>,
}

impl ProcessArguments {
    fn parse(bytes: &[u8]) -> io::Result<Self> {
        let (argument_count, mut remaining) = bytes
            .split_at_checked(size_of::<i32>())
            .ok_or_else(|| invalid_data("missing argument count"))?;
        let argument_count = i32::from_ne_bytes(
            argument_count
                .try_into()
                .map_err(|_| invalid_data("invalid argument_count"))?,
        );
        let argument_count = usize::try_from(argument_count)
            .ok()
            .filter(|count| (1..=4096).contains(count))
            .ok_or_else(|| invalid_data("invalid argument count"))?;
        let executable = Self::take_string(&mut remaining)?.to_owned();
        // The executable name is followed by NUL padding before argv[0].
        let start = remaining
            .iter()
            .position(|byte| *byte != 0)
            .ok_or_else(|| invalid_data("missing argv"))?;
        remaining = &remaining[start..];
        let mut argv = Vec::with_capacity(argument_count);
        for _ in 0..argument_count {
            argv.push(Self::take_string(&mut remaining)?.to_owned());
        }
        Ok(Self { executable, argv })
    }

    fn take_string<'a>(remaining: &mut &'a [u8]) -> io::Result<&'a str> {
        let end = remaining
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| invalid_data("unterminated process argument"))?;
        let value = std::str::from_utf8(&remaining[..end])
            .map_err(|_| invalid_data("non-UTF-8 process argument"))?;
        *remaining = &remaining[end.saturating_add(1)..];
        Ok(value)
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::{ProcessArguments, process_arguments, process_identity};

    #[test]
    fn argv_parser_does_not_include_environment_or_drop_empty_arguments() {
        let mut data = 3_i32.to_ne_bytes().to_vec();
        data.extend_from_slice(b"/usr/bin/node\0\0\0node\0/tmp/main.js\0\0SECRET=value\0");
        let parsed = ProcessArguments::parse(&data).unwrap();
        assert_eq!(parsed.executable, "/usr/bin/node");
        assert_eq!(parsed.argv, ["node", "/tmp/main.js", ""]);
    }

    #[test]
    fn malformed_native_arguments_are_rejected() {
        for data in [
            vec![],
            0_i32.to_ne_bytes().to_vec(),
            (-1_i32).to_ne_bytes().to_vec(),
            [
                2_i32.to_ne_bytes().as_slice(),
                b"/bin/node\0node\0unterminated",
            ]
            .concat(),
        ] {
            assert!(ProcessArguments::parse(&data).is_err());
        }
    }

    #[test]
    fn native_identity_and_argument_reads_work_for_this_process() {
        let pid = std::process::id();
        let native_pid = i32::try_from(pid).unwrap();
        let version = process_identity(native_pid)
            .unwrap()
            .version
            .cast_unsigned();
        assert!(process_arguments(pid, Some(version)).unwrap().is_some());
        assert!(
            process_arguments(pid, Some(version.wrapping_add(1)))
                .unwrap()
                .is_none()
        );
        assert!(process_arguments(0, None).is_err());
    }
}
