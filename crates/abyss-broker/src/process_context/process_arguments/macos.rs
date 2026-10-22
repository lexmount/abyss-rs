//! macOS startup-argument provider and `KERN_PROCARGS2` format decoding.
//! The sys adapter owns the native call. This provider discards the native buffer
//! after decoding argv and excludes environment variables; runtimes interpret argv.

use std::{io, mem::size_of};

use super::{ProcessArguments, ProcessArgumentsProvider};
use crate::sys::sysctl_read;

pub(super) struct MacOsProcessArgumentsProvider;

const MAX_ARGUMENT_BYTES: usize = 0x0010_0000;

impl ProcessArgumentsProvider for MacOsProcessArgumentsProvider {
    fn read(&self, pid: u32) -> io::Result<ProcessArguments> {
        let pid = libc::pid_t::try_from(pid)
            .ok()
            .filter(|pid| *pid > 0_i32)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid process id"))?;
        let mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
        let mut buffer = vec![0_u8; MAX_ARGUMENT_BYTES];
        let size = sysctl_read(&mib, &mut buffer)?;
        Self::parse(&buffer[..size])
    }
}

impl MacOsProcessArgumentsProvider {
    fn parse(bytes: &[u8]) -> io::Result<ProcessArguments> {
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
        Ok(ProcessArguments { executable, argv })
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
    use super::{MacOsProcessArgumentsProvider, ProcessArgumentsProvider};

    #[test]
    fn argv_parser_does_not_include_environment_or_drop_empty_arguments() {
        let mut data = 3_i32.to_ne_bytes().to_vec();
        data.extend_from_slice(b"/usr/bin/node\0\0\0node\0/tmp/main.js\0\0SECRET=value\0");
        let parsed = MacOsProcessArgumentsProvider::parse(&data).unwrap();
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
            assert!(MacOsProcessArgumentsProvider::parse(&data).is_err());
        }
    }

    #[test]
    fn native_argument_reads_work_for_this_pid() {
        let arguments = MacOsProcessArgumentsProvider
            .read(std::process::id())
            .unwrap();
        assert!(!arguments.executable.is_empty());
        assert!(!arguments.argv.is_empty());
        assert!(MacOsProcessArgumentsProvider.read(0).is_err());
        assert!(MacOsProcessArgumentsProvider.read(u32::MAX).is_err());
    }
}
