//! Linux executable, working-directory and bounded argv reads by PID.
//! All procfs process access stays here; environment variables are never read.

use std::{
    fs,
    io::{self, Read as _},
    path::PathBuf,
};

const MAX_ARGUMENT_BYTES: usize = 0x0010_0000;
const MAX_ARGUMENTS: usize = 4096;

pub struct ProcessArguments {
    pub executable: String,
    pub argv: Vec<String>,
}

pub fn process_executable(pid: u32) -> io::Result<PathBuf> {
    fs::read_link(process_directory(pid)?.join("exe"))
}

pub fn process_working_directory(pid: u32) -> io::Result<PathBuf> {
    fs::read_link(process_directory(pid)?.join("cwd"))
}

pub fn process_arguments(pid: u32) -> io::Result<ProcessArguments> {
    let executable = process_executable(pid)?;
    let executable = executable
        .to_str()
        .ok_or_else(|| invalid_data("non-UTF-8 executable"))?;
    let file = fs::File::open(process_directory(pid)?.join("cmdline"))?;
    let mut bytes = Vec::new();
    let limit =
        u64::try_from(MAX_ARGUMENT_BYTES).map_err(|_| invalid_data("argument limit overflow"))?;
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    Ok(ProcessArguments {
        executable: executable.to_owned(),
        argv: parse_arguments(&bytes)?,
    })
}

fn process_directory(pid: u32) -> io::Result<PathBuf> {
    if pid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid process id",
        ));
    }
    Ok(PathBuf::from(format!("/proc/{pid}")))
}

fn parse_arguments(bytes: &[u8]) -> io::Result<Vec<String>> {
    if bytes.len() > MAX_ARGUMENT_BYTES {
        return Err(invalid_data("oversized process arguments"));
    }
    let terminated = bytes
        .strip_suffix(&[0])
        .ok_or_else(|| invalid_data("unterminated process arguments"))?;
    let mut argv = Vec::new();
    for bytes in terminated.split(|byte| *byte == 0) {
        if argv.len() == MAX_ARGUMENTS {
            return Err(invalid_data("too many process arguments"));
        }
        let argument =
            std::str::from_utf8(bytes).map_err(|_| invalid_data("non-UTF-8 process argument"))?;
        argv.push(argument.to_owned());
    }
    if argv.first().is_none_or(String::is_empty) {
        return Err(invalid_data("missing executable argument"));
    }
    Ok(argv)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::{MAX_ARGUMENT_BYTES, MAX_ARGUMENTS, parse_arguments, process_arguments};

    #[test]
    fn preserves_argument_boundaries_and_empty_script_arguments() {
        assert_eq!(
            parse_arguments(b"node\0/tmp/my script.js\0\0").unwrap(),
            ["node", "/tmp/my script.js", ""]
        );
    }

    #[test]
    fn rejects_missing_malformed_and_excessive_arguments() {
        for bytes in [
            b"".as_slice(),
            b"\0",
            b"node\0unterminated",
            b"node\0\xff\0",
        ] {
            assert!(parse_arguments(bytes).is_err());
        }
        assert!(parse_arguments(&vec![0_u8; MAX_ARGUMENT_BYTES.saturating_add(1)]).is_err());
        assert!(parse_arguments(&b"x\0".repeat(MAX_ARGUMENTS.saturating_add(1))).is_err());
    }

    #[test]
    fn reads_current_process_and_rejects_invalid_pid() {
        let arguments = process_arguments(std::process::id()).unwrap();
        assert!(!arguments.executable.is_empty());
        assert!(!arguments.argv.is_empty());
        assert!(process_arguments(0).is_err());
        assert!(process_arguments(u32::MAX).is_err());
    }
}
