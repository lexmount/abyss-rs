//! Windows executable and argv provider; native arguments stay transient.

use std::io;

use super::{ProcessArguments, ProcessArgumentsProvider};
use crate::sys::windows::{Arguments, NativeProcess};

pub(super) struct WindowsProcessArgumentsProvider;

impl ProcessArgumentsProvider for WindowsProcessArgumentsProvider {
    fn read(&self, pid: u32) -> io::Result<ProcessArguments> {
        let process = NativeProcess::open(pid)?;
        let executable = decode(&process.executable()?)?;
        let argv = Arguments::from_utf16(process.command_line()?)?
            .iter()
            .map(decode)
            .collect::<io::Result<Vec<_>>>()?;
        if argv.first().is_none_or(String::is_empty) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing executable argument",
            ));
        }
        Ok(ProcessArguments { executable, argv })
    }
}

fn decode(value: &[u16]) -> io::Result<String> {
    if value.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "embedded NUL in process argument",
        ));
    }
    String::from_utf16(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-Unicode process argument"))
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        process::{Child, Command, Stdio},
    };

    use super::{Arguments, ProcessArgumentsProvider, WindowsProcessArgumentsProvider, decode};

    struct ChildProcess(Child);

    impl Drop for ChildProcess {
        fn drop(&mut self) {
            drop(self.0.kill());
            drop(self.0.wait());
        }
    }

    #[test]
    fn native_reader_reads_another_process_and_drops_exited_processes() {
        let executable = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let mut child = ChildProcess(
            Command::new(&executable)
                .args([
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "[Console]::ReadLine()",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let arguments = WindowsProcessArgumentsProvider.read(child.0.id()).unwrap();
        assert_eq!(
            PathBuf::from(arguments.executable.to_ascii_lowercase()),
            PathBuf::from(executable.to_str().unwrap().to_ascii_lowercase())
        );
        assert_eq!(
            &arguments.argv[1..],
            [
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[Console]::ReadLine()"
            ]
        );
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(WindowsProcessArgumentsProvider.read(child.0.id()).is_err());
    }

    #[test]
    fn native_reader_uses_the_process_image_and_rejects_invalid_pids() {
        let arguments = WindowsProcessArgumentsProvider
            .read(std::process::id())
            .unwrap();
        assert!(
            arguments.executable.ends_with(
                std::env::current_exe()
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
            )
        );
        assert_ne!(arguments.argv, Vec::<String>::new());
        assert!(WindowsProcessArgumentsProvider.read(0).is_err());
        assert!(WindowsProcessArgumentsProvider.read(u32::MAX).is_err());
    }

    #[test]
    fn windows_quoting_preserves_paths_empty_arguments_and_backslashes() {
        let command = r#""C:\Program Files\WorkBuddy\WorkBuddyAI.exe" --no-warnings "C:\项目 路径\cli\codebuddy" "" "quoted\"value" "trailing\\""#;
        let arguments = Arguments::from_utf16(command.encode_utf16().collect()).unwrap();
        let argv = arguments
            .iter()
            .map(|arg| decode(arg).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            argv,
            [
                r"C:\Program Files\WorkBuddy\WorkBuddyAI.exe",
                "--no-warnings",
                r"C:\项目 路径\cli\codebuddy",
                "",
                "quoted\"value",
                "trailing\\"
            ]
        );
        assert!(decode(&[0xd800]).is_err());
    }
}
