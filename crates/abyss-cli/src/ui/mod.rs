//! User-facing terminal rendering for interactive and redirected CLI sessions.
//!
//! Human progress is written to standard error so command results on standard
//! output remain stable. Interactive terminals use `cliclack`; redirected,
//! CI, and dumb terminals receive plain lines without cursor control.

mod deploy_local;

use std::{
    ffi::OsStr,
    fmt::Display,
    io::{self, IsTerminal as _, Write as _},
};

pub use deploy_local::LocalDeploymentUi;

/// Terminal renderer selected once for one CLI invocation.
pub struct CliUi {
    mode: OutputMode,
}

/// One in-flight indeterminate operation.
pub struct UiActivity {
    progress: Option<cliclack::ProgressBar>,
    mode: OutputMode,
}

/// One in-flight byte-oriented operation.
pub struct UiDownload {
    progress: Option<cliclack::ProgressBar>,
    mode: OutputMode,
}

#[derive(Clone, Copy)]
enum OutputMode {
    Interactive,
    Plain,
}

impl CliUi {
    /// Detects whether standard error can safely render cursor-based UI.
    pub fn detect() -> Self {
        Self {
            mode: OutputMode::detect(
                io::stderr().is_terminal(),
                std::env::var_os("TERM").as_deref(),
            ),
        }
    }

    /// Starts a visually grouped human workflow.
    pub fn intro<M: Display>(&self, message: M) {
        match self.mode {
            OutputMode::Interactive => drop(cliclack::intro(message)),
            OutputMode::Plain => write_plain(message),
        }
    }

    /// Finishes a visually grouped human workflow.
    pub fn outro<M: Display>(&self, message: M) {
        match self.mode {
            OutputMode::Interactive => drop(cliclack::outro(message)),
            OutputMode::Plain => write_plain(message),
        }
    }

    /// Writes one successful, non-progress status line.
    pub fn success<M: Display>(&self, message: M) {
        match self.mode {
            OutputMode::Interactive => drop(cliclack::log::success(message)),
            OutputMode::Plain => write_plain(message),
        }
    }

    /// Writes one warning status line.
    pub fn warning<M: Display>(&self, message: M) {
        match self.mode {
            OutputMode::Interactive => drop(cliclack::log::warning(message)),
            OutputMode::Plain => write_plain(format_args!("Warning: {message}")),
        }
    }

    /// Writes a labelled multi-line note.
    pub fn note<T: Display, M: Display>(&self, title: T, message: M) {
        match self.mode {
            OutputMode::Interactive => drop(cliclack::note(title, message)),
            OutputMode::Plain => {
                write_plain(title);
                write_plain(message);
            }
        }
    }

    /// Starts an indeterminate activity.
    pub fn activity<M: Display>(&self, message: M) -> UiActivity {
        let progress = match self.mode {
            OutputMode::Interactive => {
                let progress = cliclack::spinner();
                progress.start(message);
                Some(progress)
            }
            OutputMode::Plain => {
                write_plain(message);
                None
            }
        };
        UiActivity {
            progress,
            mode: self.mode,
        }
    }

    /// Starts a download indicator, using a spinner when the size is unknown.
    pub fn download<M: Display>(&self, total: Option<u64>, message: M) -> UiDownload {
        let progress = match self.mode {
            OutputMode::Interactive => {
                let progress = total.map_or_else(cliclack::spinner, |length| {
                    cliclack::progress_bar(length).with_download_template()
                });
                progress.start(message);
                Some(progress)
            }
            OutputMode::Plain => {
                write_plain(message);
                None
            }
        };
        UiDownload {
            progress,
            mode: self.mode,
        }
    }
}

impl UiActivity {
    /// Replaces the activity message without starting another indicator.
    pub fn set_message<M: Display>(&self, message: M) {
        if let Some(progress) = &self.progress {
            progress.set_message(message);
        } else {
            write_plain(message);
        }
    }

    /// Completes the activity with a durable status line.
    pub fn finish<M: Display>(mut self, message: M) {
        if let Some(progress) = self.progress.take() {
            progress.stop(message);
        } else if matches!(self.mode, OutputMode::Plain) {
            write_plain(message);
        }
    }
}

impl Drop for UiActivity {
    fn drop(&mut self) {
        if let Some(progress) = self.progress.take() {
            progress.clear();
        }
    }
}

impl UiDownload {
    /// Updates the number of downloaded bytes.
    pub fn set_position(&self, downloaded: u64) {
        if let Some(progress) = &self.progress {
            progress.set_position(downloaded);
        }
    }

    /// Replaces the progress message, for example while verifying a checksum.
    pub fn set_message<M: Display>(&self, message: M) {
        if let Some(progress) = &self.progress {
            progress.set_message(message);
        } else {
            write_plain(message);
        }
    }

    /// Completes the download with a durable status line.
    pub fn finish<M: Display>(mut self, message: M) {
        if let Some(progress) = self.progress.take() {
            progress.stop(message);
        } else if matches!(self.mode, OutputMode::Plain) {
            write_plain(message);
        }
    }
}

impl Drop for UiDownload {
    fn drop(&mut self) {
        if let Some(progress) = self.progress.take() {
            progress.clear();
        }
    }
}

impl OutputMode {
    fn detect(stderr_is_terminal: bool, term: Option<&OsStr>) -> Self {
        if stderr_is_terminal && term != Some(OsStr::new("dumb")) {
            Self::Interactive
        } else {
            Self::Plain
        }
    }
}

fn write_plain(message: impl Display) {
    let message = message.to_string();
    if message.is_empty() {
        drop(writeln!(io::stderr().lock(), "abyss:"));
        return;
    }
    let mut stderr = io::stderr().lock();
    for line in message.lines() {
        drop(writeln!(stderr, "abyss: {line}"));
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::OutputMode;

    #[test]
    fn interactive_output_requires_an_attended_non_dumb_terminal() {
        assert!(matches!(
            OutputMode::detect(true, Some(OsStr::new("xterm-256color"))),
            OutputMode::Interactive
        ));
        assert!(matches!(
            OutputMode::detect(true, None),
            OutputMode::Interactive
        ));
        assert!(matches!(
            OutputMode::detect(true, Some(OsStr::new("dumb"))),
            OutputMode::Plain
        ));
        assert!(matches!(
            OutputMode::detect(false, Some(OsStr::new("xterm-256color"))),
            OutputMode::Plain
        ));
    }
}
