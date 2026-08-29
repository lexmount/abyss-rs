//! Lightweight terminal rendering for local deployment progress.
//!
//! Deployment code emits semantic events. This module alone decides whether
//! to refresh one terminal line or emit durable, redirect-safe log lines.

use std::{
    ffi::OsStr,
    io::{self, IsTerminal as _, Write as _},
    time::{Duration, Instant},
};

use super::{
    ArtifactDisposition, DeployComponent, DeployProgress, ServiceDisposition,
    config::{BACKEND_VERSION, DASHBOARD_VERSION},
};

const UPDATE_INTERVAL: Duration = Duration::from_millis(80);

/// Renders one local deployment without affecting its stable standard output.
pub struct DeployProgressRenderer {
    mode: OutputMode,
    active: bool,
    last_update: Option<Instant>,
    update_kind: Option<UpdateKind>,
}

#[derive(Clone, Copy)]
enum OutputMode {
    Interactive,
    Plain,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum UpdateKind {
    Download,
    Verify,
    Install,
    ProxyHealth,
}

impl DeployProgressRenderer {
    /// Selects interactive rendering only when standard error is an attended terminal.
    pub fn detect() -> Self {
        Self::new(OutputMode::detect(
            io::stderr().is_terminal(),
            std::env::var_os("TERM").as_deref(),
        ))
    }

    /// Renders one semantic deployment transition.
    pub fn report(&mut self, event: DeployProgress) {
        match event {
            DeployProgress::CheckingDependencies => {
                self.start("[1/5] Checking local dependencies");
            }
            DeployProgress::DependenciesReady => {
                self.finish("[1/5] Checking local dependencies... done");
            }
            DeployProgress::PreparingArtifact(component) => {
                self.start(&artifact_progress_line(component, None));
            }
            DeployProgress::DownloadingBackend { downloaded, total } => {
                self.update(UpdateKind::Download, || {
                    format!(
                        "[2/5] Preparing abyss-backend v{BACKEND_VERSION}... downloading {}",
                        format_download(downloaded, total)
                    )
                });
            }
            DeployProgress::VerifyingBackend => {
                self.update(UpdateKind::Verify, || {
                    format!("[2/5] Preparing abyss-backend v{BACKEND_VERSION}... verifying SHA-256")
                });
            }
            DeployProgress::InstallingDashboard => {
                self.update(UpdateKind::Install, || {
                    format!("[3/5] Preparing abyss-dashboard v{DASHBOARD_VERSION}... installing")
                });
            }
            DeployProgress::ArtifactReady {
                component,
                disposition,
            } => {
                self.finish(&artifact_progress_line(
                    component,
                    Some(artifact_label(disposition)),
                ));
            }
            DeployProgress::StartingServices => {
                self.line("[4/5] Starting local services...");
            }
            DeployProgress::WaitingForService { component } => {
                self.start(&format!(
                    "      Starting {}; waiting for health check",
                    component_name(component)
                ));
            }
            DeployProgress::ServiceReady {
                component,
                url,
                disposition,
            } => {
                self.finish(&service_ready_line(component, &url, disposition));
            }
            DeployProgress::StartingProxy => {
                self.line("[5/5] Starting proxy...");
            }
            DeployProgress::InstallingCa => {
                self.start(ca_install_message());
            }
            DeployProgress::LaunchingProxy => {
                self.finish("      Local CA trust ready.");
                self.start("      Starting proxy");
            }
            DeployProgress::WaitingForProxy => {
                self.update(UpdateKind::ProxyHealth, || {
                    "      Waiting for proxy health check".to_owned()
                });
            }
            DeployProgress::ProxyReady { url } => {
                self.finish(&format!("      Proxy ready:     {url}"));
            }
            DeployProgress::ProxySkipped => {
                self.line("      Proxy skipped (debug configuration).");
            }
        }
    }

    const fn new(mode: OutputMode) -> Self {
        Self {
            mode,
            active: false,
            last_update: None,
            update_kind: None,
        }
    }

    fn start(&mut self, message: &str) {
        self.active = true;
        self.last_update = None;
        self.update_kind = None;
        match self.mode {
            OutputMode::Interactive => self.render_active(message),
            OutputMode::Plain => write_line(&format!("{message}...")),
        }
    }

    fn update<F>(&mut self, kind: UpdateKind, message: F)
    where
        F: FnOnce() -> String,
    {
        let kind_changed = self.update_kind != Some(kind);
        self.update_kind = Some(kind);
        if matches!(self.mode, OutputMode::Plain) {
            if kind_changed {
                write_line(&format!("{}...", message()));
            }
            return;
        }
        let now = Instant::now();
        if !kind_changed
            && self
                .last_update
                .is_some_and(|last| now.duration_since(last) < UPDATE_INTERVAL)
        {
            return;
        }
        self.render_active(&message());
    }

    fn render_active(&mut self, message: &str) {
        self.last_update = Some(Instant::now());
        replace_line(message);
    }

    fn finish(&mut self, message: &str) {
        if matches!(self.mode, OutputMode::Interactive) && self.active {
            clear_line();
        }
        write_line(message);
        self.active = false;
        self.last_update = None;
        self.update_kind = None;
    }

    fn line(&mut self, message: &str) {
        if matches!(self.mode, OutputMode::Interactive) && self.active {
            clear_line();
        }
        write_line(message);
        self.active = false;
        self.last_update = None;
        self.update_kind = None;
    }
}

impl Drop for DeployProgressRenderer {
    fn drop(&mut self) {
        if matches!(self.mode, OutputMode::Interactive) && self.active {
            clear_line();
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

const fn artifact_label(disposition: ArtifactDisposition) -> &'static str {
    match disposition {
        ArtifactDisposition::Configured => "configured",
        ArtifactDisposition::Cached => "cached",
        ArtifactDisposition::Installed => "done",
    }
}

fn artifact_progress_line(component: DeployComponent, result: Option<&str>) -> String {
    let line = match component {
        DeployComponent::Backend => {
            format!("[2/5] Preparing abyss-backend v{BACKEND_VERSION}")
        }
        DeployComponent::Dashboard => {
            format!("[3/5] Preparing abyss-dashboard v{DASHBOARD_VERSION}")
        }
    };
    result.map_or_else(|| line.clone(), |result| format!("{line}... {result}"))
}

const fn component_name(component: DeployComponent) -> &'static str {
    match component {
        DeployComponent::Backend => "backend",
        DeployComponent::Dashboard => "dashboard",
    }
}

const fn component_title(component: DeployComponent) -> &'static str {
    match component {
        DeployComponent::Backend => "Backend",
        DeployComponent::Dashboard => "Dashboard",
    }
}

fn service_ready_line(
    component: DeployComponent,
    url: &str,
    disposition: ServiceDisposition,
) -> String {
    let component = component_title(component);
    match disposition {
        ServiceDisposition::Existing => {
            format!("      {component} ready: {url} (already running)")
        }
        ServiceDisposition::Started => format!("      {component} ready: {url}"),
    }
}

fn format_download(downloaded: u64, total: Option<u64>) -> String {
    total.map_or_else(
        || format_bytes(downloaded),
        |total| format!("{}/{}", format_bytes(downloaded), format_bytes(total)),
    )
}

fn format_bytes(bytes: u64) -> String {
    const KIBIBYTE: u64 = 1024;
    const MEBIBYTE: u64 = 0x0010_0000;
    if bytes >= MEBIBYTE {
        format_decimal_unit(bytes, MEBIBYTE, "MiB")
    } else if bytes >= KIBIBYTE {
        format_decimal_unit(bytes, KIBIBYTE, "KiB")
    } else {
        format!("{bytes} B")
    }
}

fn format_decimal_unit(bytes: u64, unit: u64, label: &str) -> String {
    let whole = bytes.checked_div(unit).unwrap_or(0);
    let tenths = bytes
        .checked_rem(unit)
        .and_then(|remainder| remainder.checked_mul(10))
        .and_then(|scaled| scaled.checked_div(unit))
        .unwrap_or(0);
    format!("{whole}.{tenths} {label}")
}

#[cfg(target_os = "macos")]
const fn ca_install_message() -> &'static str {
    "      Installing local CA; macOS may request approval"
}

#[cfg(target_os = "linux")]
const fn ca_install_message() -> &'static str {
    "      Installing local CA; administrator approval may be required"
}

fn replace_line(message: &str) {
    let mut stderr = io::stderr().lock();
    drop(write!(stderr, "\r\x1b[2K{message}"));
    drop(stderr.flush());
}

fn clear_line() {
    let mut stderr = io::stderr().lock();
    drop(write!(stderr, "\r\x1b[2K"));
    drop(stderr.flush());
}

fn write_line(message: &str) {
    drop(writeln!(io::stderr().lock(), "{message}"));
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::{OutputMode, format_download};

    #[test]
    fn download_progress_formats_known_and_unknown_lengths() {
        assert_eq!(format_download(32 * 1024 * 1024, None), "32.0 MiB");
        assert_eq!(
            format_download(32 * 1024 * 1024, Some(48 * 1024 * 1024)),
            "32.0 MiB/48.0 MiB"
        );
        assert_eq!(format_download(512, Some(1024)), "512 B/1.0 KiB");
    }

    #[test]
    fn interactive_output_requires_an_attended_non_dumb_terminal() {
        assert!(matches!(
            OutputMode::detect(true, Some(OsStr::new("xterm-256color"))),
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
