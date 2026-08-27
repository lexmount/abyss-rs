//! Interactive terminal rendering for endpoint network diagnostics.
//!
//! Classification remains in the parent module. This module owns ANSI
//! capability detection, severity styling, timestamps, and the compact list
//! layout used by the public `abyss diagnostics` command.

use std::{
    fmt::Write as _,
    io::{self, IsTerminal as _},
};

use chrono::{DateTime, Local, Utc};

use super::{DiagnosisSeverity, NetworkDiagnosis, NetworkDiagnosticsReport};

impl NetworkDiagnosticsReport {
    /// Renders the report with terminal styling when stdout supports it.
    pub fn print(&self) {
        let color_enabled = io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
        print!("{}", self.render(color_enabled));
    }

    pub(super) fn render(&self, color_enabled: bool) -> String {
        let style = TerminalStyle::new(color_enabled);
        let mut output = String::new();
        writeln!(output, "{}", style.heading("Abyss Network Diagnostics"))
            .expect("writing diagnostics to a String cannot fail");

        if self.diagnoses.is_empty() {
            writeln!(output).expect("writing diagnostics to a String cannot fail");
            writeln!(output, "No Agent request has been observed.")
                .expect("writing diagnostics to a String cannot fail");
            writeln!(
                output,
                "{} Retry the Agent request after confirming traffic is routed through Abyss.",
                style.label("Action")
            )
            .expect("writing diagnostics to a String cannot fail");
            return output;
        }

        let summary = DiagnosisSummary::from_diagnoses(&self.diagnoses);
        writeln!(
            output,
            "{}  {} {}  {} {}  {} {}",
            style.muted(&format!(
                "{} most recent Agent network events",
                self.diagnoses.len()
            )),
            style.error("Errors"),
            style.error(&summary.errors.to_string()),
            style.warning("Warnings"),
            style.warning(&summary.warnings.to_string()),
            style.healthy("Normal"),
            style.healthy(&summary.healthy.to_string())
        )
        .expect("writing diagnostics to a String cannot fail");

        for (index, diagnosis) in self.diagnoses.iter().enumerate() {
            writeln!(output).expect("writing diagnostics to a String cannot fail");
            diagnosis
                .render(&mut output, &style, index.saturating_add(1))
                .expect("writing diagnostics to a String cannot fail");
        }
        output
    }
}

struct DiagnosisSummary {
    errors: usize,
    warnings: usize,
    healthy: usize,
}

impl DiagnosisSummary {
    fn from_diagnoses(diagnoses: &[NetworkDiagnosis]) -> Self {
        let mut summary = Self {
            errors: 0,
            warnings: 0,
            healthy: 0,
        };
        for diagnosis in diagnoses {
            match diagnosis.severity {
                DiagnosisSeverity::Error => {
                    summary.errors = summary.errors.saturating_add(1);
                }
                DiagnosisSeverity::Warning => {
                    summary.warnings = summary.warnings.saturating_add(1);
                }
                DiagnosisSeverity::Healthy => {
                    summary.healthy = summary.healthy.saturating_add(1);
                }
            }
        }
        summary
    }
}

impl NetworkDiagnosis {
    fn render(&self, output: &mut String, style: &TerminalStyle, index: usize) -> std::fmt::Result {
        let (symbol, severity) = match self.severity {
            DiagnosisSeverity::Error => (style.error("●"), style.error("ERROR")),
            DiagnosisSeverity::Warning => (style.warning("▲"), style.warning("WARNING")),
            DiagnosisSeverity::Healthy => (style.healthy("●"), style.healthy("NORMAL")),
        };
        writeln!(
            output,
            "{}  {}  {}  {}",
            symbol,
            style.muted(&format!("#{index}")),
            severity,
            style.muted(&format_timestamp(self.observed_at_unix_ms))
        )?;
        writeln!(output, "   {}", style.emphasis(self.message))?;
        if let Some(source_process_name) = self.source_process_name.as_deref() {
            writeln!(
                output,
                "   {} {}",
                style.label(&format!("{:<12}", "Agent")),
                source_process_name
            )?;
        }
        if let Some(destination_host) = self.destination_host.as_deref() {
            writeln!(
                output,
                "   {} {}",
                style.label(&format!("{:<12}", "Destination")),
                destination_host
            )?;
        }
        if let Some(http_status) = self.http_status {
            writeln!(
                output,
                "   {} {}",
                style.label(&format!("{:<12}", "HTTP status")),
                http_status
            )?;
        }
        writeln!(
            output,
            "   {} {}",
            style.label(&format!("{:<12}", "Action")),
            self.guidance
        )
    }
}

struct TerminalStyle {
    color_enabled: bool,
}

impl TerminalStyle {
    const RESET: &'static str = "\u{1b}[0m";
    const BOLD: &'static str = "\u{1b}[1m";
    const DIM: &'static str = "\u{1b}[2m";
    const RED: &'static str = "\u{1b}[31m";
    const YELLOW: &'static str = "\u{1b}[33m";
    const GREEN: &'static str = "\u{1b}[32m";
    const CYAN: &'static str = "\u{1b}[36m";

    const fn new(color_enabled: bool) -> Self {
        Self { color_enabled }
    }

    fn heading(&self, value: &str) -> String {
        self.paint(Self::BOLD, value)
    }

    fn emphasis(&self, value: &str) -> String {
        self.paint(Self::BOLD, value)
    }

    fn label(&self, value: &str) -> String {
        self.paint(Self::CYAN, value)
    }

    fn muted(&self, value: &str) -> String {
        self.paint(Self::DIM, value)
    }

    fn error(&self, value: &str) -> String {
        self.paint(Self::RED, value)
    }

    fn warning(&self, value: &str) -> String {
        self.paint(Self::YELLOW, value)
    }

    fn healthy(&self, value: &str) -> String {
        self.paint(Self::GREEN, value)
    }

    fn paint(&self, code: &str, value: &str) -> String {
        if self.color_enabled {
            format!("{code}{value}{}", Self::RESET)
        } else {
            value.to_owned()
        }
    }
}

fn format_timestamp(unix_ms: u64) -> String {
    i64::try_from(unix_ms)
        .ok()
        .and_then(DateTime::<Utc>::from_timestamp_millis)
        .map_or_else(
            || "unknown time".to_owned(),
            |timestamp| {
                timestamp
                    .with_timezone(&Local)
                    .format("%Y-%m-%d %H:%M:%S")
                    .to_string()
            },
        )
}
