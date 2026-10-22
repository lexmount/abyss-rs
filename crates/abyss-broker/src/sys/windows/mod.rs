//! Safe Windows process-query and command-line adapters; no runtime interpretation.

mod command_line;
mod process;

pub use command_line::command_line_arguments;
pub use process::NativeProcess;
