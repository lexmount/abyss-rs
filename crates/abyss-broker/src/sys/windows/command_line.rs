//! Windows command-line tokenization with API-owned allocation cleanup.

#![expect(
    unsafe_code,
    reason = "CommandLineToArgvW returns a LocalFree-owned pointer array."
)]

use std::io;
use windows::{
    Win32::{
        Foundation::{HLOCAL, LocalFree},
        UI::Shell::CommandLineToArgvW,
    },
    core::{PCWSTR, PWSTR},
};

struct Arguments(*mut PWSTR);

impl Drop for Arguments {
    fn drop(&mut self) {
        // SAFETY: This is the allocation returned by CommandLineToArgvW, freed
        // exactly once after all argument code units have been copied.
        unsafe { LocalFree(Some(HLOCAL(self.0.cast()))) };
    }
}

pub fn command_line_arguments(command: &[u16]) -> io::Result<Vec<Vec<u16>>> {
    // An empty command would make the API return this broker's executable.
    if command.is_empty() || command.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty or NUL-containing command line",
        ));
    }
    let mut terminated = command.to_vec();
    terminated.push(0);
    let mut count = 0_i32;
    // SAFETY: The command is NUL-terminated and count is a writable integer.
    let pointer = unsafe { CommandLineToArgvW(PCWSTR(terminated.as_ptr()), &raw mut count) };
    if pointer.is_null() {
        return Err(io::Error::last_os_error());
    }
    let arguments = Arguments(pointer);
    let count = usize::try_from(count)
        .ok()
        .filter(|count| (1..=4096).contains(count))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid argument count"))?;
    // SAFETY: A successful API call returns count pointers to NUL-terminated
    // strings in the allocation, which arguments owns for this entire copy.
    let pointers = unsafe { std::slice::from_raw_parts(arguments.0, count) };
    pointers
        .iter()
        .map(|pointer| {
            // SAFETY: Each pointer belongs to the live API allocation and is NUL-terminated.
            Ok(unsafe { pointer.as_wide() }.to_vec())
        })
        .collect()
}
