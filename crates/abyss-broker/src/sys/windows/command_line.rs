//! Windows command-line tokenization with API-owned allocation cleanup.

#![expect(
    unsafe_code,
    reason = "CommandLineToArgvW returns a LocalFree-owned pointer array."
)]

use std::{io, ptr::NonNull, slice};
use windows::{
    Win32::{
        Foundation::{HLOCAL, LocalFree},
        UI::Shell::CommandLineToArgvW,
    },
    core::{PCWSTR, PWSTR},
};

/// Owns the argument array and strings allocated by `CommandLineToArgvW`.
#[repr(transparent)]
pub struct Arguments {
    inner: NonNull<[PWSTR]>,
}

/// Iterates over UTF-16 argument slices borrowed from an `Arguments` owner.
pub struct ArgumentsIter<'a> {
    inner: slice::Iter<'a, PWSTR>,
}

impl Drop for Arguments {
    fn drop(&mut self) {
        // SAFETY: This is the allocation returned by CommandLineToArgvW, freed
        // exactly once. Any iterator or argument slice borrows this owner.
        unsafe { LocalFree(Some(HLOCAL(self.inner.as_ptr().cast()))) };
    }
}

impl Arguments {
    /// Parses a command line into independently owned native argument storage.
    ///
    /// The input excludes the terminal NUL and may contain unpaired UTF-16 surrogates.
    /// Consumes the input buffer and appends the NUL before calling the native API.
    ///
    /// # Errors
    ///
    /// Returns an error for empty or NUL-containing input or a failed native call.
    pub fn from_utf16(mut command: Vec<u16>) -> io::Result<Self> {
        // An empty command would make the API return this broker's executable.
        if command.is_empty() || command.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty or NUL-containing command line",
            ));
        }
        command.push(0);
        let mut count = 0_i32;
        // SAFETY: The command is NUL-terminated and count is a writable integer.
        let pointer = unsafe { CommandLineToArgvW(PCWSTR(command.as_ptr()), &raw mut count) };
        let pointer = NonNull::new(pointer).ok_or_else(io::Error::last_os_error)?;
        #[expect(
            clippy::as_conversions,
            clippy::cast_sign_loss,
            reason = "A successful CommandLineToArgvW call returns a nonnegative array length."
        )]
        let count = count as usize;
        Ok(Self {
            inner: NonNull::slice_from_raw_parts(pointer, count),
        })
    }

    /// Borrows argument code units without their terminal NULs or Unicode decoding.
    pub fn iter(&self) -> ArgumentsIter<'_> {
        // SAFETY: The native call initialized every pointer in this slice. The
        // allocation remains owned by self, to which the returned borrow is tied.
        let pointers = unsafe { self.inner.as_ref() };
        ArgumentsIter {
            inner: pointers.iter(),
        }
    }
}

impl<'a> Iterator for ArgumentsIter<'a> {
    type Item = &'a [u16];

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|pointer| {
            // SAFETY: Each pointer addresses a NUL-terminated string in the same
            // live allocation. Its slice is tied to the Arguments owner's borrow.
            unsafe { pointer.as_wide() }
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::Arguments;

    #[test]
    fn native_storage_outlives_input_and_supports_repeated_borrowed_iteration() {
        let arguments = {
            let command = "node script.js".encode_utf16().collect::<Vec<_>>();
            Arguments::from_utf16(command).unwrap()
        };
        let mut iterator = arguments.iter();
        let executable = iterator.next().unwrap();
        let script = iterator.next().unwrap();
        assert!(iterator.next().is_none());
        assert_eq!(String::from_utf16(executable).unwrap(), "node");
        assert_eq!(String::from_utf16(script).unwrap(), "script.js");
        assert!(std::ptr::eq(executable, arguments.iter().next().unwrap()));
        assert_eq!(arguments.iter().count(), 2);
    }

    #[test]
    fn iteration_preserves_unpaired_utf16_surrogates() {
        let arguments = Arguments::from_utf16(vec![0xd800, 0x20, 0xdc00]).unwrap();
        assert_eq!(
            arguments.iter().collect::<Vec<_>>(),
            [&[0xd800][..], &[0xdc00][..]]
        );
    }

    #[test]
    fn constructor_rejects_invalid_input_and_accepts_large_argument_lists() {
        assert!(Arguments::from_utf16(Vec::new()).is_err());
        assert!(Arguments::from_utf16(vec![65, 0, 66]).is_err());
        let command = "a ".repeat(4097).encode_utf16().collect::<Vec<_>>();
        assert_eq!(Arguments::from_utf16(command).unwrap().iter().count(), 4097);
    }
}
