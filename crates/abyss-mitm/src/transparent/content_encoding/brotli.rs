//! Strict RFC 7932 Brotli decoding with bounded input steps and window size.

use std::{
    io::{self, Read},
    time::Instant,
};

use brotli::{BrotliDecompressStream, BrotliResult, BrotliState, HeapAlloc, HuffmanCode};

pub(super) struct BrotliReader<'a> {
    input: &'a [u8],
    state: BrotliState<HeapAlloc<u8>, HeapAlloc<u32>, HeapAlloc<HuffmanCode>>,
    total_out: usize,
    finished: bool,
    deadline: Instant,
}

impl<'a> BrotliReader<'a> {
    pub(super) fn new(input: &'a [u8], deadline: Instant) -> Self {
        let mut state = BrotliState::new(
            HeapAlloc::default(),
            HeapAlloc::default(),
            HeapAlloc::default(),
        );
        // HTTP br uses RFC 7932 (at most a 24-bit window), not the optional
        // large-window extension accepted by the library's default reader.
        state.large_window = false;
        Self {
            input,
            state,
            total_out: 0,
            finished: false,
            deadline,
        }
    }
}

impl Read for BrotliReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            if Instant::now() >= self.deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Brotli decoding budget exceeded",
                ));
            }
            if self.finished {
                return if self.input.is_empty() {
                    Ok(0)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "bytes after Brotli stream",
                    ))
                };
            }
            let mut available_in = self.input.len().min(super::CHUNK_BYTES);
            let mut consumed = 0;
            let mut available_out = output.len();
            let mut produced = 0;
            let result = BrotliDecompressStream(
                &mut available_in,
                &mut consumed,
                self.input,
                &mut available_out,
                &mut produced,
                output,
                &mut self.total_out,
                &mut self.state,
            );
            self.input = &self.input[consumed..];
            match result {
                BrotliResult::ResultSuccess => self.finished = true,
                BrotliResult::ResultFailure => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid Brotli stream",
                    ));
                }
                BrotliResult::NeedsMoreInput if self.input.is_empty() && produced == 0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "incomplete Brotli stream",
                    ));
                }
                BrotliResult::NeedsMoreInput | BrotliResult::NeedsMoreOutput => {}
            }
            if produced > 0 {
                return Ok(produced);
            }
        }
    }
}
