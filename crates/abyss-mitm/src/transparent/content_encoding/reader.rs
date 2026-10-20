//! Input budgets and strict zlib stream completion for observer-only decoding.

use std::{
    io::{self, BufRead, Read},
    time::Instant,
};

use flate2::{Decompress, FlushDecompress, Status};

pub(super) struct BudgetReader<'a> {
    remaining: &'a [u8],
    deadline: Instant,
}

impl<'a> BudgetReader<'a> {
    pub(super) const fn new(remaining: &'a [u8], deadline: Instant) -> Self {
        Self {
            remaining,
            deadline,
        }
    }
}

impl Read for BudgetReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let bytes = self.fill_buf()?;
        let count = bytes.len().min(buffer.len());
        buffer[..count].copy_from_slice(&bytes[..count]);
        self.consume(count);
        Ok(count)
    }
}

impl BufRead for BudgetReader<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "content decoding budget exceeded",
            ));
        }
        Ok(&self.remaining[..self.remaining.len().min(super::CHUNK_BYTES)])
    }

    fn consume(&mut self, amount: usize) {
        self.remaining = &self.remaining[amount.min(self.remaining.len())..];
    }
}

/// `deflate` means zlib-wrapped DEFLATE. Track `StreamEnd` explicitly: a
/// reader returning zero without it must not hide a missing checksum/trailer.
pub(super) struct ZlibReader<'a> {
    input: BudgetReader<'a>,
    decoder: Decompress,
    finished: bool,
}

impl<'a> ZlibReader<'a> {
    pub(super) fn new(input: BudgetReader<'a>) -> Self {
        Self {
            input,
            decoder: Decompress::new(true),
            finished: false,
        }
    }
}

impl Read for ZlibReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            let input = self.input.fill_buf()?;
            if self.finished {
                return if input.is_empty() {
                    Ok(0)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "bytes after zlib stream",
                    ))
                };
            }
            let before_in = self.decoder.total_in();
            let before_out = self.decoder.total_out();
            let status = self
                .decoder
                .decompress(input, buffer, FlushDecompress::None)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            let consumed = usize::try_from(self.decoder.total_in().saturating_sub(before_in))
                .map_err(io::Error::other)?;
            let produced = usize::try_from(self.decoder.total_out().saturating_sub(before_out))
                .map_err(io::Error::other)?;
            self.input.consume(consumed);
            self.finished = status == Status::StreamEnd;
            if produced > 0 {
                return Ok(produced);
            }
            if !self.finished && consumed == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete zlib stream",
                ));
            }
        }
    }
}
