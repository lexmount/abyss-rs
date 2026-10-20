//! Bounded HTTP content decoding for background observers.
//!
//! The relay retains and forwards original bytes. This module prepares only the
//! hook's decoded view, using headers rather than application routes or hosts.

mod brotli;
mod reader;
#[cfg(test)]
mod tests;

use std::{
    io::{self, Read},
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::{
    HeaderMap, Method, StatusCode,
    header::{CONTENT_ENCODING, TRANSFER_ENCODING},
};

use self::brotli::BrotliReader;
use super::{BodyDecodingStatus, CapturedBody, HttpExchange, engine::DEFAULT_MAX_HTTP1_BODY_BYTES};
use reader::{BudgetReader, ZlibReader};

const MAX_CODINGS: usize = 4;
const DECODE_TIME_BUDGET: Duration = Duration::from_secs(2);
const CHUNK_BYTES: usize = 16 * 1024;
const MAX_WINDOW_LOG: u32 = 24;

#[derive(Clone, Copy)]
enum ContentCoding {
    Gzip,
    Deflate,
    Brotli,
    Zstd,
    Identity,
}

impl ContentCoding {
    const fn parse(value: &str) -> Result<Self, BodyDecodingStatus> {
        if value.eq_ignore_ascii_case("gzip") || value.eq_ignore_ascii_case("x-gzip") {
            Ok(Self::Gzip)
        } else if value.eq_ignore_ascii_case("deflate") {
            Ok(Self::Deflate)
        } else if value.eq_ignore_ascii_case("br") {
            Ok(Self::Brotli)
        } else if value.eq_ignore_ascii_case("zstd") {
            Ok(Self::Zstd)
        } else if value.eq_ignore_ascii_case("identity") {
            Ok(Self::Identity)
        } else {
            Err(BodyDecodingStatus::UnsupportedEncoding)
        }
    }
}

pub(super) struct ContentDecoder {
    deadline: Instant,
    limit: usize,
}

impl ContentDecoder {
    /// Keeps already parsed identity captures ready for direct hook delivery.
    pub(super) fn prepare_body(headers: &HeaderMap, body: &mut CapturedBody) {
        if !Self::identity_only(headers) {
            body.set_decoded(Bytes::new(), BodyDecodingStatus::Pending);
        }
    }

    /// Both sides must be ready before bypassing the blocking decoder.
    /// Reapplying a smaller output limit can also require expensive JSON parsing.
    pub(super) fn requires_processing(exchange: &HttpExchange) -> bool {
        !Self::body_ready(exchange.request.headers(), exchange.request.body(), false)
            || !Self::body_ready(
                exchange.response.headers(),
                exchange.response.body(),
                Self::response_has_no_body(exchange),
            )
    }

    fn response_has_no_body(exchange: &HttpExchange) -> bool {
        exchange.request.method() == Method::HEAD
            || exchange.response.status().is_informational()
            || matches!(
                exchange.response.status(),
                StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED
            )
    }

    fn identity_only(headers: &HeaderMap) -> bool {
        Self::codings(headers).is_ok_and(|codings| {
            codings
                .iter()
                .all(|coding| matches!(coding, ContentCoding::Identity))
        })
    }

    fn body_ready(headers: &HeaderMap, body: &CapturedBody, no_body: bool) -> bool {
        if no_body {
            return body.decoding_status() == BodyDecodingStatus::Complete
                && body.bytes().is_empty();
        }
        Self::identity_only(headers)
            && matches!(
                body.decoding_status(),
                BodyDecodingStatus::Complete | BodyDecodingStatus::Truncated
            )
            && body.raw_bytes().len() <= body.decode_limit.min(DEFAULT_MAX_HTTP1_BODY_BYTES)
    }

    pub(super) fn decode_exchange(mut exchange: HttpExchange) -> HttpExchange {
        let (parts, mut body) = exchange.request.into_parts();
        Self::decode_body(&parts.headers, &mut body, false);
        exchange.request = http::Request::from_parts(parts, body);
        let no_body = Self::response_has_no_body(&exchange);
        let (parts, mut body) = exchange.response.into_parts();
        Self::decode_body(&parts.headers, &mut body, no_body);
        exchange.response = http::Response::from_parts(parts, body);
        exchange
    }

    fn decode_body(headers: &HeaderMap, body: &mut CapturedBody, no_body: bool) {
        if Self::body_ready(headers, body, no_body) {
            Self::log_decoded(headers, body);
            return;
        }
        if no_body {
            body.set_decoded(Bytes::new(), BodyDecodingStatus::Complete);
            return;
        }
        let decoder = Self {
            deadline: Instant::now()
                .checked_add(DECODE_TIME_BUDGET)
                .expect("two-second deadline fits monotonic clock"),
            limit: body.decode_limit.min(DEFAULT_MAX_HTTP1_BODY_BYTES),
        };
        match decoder.decode(headers, body.encoded_bytes(), body.raw_truncated()) {
            Ok((bytes, status)) => body.set_decoded(bytes, status),
            Err(status) => {
                tracing::debug!(?status, "HTTP content capture could not be decoded");
                body.set_decoded(Bytes::new(), status);
            }
        }
        Self::log_decoded(headers, body);
    }

    fn log_decoded(headers: &HeaderMap, body: &CapturedBody) {
        tracing::debug!(
            content_encoding = ?headers.get(CONTENT_ENCODING),
            status = ?body.decoding_status(),
            encoded_bytes = body.raw_bytes().len(),
            decoded_bytes = body.bytes().len(),
            "HTTP observation content decoded"
        );
    }

    fn codings(headers: &HeaderMap) -> Result<Vec<ContentCoding>, BodyDecodingStatus> {
        // The relay currently removes chunk framing only. Never interpret an
        // unhandled transfer-compressed representation as plaintext.
        for value in headers.get_all(TRANSFER_ENCODING) {
            let value = value
                .to_str()
                .map_err(|_| BodyDecodingStatus::InvalidEncoding)?;
            if !value.trim().eq_ignore_ascii_case("chunked") {
                return Err(BodyDecodingStatus::UnsupportedTransferEncoding);
            }
        }
        let mut codings = Vec::new();
        for value in headers.get_all(CONTENT_ENCODING) {
            let value = value
                .to_str()
                .map_err(|_| BodyDecodingStatus::InvalidEncoding)?;
            for coding in value.split(',') {
                let coding = coding.trim();
                if coding.is_empty() {
                    return Err(BodyDecodingStatus::InvalidEncoding);
                }
                if codings.len() == MAX_CODINGS {
                    return Err(BodyDecodingStatus::BudgetExceeded);
                }
                codings.push(ContentCoding::parse(coding)?);
            }
        }
        Ok(codings)
    }

    fn decode(
        &self,
        headers: &HeaderMap,
        mut bytes: Bytes,
        mut truncated: bool,
    ) -> Result<(Bytes, BodyDecodingStatus), BodyDecodingStatus> {
        let codings = Self::codings(headers)?;
        if bytes.len() > self.limit {
            bytes.truncate(self.limit);
            truncated = true;
        }
        for coding in codings.into_iter().rev() {
            if matches!(coding, ContentCoding::Identity) {
                continue;
            }
            let (decoded, partial) = self.decode_layer(coding, &bytes, truncated)?;
            bytes = decoded;
            truncated |= partial;
        }
        Ok((
            bytes,
            if truncated {
                BodyDecodingStatus::Truncated
            } else {
                BodyDecodingStatus::Complete
            },
        ))
    }

    fn decode_layer(
        &self,
        coding: ContentCoding,
        bytes: &[u8],
        truncated: bool,
    ) -> Result<(Bytes, bool), BodyDecodingStatus> {
        let input = BudgetReader::new(bytes, self.deadline);
        match coding {
            ContentCoding::Gzip => {
                self.collect(flate2::bufread::MultiGzDecoder::new(input), truncated)
            }
            ContentCoding::Deflate => self.collect(ZlibReader::new(input), truncated),
            ContentCoding::Brotli => {
                self.collect(BrotliReader::new(bytes, self.deadline), truncated)
            }
            ContentCoding::Zstd => {
                let mut decoder = zstd::stream::read::Decoder::with_buffer(input)
                    .map_err(|_| BodyDecodingStatus::InvalidData)?;
                decoder
                    .window_log_max(MAX_WINDOW_LOG)
                    .map_err(|_| BodyDecodingStatus::InvalidData)?;
                self.collect(decoder, truncated)
            }
            ContentCoding::Identity => Ok((Bytes::copy_from_slice(bytes), truncated)),
        }
    }

    fn collect<R: Read>(
        &self,
        mut reader: R,
        input_truncated: bool,
    ) -> Result<(Bytes, bool), BodyDecodingStatus> {
        let mut output = Vec::new();
        let mut buffer = [0_u8; CHUNK_BYTES];
        loop {
            if Instant::now() >= self.deadline {
                return Err(BodyDecodingStatus::BudgetExceeded);
            }
            let remaining = self.limit.saturating_sub(output.len());
            // Read one extra byte to distinguish an exact-limit representation
            // from an output-limited prefix, without allocating past the limit.
            let read_limit = buffer.len().min(remaining.saturating_add(1));
            match reader.read(&mut buffer[..read_limit]) {
                Ok(0) => match reader.read(&mut buffer[..1]) {
                    Ok(0) => return Ok((Bytes::from(output), input_truncated)),
                    Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                        return Err(BodyDecodingStatus::BudgetExceeded);
                    }
                    _ => return Err(BodyDecodingStatus::InvalidData),
                },
                Ok(count) => {
                    output.extend_from_slice(&buffer[..count.min(remaining)]);
                    if count > remaining {
                        return Ok((Bytes::from(output), true));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                    return Err(BodyDecodingStatus::BudgetExceeded);
                }
                Err(error) if input_truncated && error.kind() == io::ErrorKind::UnexpectedEof => {
                    return Ok((Bytes::from(output), true));
                }
                Err(_) => return Err(BodyDecodingStatus::InvalidData),
            }
        }
    }
}
