//! Bounded write-based content decoding for live HTTP observations.

use std::io::{self, Write};

use brotli::DecompressorWriter;
use flate2::write::{MultiGzDecoder, ZlibDecoder};
use http::HeaderMap;
use zstd::stream::write::Decoder as ZstdDecoder;

use super::{CHUNK_BYTES, ContentCoding, ContentDecoder, MAX_WINDOW_LOG};
use crate::BodyDecodingStatus;

pub(in crate::transparent) struct StreamDecoder(Vec<Layer>);

impl StreamDecoder {
    pub(in crate::transparent) fn new(
        headers: &HeaderMap,
        limit: usize,
    ) -> Result<Self, BodyDecodingStatus> {
        let mut layers = Vec::new();
        for coding in ContentDecoder::codings(headers)?.into_iter().rev() {
            let output = BoundedOutput {
                bytes: Vec::new(),
                limit,
            };
            match coding {
                ContentCoding::Gzip => layers.push(Layer::Gzip(MultiGzDecoder::new(output))),
                ContentCoding::Deflate => layers.push(Layer::Deflate(ZlibDecoder::new(output))),
                ContentCoding::Brotli => layers.push(Layer::Brotli(Box::new(
                    DecompressorWriter::new(output, CHUNK_BYTES),
                ))),
                ContentCoding::Zstd => {
                    let mut decoder =
                        ZstdDecoder::new(output).map_err(|_| BodyDecodingStatus::InvalidData)?;
                    decoder
                        .window_log_max(MAX_WINDOW_LOG)
                        .map_err(|_| BodyDecodingStatus::InvalidData)?;
                    layers.push(Layer::Zstd(decoder));
                }
                ContentCoding::Identity => {}
            }
        }
        Ok(Self(layers))
    }

    pub(in crate::transparent) fn decode<'a>(
        &'a mut self,
        mut bytes: &'a [u8],
    ) -> io::Result<&'a [u8]> {
        for layer in &mut self.0 {
            bytes = layer.decode(bytes)?;
        }
        Ok(bytes)
    }
}

enum Layer {
    Gzip(MultiGzDecoder<BoundedOutput>),
    Deflate(ZlibDecoder<BoundedOutput>),
    Brotli(Box<DecompressorWriter<BoundedOutput>>),
    Zstd(ZstdDecoder<'static, BoundedOutput>),
}

impl Layer {
    fn decode<'a>(&'a mut self, input: &[u8]) -> io::Result<&'a [u8]> {
        match self {
            Self::Gzip(writer) => collect(writer, input, MultiGzDecoder::get_mut),
            Self::Deflate(writer) => collect(writer, input, ZlibDecoder::get_mut),
            Self::Brotli(writer) => collect(writer.as_mut(), input, DecompressorWriter::get_mut),
            Self::Zstd(writer) => collect(writer, input, ZstdDecoder::get_mut),
        }
    }
}

fn collect<'a, W: Write>(
    writer: &'a mut W,
    input: &[u8],
    output: fn(&mut W) -> &mut BoundedOutput,
) -> io::Result<&'a [u8]> {
    output(writer).bytes.clear();
    writer.write_all(input)?;
    writer.flush()?;
    Ok(&output(writer).bytes)
}

struct BoundedOutput {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.bytes.len().saturating_add(bytes.len()) > self.limit {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "HTTP observation exceeded its decoded chunk limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use flate2::{
        Compression, Crc, GzBuilder,
        write::{GzEncoder, ZlibEncoder},
    };
    use http::{HeaderValue, header::CONTENT_ENCODING};

    use super::*;

    fn decoder(codings: &'static str, limit: usize) -> StreamDecoder {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static(codings));
        StreamDecoder::new(&headers, limit).unwrap()
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut writer = GzEncoder::new(Vec::new(), Compression::fast());
        writer.write_all(bytes).unwrap();
        writer.finish().unwrap()
    }

    #[test]
    fn decodes_stacked_codings_and_gzip_members_across_chunk_boundaries() {
        let mut writer = GzBuilder::new()
            .extra(b"extra")
            .filename("first")
            .comment("optional header fields")
            .write(Vec::new(), Compression::fast());
        writer.write_all(b"data: one\n\n").unwrap();
        let mut encoded = writer.finish().unwrap();
        let mut second = gzip(b"data: two\n\n");
        second[3] |= 2; // FHCRC, following the fixed 10-byte header.
        let mut header_crc = Crc::new();
        header_crc.update(&second[..10]);
        drop(second.splice(10..10, header_crc.sum().to_le_bytes().into_iter().take(2)));
        encoded.extend(second);

        let mut zlib = ZlibEncoder::new(Vec::new(), Compression::fast());
        zlib.write_all(&encoded).unwrap();
        let encoded = zlib.finish().unwrap();

        let mut brotli = brotli::CompressorWriter::new(Vec::new(), CHUNK_BYTES, 1, MAX_WINDOW_LOG);
        brotli.write_all(&encoded).unwrap();
        let encoded = brotli.into_inner();
        let encoded = zstd::stream::encode_all(encoded.as_slice(), 1).unwrap();

        let mut decoder = decoder("x-gzip, deflate, br, zstd", CHUNK_BYTES);
        let mut plaintext = Vec::new();
        for chunk in encoded.chunks(1) {
            plaintext.extend_from_slice(decoder.decode(chunk).unwrap());
        }
        assert_eq!(plaintext, b"data: one\n\ndata: two\n\n");
    }

    #[test]
    fn gzip_flushes_output_while_the_member_is_open() {
        let payload = vec![b'x'; CHUNK_BYTES.saturating_mul(3)];
        let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
        gzip.write_all(&payload).unwrap();
        gzip.flush().unwrap();

        let mut decoder = decoder("gzip", payload.len());
        assert_eq!(decoder.decode(gzip.get_ref()).unwrap(), payload);
    }

    #[test]
    fn bounds_intermediate_layer_output() {
        let payload = vec![b'x'; CHUNK_BYTES.checked_add(1).unwrap()];
        let encoded = gzip(&payload);
        let mut decoder = decoder("gzip, gzip", CHUNK_BYTES);
        assert_eq!(
            decoder.decode(&encoded).unwrap_err().kind(),
            io::ErrorKind::FileTooLarge
        );
    }
}
