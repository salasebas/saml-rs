//! Raw DEFLATE (RFC 1951) used by the SAML HTTP-Redirect binding.

use std::io::{Read, Write};

use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;

use crate::error::{ResourceLimit, SamlError};

/// Default maximum inflated size accepted by [`deflate_raw_decode`].
///
/// SAML does not define this number. It is a conservative library default for
/// HTTP-Redirect, where messages are decoded before XML or signature validation
/// and normally remain well below this size. Use
/// [`deflate_raw_decode_with_limit`] when a caller needs a different cap.
pub const MAX_DEFLATE_RAW_DECODE_BYTES: usize = 1024 * 1024;

/// Raw-DEFLATE compress `input` (no zlib/gzip header), as required by the
/// HTTP-Redirect binding.
pub fn deflate_raw_encode(input: &[u8]) -> Result<Vec<u8>, SamlError> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(input).map_err(deflate_error)?;
    encoder.finish().map_err(deflate_error)
}

/// Inflate raw-DEFLATE `input` produced by [`deflate_raw_encode`].
pub fn deflate_raw_decode(input: &[u8]) -> Result<Vec<u8>, SamlError> {
    deflate_raw_decode_with_limit(input, MAX_DEFLATE_RAW_DECODE_BYTES)
}

/// Inflate raw-DEFLATE `input`, failing if the inflated output exceeds
/// `max_output_len` bytes.
pub fn deflate_raw_decode_with_limit(
    input: &[u8],
    max_output_len: usize,
) -> Result<Vec<u8>, SamlError> {
    let decoder = DeflateDecoder::new(input);
    let mut out = Vec::with_capacity(input.len().min(max_output_len));
    let read_limit = max_output_len.saturating_add(1);
    let mut limited = decoder.take(read_limit as u64);
    limited.read_to_end(&mut out).map_err(deflate_error)?;

    if out.len() > max_output_len {
        return Err(SamlError::LimitExceeded {
            limit: ResourceLimit::InflatedBytes,
            maximum: max_output_len,
        });
    }

    Ok(out)
}

fn deflate_error(source: std::io::Error) -> SamlError {
    SamlError::Deflate {
        source: Box::new(source),
    }
}
