//! Raw DEFLATE (RFC 1951) used by the SAML HTTP-Redirect binding.

use std::io::{Read, Write};

use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;

use crate::error::{ResourceLimit, SamlError};

pub const MAX_DEFLATE_RAW_DECODE_BYTES: usize = 1024 * 1024;

/// Raw-DEFLATE compress `input` (no zlib/gzip header), as required by the
/// HTTP-Redirect binding.
pub fn deflate_raw_encode(input: &[u8]) -> Result<Vec<u8>, SamlError> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(input).map_err(deflate_error)?;
    encoder.finish().map_err(deflate_error)
}

pub fn deflate_raw_decode(input: &[u8], max_output_len: usize) -> Result<Vec<u8>, SamlError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_OUTPUT_LEN: usize = 64;

    #[test]
    fn output_of_exactly_the_limit_is_inflated() -> Result<(), Box<dyn std::error::Error>> {
        let original = [b'A'; MAX_OUTPUT_LEN];
        let compressed = deflate_raw_encode(&original)?;

        assert_eq!(deflate_raw_decode(&compressed, MAX_OUTPUT_LEN)?, original);
        Ok(())
    }

    #[test]
    fn output_one_byte_over_the_limit_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let compressed = deflate_raw_encode(&[b'A'; MAX_OUTPUT_LEN + 1])?;

        match deflate_raw_decode(&compressed, MAX_OUTPUT_LEN) {
            Err(SamlError::LimitExceeded {
                limit: ResourceLimit::InflatedBytes,
                maximum: MAX_OUTPUT_LEN,
            }) => Ok(()),
            other => Err(format!("expected an InflatedBytes limit, got {other:?}").into()),
        }
    }
}
