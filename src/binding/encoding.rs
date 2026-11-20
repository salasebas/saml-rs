//! Base64 helpers with SAML whitespace normalization.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::error::{ResourceLimit, SamlError};

pub(crate) fn encode_base64(input: &[u8]) -> String {
    STANDARD.encode(input)
}

/// Decode standard base64 with no size limit.
///
/// For base64 that the crate or its crypto provider produced, and for a
/// detached signature value. A received protocol message is decoded with
/// [`decode_base64_with_limit`].
///
/// ASCII whitespace is ignored: space, tab, line feed, form feed, and carriage
/// return. Any other byte outside the base64 alphabet is rejected.
pub(crate) fn decode_base64(input: &str) -> Result<Vec<u8>, SamlError> {
    let normalized: Vec<u8> = non_whitespace_bytes(input).collect();
    STANDARD.decode(normalized).map_err(base64_error)
}

/// Decode standard base64, rejecting inputs whose decoded output would exceed
/// `max_output_len` bytes.
///
/// ASCII whitespace is ignored: space, tab, line feed, form feed, and carriage
/// return. Ignored whitespace does not count toward the limit. Any other byte
/// outside the base64 alphabet is rejected.
pub(crate) fn decode_base64_with_limit(
    input: &str,
    max_output_len: usize,
) -> Result<Vec<u8>, SamlError> {
    let normalized_len = non_whitespace_bytes(input).count();
    let max_encoded_len = max_output_len
        .saturating_add(2)
        .saturating_div(3)
        .saturating_mul(4);
    let limit_exceeded = SamlError::LimitExceeded {
        limit: ResourceLimit::Base64DecodedBytes,
        maximum: max_output_len,
    };
    if normalized_len > max_encoded_len {
        return Err(limit_exceeded);
    }

    let mut normalized = Vec::with_capacity(normalized_len);
    normalized.extend(non_whitespace_bytes(input));
    let out = STANDARD.decode(normalized).map_err(base64_error)?;
    if out.len() > max_output_len {
        return Err(limit_exceeded);
    }
    Ok(out)
}

pub(crate) fn base64_error(source: base64::DecodeError) -> SamlError {
    SamlError::Base64 {
        source: Box::new(source),
    }
}

fn non_whitespace_bytes(input: &str) -> impl Iterator<Item = u8> + '_ {
    input.bytes().filter(|byte| !byte.is_ascii_whitespace())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_whitespace_is_ignored_and_does_not_count_toward_the_limit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(decode_base64_with_limit("QQ==", 1)?, b"A");
        assert_eq!(decode_base64_with_limit("Q Q\n=\t=\r\u{000c}", 1)?, b"A");
        assert_eq!(decode_base64_with_limit("", 0)?, b"");
        assert_eq!(decode_base64_with_limit(" \n\t\r\u{000c}", 0)?, b"");
        assert_eq!(decode_base64_with_limit("QUFBQQ==", 4)?, b"AAAA");
        assert_eq!(decode_base64_with_limit("QU FB\nQQ==", 4)?, b"AAAA");
        assert_eq!(decode_base64("Q Q\n=\t=\r\u{000c}")?, b"A");
        assert_eq!(decode_base64(" \n\t\r\u{000c}")?, b"");
        match decode_base64_with_limit("QUFBQQ==", 1) {
            Err(SamlError::LimitExceeded {
                limit: ResourceLimit::Base64DecodedBytes,
                maximum: 1,
            }) => Ok(()),
            other => Err(format!("expected an output-limit error, got {other:?}").into()),
        }
    }

    #[test]
    fn non_ascii_whitespace_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        for input in [
            "QQ==\u{00a0}",
            "Q\u{000b}Q==",
            "QQ==\u{2028}",
            "QUJD\u{3000}",
            "\u{00a0}",
        ] {
            for (decoder, result) in [
                (
                    "decode_base64_with_limit",
                    decode_base64_with_limit(input, 64),
                ),
                ("decode_base64", decode_base64(input)),
            ] {
                match result {
                    Err(SamlError::Base64 { .. }) => {}
                    other => {
                        return Err(format!("{decoder} input {input:?} produced {other:?}").into());
                    }
                }
            }
        }
        Ok(())
    }
}
