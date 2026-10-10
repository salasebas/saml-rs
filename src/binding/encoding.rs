//! Base64 helpers with SAML whitespace normalization.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::error::SamlError;

const BASE64_OUTPUT_LIMIT_EXCEEDED: &str = "ERR_BASE64_OUTPUT_LIMIT_EXCEEDED";

/// Standard base64 encoding (no line wrapping).
pub fn base64_encode(input: &[u8]) -> String {
    STANDARD.encode(input)
}

/// Decode standard base64, ignoring any SAML-inserted whitespace.
pub fn base64_decode(input: &str) -> Result<Vec<u8>, SamlError> {
    let normalized: String = input.split_whitespace().collect();
    Ok(STANDARD.decode(normalized)?)
}

/// Decode standard base64, rejecting inputs whose decoded output would exceed
/// `max_output_len` bytes.
///
/// The size check and the decoder both ignore ASCII whitespace: space, tab,
/// line feed, form feed, and carriage return. Any other byte outside the
/// base64 alphabet is rejected.
pub fn base64_decode_with_limit(input: &str, max_output_len: usize) -> Result<Vec<u8>, SamlError> {
    let normalized_len = input
        .bytes()
        .filter(|byte| !is_ignored_base64_whitespace(*byte))
        .count();
    let max_encoded_len = max_output_len
        .saturating_add(2)
        .saturating_div(3)
        .saturating_mul(4);
    if normalized_len > max_encoded_len {
        return Err(SamlError::Invalid(BASE64_OUTPUT_LIMIT_EXCEEDED.into()));
    }

    let mut normalized = Vec::with_capacity(normalized_len);
    normalized.extend(
        input
            .bytes()
            .filter(|byte| !is_ignored_base64_whitespace(*byte)),
    );
    let out = STANDARD.decode(normalized)?;
    if out.len() > max_output_len {
        return Err(SamlError::Invalid(BASE64_OUTPUT_LIMIT_EXCEEDED.into()));
    }
    Ok(out)
}

fn is_ignored_base64_whitespace(byte: u8) -> bool {
    byte.is_ascii_whitespace()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_whitespace_is_ignored_and_does_not_count_toward_the_limit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(base64_decode_with_limit("QQ==", 1)?, b"A");
        assert_eq!(base64_decode_with_limit("Q Q\n=\t=\r\u{000c}", 1)?, b"A");
        assert_eq!(base64_decode_with_limit("", 0)?, b"");
        assert_eq!(base64_decode_with_limit(" \n\t\r\u{000c}", 0)?, b"");
        assert_eq!(base64_decode_with_limit("QUFBQQ==", 4)?, b"AAAA");
        assert_eq!(base64_decode_with_limit("QU FB\nQQ==", 4)?, b"AAAA");
        match base64_decode_with_limit("QUFBQQ==", 1) {
            Err(SamlError::Invalid(message)) if message == BASE64_OUTPUT_LIMIT_EXCEEDED => Ok(()),
            other => Err(format!("expected an output-limit error, got {other:?}").into()),
        }
    }

    #[test]
    fn non_ascii_whitespace_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        for input in ["QQ==\u{00a0}", "Q\u{000b}Q==", "QQ==\u{2028}", "\u{00a0}"] {
            match base64_decode_with_limit(input, 64) {
                Err(SamlError::Base64(_)) => {}
                other => {
                    return Err(format!("input {input:?} produced {other:?}").into());
                }
            }
        }
        Ok(())
    }
}
