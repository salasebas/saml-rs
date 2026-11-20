//! SAML HTTP binding helpers: the HTTP-POST form, the HTTP-Redirect URL and
//! the octets it signs, raw DEFLATE, and the deprecated base64 functions.

mod deflate;
mod encoding;
mod escape;
mod parameters;
mod post_form;
mod redirect;
#[cfg(crypto)]
mod signing;

#[cfg(crypto)]
pub(crate) use signing::sign_detached_message;

pub use deflate::{
    deflate_raw_decode, deflate_raw_decode_with_limit, deflate_raw_encode,
    MAX_DEFLATE_RAW_DECODE_BYTES,
};
pub(crate) use encoding::{decode_base64, decode_base64_with_limit, encode_base64};
pub(crate) use escape::xml_escape;
pub(crate) use parameters::single_parameter;
pub use post_form::saml_post_binding_form;
pub(crate) use post_form::{build_simplesign_octet, saml_post_binding_form_with_signature};
pub(crate) use redirect::{append_redirect_query, redirect_binding_query};
pub use redirect::{append_signature, build_redirect_octet, build_redirect_url};

/// Standard base64 encoding (no line wrapping).
#[deprecated(
    note = "`saml_rs::binding` becomes crate-private in the next minor release; use `base64::engine::general_purpose::STANDARD.encode`"
)]
pub fn base64_encode(input: &[u8]) -> String {
    encoding::encode_base64(input)
}

/// Decode standard base64.
///
/// ASCII whitespace is ignored: space, tab, line feed, form feed, and carriage
/// return. Any other byte outside the base64 alphabet is rejected.
#[deprecated(
    note = "`saml_rs::binding` becomes crate-private in the next minor release; remove ASCII whitespace and use `base64::engine::general_purpose::STANDARD.decode`"
)]
pub fn base64_decode(input: &str) -> Result<Vec<u8>, crate::error::SamlError> {
    encoding::decode_base64(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        deprecated,
        reason = "the deprecated public base64 functions keep their behaviour until removal"
    )]
    fn deprecated_base64_functions_keep_their_behaviour() -> Result<(), Box<dyn std::error::Error>>
    {
        assert_eq!(base64_encode(b"A"), "QQ==");
        assert_eq!(base64_decode("Q Q\n=\t=\r\u{000c}")?, b"A");
        assert!(matches!(
            base64_decode("QQ==\u{00a0}"),
            Err(crate::error::SamlError::Base64 { .. })
        ));
        Ok(())
    }
}
