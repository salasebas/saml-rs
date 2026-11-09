//! Decryption of the `<EncryptedID>` and `<EncryptedAttribute>` children of a
//! verified login response.

use crate::error::SamlError;
use crate::flow::FlowOptions;
use crate::xml::XmlLimits;

/// Reject a response with several assertions unless a verified signature
/// covers the whole response. Encrypted children are decrypted only inside
/// content that a verified signature covers.
pub(crate) fn require_one_assertion_unless_message_authenticated(
    saml_content: &str,
    message_authenticated: bool,
    limits: XmlLimits,
) -> Result<(), SamlError> {
    if message_authenticated {
        return Ok(());
    }
    let document = crate::xml::dom::parse_with_limits(saml_content, limits)?;
    let assertions = document
        .root
        .children
        .iter()
        .filter(|child| child.local_name == "Assertion")
        .count();
    if assertions > 1 {
        return Err(SamlError::Unsupported(
            "EncryptedID or EncryptedAttribute in several assertions requires a signed Response"
                .into(),
        ));
    }
    Ok(())
}

/// Decrypt the selected `<EncryptedID>` and `<EncryptedAttribute>` children of
/// the verified response and of its consumed assertion.
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
pub(crate) fn decrypt_verified_assertion_elements(
    saml_content: &str,
    assertion: Option<&str>,
    key_pem: &str,
    opts: &FlowOptions<'_>,
) -> Result<(String, Option<String>), SamlError> {
    use crate::constants::ParserType;
    use crate::context::is_valid_xml_with_limits;
    use crate::crypto::{
        enc::{decrypt_assertion_elements, AssertionDecryptionOptions},
        keys::load_private_key,
    };
    use crate::xml::validate_protocol_profile;

    let key = load_private_key(key_pem, opts.decrypt_key_pass)?;
    let options = AssertionDecryptionOptions {
        allow_insecure_software_rsa_key_transport_decryption: opts
            .allow_insecure_software_rsa_key_transport_decryption,
    };
    let decrypt = |xml: &str| {
        decrypt_assertion_elements(xml, &key, options, opts.xml_limits, opts.assertion_elements)
    };
    let content = decrypt(saml_content)?;
    is_valid_xml_with_limits(&content, opts.xml_limits)?;
    validate_protocol_profile(&content, ParserType::SamlResponse, opts.xml_limits)?;
    let assertion = assertion.map(decrypt).transpose()?;
    Ok((content, assertion))
}

#[cfg(not(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
)))]
pub(crate) fn decrypt_verified_assertion_elements(
    _saml_content: &str,
    _assertion: Option<&str>,
    _key_pem: &str,
    _opts: &FlowOptions<'_>,
) -> Result<(String, Option<String>), SamlError> {
    Err(SamlError::Unsupported(
        "XML decryption requires a crypto provider feature".into(),
    ))
}
