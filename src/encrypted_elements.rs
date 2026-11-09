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
    let content = decrypt_assertion_elements(
        saml_content,
        &key,
        options,
        opts.xml_limits,
        opts.assertion_elements,
    )?;
    is_valid_xml_with_limits(&content, opts.xml_limits)?;
    validate_protocol_profile(&content, ParserType::SamlResponse, opts.xml_limits)?;
    let assertion = assertion
        .map(|assertion| {
            let position = direct_assertion_position(saml_content, assertion, opts.xml_limits)?;
            direct_assertion(&content, position, opts.xml_limits)
        })
        .transpose()?;
    Ok((content, assertion))
}

/// Direct `<Assertion>` children of the response root.
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn direct_assertions(root: &crate::xml::dom::Node) -> impl Iterator<Item = &crate::xml::dom::Node> {
    root.children
        .iter()
        .filter(|child| child.local_name == "Assertion")
}

/// Position of the consumed `assertion` among the direct assertions of
/// `response`, which contains its source.
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn direct_assertion_position(
    response: &str,
    assertion: &str,
    limits: XmlLimits,
) -> Result<usize, SamlError> {
    let start = response
        .find(assertion)
        .ok_or(SamlError::SignedReferenceMismatch)?;
    let document = crate::xml::dom::parse_with_limits(response, limits)?;
    let position = direct_assertions(&document.root).position(|node| node.start == start);
    position.ok_or(SamlError::SignedReferenceMismatch)
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn direct_assertion(
    response: &str,
    position: usize,
    limits: XmlLimits,
) -> Result<String, SamlError> {
    let document = crate::xml::dom::parse_with_limits(response, limits)?;
    let node = direct_assertions(&document.root)
        .nth(position)
        .ok_or(SamlError::SignedReferenceMismatch)?;
    Ok(response[node.start..node.end].to_string())
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
