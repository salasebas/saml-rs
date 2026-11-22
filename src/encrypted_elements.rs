//! Decryption of the `<EncryptedAssertion>`, `<EncryptedID>`, and
//! `<EncryptedAttribute>` children of a verified login response.

use crate::constants::ParserType;
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
    let document = crate::xml::dom::parse_document(saml_content, limits)?;
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

/// Whether an assertion of `saml_content` carries an `<EncryptedID>` or an
/// `<EncryptedAttribute>`.
#[cfg(crypto)]
pub(crate) fn carries_encrypted_elements(saml_content: &str) -> Result<bool, SamlError> {
    crate::crypto::enc::carries_encrypted_assertion_elements(saml_content)
}

#[cfg(not(crypto))]
pub(crate) fn carries_encrypted_elements(_saml_content: &str) -> Result<bool, SamlError> {
    Ok(false)
}

/// Decrypt the `<EncryptedID>` and `<EncryptedAttribute>` children of the
/// verified response and of its consumed assertion.
#[cfg(crypto)]
pub(crate) fn decrypt_verified_assertion_elements(
    saml_content: &str,
    assertion: Option<&str>,
    key_pem: &str,
    opts: &FlowOptions<'_>,
) -> Result<(String, Option<String>), SamlError> {
    use crate::constants::ParserType;
    use crate::crypto::{
        enc::{decrypt_assertion_elements, AssertionDecryptionOptions},
        keys::load_decryption_keys,
    };
    use crate::xml::validate_protocol_profile;

    let keys = load_decryption_keys(key_pem, opts.decrypt_key_pass, opts.additional_decrypt_keys)?;
    let options = AssertionDecryptionOptions {
        allow_rsa15_key_transport_decryption: opts.allow_rsa15_key_transport_decryption,
        max_decryption_work: opts.max_decryption_work,
    };
    let content = decrypt_assertion_elements(
        saml_content,
        &keys,
        options,
        opts.xml_limits,
        opts.assertion_elements,
    )?;
    crate::schema::document(&content, opts.xml_limits, opts.schema_validator)?;
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
#[cfg(crypto)]
fn direct_assertions(root: &crate::xml::dom::Node) -> impl Iterator<Item = &crate::xml::dom::Node> {
    root.children
        .iter()
        .filter(|child| child.local_name == "Assertion")
}

/// Position of the consumed `assertion` among the direct assertions of
/// `response`, which contains its source.
#[cfg(crypto)]
fn direct_assertion_position(
    response: &str,
    assertion: &str,
    limits: XmlLimits,
) -> Result<usize, SamlError> {
    let start = response
        .find(assertion)
        .ok_or(SamlError::SignedReferenceMismatch)?;
    let document = crate::xml::dom::parse_document(response, limits)?;
    let position = direct_assertions(&document.root).position(|node| node.start == start);
    position.ok_or(SamlError::SignedReferenceMismatch)
}

#[cfg(crypto)]
fn direct_assertion(
    response: &str,
    position: usize,
    limits: XmlLimits,
) -> Result<String, SamlError> {
    let document = crate::xml::dom::parse_document(response, limits)?;
    let node = direct_assertions(&document.root)
        .nth(position)
        .ok_or(SamlError::SignedReferenceMismatch)?;
    Ok(response[node.start..node.end].to_string())
}

#[cfg(not(crypto))]
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

/// The SP key when a login response requires or carries an encrypted assertion.
#[cfg(crypto)]
pub(crate) fn encrypted_assertion_key<'a>(
    root: &crate::xml::dom::Node,
    parser_type: ParserType,
    opts: &FlowOptions<'a>,
) -> Option<&'a str> {
    if parser_type == ParserType::SamlResponse
        && (opts.require_encrypted_assertion || root.child_named("EncryptedAssertion").is_some())
    {
        opts.decrypt_key
    } else {
        None
    }
}

/// `xml`, whose detached signature verified, with each `<EncryptedAssertion>`
/// decrypted for a typed service provider, and the decrypted assertions.
/// Returns `None` when no key applies.
#[cfg(crypto)]
pub(crate) fn decrypt_detached_signed_assertions(
    xml: &str,
    root: &crate::xml::dom::Node,
    parser_type: ParserType,
    opts: &FlowOptions<'_>,
) -> Result<Option<(String, Vec<String>)>, SamlError> {
    use crate::crypto::{
        enc::{decrypt_assertions_with_limits, AssertionDecryptionOptions},
        keys::load_decryption_keys,
    };

    let Some(key_pem) = encrypted_assertion_key(root, parser_type, opts) else {
        return Ok(None);
    };
    let (content, assertions) = decrypt_assertions_with_limits(
        xml,
        &load_decryption_keys(key_pem, opts.decrypt_key_pass, opts.additional_decrypt_keys)?,
        AssertionDecryptionOptions {
            allow_rsa15_key_transport_decryption: opts.allow_rsa15_key_transport_decryption,
            max_decryption_work: opts.max_decryption_work,
        },
        opts.xml_limits,
    )?;
    crate::schema::document(&content, opts.xml_limits, opts.schema_validator)?;
    crate::xml::validate_protocol_profile(&content, parser_type, opts.xml_limits)?;
    Ok(Some((content, assertions)))
}

#[cfg(not(crypto))]
pub(crate) fn decrypt_detached_signed_assertions(
    _xml: &str,
    _root: &crate::xml::dom::Node,
    _parser_type: ParserType,
    _opts: &FlowOptions<'_>,
) -> Result<Option<(String, Vec<String>)>, SamlError> {
    Ok(None)
}
