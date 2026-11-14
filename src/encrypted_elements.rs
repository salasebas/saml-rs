//! Decryption of the `<EncryptedAssertion>`, `<EncryptedID>`, and
//! `<EncryptedAttribute>` children of a verified login response.

#[cfg(crypto)]
use crate::config::ReceivedEncryptedElements;
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
    use crate::context::is_valid_xml_with_limits;
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
        opts.received_encrypted_elements,
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
    let document = crate::xml::dom::parse_with_limits(response, limits)?;
    let position = direct_assertions(&document.root).position(|node| node.start == start);
    position.ok_or(SamlError::SignedReferenceMismatch)
}

#[cfg(crypto)]
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

/// The key that decrypts each `<EncryptedAssertion>` child of `root`. A selected
/// `decrypt_key` requires one. A typed service provider also decrypts one it
/// did not select.
#[cfg(crypto)]
pub(crate) fn encrypted_assertion_key<'a>(
    root: &crate::xml::dom::Node,
    parser_type: ParserType,
    opts: &FlowOptions<'a>,
) -> Option<&'a str> {
    if opts.decrypt_key.is_some() {
        return opts.decrypt_key;
    }
    match (opts.received_encrypted_elements, parser_type) {
        (ReceivedEncryptedElements::DecryptReceived, ParserType::SamlResponse) => {
            let carries_encrypted_assertion = root
                .children
                .iter()
                .any(|child| child.local_name == "EncryptedAssertion");
            if carries_encrypted_assertion {
                opts.element_decrypt_key
            } else {
                None
            }
        }
        (ReceivedEncryptedElements::DecryptReceived, _)
        | (ReceivedEncryptedElements::DecryptSelected, _) => None,
    }
}

/// `xml`, whose detached signature verified, with each `<EncryptedAssertion>`
/// decrypted for a typed service provider, and the decrypted assertions.
/// `None` when no key applies, and for the raw service provider.
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

    let key_pem = match opts.received_encrypted_elements {
        ReceivedEncryptedElements::DecryptReceived => {
            encrypted_assertion_key(root, parser_type, opts)
        }
        ReceivedEncryptedElements::DecryptSelected => None,
    };
    let Some(key_pem) = key_pem else {
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
    crate::context::is_valid_xml_with_limits(&content, opts.xml_limits)?;
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
