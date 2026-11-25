#[cfg(crypto)]
use crate::constants::ParserType;
use crate::error::SamlError;
use crate::flow::{FlowOptions, MessageAuthentication};
use crate::xml::XmlLimits;

pub(crate) fn require_one_assertion_unless_message_authenticated(
    saml_content: &str,
    authentication: MessageAuthentication,
    limits: XmlLimits,
) -> Result<(), SamlError> {
    match authentication {
        MessageAuthentication::Authenticated => return Ok(()),
        MessageAuthentication::Unauthenticated => {}
    }
    let document = crate::xml::dom::parse_document(saml_content, limits)?;
    let assertions = document.root.children_named("Assertion").count();
    if assertions > 1 {
        return Err(SamlError::Unsupported(
            "EncryptedID or EncryptedAttribute in several assertions requires a signed Response"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(crypto)]
pub(crate) fn carries_encrypted_elements(saml_content: &str) -> Result<bool, SamlError> {
    crate::crypto::enc::carries_encrypted_assertion_elements(saml_content)
}

#[cfg(not(crypto))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "The provider parses XML and can fail through this interface"
)]
pub(crate) fn carries_encrypted_elements(_saml_content: &str) -> Result<bool, SamlError> {
    Ok(false)
}

#[cfg(crypto)]
pub(crate) fn decrypt_verified_assertion_elements(
    saml_content: &str,
    assertion: Option<&str>,
    key_pem: &str,
    opts: &FlowOptions<'_>,
) -> Result<(String, Option<String>), SamlError> {
    use crate::constants::ParserType;
    use crate::crypto::{enc::decrypt_assertion_elements, keys::load_decryption_keys};
    use crate::xml::validate_protocol_profile;

    let keys = load_decryption_keys(key_pem, opts.decrypt_key_pass, opts.additional_decrypt_keys)?;
    let content = decrypt_assertion_elements(
        saml_content,
        &keys,
        opts.into(),
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
    let position = document
        .root
        .children_named("Assertion")
        .position(|node| node.start == start);
    position.ok_or(SamlError::SignedReferenceMismatch)
}

#[cfg(crypto)]
fn direct_assertion(
    response: &str,
    position: usize,
    limits: XmlLimits,
) -> Result<String, SamlError> {
    let document = crate::xml::dom::parse_document(response, limits)?;
    let node = document
        .root
        .children_named("Assertion")
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

#[cfg(crypto)]
pub(crate) fn encrypted_assertion_key<'a>(
    root: &crate::xml::dom::Node,
    parser_type: ParserType,
    opts: &FlowOptions<'a>,
) -> Option<&'a str> {
    if parser_type == ParserType::SamlResponse
        && (opts.require_encrypted_assertions || root.child_named("EncryptedAssertion").is_some())
    {
        opts.decrypt_key
    } else {
        None
    }
}

#[cfg(crypto)]
pub(crate) fn decrypt_assertions(
    xml: &str,
    key_pem: &str,
    parser_type: ParserType,
    opts: &FlowOptions<'_>,
) -> Result<(String, Vec<std::ops::Range<usize>>), SamlError> {
    use crate::crypto::{enc::decrypt_assertions_with_limits, keys::load_decryption_keys};

    let (content, assertions) = decrypt_assertions_with_limits(
        xml,
        &load_decryption_keys(key_pem, opts.decrypt_key_pass, opts.additional_decrypt_keys)?,
        opts.into(),
        opts.xml_limits,
    )?;
    crate::schema::document(&content, opts.xml_limits, opts.schema_validator)?;
    crate::xml::validate_protocol_profile(&content, parser_type, opts.xml_limits)?;
    Ok((content, assertions))
}
