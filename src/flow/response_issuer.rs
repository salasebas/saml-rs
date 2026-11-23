//! Issuers in a login response, for peer lookup and validation.

use crate::config::validate_entity_id_syntax;
use crate::constants::namespace;
use crate::error::{IdpResolutionReason, SamlError};
use crate::util::Value;
use crate::xml::any_uri::collapse_whitespace;
use crate::xml::protocol_element::{issuer_format_is_entity, parse_saml_with_limits, SamlElement};
use crate::xml::{extract_with_limits, fields, ExtractorField, XmlLimits};

pub(super) fn validate_response_issuer(
    expected: &str,
    xml: &str,
    limits: XmlLimits,
) -> Result<(), SamlError> {
    let issuer = [ExtractorField::new(fields::ISSUER, &["Response", "Issuer"])];
    let extracted = extract_with_limits(xml, &issuer, limits)?;
    match extracted.get(fields::ISSUER) {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Str(actual)) if actual == expected => Ok(()),
        Some(Value::Str(actual)) => Err(SamlError::issuer_mismatch(expected, Some(actual))),
        Some(Value::Array(_) | Value::Object(_)) => Err(SamlError::issuer_mismatch(expected, None)),
    }
}

pub(crate) fn issuer_for_idp_resolution(xml: &str, limits: XmlLimits) -> Result<String, SamlError> {
    let response = parse_saml_with_limits(xml, limits)?;
    if !response.is(namespace::PROTOCOL, "Response") {
        return Err(SamlError::ProtocolProfile(
            "expected a SAML protocol Response".into(),
        ));
    }
    lookup_issuer(&response)
        .map(str::to_owned)
        .map_err(|reason| SamlError::IdpResolution { reason })
}

fn lookup_issuer(response: &SamlElement) -> Result<&str, IdpResolutionReason> {
    use IdpResolutionReason::{AmbiguousIssuer, MissingIssuer};

    if let Some(issuer) = direct_entity_issuer(response)? {
        return Ok(issuer);
    }
    if response.children.iter().any(|child| {
        child.is(namespace::DSIG, "Signature")
            || child.is(namespace::ASSERTION, "EncryptedAssertion")
    }) {
        return Err(MissingIssuer);
    }
    let mut issuer = None;
    for assertion in response
        .children
        .iter()
        .filter(|child| child.is(namespace::ASSERTION, "Assertion"))
    {
        let candidate = direct_entity_issuer(assertion)?.ok_or(MissingIssuer)?;
        if issuer.is_some_and(|issuer| candidate != issuer) {
            return Err(AmbiguousIssuer);
        }
        issuer = Some(candidate);
    }
    issuer.ok_or(MissingIssuer)
}

fn direct_entity_issuer(element: &SamlElement) -> Result<Option<&str>, IdpResolutionReason> {
    let mut issuers = element
        .children
        .iter()
        .filter(|child| child.is(namespace::ASSERTION, "Issuer"));
    let Some(issuer) = issuers.next() else {
        return Ok(None);
    };
    if issuers.next().is_some() {
        return Err(IdpResolutionReason::AmbiguousIssuer);
    }
    let format = issuer.attr("Format").map(collapse_whitespace);
    if !issuer.children.is_empty()
        || !issuer_format_is_entity(format.as_deref())
        || ["NameQualifier", "SPNameQualifier", "SPProvidedID"]
            .iter()
            .any(|name| issuer.attr(name).is_some())
        || validate_entity_id_syntax(&issuer.text).is_err()
    {
        return Err(IdpResolutionReason::InvalidIssuer);
    }
    Ok(Some(&issuer.text))
}
