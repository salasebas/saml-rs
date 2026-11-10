//! Checks on a login `<Response>` whose status is not `Success`, run before
//! that status is reported.

use super::{
    signature_is_present, validate_in_response_to, validate_message_destination,
    verify_and_prepare, verify_detached, AssertionSignatureRequirement, FlowOptions, HttpRequest,
    ResponseSignatureRequirement, SignedMessageDestination,
};
use crate::constants::{Binding, ParserType};
use crate::error::SamlError;
use crate::util::Value;
use crate::xml::{extract_with_limits, fields};

pub(super) fn validate_error_response(
    opts: &FlowOptions<'_>,
    request: &HttpRequest,
    binding: Binding,
    xml: &str,
    expected_recipient: Option<&str>,
    signed_destination: SignedMessageDestination,
) -> Result<(), SamlError> {
    let message_authenticated = verify_present_signature(opts, request, binding, xml)?;
    let extracted =
        extract_with_limits(xml, &fields::login_error_response_fields(), opts.xml_limits)?;
    if let Some(expected) = opts.from_issuer {
        validate_issuer(expected, extracted.get("issuer"))?;
    }
    validate_in_response_to(&extracted, opts.expected_in_response_to)?;
    validate_message_destination(
        ParserType::SamlResponse,
        &extracted,
        expected_recipient,
        message_authenticated,
        signed_destination,
    )
}

fn validate_issuer(expected: &str, issuer: Option<&Value>) -> Result<(), SamlError> {
    match issuer {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Str(actual)) if actual == expected => Ok(()),
        Some(Value::Str(actual)) => Err(SamlError::issuer_mismatch(expected, Some(actual))),
        Some(Value::Array(_) | Value::Object(_)) => Err(SamlError::issuer_mismatch(expected, None)),
    }
}

fn verify_present_signature(
    opts: &FlowOptions<'_>,
    request: &HttpRequest,
    binding: Binding,
    xml: &str,
) -> Result<bool, SamlError> {
    let verify = (opts.check_signature || opts.verify_signature_if_present)
        && signature_is_present(binding, request, xml, opts.xml_limits)?;
    if !verify {
        return Ok(false);
    }
    match binding {
        Binding::Redirect | Binding::SimpleSign => {
            verify_detached(binding, ParserType::SamlResponse, request, opts, xml)?;
            Ok(true)
        }
        Binding::Post | Binding::Artifact | Binding::Soap => Ok(verify_and_prepare(
            xml,
            ParserType::SamlResponse,
            opts,
            AssertionSignatureRequirement::Compatible,
            ResponseSignatureRequirement::Optional,
        )?
        .message_authenticated),
    }
}
