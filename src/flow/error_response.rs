//! Checks on a login `<Response>` whose status is not `Success`, run before
//! that status is reported.

use super::response_issuer::validate_response_issuer;
use super::{
    correlated_status_message, signature_is_present, validate_in_response_to,
    validate_message_destination, verify_and_prepare, verify_detached, verify_present_signatures,
    AssertionSignatureRequirement, FlowOptions, HttpRequest, MessageAuthentication,
    ResponseSignatureRequirement, SignatureCheck, SignedMessageDestination,
};
use crate::constants::{Binding, ParserType};
use crate::error::SamlError;
use crate::model::StatusMessage;
use crate::xml::{extract_with_limits, fields};

pub(super) fn validate_error_response(
    opts: &FlowOptions<'_>,
    request: &HttpRequest,
    binding: Binding,
    xml: &str,
    root: &crate::xml::dom::Node,
    expected_recipient: Option<&str>,
    signed_destination: SignedMessageDestination,
) -> Result<Option<StatusMessage>, SamlError> {
    let authentication = verify_present_signature(opts, request, binding, xml, root)?;
    if let Some(expected) = opts.from_issuer {
        validate_response_issuer(expected, xml, opts.xml_limits)?;
    }
    let extracted =
        extract_with_limits(xml, &fields::login_error_response_fields(), opts.xml_limits)?;
    if let Some(actual) = extracted.get_str(fields::response::IN_RESPONSE_TO) {
        validate_in_response_to(Some(actual), opts.expected_in_response_to)?;
    }
    validate_message_destination(
        ParserType::SamlResponse,
        &extracted,
        expected_recipient,
        authentication,
        signed_destination,
    )?;
    if authentication == MessageAuthentication::Authenticated && expected_recipient.is_some() {
        return Ok(correlated_status_message(
            xml,
            opts.xml_limits,
            opts.expected_in_response_to,
            expected_recipient,
            signed_destination,
        ));
    }
    Ok(None)
}

fn verify_present_signature(
    opts: &FlowOptions<'_>,
    request: &HttpRequest,
    binding: Binding,
    xml: &str,
    root: &crate::xml::dom::Node,
) -> Result<MessageAuthentication, SamlError> {
    let verify = match opts.signature_check {
        SignatureCheck::Skip => false,
        SignatureCheck::VerifyIfPresent | SignatureCheck::Require => {
            signature_is_present(binding, request, root)
        }
    };
    if !verify {
        return Ok(MessageAuthentication::Unauthenticated);
    }
    match binding {
        Binding::Redirect | Binding::SimpleSign => {
            verify_detached(binding, ParserType::SamlResponse, request, opts, xml)?;
            verify_present_signatures(xml, opts)?;
            Ok(MessageAuthentication::Authenticated)
        }
        Binding::Post | Binding::Artifact | Binding::Soap => {
            let signature_only = FlowOptions {
                decrypt_key: None,
                ..opts.clone()
            };
            Ok(verify_and_prepare(
                xml.to_string(),
                root,
                ParserType::SamlResponse,
                &signature_only,
                AssertionSignatureRequirement::Compatible,
                ResponseSignatureRequirement::Optional,
            )?
            .authentication)
        }
    }
}
