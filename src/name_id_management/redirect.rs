//! `ManageNameIDRequest` and `ManageNameIDResponse` over HTTP-Redirect.

use std::time::SystemTime;

use crate::browser::NameIdManagementBinding;
use crate::config::EntityId;
use crate::config::HmacSecret;
use crate::config::IdentifierEncryptionPolicy;
use crate::constants::{CertUse, ParserType};
use crate::entity::{BindingContext, EntitySetting};
use crate::error::SamlError;
use crate::flow::{
    flow_with_expected_recipient_and_signature_evidence, AssertionSignatureRequirement,
    FlowOptions, FlowResult, HttpRequest, ResponseSignatureRequirement, SignedMessageDestination,
};
use crate::logout::sign_browser_message;
use crate::metadata::Metadata;
use crate::model::MessageId;
use crate::xml::protocol_element::{issuer, parse_saml_with_limits};
use crate::xml::XmlLimits;

use super::xml::{render_request, render_response, Prefixes, RequestXml, ResponseXml};
use super::{
    identifier_and_change, plaintext_content, protect_request, require_one_status_code,
    ManageNameIdRequest, NameIdManagementRefusal,
};

/// The receiving endpoint and clock for an inbound message.
pub(crate) struct InboundValidation<'a> {
    pub(crate) expected_recipient: &'a str,
    pub(crate) peer_hmac_secret: Option<&'a HmacSecret>,
    pub(crate) now: SystemTime,
    pub(crate) clock_drifts: (i64, i64),
}

pub(crate) fn create_request(
    setting: &EntitySetting,
    peer_meta: &Metadata,
    request: &RequestXml<'_>,
    identifier_encryption: IdentifierEncryptionPolicy,
    relay_state: Option<&str>,
) -> Result<BindingContext, SamlError> {
    let xml = protect_request(
        render_request(&Prefixes::of(setting)?, request)?,
        identifier_encryption,
        setting,
        peer_meta,
    )?;
    bind_signed(
        setting,
        request.id.to_string(),
        &xml,
        request.destination,
        relay_state,
        ParserType::ManageNameIdRequest,
    )
}

pub(crate) fn create_response(
    setting: &EntitySetting,
    response: &ResponseXml<'_>,
    relay_state: Option<&str>,
) -> Result<BindingContext, SamlError> {
    let destination = response.destination.ok_or_else(|| {
        SamlError::Invalid("an HTTP-Redirect ManageNameIDResponse names its Destination".into())
    })?;
    let xml = render_response(&Prefixes::of(setting)?, response);
    bind_signed(
        setting,
        response.id.to_string(),
        &xml,
        destination,
        relay_state,
        ParserType::ManageNameIdResponse,
    )
}

/// Parse a signed `ManageNameIDRequest` from `peer_meta`'s entity.
pub(crate) fn parse_request(
    setting: &EntitySetting,
    peer_meta: &Metadata,
    request: &HttpRequest,
    validation: InboundValidation<'_>,
) -> Result<FlowResult, SamlError> {
    parse_signed(
        setting,
        peer_meta,
        request,
        ParserType::ManageNameIdRequest,
        None,
        validation,
    )
}

/// Parse a signed `ManageNameIDResponse` that answers `request_id`.
pub(crate) fn parse_response(
    setting: &EntitySetting,
    peer_meta: &Metadata,
    request: &HttpRequest,
    request_id: &str,
    validation: InboundValidation<'_>,
) -> Result<FlowResult, SamlError> {
    parse_signed(
        setting,
        peer_meta,
        request,
        ParserType::ManageNameIdResponse,
        Some(request_id),
        validation,
    )
}

/// What a parsed request names, before the caller decides how to answer.
pub(crate) enum ParsedRequest {
    Plain(ManageNameIdRequest),
    Refused {
        id: MessageId,
        issuer: EntityId,
        reason: NameIdManagementRefusal,
    },
}

/// The request in `flow`, with `EncryptedID` and `NewEncryptedID` decrypted
/// by the key in `setting`.
pub(crate) fn request_from_flow(
    flow: &FlowResult,
    setting: &EntitySetting,
) -> Result<ParsedRequest, SamlError> {
    let request = parse_saml_with_limits(&flow.saml_content, setting.xml_limits)?;
    let id = MessageId::try_new(request.required_attr("ID")?)?;
    let issuer = issuer(&request).ok_or_else(|| {
        SamlError::ProtocolProfile("ManageNameIDRequest is missing Issuer".into())
    })?;
    let issuer = EntityId::try_new(issuer.value)?;
    if request.required_attr("Version")? != "2.0" {
        return Ok(ParsedRequest::Refused {
            id,
            issuer,
            reason: NameIdManagementRefusal::VersionMismatch,
        });
    }
    let (identifier, change) = identifier_and_change(&request)?;
    Ok(
        match plaintext_content(&flow.saml_content, identifier, change, setting) {
            Ok((name_id, change)) => ParsedRequest::Plain(ManageNameIdRequest {
                id,
                issuer,
                name_id,
                change,
            }),
            Err(reason) => ParsedRequest::Refused { id, issuer, reason },
        },
    )
}

pub(crate) fn response_id_from_flow(
    flow: &FlowResult,
    limits: XmlLimits,
) -> Result<MessageId, SamlError> {
    let response = parse_saml_with_limits(&flow.saml_content, limits)?;
    require_one_status_code(&response)?;
    MessageId::try_new(response.required_attr("ID")?)
}

fn parse_signed(
    setting: &EntitySetting,
    peer_meta: &Metadata,
    request: &HttpRequest,
    parser_type: ParserType,
    expected_in_response_to: Option<&str>,
    validation: InboundValidation<'_>,
) -> Result<FlowResult, SamlError> {
    let signing_certs = peer_meta.x509_certificates(CertUse::Signing);
    let options = FlowOptions {
        binding: Some(NameIdManagementBinding::Redirect.as_binding()),
        parser_type: Some(parser_type),
        // SAML Profiles 2.0 §4.5.3.1 and §4.5.3.2 require a signed message on
        // HTTP-Redirect.
        check_signature: true,
        strict_xml_signature_profile: setting.strict_xml_signature_profile,
        from_issuer: peer_meta.get_entity_id(),
        signing_certs: &signing_certs,
        clock_drifts: validation.clock_drifts,
        now: Some(validation.now),
        redirect_inflate_max_bytes: setting.redirect_inflate_max_bytes,
        xml_limits: setting.xml_limits,
        expected_in_response_to,
        hmac_secret: validation.peer_hmac_secret,
        ..FlowOptions::default()
    };
    Ok(flow_with_expected_recipient_and_signature_evidence(
        &options,
        request,
        validation.expected_recipient,
        AssertionSignatureRequirement::Compatible,
        ResponseSignatureRequirement::Optional,
        SignedMessageDestination::Required,
    )?
    .into_parts()
    .0)
}

fn bind_signed(
    setting: &EntitySetting,
    id: String,
    xml: &str,
    destination: &str,
    relay_state: Option<&str>,
    parser_type: ParserType,
) -> Result<BindingContext, SamlError> {
    let binding = NameIdManagementBinding::Redirect.as_binding();
    let (context, signature, sig_alg) =
        sign_browser_message(setting, binding, xml, destination, relay_state, parser_type)?;
    Ok(BindingContext {
        id,
        context,
        relay_state: relay_state.map(str::to_string),
        entity_endpoint: destination.to_string(),
        binding,
        request_type: parser_type.query_param(),
        signature,
        sig_alg,
    })
}
