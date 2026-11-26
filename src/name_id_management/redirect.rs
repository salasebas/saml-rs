use std::time::SystemTime;

use crate::binding::sign_message;
use crate::browser::NameIdManagementBinding;
use crate::config::EntityId;
use crate::config::HmacSecret;
use crate::config::IdentifierEncryptionPolicy;
use crate::constants::{Binding, ParserType};
use crate::entity::{BindingContext, EntitySetting};
use crate::error::SamlError;
use crate::flow::{
    flow_with_expected_recipient_and_signature_evidence, AssertionSignatureRequirement,
    FlowOptions, FlowResult, HttpRequest, ResponseSignatureRequirement, SignatureCheck,
    SignedMessageDestination,
};
use crate::metadata::Metadata;
use crate::model::{
    ClockSkew, MessageId, ReplayKey, RequestVersionMismatch, SamlInstant, SamlValidationContext,
};
use crate::xml::protocol_element::{issuer, parse_saml_with_limits};
use crate::xml::write::Prefixes;
use crate::xml::XmlLimits;

use super::xml::{render_request, render_response, RequestXml, ResponseXml};
use super::{
    identifier_and_change, plaintext_content, protect_request, Change, Identifier,
    ManageNameIdRequest, Refusal,
};

#[derive(Clone, Copy)]
pub(crate) struct InboundValidation<'a> {
    pub(crate) expected_recipient: &'a str,
    pub(crate) peer_hmac_secret: Option<&'a HmacSecret>,
    pub(crate) now: SystemTime,
    pub(crate) clock_skew: ClockSkew,
}

pub(crate) fn create_request(
    setting: &EntitySetting,
    peer_meta: &Metadata,
    peer_role: usize,
    request: &RequestXml<'_>,
    identifier_encryption: IdentifierEncryptionPolicy,
    relay_state: Option<&str>,
) -> Result<BindingContext, SamlError> {
    let xml = protect_request(
        render_request(&Prefixes::of(setting)?, request)?,
        identifier_encryption,
        setting,
        peer_meta,
        peer_role,
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
    let xml = render_response(&Prefixes::of(setting)?, response)?;
    bind_signed(
        setting,
        response.id.to_string(),
        &xml,
        destination,
        relay_state,
        ParserType::ManageNameIdResponse,
    )
}

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

pub(crate) struct UndecryptedRequest {
    pub(crate) id: MessageId,
    pub(crate) issuer: EntityId,
    issue_instant: SamlInstant,
    content: RequestContent,
}

enum RequestContent {
    VersionMismatch(RequestVersionMismatch),
    Identifiers(Identifier, Change),
}

pub(crate) enum ParsedRequest {
    Plain(ManageNameIdRequest),
    Refused(Refusal),
}

pub(crate) fn request_from_flow(
    flow: &FlowResult,
    setting: &EntitySetting,
) -> Result<UndecryptedRequest, SamlError> {
    let request = parse_saml_with_limits(&flow.saml_content, setting.xml_limits)?;
    let id = MessageId::try_new(request.required_attr("ID")?)?;
    let issue_instant = request.required_issue_instant()?;
    let issuer = issuer(&request)?.ok_or_else(|| {
        SamlError::ProtocolProfile("ManageNameIDRequest is missing Issuer".into())
    })?;
    let issuer = EntityId::try_new(issuer.value)?;
    let content = match RequestVersionMismatch::for_request(&request.required_attr("Version")?)? {
        Some(mismatch) => RequestContent::VersionMismatch(mismatch),
        None => {
            let (identifier, change) = identifier_and_change(&request)?;
            RequestContent::Identifiers(identifier, change)
        }
    };
    Ok(UndecryptedRequest {
        id,
        issuer,
        issue_instant,
        content,
    })
}

impl UndecryptedRequest {
    pub(crate) fn validate_and_decrypt(
        self,
        flow: &FlowResult,
        setting: &EntitySetting,
        mut validation: SamlValidationContext<'_>,
    ) -> Result<ParsedRequest, SamlError> {
        let (identifier, change) = match self.content {
            RequestContent::VersionMismatch(mismatch) => {
                return Ok(ParsedRequest::Refused(Refusal::VersionMismatch(mismatch)));
            }
            RequestContent::Identifiers(identifier, change) => (identifier, change),
        };
        if validation
            .check_manage_name_id_request_issue_instant(&self.issue_instant)
            .is_err()
        {
            return Ok(ParsedRequest::Refused(Refusal::RequestAgeOutsideWindow));
        }
        validation
            .check_and_store_message_replay(ReplayKey::ManageNameIdRequest(self.id.clone()))?;
        Ok(
            match plaintext_content(&flow.saml_content, identifier, change, setting) {
                Ok((name_id, change)) => ParsedRequest::Plain(ManageNameIdRequest {
                    id: self.id,
                    issuer: self.issuer,
                    name_id,
                    change,
                }),
                Err(undecryptable) => ParsedRequest::Refused(Refusal::Undecryptable(undecryptable)),
            },
        )
    }
}

pub(crate) fn response_id_from_flow(
    flow: &FlowResult,
    limits: XmlLimits,
) -> Result<MessageId, SamlError> {
    let response = parse_saml_with_limits(&flow.saml_content, limits)?;
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
    let options = FlowOptions {
        // SAML Profiles 2.0 §4.5.3.1 and §4.5.3.2 require a signed message on
        // HTTP-Redirect.
        signature_check: SignatureCheck::Require,
        expected_in_response_to,
        ..FlowOptions::for_peer(
            Binding::from(NameIdManagementBinding::Redirect),
            parser_type,
            setting,
            peer_meta,
            validation.peer_hmac_secret,
            validation.now,
            validation.clock_skew,
        )
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
    let binding = Binding::from(NameIdManagementBinding::Redirect);
    Ok(
        sign_message(setting, binding, xml, destination, relay_state, parser_type)?.bind(
            id,
            destination.to_owned(),
            relay_state,
        ),
    )
}
