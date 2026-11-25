use crate::browser::{Inbound, Transport};
use crate::config::HmacSecret;
use crate::constants::{namespace, Binding, ParserType};
use crate::entity::EntitySetting;
use crate::error::SamlError;
use crate::flow::{
    correlated_status_message, flow_with_authentication,
    flow_with_expected_recipient_and_signature_evidence, AssertionSignatureRequirement,
    FlowOptions, FlowResult, HttpRequest, ResponseSignatureRequirement, SignatureCheck,
    SignedMessageDestination,
};
use crate::metadata::Metadata;
use crate::model::{ClockSkew, Status, StatusMessage};
use crate::xml::dom::{is_xml_whitespace_char, push_normalized_namespaces, reader_err};
use crate::xml::fields;
use crate::xml::fragment::standalone_element;
use crate::xml::name::is_ncname;
use crate::xml::protocol_element::SamlElement;
use crate::xml::status::read_status;
use quick_xml::events::Event;
use quick_xml::name::{Namespace, NamespaceResolver, QName, ResolveResult};
use quick_xml::Reader;
use std::time::SystemTime;

use super::ASYNC_SLO_NAMESPACE;

const XML_SCHEMA_INSTANCE_NAMESPACE: &str = "http://www.w3.org/2001/XMLSchema-instance";

pub(crate) fn has_async_slo_marker(xml: &str, request: &SamlElement) -> Result<bool, SamlError> {
    if !request.is(namespace::PROTOCOL, "LogoutRequest") {
        return Ok(false);
    }
    let candidates = request
        .children
        .iter()
        .filter(|child| child.is(namespace::PROTOCOL, "Extensions"))
        .flat_map(|extensions| &extensions.children)
        .filter(|child| {
            child.is(ASYNC_SLO_NAMESPACE, "Asynchronous")
                && child.children.is_empty()
                && child.text.is_empty()
        });
    for marker in candidates {
        if marker_attributes_allowed(xml, marker)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn marker_attributes_allowed(xml: &str, marker: &SamlElement) -> Result<bool, SamlError> {
    for (attribute_namespace, local_name, value) in &marker.attrs {
        if attribute_namespace.as_deref() != Some(XML_SCHEMA_INSTANCE_NAMESPACE) {
            return Ok(false);
        }
        let allowed = match local_name.as_str() {
            "schemaLocation" | "noNamespaceSchemaLocation" => true,
            "type" => names_asynchronous_type(xml, marker, value)?,
            _ => false,
        };
        if !allowed {
            return Ok(false);
        }
    }
    Ok(true)
}

fn names_asynchronous_type(
    xml: &str,
    marker: &SamlElement,
    value: &str,
) -> Result<bool, SamlError> {
    let value = value.trim_matches(is_xml_whitespace_char);
    if !value.splitn(2, ':').all(is_ncname) {
        return Ok(false);
    }
    let marker_xml = standalone_element(xml, marker.start, marker.end)?;
    let mut reader = Reader::from_str(&marker_xml);
    let mut resolver = NamespaceResolver::default();
    loop {
        match reader.read_event().map_err(reader_err)? {
            Event::Start(element) | Event::Empty(element) => {
                push_normalized_namespaces(&mut resolver, &element)?;
                let (type_namespace, type_name) = resolver.resolve_element(QName(value));
                return Ok(type_name.into_inner() == "AsynchronousType"
                    && matches!(
                        type_namespace,
                        ResolveResult::Bound(Namespace(uri)) if uri == ASYNC_SLO_NAMESPACE
                    ));
            }
            Event::Eof => return Err(SamlError::xml("asynchronous marker is not an element")),
            Event::End(_)
            | Event::Text(_)
            | Event::CData(_)
            | Event::Comment(_)
            | Event::Decl(_)
            | Event::PI(_)
            | Event::DocType(_)
            | Event::GeneralRef(_) => {}
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct LogoutFlowValidation<'a> {
    expected_recipient: Option<&'a str>,
    now: SystemTime,
    clock_skew: ClockSkew,
    peer_hmac_secret: Option<&'a HmacSecret>,
}

impl<'a> LogoutFlowValidation<'a> {
    pub(crate) fn typed(
        expected_recipient: Option<&'a str>,
        now: SystemTime,
        clock_skew: ClockSkew,
        peer_hmac_secret: Option<&'a HmacSecret>,
    ) -> Self {
        Self {
            expected_recipient,
            now,
            clock_skew,
            peer_hmac_secret,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct LogoutReceipt {
    decode_as: Binding,
    signature: SignatureCheck,
    signed_destination: SignedMessageDestination,
}

impl LogoutReceipt {
    pub(crate) fn browser(binding: Binding) -> Self {
        Self {
            decode_as: binding,
            signature: SignatureCheck::Require,
            signed_destination: SignedMessageDestination::Required,
        }
    }

    pub(crate) fn of_input<Message>(input: &Inbound<Message>) -> Result<Self, SamlError> {
        match &input.transport {
            Transport::Redirect { .. } => Ok(Self::browser(Binding::Redirect)),
            Transport::Post { .. } => Ok(Self::browser(Binding::Post)),
            Transport::SimpleSign { .. } => Ok(Self::browser(Binding::SimpleSign)),
            Transport::Soap { channel, .. } => Ok(Self::soap(*channel)),
            Transport::Artifact { .. } => Err(SamlError::UnsupportedBinding {
                binding: Binding::Artifact,
            }),
        }
    }

    pub(crate) fn soap(channel: crate::SoapChannel) -> Self {
        Self {
            decode_as: Binding::Post,
            signature: if channel.authenticates_peer() {
                SignatureCheck::VerifyIfPresent
            } else {
                SignatureCheck::Require
            },
            signed_destination: SignedMessageDestination::Optional,
        }
    }
}

pub(crate) fn parse_logout_request_at(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    receipt: LogoutReceipt,
    request: &HttpRequest,
    validation: LogoutFlowValidation<'_>,
) -> Result<FlowResult, SamlError> {
    run_logout_flow(
        &FlowOptions {
            defer_logout_request_version: true,
            signature_check: receipt.signature,
            require_audience_restriction: true,
            ..FlowOptions::for_peer(
                receipt.decode_as,
                ParserType::LogoutRequest,
                self_setting,
                from_meta,
                validation.peer_hmac_secret,
                validation.now,
                validation.clock_skew,
            )
        },
        request,
        validation.expected_recipient,
        receipt.signed_destination,
    )
}

pub(crate) struct ParsedLogoutResponse {
    pub(crate) flow: FlowResult,
    pub(crate) status: Status,
    pub(crate) status_message: Option<StatusMessage>,
}

pub(crate) fn parse_logout_response_at(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    receipt: LogoutReceipt,
    request: &HttpRequest,
    request_id: &str,
    validation: LogoutFlowValidation<'_>,
    unresolved_recipient: Option<SamlError>,
) -> Result<ParsedLogoutResponse, SamlError> {
    if request_id.is_empty() {
        return Err(SamlError::InvalidInResponseTo);
    }
    let flow = run_logout_flow(
        &FlowOptions {
            signature_check: receipt.signature,
            require_audience_restriction: true,
            expected_in_response_to: Some(request_id),
            ..FlowOptions::for_peer(
                receipt.decode_as,
                ParserType::LogoutResponse,
                self_setting,
                from_meta,
                validation.peer_hmac_secret,
                validation.now,
                validation.clock_skew,
            )
        },
        request,
        validation.expected_recipient,
        receipt.signed_destination,
    )?;
    if let Some(error) = unresolved_recipient {
        if flow
            .extract
            .get_str(fields::response::DESTINATION)
            .is_some()
        {
            return Err(error);
        }
    }
    let status = read_status(&flow.saml_content, self_setting.xml_limits)
        .and_then(|status| status.clone().require_success().map(|()| status));
    let status_message = correlated_status_message(
        &flow.saml_content,
        self_setting.xml_limits,
        Some(request_id),
        validation.expected_recipient,
        receipt.signed_destination,
    );
    match status {
        Ok(status) => Ok(ParsedLogoutResponse {
            flow,
            status,
            status_message,
        }),
        Err(error) => Err(error.with_status_message(status_message)),
    }
}

fn run_logout_flow(
    options: &FlowOptions<'_>,
    request: &HttpRequest,
    expected_recipient: Option<&str>,
    signed_destination: SignedMessageDestination,
) -> Result<FlowResult, SamlError> {
    match expected_recipient {
        Some(expected_recipient) => {
            let result = flow_with_expected_recipient_and_signature_evidence(
                options,
                request,
                expected_recipient,
                AssertionSignatureRequirement::Compatible,
                ResponseSignatureRequirement::Optional,
                signed_destination,
            )?;
            Ok(result.into_parts().0)
        }
        None => Ok(flow_with_authentication(options, request)?.into_flow_result()),
    }
}
