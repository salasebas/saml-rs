use super::{
    classify_namespace, element_label, profile_error, require_version_2,
    validate_closed_unqualified_attributes, NamespaceKind,
};
use crate::constants::{name_id_format, namespace, status_code};
use crate::error::SamlError;
use crate::xml::dom::{parse_with_limits, Document, XmlLimits};
use crate::xml::name::is_ncname;
use crate::xml::parse_generated_saml_utc_date_time;
use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::NsReader;
use url::Url;

#[derive(Debug)]
enum OutboundLogoutElement {
    Root,
    Issuer,
    Signature,
    Extensions { child_seen: bool },
    Status,
    StatusCode { child_seen: bool },
    StatusMessage,
    StatusDetail,
    ExtensionContent,
}

#[derive(Debug, Default)]
enum RootStage {
    #[default]
    ExpectIssuer,
    AfterIssuer,
    AfterSignature,
    AfterExtensions,
    AfterStatus,
}

#[derive(Debug, Default)]
enum StatusStage {
    #[default]
    ExpectStatusCode,
    AfterStatusCode,
    AfterStatusMessage,
    AfterStatusDetail,
}

#[derive(Debug, Default)]
struct OutboundLogoutState {
    root_stage: RootStage,
    status_stage: StatusStage,
    saw_signature: bool,
    destination: Option<String>,
}

struct OutboundLogoutExpectation<'a> {
    id: &'a str,
    destination: &'a str,
    issuer: &'a str,
    in_response_to: Option<&'a str>,
    validation: OutboundLogoutValidation,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum OutboundLogoutValidation {
    BeforeSigning { destination_required: bool },
    AfterPostSigning,
}

impl OutboundLogoutValidation {
    fn destination_required(self) -> bool {
        match self {
            Self::BeforeSigning {
                destination_required,
            } => destination_required,
            Self::AfterPostSigning => true,
        }
    }

    fn root_signature_required(self) -> bool {
        matches!(self, Self::AfterPostSigning)
    }

    fn root_signature_allowed(self) -> bool {
        matches!(self, Self::AfterPostSigning)
    }
}

fn attribute_value<'a>(values: &'a [(Vec<u8>, String)], name: &[u8]) -> Option<&'a str> {
    values
        .iter()
        .find_map(|(candidate, value)| (candidate == name).then_some(value.as_str()))
}

fn require_generated_issue_instant(
    values: &[(Vec<u8>, String)],
    element: &BytesStart<'_>,
) -> Result<(), SamlError> {
    let issue_instant = attribute_value(values, b"IssueInstant").ok_or_else(|| {
        profile_error(format!(
            "{} is missing required unqualified attribute IssueInstant",
            element_label(element),
        ))
    })?;
    if parse_generated_saml_utc_date_time(issue_instant).is_none() {
        return Err(profile_error(format!(
            "{} IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z",
            element_label(element),
        )));
    }
    Ok(())
}

fn validate_outbound_logout_root(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    element_namespace: NamespaceKind,
    expectation: &OutboundLogoutExpectation<'_>,
    state: &mut OutboundLogoutState,
) -> Result<(), SamlError> {
    if element.local_name().into_inner().as_bytes() != b"LogoutResponse"
        || element_namespace != NamespaceKind::Protocol
    {
        return Err(profile_error(format!(
            "expected root {{{}}}LogoutResponse, got {}",
            namespace::PROTOCOL,
            element_label(element),
        )));
    }
    let attributes = validate_closed_unqualified_attributes(
        reader,
        element,
        &[
            b"ID",
            b"InResponseTo",
            b"Version",
            b"IssueInstant",
            b"Destination",
            b"Consent",
        ],
        &[b"ID", b"Version", b"IssueInstant"],
    )?;
    require_version_2(&attributes, element)?;
    require_generated_issue_instant(&attributes, element)?;

    let id = attribute_value(&attributes, b"ID").ok_or_else(|| {
        profile_error("LogoutResponse is missing required unqualified attribute ID")
    })?;
    if !is_ncname(id) {
        return Err(profile_error(
            "LogoutResponse ID must use the XML Schema xs:ID lexical form",
        ));
    }
    if id != expectation.id {
        return Err(SamlError::Invalid(format!(
            "outbound LogoutResponse ID mismatch: expected {}, got {id}",
            expectation.id
        )));
    }

    state.destination = attribute_value(&attributes, b"Destination").map(str::to_string);
    if let Some(actual) = state.destination.as_deref() {
        if !is_absolute_saml_uri(actual) {
            return Err(profile_error(
                "LogoutResponse Destination must be a non-empty absolute URI without whitespace",
            ));
        }
        if actual != expectation.destination {
            return Err(SamlError::destination_mismatch(
                expectation.destination,
                Some(actual),
            ));
        }
    }

    if let Some(consent) = attribute_value(&attributes, b"Consent") {
        if !is_absolute_saml_uri(consent) {
            return Err(profile_error(
                "LogoutResponse Consent must be a non-empty absolute URI without whitespace",
            ));
        }
    }

    let actual_in_response_to = attribute_value(&attributes, b"InResponseTo");
    if actual_in_response_to.is_some_and(|value| !is_ncname(value)) {
        return Err(profile_error(
            "LogoutResponse InResponseTo must use the XML Schema NCName lexical form",
        ));
    }
    // SAML Core 2.0 §3.2.2 requires correlation when the request is known and
    // requires omission when there is no known request to reference.
    if actual_in_response_to != expectation.in_response_to {
        return Err(SamlError::in_response_to_mismatch(
            expectation.in_response_to,
            actual_in_response_to,
        ));
    }
    Ok(())
}

fn validate_outbound_issuer(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    element_namespace: NamespaceKind,
) -> Result<(), SamlError> {
    if element_namespace != NamespaceKind::Assertion {
        return Err(profile_error("Issuer has an invalid namespace"));
    }
    let attributes = validate_closed_unqualified_attributes(
        reader,
        element,
        &[
            b"Format",
            b"NameQualifier",
            b"SPNameQualifier",
            b"SPProvidedID",
        ],
        &[],
    )?;
    if let Some(format) = attribute_value(&attributes, b"Format") {
        if format != name_id_format::ENTITY {
            return Err(profile_error(
                "LogoutResponse Issuer Format must be omitted or use the entity identifier format",
            ));
        }
    }
    if [
        b"NameQualifier".as_slice(),
        b"SPNameQualifier".as_slice(),
        b"SPProvidedID".as_slice(),
    ]
    .iter()
    .any(|name| attribute_value(&attributes, name).is_some())
    {
        return Err(profile_error(
            "entity-format LogoutResponse Issuer must omit NameQualifier, SPNameQualifier, and SPProvidedID",
        ));
    }
    Ok(())
}

fn is_absolute_saml_uri(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_whitespace) && Url::parse(value).is_ok()
}

fn is_entity_identifier(value: &str) -> bool {
    value.chars().count() <= 1024 && is_absolute_saml_uri(value)
}

fn validate_outbound_status_code(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    element_namespace: NamespaceKind,
    top_level: bool,
) -> Result<(), SamlError> {
    if element_namespace != NamespaceKind::Protocol {
        return Err(profile_error("StatusCode has an invalid namespace"));
    }
    let attributes =
        validate_closed_unqualified_attributes(reader, element, &[b"Value"], &[b"Value"])?;
    let value = attribute_value(&attributes, b"Value").ok_or_else(|| {
        profile_error("StatusCode is missing required unqualified attribute Value")
    })?;
    if !is_absolute_saml_uri(value) {
        return Err(profile_error(
            "StatusCode Value must be a non-empty absolute URI without whitespace",
        ));
    }
    if top_level
        && !matches!(
            value,
            status_code::SUCCESS
                | status_code::REQUESTER
                | status_code::RESPONDER
                | status_code::VERSION_MISMATCH
        )
    {
        return Err(profile_error(
            "top-level StatusCode Value must be Success, Requester, Responder, or VersionMismatch",
        ));
    }
    Ok(())
}

fn validate_outbound_root_child(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    element_namespace: NamespaceKind,
    expectation: &OutboundLogoutExpectation<'_>,
    state: &mut OutboundLogoutState,
) -> Result<OutboundLogoutElement, SamlError> {
    let local = element.local_name();
    match (local.into_inner().as_bytes(), element_namespace, &state.root_stage) {
        (b"Issuer", NamespaceKind::Assertion, RootStage::ExpectIssuer) => {
            validate_outbound_issuer(reader, element, element_namespace)?;
            state.root_stage = RootStage::AfterIssuer;
            Ok(OutboundLogoutElement::Issuer)
        }
        (b"Signature", NamespaceKind::Dsig, RootStage::AfterIssuer) => {
            if !expectation.validation.root_signature_allowed() {
                // HTTP-Redirect removes a protocol signature before DEFLATE.
                return Err(profile_error(
                    "outbound LogoutResponse templates must not contain a root ds:Signature before library signing",
                ));
            }
            state.root_stage = RootStage::AfterSignature;
            state.saw_signature = true;
            Ok(OutboundLogoutElement::Signature)
        }
        (
            b"Extensions",
            NamespaceKind::Protocol,
            RootStage::AfterIssuer | RootStage::AfterSignature,
        ) => {
            validate_closed_unqualified_attributes(reader, element, &[], &[])?;
            state.root_stage = RootStage::AfterExtensions;
            Ok(OutboundLogoutElement::Extensions { child_seen: false })
        }
        (
            b"Status",
            NamespaceKind::Protocol,
            RootStage::AfterIssuer | RootStage::AfterSignature | RootStage::AfterExtensions,
        ) => {
            validate_closed_unqualified_attributes(reader, element, &[], &[])?;
            state.root_stage = RootStage::AfterStatus;
            Ok(OutboundLogoutElement::Status)
        }
        _ => Err(profile_error(
            "LogoutResponse children must be Issuer, optional Signature, optional Extensions, and exactly one final Status",
        )),
    }
}

fn validate_outbound_status_child(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    element_namespace: NamespaceKind,
    state: &mut OutboundLogoutState,
) -> Result<OutboundLogoutElement, SamlError> {
    let local = element.local_name();
    match (
        local.into_inner().as_bytes(),
        element_namespace,
        &state.status_stage,
    ) {
        (
            b"StatusCode",
            NamespaceKind::Protocol,
            StatusStage::ExpectStatusCode,
        ) => {
            validate_outbound_status_code(reader, element, element_namespace, true)?;
            state.status_stage = StatusStage::AfterStatusCode;
            Ok(OutboundLogoutElement::StatusCode { child_seen: false })
        }
        (
            b"StatusMessage",
            NamespaceKind::Protocol,
            StatusStage::AfterStatusCode,
        ) => {
            validate_closed_unqualified_attributes(reader, element, &[], &[])?;
            state.status_stage = StatusStage::AfterStatusMessage;
            Ok(OutboundLogoutElement::StatusMessage)
        }
        (
            b"StatusDetail",
            NamespaceKind::Protocol,
            StatusStage::AfterStatusCode | StatusStage::AfterStatusMessage,
        ) => {
            validate_closed_unqualified_attributes(reader, element, &[], &[])?;
            state.status_stage = StatusStage::AfterStatusDetail;
            Ok(OutboundLogoutElement::StatusDetail)
        }
        _ => Err(profile_error(
            "Status children must be exactly one StatusCode, optional StatusMessage, and optional StatusDetail in that order",
        )),
    }
}

fn validate_outbound_logout_start(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    element_namespace: NamespaceKind,
    stack: &mut [OutboundLogoutElement],
    expectation: &OutboundLogoutExpectation<'_>,
    state: &mut OutboundLogoutState,
) -> Result<OutboundLogoutElement, SamlError> {
    let Some(parent) = stack.last_mut() else {
        validate_outbound_logout_root(reader, element, element_namespace, expectation, state)?;
        return Ok(OutboundLogoutElement::Root);
    };

    match parent {
        OutboundLogoutElement::Root => {
            validate_outbound_root_child(reader, element, element_namespace, expectation, state)
        }
        OutboundLogoutElement::Issuer => Err(profile_error(
            "LogoutResponse Issuer must not contain child elements",
        )),
        OutboundLogoutElement::Status => {
            validate_outbound_status_child(reader, element, element_namespace, state)
        }
        OutboundLogoutElement::StatusCode { child_seen } => {
            if *child_seen
                || element.local_name().into_inner().as_bytes() != b"StatusCode"
                || element_namespace != NamespaceKind::Protocol
            {
                return Err(profile_error(
                    "StatusCode may contain at most one subordinate StatusCode",
                ));
            }
            validate_outbound_status_code(reader, element, element_namespace, false)?;
            *child_seen = true;
            Ok(OutboundLogoutElement::StatusCode { child_seen: false })
        }
        OutboundLogoutElement::StatusMessage => Err(profile_error(
            "StatusMessage must not contain child elements",
        )),
        OutboundLogoutElement::Extensions { child_seen } => {
            // Core 2.0 §3.2.2 narrows the protocol schema's ##other wildcard:
            // direct extension elements must use a namespace not defined by SAML.
            if !matches!(
                element_namespace,
                NamespaceKind::Dsig | NamespaceKind::XmlEncryption | NamespaceKind::Other
            ) {
                return Err(profile_error(
                    "Extensions direct children must use a namespace not defined by SAML",
                ));
            }
            *child_seen = true;
            Ok(OutboundLogoutElement::ExtensionContent)
        }
        OutboundLogoutElement::StatusDetail
        | OutboundLogoutElement::Signature
        | OutboundLogoutElement::ExtensionContent => Ok(OutboundLogoutElement::ExtensionContent),
    }
}

fn finish_outbound_logout_element(
    element: &OutboundLogoutElement,
    state: &OutboundLogoutState,
) -> Result<(), SamlError> {
    match element {
        OutboundLogoutElement::Root if !matches!(state.root_stage, RootStage::AfterStatus) => Err(
            profile_error("LogoutResponse must contain Issuer and exactly one final Status"),
        ),
        OutboundLogoutElement::Status
            if matches!(state.status_stage, StatusStage::ExpectStatusCode) =>
        {
            Err(profile_error(
                "Status must contain exactly one StatusCode as its first child",
            ))
        }
        OutboundLogoutElement::Extensions { child_seen: false } => Err(profile_error(
            "Extensions must contain at least one extension element",
        )),
        _ => Ok(()),
    }
}

fn validate_structural_text(
    parent: Option<&OutboundLogoutElement>,
    text: &[u8],
) -> Result<(), SamlError> {
    if is_structural_element(parent)
        && !text
            .iter()
            .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
    {
        return Err(profile_error(
            "structural LogoutResponse elements may contain only whitespace text",
        ));
    }
    Ok(())
}

fn is_structural_element(parent: Option<&OutboundLogoutElement>) -> bool {
    matches!(
        parent,
        Some(
            OutboundLogoutElement::Root
                | OutboundLogoutElement::Status
                | OutboundLogoutElement::StatusCode { .. }
                | OutboundLogoutElement::Extensions { .. }
                | OutboundLogoutElement::StatusDetail
        )
    )
}

fn validate_structural_reference(
    parent: Option<&OutboundLogoutElement>,
    reference: &BytesRef<'_>,
) -> Result<(), SamlError> {
    if is_structural_element(parent)
        && !matches!(
            reference
                .resolve_char_ref()
                .map_err(|error| SamlError::Xml(error.to_string()))?,
            Some(' ' | '\t' | '\r' | '\n')
        )
    {
        return Err(profile_error(
            "structural LogoutResponse elements may contain only whitespace text",
        ));
    }
    Ok(())
}

fn validate_outbound_logout_stream(
    xml: &str,
    expectation: &OutboundLogoutExpectation<'_>,
) -> Result<OutboundLogoutState, SamlError> {
    let mut reader = NsReader::from_str(xml);
    let mut stack = Vec::new();
    let mut state = OutboundLogoutState::default();

    loop {
        let (resolved, event) = reader
            .read_resolved_event()
            .map_err(|error| SamlError::Xml(error.to_string()))?;
        let element_namespace = classify_namespace(resolved);
        match event {
            Event::Start(element) => {
                let current = validate_outbound_logout_start(
                    &reader,
                    &element,
                    element_namespace,
                    &mut stack,
                    expectation,
                    &mut state,
                )?;
                stack.push(current);
            }
            Event::Empty(element) => {
                let current = validate_outbound_logout_start(
                    &reader,
                    &element,
                    element_namespace,
                    &mut stack,
                    expectation,
                    &mut state,
                )?;
                finish_outbound_logout_element(&current, &state)?;
            }
            Event::End(_) => {
                let current = stack
                    .pop()
                    .ok_or_else(|| SamlError::Xml("unexpected closing element".into()))?;
                finish_outbound_logout_element(&current, &state)?;
            }
            Event::Text(text) => {
                validate_structural_text(stack.last(), text.as_bytes())?;
            }
            Event::CData(text) => {
                validate_structural_text(stack.last(), text.as_bytes())?;
            }
            Event::GeneralRef(reference) => {
                validate_structural_reference(stack.last(), &reference)?;
            }
            Event::DocType(_) => return Err(SamlError::Xml("DOCTYPE is not allowed".into())),
            Event::Eof => break,
            Event::Decl(_) | Event::Comment(_) | Event::PI(_) => {}
        }
    }
    Ok(state)
}

pub(crate) fn validate_logout_response_outbound(
    xml: &str,
    expected_id: &str,
    expected_destination: &str,
    expected_issuer: &str,
    expected_in_response_to: Option<&str>,
    validation: OutboundLogoutValidation,
) -> Result<Document, SamlError> {
    let document = parse_with_limits(xml, XmlLimits::unbounded())?;
    let expectation = OutboundLogoutExpectation {
        id: expected_id,
        destination: expected_destination,
        issuer: expected_issuer,
        in_response_to: expected_in_response_to,
        validation,
    };
    let state = validate_outbound_logout_stream(xml, &expectation)?;

    let issuer = document.root.children.first().ok_or_else(|| {
        profile_error("LogoutResponse must contain an Issuer before all other children")
    })?;
    if issuer.text.is_empty() {
        return Err(profile_error(
            "LogoutResponse Issuer must identify the responding entity",
        ));
    }
    if !is_entity_identifier(&issuer.text) {
        return Err(profile_error(
            "entity-format LogoutResponse Issuer must be an absolute URI no longer than 1024 characters",
        ));
    }
    if issuer.text != expectation.issuer {
        return Err(SamlError::issuer_mismatch(
            expectation.issuer,
            Some(&issuer.text),
        ));
    }
    if (expectation.validation.destination_required() || state.saw_signature)
        && state.destination.is_none()
    {
        return Err(SamlError::destination_mismatch(
            expectation.destination,
            None,
        ));
    }
    if expectation.validation.root_signature_required() && !state.saw_signature {
        return Err(profile_error(
            "signed POST LogoutResponse must contain a root ds:Signature in schema order",
        ));
    }
    Ok(document)
}

#[cfg(test)]
#[path = "outbound_logout/tests.rs"]
mod tests;
