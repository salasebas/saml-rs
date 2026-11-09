use crate::constants::{namespace, ParserType};
use crate::error::SamlError;
use crate::xml::dom::XmlLimits;
use crate::xml::parse_saml_utc_date_time;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::ResolveResult;
use quick_xml::{NsReader, XmlVersion};

mod outbound_logout;
mod outbound_logout_request;

pub(crate) use outbound_logout::{validate_logout_response_outbound, OutboundLogoutValidation};
pub(crate) use outbound_logout_request::{
    validate_logout_request_outbound, OutboundLogoutExpiration, OutboundLogoutRequestExpectation,
    OutboundLogoutRequestValidation, OutboundNameIdQualifiers,
};

const XML_ENCRYPTION_NS: &str = "http://www.w3.org/2001/04/xmlenc#";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NamespaceKind {
    Protocol,
    Assertion,
    Dsig,
    XmlEncryption,
    Unbound,
    Other,
    Unknown,
}

#[derive(Debug)]
struct ExpandedName {
    local: Vec<u8>,
    namespace: NamespaceKind,
}

impl ExpandedName {
    fn is(&self, local: &[u8], namespace: NamespaceKind) -> bool {
        self.local == local && self.namespace == namespace
    }
}

fn classify_namespace(resolved: ResolveResult<'_>) -> NamespaceKind {
    match resolved {
        ResolveResult::Bound(value) if value.into_inner() == namespace::PROTOCOL => {
            NamespaceKind::Protocol
        }
        ResolveResult::Bound(value) if value.into_inner() == namespace::ASSERTION => {
            NamespaceKind::Assertion
        }
        ResolveResult::Bound(value) if value.into_inner() == namespace::DSIG => NamespaceKind::Dsig,
        ResolveResult::Bound(value) if value.into_inner() == XML_ENCRYPTION_NS => {
            NamespaceKind::XmlEncryption
        }
        ResolveResult::Bound(_) => NamespaceKind::Other,
        ResolveResult::Unbound => NamespaceKind::Unbound,
        ResolveResult::Unknown(_) => NamespaceKind::Unknown,
    }
}

fn profile_error(message: impl Into<String>) -> SamlError {
    SamlError::ProtocolProfile(message.into())
}

fn parser_root(parser_type: ParserType) -> &'static [u8] {
    match parser_type {
        ParserType::SamlRequest => b"AuthnRequest",
        ParserType::SamlResponse => b"Response",
        ParserType::LogoutRequest => b"LogoutRequest",
        ParserType::LogoutResponse => b"LogoutResponse",
    }
}

fn element_label(element: &BytesStart<'_>) -> String {
    element.local_name().into_inner().to_owned()
}

#[derive(Debug, Clone, Copy)]
enum UnexpectedAttributePolicy {
    Ignore,
    Reject,
}

fn validate_attributes(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    consumed: &[&[u8]],
    required: &[&[u8]],
    unexpected: UnexpectedAttributePolicy,
) -> Result<Vec<(Vec<u8>, String)>, SamlError> {
    let mut values = Vec::new();
    for attribute in element.attributes() {
        let attribute = attribute.map_err(|error| SamlError::Xml(error.to_string()))?;
        if attribute.key.as_namespace_binding().is_some() {
            continue;
        }
        let (resolved, local) = reader.resolver().resolve_attribute(attribute.key);
        if !consumed.contains(&local.into_inner().as_bytes()) {
            if matches!(unexpected, UnexpectedAttributePolicy::Reject) {
                return Err(profile_error(format!(
                    "unexpected attribute {} on {}",
                    attribute.key.into_inner(),
                    element_label(element),
                )));
            }
            continue;
        }
        if !matches!(resolved, ResolveResult::Unbound) {
            return Err(profile_error(format!(
                "attribute {} on {} must be unqualified",
                local.into_inner(),
                element_label(element),
            )));
        }
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|error| SamlError::Xml(error.to_string()))?
            .into_owned();
        values.push((local.into_inner().as_bytes().to_vec(), value));
    }

    for required_name in required {
        if !values.iter().any(|(name, _)| name == required_name) {
            return Err(profile_error(format!(
                "{} is missing required unqualified attribute {}",
                element_label(element),
                String::from_utf8_lossy(required_name),
            )));
        }
    }
    Ok(values)
}

fn validate_unqualified_attributes(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    consumed: &[&[u8]],
    required: &[&[u8]],
) -> Result<Vec<(Vec<u8>, String)>, SamlError> {
    validate_attributes(
        reader,
        element,
        consumed,
        required,
        UnexpectedAttributePolicy::Ignore,
    )
}

fn validate_closed_unqualified_attributes(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    consumed: &[&[u8]],
    required: &[&[u8]],
) -> Result<Vec<(Vec<u8>, String)>, SamlError> {
    validate_attributes(
        reader,
        element,
        consumed,
        required,
        UnexpectedAttributePolicy::Reject,
    )
}

fn require_version_2(
    values: &[(Vec<u8>, String)],
    element: &BytesStart<'_>,
) -> Result<(), SamlError> {
    let version = values
        .iter()
        .find_map(|(name, value)| (name == b"Version").then_some(value.as_str()));
    if version != Some("2.0") {
        return Err(profile_error(format!(
            "{} Version must be 2.0",
            element_label(element),
        )));
    }
    Ok(())
}

fn require_issue_instant(
    values: &[(Vec<u8>, String)],
    element: &BytesStart<'_>,
) -> Result<(), SamlError> {
    let issue_instant = values
        .iter()
        .find_map(|(name, value)| (name == b"IssueInstant").then_some(value.as_str()))
        .ok_or_else(|| {
            profile_error(format!(
                "{} is missing required unqualified attribute IssueInstant",
                element_label(element),
            ))
        })?;
    if parse_saml_utc_date_time(issue_instant).is_none() {
        return Err(profile_error(format!(
            "{} IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z",
            element_label(element),
        )));
    }
    Ok(())
}

fn require_optional_saml_utc_date_time(
    values: &[(Vec<u8>, String)],
    element: &BytesStart<'_>,
    attribute: &[u8],
) -> Result<(), SamlError> {
    let value = values
        .iter()
        .find_map(|(name, value)| (name == attribute).then_some(value.as_str()));
    if value.is_some_and(|value| parse_saml_utc_date_time(value).is_none()) {
        return Err(profile_error(format!(
            "{} {} must use the SAML-conformant UTC xs:dateTime form ending in Z",
            element_label(element),
            String::from_utf8_lossy(attribute),
        )));
    }
    Ok(())
}

fn root_consumed_attributes(parser_type: ParserType) -> &'static [&'static [u8]] {
    match parser_type {
        ParserType::SamlRequest => &[
            b"ID",
            b"Version",
            b"IssueInstant",
            b"Destination",
            b"AssertionConsumerServiceURL",
            b"ProtocolBinding",
            b"AssertionConsumerServiceIndex",
            b"ForceAuthn",
            b"IsPassive",
        ],
        ParserType::SamlResponse => &[
            b"ID",
            b"Version",
            b"IssueInstant",
            b"Destination",
            b"InResponseTo",
        ],
        ParserType::LogoutRequest => &[
            b"ID",
            b"Version",
            b"IssueInstant",
            b"Destination",
            b"NotOnOrAfter",
        ],
        ParserType::LogoutResponse => &[
            b"ID",
            b"Version",
            b"IssueInstant",
            b"Destination",
            b"InResponseTo",
        ],
    }
}

fn validate_root(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    element_namespace: NamespaceKind,
    parser_type: ParserType,
) -> Result<(), SamlError> {
    let expected = parser_root(parser_type);
    if element.local_name().into_inner().as_bytes() != expected
        || element_namespace != NamespaceKind::Protocol
    {
        return Err(profile_error(format!(
            "expected root {{{}}}{}, got {}",
            namespace::PROTOCOL,
            String::from_utf8_lossy(expected),
            element_label(element),
        )));
    }
    let required: &[&[u8]] = match parser_type {
        ParserType::SamlRequest => &[b"ID", b"Version", b"IssueInstant"],
        ParserType::SamlResponse => &[b"ID", b"Version", b"IssueInstant"],
        ParserType::LogoutRequest => &[b"ID", b"Version", b"IssueInstant"],
        ParserType::LogoutResponse => &[b"ID", b"Version", b"IssueInstant"],
    };
    let attributes = validate_unqualified_attributes(
        reader,
        element,
        root_consumed_attributes(parser_type),
        required,
    )?;
    require_version_2(&attributes, element)?;
    if matches!(
        parser_type,
        ParserType::SamlRequest
            | ParserType::SamlResponse
            | ParserType::LogoutRequest
            | ParserType::LogoutResponse
    ) {
        require_issue_instant(&attributes, element)?;
    }
    if parser_type == ParserType::LogoutRequest {
        require_optional_saml_utc_date_time(&attributes, element, b"NotOnOrAfter")?;
    }
    Ok(())
}

fn expected_child_namespace(stack: &[ExpandedName], child: &[u8]) -> Option<NamespaceKind> {
    let parent = stack.last()?;
    let root = stack.first()?;

    if stack.len() == 1 && parent.namespace == NamespaceKind::Protocol {
        if matches!(child, b"Issuer") {
            return Some(NamespaceKind::Assertion);
        }
        if matches!(child, b"Signature") {
            return Some(NamespaceKind::Dsig);
        }
        if root.is(b"AuthnRequest", NamespaceKind::Protocol) {
            return match child {
                b"NameIDPolicy" | b"RequestedAuthnContext" => Some(NamespaceKind::Protocol),
                b"Subject" | b"AuthnContextClassRef" => Some(NamespaceKind::Assertion),
                _ => None,
            };
        }
        if root.is(b"Response", NamespaceKind::Protocol) {
            return match child {
                b"Status" => Some(NamespaceKind::Protocol),
                b"Assertion" | b"EncryptedAssertion" => Some(NamespaceKind::Assertion),
                _ => None,
            };
        }
        if root.is(b"LogoutRequest", NamespaceKind::Protocol) {
            return match child {
                b"NameID" => Some(NamespaceKind::Assertion),
                b"SessionIndex" => Some(NamespaceKind::Protocol),
                _ => None,
            };
        }
        if root.is(b"LogoutResponse", NamespaceKind::Protocol) && child == b"Status" {
            return Some(NamespaceKind::Protocol);
        }
    }

    if parent.is(b"Status", NamespaceKind::Protocol)
        || parent.is(b"StatusCode", NamespaceKind::Protocol)
    {
        return (child == b"StatusCode").then_some(NamespaceKind::Protocol);
    }
    if parent.is(b"RequestedAuthnContext", NamespaceKind::Protocol) {
        return (child == b"AuthnContextClassRef").then_some(NamespaceKind::Assertion);
    }
    if parent.is(b"Assertion", NamespaceKind::Assertion) {
        return match child {
            b"Signature" => Some(NamespaceKind::Dsig),
            b"Issuer" | b"Subject" | b"Conditions" | b"AuthnStatement" | b"AttributeStatement" => {
                Some(NamespaceKind::Assertion)
            }
            _ => None,
        };
    }
    if root.is(b"AuthnRequest", NamespaceKind::Protocol)
        && parent.is(b"Subject", NamespaceKind::Assertion)
        && matches!(child, b"BaseID" | b"EncryptedID")
    {
        return Some(NamespaceKind::Assertion);
    }
    if parent.is(b"Subject", NamespaceKind::Assertion) {
        return match child {
            b"NameID" | b"SubjectConfirmation" => Some(NamespaceKind::Assertion),
            _ => None,
        };
    }
    if parent.is(b"SubjectConfirmation", NamespaceKind::Assertion) {
        return (child == b"SubjectConfirmationData").then_some(NamespaceKind::Assertion);
    }
    if parent.is(b"Conditions", NamespaceKind::Assertion) {
        return (child == b"AudienceRestriction").then_some(NamespaceKind::Assertion);
    }
    if parent.is(b"AudienceRestriction", NamespaceKind::Assertion) {
        return (child == b"Audience").then_some(NamespaceKind::Assertion);
    }
    if parent.is(b"AttributeStatement", NamespaceKind::Assertion) {
        return (child == b"Attribute").then_some(NamespaceKind::Assertion);
    }
    if parent.is(b"Attribute", NamespaceKind::Assertion) {
        return (child == b"AttributeValue").then_some(NamespaceKind::Assertion);
    }
    if parent.is(b"EncryptedAssertion", NamespaceKind::Assertion) {
        return (child == b"EncryptedData").then_some(NamespaceKind::XmlEncryption);
    }
    None
}

fn consumed_attributes_for(
    element: &ExpandedName,
    stack: &[ExpandedName],
) -> &'static [&'static [u8]] {
    if element.is(b"NameID", NamespaceKind::Assertion) && authn_request_subject(stack) {
        return &[
            b"Format",
            b"NameQualifier",
            b"SPNameQualifier",
            b"SPProvidedID",
        ];
    }
    consumed_attributes(element)
}

fn authn_request_subject(stack: &[ExpandedName]) -> bool {
    stack
        .first()
        .is_some_and(|root| root.is(b"AuthnRequest", NamespaceKind::Protocol))
        && stack
            .iter()
            .any(|parent| parent.is(b"Subject", NamespaceKind::Assertion))
}

fn consumed_attributes(element: &ExpandedName) -> &'static [&'static [u8]] {
    match (element.namespace, element.local.as_slice()) {
        (NamespaceKind::Assertion, b"Assertion") => &[b"ID", b"Version", b"IssueInstant"],
        (NamespaceKind::Protocol, b"StatusCode") => &[b"Value"],
        (NamespaceKind::Protocol, b"NameIDPolicy") => &[b"Format", b"AllowCreate"],
        (NamespaceKind::Assertion, b"Conditions") => &[b"NotBefore", b"NotOnOrAfter"],
        (NamespaceKind::Assertion, b"NameID") => &[b"Format"],
        (NamespaceKind::Assertion, b"SubjectConfirmation") => &[b"Method"],
        (NamespaceKind::Assertion, b"SubjectConfirmationData") => {
            &[b"NotOnOrAfter", b"Recipient", b"InResponseTo"]
        }
        (NamespaceKind::Assertion, b"AuthnStatement") => {
            &[b"AuthnInstant", b"SessionNotOnOrAfter", b"SessionIndex"]
        }
        (NamespaceKind::Assertion, b"Attribute") => &[b"Name"],
        _ => &[],
    }
}

fn validate_element(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    element_namespace: NamespaceKind,
    stack: &[ExpandedName],
    parser_type: ParserType,
) -> Result<(), SamlError> {
    if stack.is_empty() {
        return validate_root(reader, element, element_namespace, parser_type);
    }

    let local = element.local_name();
    let expected_namespace = expected_child_namespace(stack, local.into_inner().as_bytes());
    if let Some(expected) = expected_namespace {
        if element_namespace != expected {
            return Err(profile_error(format!(
                "{} has an invalid namespace",
                element_label(element),
            )));
        }
    }
    if expected_namespace.is_none() {
        return Ok(());
    }

    let expanded = ExpandedName {
        local: local.into_inner().as_bytes().to_vec(),
        namespace: element_namespace,
    };
    let consumed = consumed_attributes_for(&expanded, stack);
    if expanded.is(b"Assertion", NamespaceKind::Assertion) {
        let attributes = validate_unqualified_attributes(
            reader,
            element,
            consumed,
            &[b"ID", b"Version", b"IssueInstant"],
        )?;
        require_version_2(&attributes, element)?;
        require_issue_instant(&attributes, element)?;
    } else if !consumed.is_empty() {
        validate_unqualified_attributes(reader, element, consumed, &[])?;
    }
    Ok(())
}

pub(crate) fn validate_protocol_profile(
    xml: &str,
    parser_type: ParserType,
    limits: XmlLimits,
) -> Result<(), SamlError> {
    limits.check_input_bytes(xml.len())?;
    let mut reader = NsReader::from_str(xml);
    // quick-xml 0.42 caps bindings currently in scope, not declarations on one
    // element. The configured attribute budget remains that cap.
    reader
        .resolver_mut()
        .set_max_namespace_bindings(limits.max_attributes_per_element);
    let mut stack = Vec::new();
    let mut saw_root = false;

    loop {
        let (resolved, event) = reader
            .read_resolved_event()
            .map_err(|error| SamlError::Xml(error.to_string()))?;
        let element_namespace = classify_namespace(resolved);
        match event {
            Event::Start(element) => {
                validate_element(&reader, &element, element_namespace, &stack, parser_type)?;
                saw_root = true;
                stack.push(ExpandedName {
                    local: element.local_name().into_inner().as_bytes().to_vec(),
                    namespace: element_namespace,
                });
            }
            Event::Empty(element) => {
                validate_element(&reader, &element, element_namespace, &stack, parser_type)?;
                saw_root = true;
            }
            Event::End(_) => {
                stack.pop();
            }
            Event::Eof => break,
            Event::Decl(_)
            | Event::Text(_)
            | Event::CData(_)
            | Event::Comment(_)
            | Event::PI(_)
            | Event::DocType(_)
            | Event::GeneralRef(_) => {}
        }
    }

    if !saw_root {
        return Err(profile_error("missing SAML protocol root"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTHN_REQUEST_START: &str = concat!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" "#,
        r#"ID="a" Version="2.0" IssueInstant="2020-01-01T00:00:00Z">"#,
    );

    fn limits_with_attribute_budget(max_attributes_per_element: usize) -> XmlLimits {
        XmlLimits {
            max_attributes_per_element,
            ..XmlLimits::default()
        }
    }

    fn namespace_binding_limit(result: Result<(), SamlError>) -> bool {
        matches!(
            result,
            Err(SamlError::Xml(message)) if message.contains("namespace bindings in scope")
        )
    }

    #[test]
    fn in_scope_namespace_budget_counts_nested_bindings_not_siblings() {
        let limits = limits_with_attribute_budget(2);
        let siblings = format!(
            "{AUTHN_REQUEST_START}\
             <p0 xmlns:p0=\"urn:test:0\"/>\
             <p1 xmlns:p1=\"urn:test:1\"/>\
             </samlp:AuthnRequest>"
        );
        let nested = format!(
            "{AUTHN_REQUEST_START}\
             <p0 xmlns:p0=\"urn:test:0\">\
             <p1 xmlns:p1=\"urn:test:1\"/>\
             </p0>\
             </samlp:AuthnRequest>"
        );

        assert!(validate_protocol_profile(&siblings, ParserType::SamlRequest, limits).is_ok());
        assert!(namespace_binding_limit(validate_protocol_profile(
            &nested,
            ParserType::SamlRequest,
            limits,
        )));
    }
}
