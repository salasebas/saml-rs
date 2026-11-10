//! SOAP envelopes and the PAOS HTTP header for Enhanced Client/Proxy SSO.

use crate::error::SamlError;
use crate::model::RelayStateParam;
use crate::soap::envelope_parts;
use crate::xml::dom::{parse_with_limits, Node};
use crate::xml::write::XmlWriter;
use crate::xml::XmlLimits;

pub(super) const PAOS_VERSION: &str = "urn:liberty:paos:2003-08";
pub(super) const ECP_PROFILE: &str = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp";
pub(super) const PAOS_MEDIA_TYPE: &str = "application/vnd.paos+xml";
pub(super) const SOAP_MEDIA_TYPE: &str = "text/xml; charset=utf-8";
const SOAP_ACTOR_NEXT: &str = "http://schemas.xmlsoap.org/soap/actor/next";
const SOAP_ENVELOPE_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const PAOS_NS: &str = "urn:liberty:paos:2003-08";
const ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const PROTOCOL_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";

/// PAOS header field value with a double-quoted version and service.
pub(super) const E54_PAOS_HEADER: &str = concat!(
    "ver=\"urn:liberty:paos:2003-08\";",
    "\"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp\""
);

pub(super) fn parse_client_headers(accept: &str, paos: &str) -> Result<(), SamlError> {
    let accept = header_value(accept, "Accept");
    if !lists_media_type(accept, PAOS_MEDIA_TYPE) {
        return Err(SamlError::ProtocolProfile(
            "Accept must include application/vnd.paos+xml".into(),
        ));
    }
    let paos = header_value(paos, "PAOS");
    if !has_double_quoted_version(paos) {
        return Err(SamlError::ProtocolProfile(
            "PAOS header must include ver=\"urn:liberty:paos:2003-08\" with double quotes".into(),
        ));
    }
    if !has_ecp_service(paos) {
        return Err(SamlError::ProtocolProfile(
            "PAOS header must include \"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp\" with double quotes"
                .into(),
        ));
    }
    Ok(())
}

pub(super) struct SpToEcp<'a> {
    pub(super) response_consumer_url: &'a str,
    pub(super) provider_name: Option<&'a str>,
    pub(super) is_passive: Option<bool>,
    pub(super) issuer: &'a str,
    pub(super) identity_provider_id: &'a str,
    pub(super) identity_provider_loc: &'a str,
    pub(super) relay_state: Option<&'a str>,
    pub(super) authn_request_xml: &'a str,
}

pub(super) fn sp_to_ecp_envelope(input: &SpToEcp<'_>) -> String {
    let mut header = XmlWriter::new();
    header.empty(
        "paos:Request",
        &[
            ("xmlns:paos", PAOS_NS),
            ("responseConsumerURL", input.response_consumer_url),
            ("service", ECP_PROFILE),
            ("SOAP-ENV:mustUnderstand", "1"),
            ("SOAP-ENV:actor", SOAP_ACTOR_NEXT),
        ],
    );

    let mut ecp_attrs = vec![
        ("xmlns:ecp", ECP_PROFILE),
        ("SOAP-ENV:mustUnderstand", "1"),
        ("SOAP-ENV:actor", SOAP_ACTOR_NEXT),
    ];
    if let Some(provider_name) = input.provider_name {
        ecp_attrs.push(("ProviderName", provider_name));
    }
    let is_passive = match input.is_passive {
        Some(true) => "true",
        Some(false) | None => "false",
    };
    ecp_attrs.push(("IsPassive", is_passive));
    header.start("ecp:Request", &ecp_attrs);
    header.text_element("saml:Issuer", &[("xmlns:saml", ASSERTION_NS)], input.issuer);
    header.start("samlp:IDPList", &[("xmlns:samlp", PROTOCOL_NS)]);
    header.empty(
        "samlp:IDPEntry",
        &[
            ("ProviderID", input.identity_provider_id),
            ("Loc", input.identity_provider_loc),
        ],
    );
    header.end("samlp:IDPList");
    header.end("ecp:Request");
    if let Some(relay_state) = input.relay_state {
        header.text_element(
            "ecp:RelayState",
            &[
                ("xmlns:ecp", ECP_PROFILE),
                ("SOAP-ENV:mustUnderstand", "1"),
                ("SOAP-ENV:actor", SOAP_ACTOR_NEXT),
            ],
            relay_state,
        );
    }
    envelope(&header.finish(), input.authn_request_xml)
}

pub(super) struct IdpToEcp<'a> {
    pub(super) assertion_consumer_service_url: &'a str,
    pub(super) response_xml: &'a str,
}

pub(super) fn idp_to_ecp_envelope(input: &IdpToEcp<'_>) -> String {
    let mut header = XmlWriter::new();
    header.empty(
        "ecp:Response",
        &[
            ("xmlns:ecp", ECP_PROFILE),
            ("SOAP-ENV:mustUnderstand", "1"),
            ("SOAP-ENV:actor", SOAP_ACTOR_NEXT),
            (
                "AssertionConsumerServiceURL",
                input.assertion_consumer_service_url,
            ),
        ],
    );
    envelope(&header.finish(), input.response_xml)
}

pub(super) fn soap_fault_envelope() -> String {
    format!(
        "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\"><SOAP-ENV:Body><SOAP-ENV:Fault><faultcode>SOAP-ENV:Client</faultcode><faultstring>SOAP request could not be processed</faultstring></SOAP-ENV:Fault></SOAP-ENV:Body></SOAP-ENV:Envelope>"
    )
}

pub(super) struct SoapBody {
    pub(super) element_xml: String,
    pub(super) relay_state: RelayStateParam,
}

pub(super) fn read_soap_body(
    envelope_xml: &str,
    element_name: &str,
    limits: XmlLimits,
) -> Result<SoapBody, SamlError> {
    let document = parse_with_limits(envelope_xml, limits)?;
    let scan = scan_envelope(envelope_xml)?;
    if document.root.local_name != "Envelope" || !scan.root_is_soap_envelope {
        return Err(SamlError::ProtocolProfile(
            "SOAP message must be an Envelope".into(),
        ));
    }
    if scan.child_is_soap.len() != document.root.children.len() {
        return Err(SamlError::Xml(
            "SOAP child count did not match the envelope".into(),
        ));
    }
    if scan.child_is_soap.contains(&false) {
        return Err(SamlError::ProtocolProfile(
            "SOAP envelope must contain only a Header and a Body".into(),
        ));
    }
    let parts = envelope_parts(&document.root)?;
    let body = parts.body;
    let [element] = body.children.as_slice() else {
        return Err(SamlError::ProtocolProfile(format!(
            "SOAP body must contain one {element_name}"
        )));
    };
    if element.local_name != element_name {
        return Err(SamlError::ProtocolProfile(format!(
            "SOAP body must contain one {element_name}"
        )));
    }
    match scan.body_child_in_protocol.as_slice() {
        [true] => {}
        [false] => {
            return Err(SamlError::ProtocolProfile(format!(
                "SOAP body element must use the {PROTOCOL_NS} namespace"
            )));
        }
        _ => {
            return Err(SamlError::Xml(
                "SAML element count did not match the SOAP body".into(),
            ));
        }
    }
    let element_xml = scan.with_inherited_namespaces(xml_slice(envelope_xml, element)?)?;
    let relay_state = match parts.header {
        Some(header) => relay_state_header(header, &scan.relay_state_in_ecp)?,
        None => RelayStateParam::absent(),
    };
    Ok(SoapBody {
        element_xml,
        relay_state,
    })
}

fn envelope(header_xml: &str, body_xml: &str) -> String {
    format!(
        "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\"><SOAP-ENV:Header>{header_xml}</SOAP-ENV:Header><SOAP-ENV:Body>{body_xml}</SOAP-ENV:Body></SOAP-ENV:Envelope>"
    )
}

/// Namespace-resolved facts about one SOAP envelope, in document order.
#[derive(Default)]
struct EnvelopeScan {
    root_is_soap_envelope: bool,
    /// Whether each child of the root is a SOAP 1.1 element.
    child_is_soap: Vec<bool>,
    /// Whether each child of the first SOAP `Body` is in the SAML protocol namespace.
    body_child_in_protocol: Vec<bool>,
    /// Whether each `RelayState` child of the first SOAP `Header` is in the ECP namespace.
    relay_state_in_ecp: Vec<bool>,
    /// Byte length of the first `Body` child's qualified name.
    body_child_name_len: usize,
    /// Start-tag text for the `Envelope` and `Body` namespace declarations the
    /// first `Body` child uses and does not declare itself.
    inherited_declarations: String,
}

impl EnvelopeScan {
    /// `element_xml` with the namespace declarations it inherited from the
    /// envelope written on its own start tag.
    fn with_inherited_namespaces(&self, element_xml: &str) -> Result<String, SamlError> {
        if self.inherited_declarations.is_empty() {
            return Ok(element_xml.to_string());
        }
        let name_end = 1 + self.body_child_name_len;
        let (name, rest) = element_xml
            .split_at_checked(name_end)
            .ok_or_else(|| SamlError::Xml("SOAP element name fell outside the element".into()))?;
        Ok(format!("{name}{}{rest}", self.inherited_declarations))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    NotSeen,
    Open,
    Closed,
}

/// A namespace prefix as written, empty for the default namespace.
type Prefix = String;

fn scan_envelope(xml: &str) -> Result<EnvelopeScan, SamlError> {
    use quick_xml::events::Event;
    use quick_xml::reader::NsReader;

    let mut reader = NsReader::from_str(xml);
    let mut buf = Vec::new();
    let mut depth = 0usize;
    let mut saw_root = false;
    let mut header = Section::NotSeen;
    let mut body = Section::NotSeen;
    let mut scan = EnvelopeScan::default();
    // Declarations on Envelope and Body, with the raw attribute value.
    let mut in_scope: Vec<(Prefix, String)> = Vec::new();
    let mut declared: Vec<Prefix> = Vec::new();
    let mut used: Vec<Prefix> = Vec::new();
    loop {
        let (resolved, event) = reader
            .read_resolved_event_into(&mut buf)
            .map_err(|err| SamlError::Xml(err.to_string()))?;
        match &event {
            Event::Start(element) | Event::Empty(element) => {
                let next_depth = depth + 1;
                let opens = matches!(event, Event::Start(_));
                let local_name = element.local_name();
                let local_name = local_name.as_ref();
                let is_soap = is_bound_to(&resolved, SOAP_ENVELOPE_NS);
                if next_depth == 1 && !saw_root {
                    saw_root = true;
                    scan.root_is_soap_envelope = is_soap && local_name == "Envelope";
                    namespace_declarations(element, &mut in_scope)?;
                } else if next_depth == 2 {
                    scan.child_is_soap.push(is_soap);
                    if is_soap && local_name == "Header" && header == Section::NotSeen {
                        header = if opens {
                            Section::Open
                        } else {
                            Section::Closed
                        };
                    } else if is_soap && local_name == "Body" && body == Section::NotSeen {
                        body = if opens {
                            Section::Open
                        } else {
                            Section::Closed
                        };
                        namespace_declarations(element, &mut in_scope)?;
                    }
                } else if next_depth == 3 && header == Section::Open {
                    if local_name == "RelayState" {
                        scan.relay_state_in_ecp
                            .push(is_bound_to(&resolved, ECP_PROFILE));
                    }
                } else if next_depth == 3 && body == Section::Open {
                    scan.body_child_in_protocol
                        .push(is_bound_to(&resolved, PROTOCOL_NS));
                    if scan.body_child_in_protocol.len() == 1 {
                        scan.body_child_name_len = element.name().as_ref().len();
                        let mut own = Vec::new();
                        namespace_declarations(element, &mut own)?;
                        declared = own.into_iter().map(|(prefix, _)| prefix).collect();
                    }
                }
                if next_depth >= 3
                    && body == Section::Open
                    && scan.body_child_in_protocol.len() == 1
                {
                    used_prefixes(element, &mut used)?;
                }
                if opens {
                    depth = next_depth;
                }
            }
            Event::End(_) => {
                if depth == 1 {
                    break;
                }
                if depth == 2 {
                    if header == Section::Open {
                        header = Section::Closed;
                    }
                    if body == Section::Open {
                        body = Section::Closed;
                    }
                }
                depth = depth.saturating_sub(1);
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    for (prefix, value) in &in_scope {
        if !used.contains(prefix) || declared.contains(prefix) {
            continue;
        }
        // The raw value was delimited by one quote character, so it holds at
        // most the other one.
        let quote = if value.contains('"') { '\'' } else { '"' };
        scan.inherited_declarations.push_str(" xmlns");
        if !prefix.is_empty() {
            scan.inherited_declarations.push(':');
            scan.inherited_declarations.push_str(prefix);
        }
        scan.inherited_declarations.push('=');
        scan.inherited_declarations.push(quote);
        scan.inherited_declarations.push_str(value);
        scan.inherited_declarations.push(quote);
    }
    Ok(scan)
}

fn is_bound_to(resolved: &quick_xml::name::ResolveResult<'_>, namespace: &str) -> bool {
    matches!(
        resolved,
        quick_xml::name::ResolveResult::Bound(bound) if bound.as_ref() == namespace
    )
}

/// Record the namespace declarations on `element`. A later declaration of a
/// prefix replaces an earlier one.
fn namespace_declarations(
    element: &quick_xml::events::BytesStart<'_>,
    declarations: &mut Vec<(Prefix, String)>,
) -> Result<(), SamlError> {
    use quick_xml::name::PrefixDeclaration;

    for attribute in element.attributes() {
        let attribute = attribute.map_err(|err| SamlError::Xml(err.to_string()))?;
        let prefix = match attribute.key.as_namespace_binding() {
            Some(PrefixDeclaration::Default) => Prefix::new(),
            Some(PrefixDeclaration::Named(prefix)) => prefix.to_string(),
            None => continue,
        };
        declarations.retain(|(declared, _)| declared != &prefix);
        declarations.push((prefix, attribute.value.into_owned()));
    }
    Ok(())
}

/// Record the prefixes of `element`'s name and of its attribute names.
fn used_prefixes(
    element: &quick_xml::events::BytesStart<'_>,
    used: &mut Vec<Prefix>,
) -> Result<(), SamlError> {
    let mut record = |prefix: &str| {
        if !used.iter().any(|seen| seen == prefix) {
            used.push(prefix.to_string());
        }
    };
    match element.name().prefix() {
        Some(prefix) => record(prefix.into_inner()),
        None => record(""),
    }
    for attribute in element.attributes() {
        let attribute = attribute.map_err(|err| SamlError::Xml(err.to_string()))?;
        if attribute.key.as_namespace_binding().is_some() {
            continue;
        }
        if let Some(prefix) = attribute.key.prefix() {
            record(prefix.into_inner());
        }
    }
    Ok(())
}

fn relay_state_header(
    header: &Node,
    in_ecp_namespace: &[bool],
) -> Result<RelayStateParam, SamlError> {
    let relay_states: Vec<&Node> = header
        .children
        .iter()
        .filter(|node| node.local_name == "RelayState")
        .collect();
    match relay_states.as_slice() {
        [] => Ok(RelayStateParam::absent()),
        [relay_state] => match in_ecp_namespace {
            [true] => RelayStateParam::try_from_option(Some(relay_state.text.clone())),
            [false] => Err(SamlError::ProtocolProfile(
                "RelayState header must use the ECP profile namespace".into(),
            )),
            _ => Err(SamlError::Xml(
                "RelayState header count did not match the SOAP header".into(),
            )),
        },
        _ => Err(SamlError::ProtocolProfile(
            "SOAP header must contain at most one RelayState".into(),
        )),
    }
}

fn xml_slice<'a>(xml: &'a str, node: &Node) -> Result<&'a str, SamlError> {
    xml.get(node.start..node.end)
        .ok_or_else(|| SamlError::Xml("SOAP element offsets fell outside the message".into()))
}

fn header_value<'a>(header: &'a str, name: &str) -> &'a str {
    let trimmed = header.trim();
    let Some((field, value)) = trimmed.split_once(':') else {
        return trimmed;
    };
    if field.trim().eq_ignore_ascii_case(name) {
        value.trim()
    } else {
        trimmed
    }
}

fn lists_media_type(header: &str, media_type: &str) -> bool {
    header
        .split([',', ';'])
        .any(|part| part.trim().eq_ignore_ascii_case(media_type))
}

fn paos_tokens(header: &str) -> impl Iterator<Item = &str> {
    header
        .split([',', ';'])
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

fn has_double_quoted_version(header: &str) -> bool {
    let expected = format!("\"{PAOS_VERSION}\"");
    paos_tokens(header).any(|token| {
        let Some(rest) = token.strip_prefix("ver") else {
            return false;
        };
        let Some(rest) = rest.trim_start().strip_prefix('=') else {
            return false;
        };
        rest.trim_start() == expected
    })
}

fn has_ecp_service(header: &str) -> bool {
    let expected = format!("\"{ECP_PROFILE}\"");
    paos_tokens(header).any(|token| token == expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e54_header_is_accepted() {
        let accept = "text/html; application/vnd.paos+xml";
        assert!(parse_client_headers(accept, E54_PAOS_HEADER).is_ok());
    }

    #[test]
    fn single_quoted_paos_header_is_rejected() -> Result<(), String> {
        let paos = "ver='urn:liberty:paos:2003-08';'urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp'";
        match parse_client_headers("application/vnd.paos+xml", paos) {
            Err(SamlError::ProtocolProfile(_)) => Ok(()),
            other => Err(format!("expected ProtocolProfile, got {other:?}")),
        }
    }

    #[test]
    fn comma_separated_double_quotes_are_accepted() {
        let paos =
            "ver=\"urn:liberty:paos:2003-08\",\"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp\"";
        assert!(parse_client_headers("application/vnd.paos+xml", paos).is_ok());
    }

    #[test]
    fn ver_attribute_name_must_match_exactly() {
        let ecp = "\"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp\"";
        for paos in [
            format!("server=\"urn:liberty:paos:2003-08\";{ecp}"),
            format!("xver=\"urn:liberty:paos:2003-08\";{ecp}"),
            format!("version=\"urn:liberty:paos:2003-08\";{ecp}"),
            format!("cover=\"urn:liberty:paos:2003-08\";{ecp}"),
        ] {
            assert!(
                parse_client_headers("application/vnd.paos+xml", &paos).is_err(),
                "accepted {paos}"
            );
        }
    }

    #[test]
    fn ecp_service_must_be_its_own_token() {
        let paos =
            "ver=\"urn:liberty:paos:2003-08\";foo=\"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp\"";
        assert!(parse_client_headers("application/vnd.paos+xml", paos).is_err());
    }

    #[test]
    fn accept_without_paos_is_rejected() {
        assert!(parse_client_headers("text/html", E54_PAOS_HEADER).is_err());
    }

    #[test]
    fn soap_body_preserves_the_saml_element() -> Result<(), SamlError> {
        let authn = format!(
            "<samlp:AuthnRequest xmlns:samlp=\"{PROTOCOL_NS}\" ID=\"_1\"></samlp:AuthnRequest>"
        );
        let envelope = sp_to_ecp_envelope(&SpToEcp {
            response_consumer_url: "https://sp.example.com/acs",
            provider_name: Some("Example SP"),
            is_passive: Some(false),
            issuer: "https://sp.example.com/metadata",
            identity_provider_id: "https://idp.example.com/metadata",
            identity_provider_loc: "https://idp.example.com/soap",
            relay_state: Some("state"),
            authn_request_xml: &authn,
        });
        let body = read_soap_body(&envelope, "AuthnRequest", XmlLimits::default())?;
        assert_eq!(body.element_xml, authn);
        assert_eq!(body.relay_state.as_deref(), Some("state"));
        assert!(envelope.contains("responseConsumerURL=\"https://sp.example.com/acs\""));
        assert!(envelope.contains(&format!("service=\"{ECP_PROFILE}\"")));
        Ok(())
    }

    #[test]
    fn relay_state_namespace_may_be_declared_on_an_ancestor() -> Result<(), SamlError> {
        let xml = format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:ecp=\"{ECP_PROFILE}\" xmlns:samlp=\"{PROTOCOL_NS}\"><SOAP-ENV:Header><ecp:RelayState>state</ecp:RelayState></SOAP-ENV:Header><SOAP-ENV:Body><samlp:AuthnRequest ID=\"_1\"></samlp:AuthnRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>"
        );
        let body = read_soap_body(&xml, "AuthnRequest", XmlLimits::default())?;
        assert_eq!(body.relay_state.as_deref(), Some("state"));
        Ok(())
    }

    #[test]
    fn relay_state_in_another_namespace_is_rejected() -> Result<(), String> {
        let xml = format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:other=\"urn:example:other\" xmlns:samlp=\"{PROTOCOL_NS}\"><SOAP-ENV:Header><other:RelayState>state</other:RelayState></SOAP-ENV:Header><SOAP-ENV:Body><samlp:AuthnRequest ID=\"_1\"></samlp:AuthnRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>"
        );
        match read_soap_body(&xml, "AuthnRequest", XmlLimits::default()) {
            Err(SamlError::ProtocolProfile(_)) => Ok(()),
            Err(other) => Err(format!("expected ProtocolProfile, got {other:?}")),
            Ok(_) => Err("expected ProtocolProfile, got a SOAP body".into()),
        }
    }

    #[test]
    fn soap_body_must_contain_one_element() -> Result<(), String> {
        let xml = format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:samlp=\"{PROTOCOL_NS}\"><SOAP-ENV:Body><samlp:AuthnRequest ID=\"_1\"></samlp:AuthnRequest><samlp:Response ID=\"_2\"></samlp:Response></SOAP-ENV:Body></SOAP-ENV:Envelope>"
        );
        match read_soap_body(&xml, "AuthnRequest", XmlLimits::default()) {
            Err(SamlError::ProtocolProfile(_)) => Ok(()),
            Err(other) => Err(format!("expected ProtocolProfile, got {other:?}")),
            Ok(_) => Err("expected ProtocolProfile, got a SOAP body".into()),
        }
    }

    #[test]
    fn omitted_is_passive_is_false_on_the_ecp_request() {
        let envelope = sp_to_ecp_envelope(&SpToEcp {
            response_consumer_url: "https://sp.example.com/acs?a=1&b=2",
            provider_name: Some("A\"B&C"),
            is_passive: None,
            issuer: "https://sp.example.com/metadata",
            identity_provider_id: "https://idp.example.com/metadata",
            identity_provider_loc: "https://idp.example.com/soap",
            relay_state: None,
            authn_request_xml: "<samlp:AuthnRequest ID=\"_1\"></samlp:AuthnRequest>",
        });
        assert!(envelope.contains("IsPassive=\"false\""));
        assert!(envelope.contains("ProviderName=\"A&quot;B&amp;C\""));
        assert!(envelope.contains("responseConsumerURL=\"https://sp.example.com/acs?a=1&amp;b=2\""));
    }

    #[test]
    fn a_non_soap_body_is_rejected() -> Result<(), String> {
        let xml = format!(
            "<!-- {SOAP_ENVELOPE_NS} --><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:other=\"urn:example:other\" xmlns:samlp=\"{PROTOCOL_NS}\"><other:Body><samlp:AuthnRequest ID=\"_1\"></samlp:AuthnRequest></other:Body></SOAP-ENV:Envelope>"
        );
        match read_soap_body(&xml, "AuthnRequest", XmlLimits::default()) {
            Err(SamlError::ProtocolProfile(_)) => Ok(()),
            Err(other) => Err(format!("expected ProtocolProfile, got {other:?}")),
            Ok(_) => Err("expected ProtocolProfile, got a SOAP body".into()),
        }
    }

    #[test]
    fn body_element_in_another_namespace_is_rejected() -> Result<(), String> {
        let xml = format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:other=\"urn:example:other\"><SOAP-ENV:Header/><SOAP-ENV:Body><other:Response ID=\"_1\"></other:Response></SOAP-ENV:Body></SOAP-ENV:Envelope>"
        );
        match read_soap_body(&xml, "Response", XmlLimits::default()) {
            Err(SamlError::ProtocolProfile(_)) => Ok(()),
            Err(other) => Err(format!("expected ProtocolProfile, got {other:?}")),
            Ok(_) => Err("expected ProtocolProfile, got a SOAP body".into()),
        }
    }

    #[test]
    fn saml_protocol_namespace_may_be_declared_on_an_ancestor() -> Result<(), SamlError> {
        for xml in [
            format!(
                "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:samlp=\"{PROTOCOL_NS}\"><SOAP-ENV:Header/><SOAP-ENV:Body><samlp:Response ID=\"_1\"></samlp:Response></SOAP-ENV:Body></SOAP-ENV:Envelope>"
            ),
            format!(
                "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns=\"{PROTOCOL_NS}\"><SOAP-ENV:Header/><SOAP-ENV:Body><Response ID=\"_1\"></Response></SOAP-ENV:Body></SOAP-ENV:Envelope>"
            ),
        ] {
            let body = read_soap_body(&xml, "Response", XmlLimits::default())?;
            assert!(body.element_xml.contains("ID=\"_1\""));
        }
        Ok(())
    }

    #[test]
    fn inherited_namespaces_are_written_on_the_saml_element() -> Result<(), SamlError> {
        let xml = format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:samlp=\"urn:example:shadowed\" xmlns:unused=\"urn:example:unused\"><SOAP-ENV:Body xmlns:samlp=\"{PROTOCOL_NS}\" xmlns:saml='{ASSERTION_NS}'><samlp:Response ID=\"_1\"><saml:Issuer>idp</saml:Issuer></samlp:Response></SOAP-ENV:Body></SOAP-ENV:Envelope>"
        );
        let body = read_soap_body(&xml, "Response", XmlLimits::default())?;
        assert_eq!(
            body.element_xml,
            format!(
                "<samlp:Response xmlns:samlp=\"{PROTOCOL_NS}\" xmlns:saml=\"{ASSERTION_NS}\" ID=\"_1\"><saml:Issuer>idp</saml:Issuer></samlp:Response>"
            )
        );

        let xml = format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns=\"{PROTOCOL_NS}\"><SOAP-ENV:Body><Response ID=\"_1\"/></SOAP-ENV:Body></SOAP-ENV:Envelope>"
        );
        let body = read_soap_body(&xml, "Response", XmlLimits::default())?;
        assert_eq!(
            body.element_xml,
            format!("<Response xmlns=\"{PROTOCOL_NS}\" ID=\"_1\"/>")
        );
        Ok(())
    }

    #[test]
    fn extra_envelope_child_is_rejected() -> Result<(), String> {
        let xml = format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:samlp=\"{PROTOCOL_NS}\"><SOAP-ENV:Header/><SOAP-ENV:Body><samlp:Response ID=\"_1\"></samlp:Response></SOAP-ENV:Body><SOAP-ENV:Extra/></SOAP-ENV:Envelope>"
        );
        match read_soap_body(&xml, "Response", XmlLimits::default()) {
            Err(SamlError::ProtocolProfile(_)) => Ok(()),
            Err(other) => Err(format!("expected ProtocolProfile, got {other:?}")),
            Ok(_) => Err("expected ProtocolProfile, got a SOAP body".into()),
        }
    }

    #[test]
    fn duplicate_body_is_rejected() -> Result<(), String> {
        let xml = format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:samlp=\"{PROTOCOL_NS}\"><SOAP-ENV:Body><samlp:Response ID=\"_1\"></samlp:Response></SOAP-ENV:Body><SOAP-ENV:Body><samlp:Response ID=\"_2\"></samlp:Response></SOAP-ENV:Body></SOAP-ENV:Envelope>"
        );
        match read_soap_body(&xml, "Response", XmlLimits::default()) {
            Err(SamlError::ProtocolProfile(_)) => Ok(()),
            Err(other) => Err(format!("expected ProtocolProfile, got {other:?}")),
            Ok(_) => Err("expected ProtocolProfile, got a SOAP body".into()),
        }
    }

    #[test]
    fn header_after_body_is_rejected() -> Result<(), String> {
        let xml = format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:samlp=\"{PROTOCOL_NS}\" xmlns:ecp=\"{ECP_PROFILE}\"><SOAP-ENV:Body><samlp:Response ID=\"_1\"></samlp:Response></SOAP-ENV:Body><SOAP-ENV:Header><ecp:RelayState>state</ecp:RelayState></SOAP-ENV:Header></SOAP-ENV:Envelope>"
        );
        match read_soap_body(&xml, "Response", XmlLimits::default()) {
            Err(SamlError::ProtocolProfile(_)) => Ok(()),
            Err(other) => Err(format!("expected ProtocolProfile, got {other:?}")),
            Ok(_) => Err("expected ProtocolProfile, got a SOAP body".into()),
        }
    }

    #[test]
    fn soap_12_envelope_is_rejected() -> Result<(), String> {
        let xml = format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:samlp=\"{PROTOCOL_NS}\"><SOAP-ENV:Body><samlp:Response ID=\"_1\"></samlp:Response></SOAP-ENV:Body></SOAP-ENV:Envelope>"
        );
        match read_soap_body(&xml, "Response", XmlLimits::default()) {
            Err(SamlError::ProtocolProfile(_)) => Ok(()),
            Err(other) => Err(format!("expected ProtocolProfile, got {other:?}")),
            Ok(_) => Err("expected ProtocolProfile, got a SOAP body".into()),
        }
    }

    #[test]
    fn requested_is_passive_true_is_carried() {
        let envelope = sp_to_ecp_envelope(&SpToEcp {
            response_consumer_url: "https://sp.example.com/acs",
            provider_name: None,
            is_passive: Some(true),
            issuer: "https://sp.example.com/metadata",
            identity_provider_id: "https://idp.example.com/metadata",
            identity_provider_loc: "https://idp.example.com/soap",
            relay_state: None,
            authn_request_xml: "<samlp:AuthnRequest ID=\"_1\"></samlp:AuthnRequest>",
        });
        assert!(envelope.contains("IsPassive=\"true\""));
    }
}
