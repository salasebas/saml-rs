//! SOAP 1.1 envelope for one synchronous SAML request and response.
//!
//! The deployment sends the envelope. TLS and HTTP authentication stay there.

use quick_xml::events::{BytesStart, Event};
use quick_xml::name::{Namespace, ResolveResult};
use quick_xml::reader::NsReader;

use crate::error::SamlError;
use crate::model::EndpointUrl;
use crate::xml::dom::{self, Node};
use crate::xml::fragment::standalone_element;
use crate::xml::write::XmlWriter;
use crate::xml::XmlLimits;

const SOAP_NAMESPACE: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const SOAP_ACTION: &str = "http://www.oasis-open.org/committees/security";
const REQUEST_CACHE_CONTROL: &str = "no-cache, no-store";
const RESPONSE_CACHE_CONTROL: &str = "no-cache, no-store, must-revalidate, private";
const PRAGMA: &str = "no-cache";
const CONTENT_TYPE: &str = "text/xml; charset=utf-8";

/// Whether the deployment authenticated both SOAP parties.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartyAuthentication {
    /// Each party authenticated the other for this exchange.
    Mutual,
    /// The caller did not attest mutual authentication.
    Absent,
}

/// Whether the deployment protected the SOAP bytes against modification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageIntegrity {
    /// The exchange is integrity protected.
    Protected,
    /// The caller did not attest integrity protection.
    Absent,
}

/// Whether the deployment kept the SOAP bytes confidential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageConfidentiality {
    /// The exchange is confidential.
    Protected,
    /// The caller did not attest confidentiality.
    Absent,
}

/// Protection the deployment established for one SOAP exchange.
///
/// saml-rs does not open TLS or check HTTP credentials. Pass the properties
/// the deployment actually provided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoapChannel {
    authentication: PartyAuthentication,
    integrity: MessageIntegrity,
    confidentiality: MessageConfidentiality,
}

impl SoapChannel {
    /// Record the protection the deployment provided.
    pub fn new(
        authentication: PartyAuthentication,
        integrity: MessageIntegrity,
        confidentiality: MessageConfidentiality,
    ) -> Self {
        Self {
            authentication,
            integrity,
            confidentiality,
        }
    }

    /// No protection attested.
    pub fn unattested() -> Self {
        Self::new(
            PartyAuthentication::Absent,
            MessageIntegrity::Absent,
            MessageConfidentiality::Absent,
        )
    }

    /// Mutual authentication, integrity protection, and confidentiality.
    pub fn mutually_authenticated_confidential() -> Self {
        Self::new(
            PartyAuthentication::Mutual,
            MessageIntegrity::Protected,
            MessageConfidentiality::Protected,
        )
    }

    /// How the parties authenticated.
    pub fn authentication(self) -> PartyAuthentication {
        self.authentication
    }

    /// Whether the exchange is integrity protected.
    pub fn integrity(self) -> MessageIntegrity {
        self.integrity
    }

    /// Whether the exchange is confidential.
    pub fn confidentiality(self) -> MessageConfidentiality {
        self.confidentiality
    }

    /// Mutual authentication with integrity protection.
    pub(crate) fn authenticates_peer(self) -> bool {
        self.authentication == PartyAuthentication::Mutual
            && self.integrity == MessageIntegrity::Protected
    }
}

/// Outbound SOAP 1.1 request carrying one SAML protocol element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoapRequest {
    endpoint: EndpointUrl,
    envelope: String,
}

impl SoapRequest {
    /// URL the deployment POSTs this envelope to.
    pub fn endpoint(&self) -> &EndpointUrl {
        &self.endpoint
    }

    /// SOAP 1.1 envelope.
    pub fn envelope(&self) -> &str {
        &self.envelope
    }

    /// `SOAPAction` value a requester may send.
    pub fn soap_action(&self) -> &'static str {
        SOAP_ACTION
    }

    /// `Cache-Control` value a requester should send.
    pub fn cache_control(&self) -> &'static str {
        REQUEST_CACHE_CONTROL
    }

    /// `Pragma` value a requester should send.
    pub fn pragma(&self) -> &'static str {
        PRAGMA
    }

    /// `Content-Type` for SOAP 1.1.
    pub fn content_type(&self) -> &'static str {
        CONTENT_TYPE
    }
}

/// SOAP 1.1 response carrying one SAML protocol element.
///
/// The deployment returns [`Self::envelope`] as the HTTP 200 body of the SOAP
/// request it answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoapResponse {
    envelope: String,
}

impl SoapResponse {
    pub(crate) fn new(protocol_xml: &str) -> Result<Self, SamlError> {
        Ok(Self {
            envelope: SoapProtocolMessage::response_envelope(protocol_xml)?,
        })
    }

    /// SOAP 1.1 envelope.
    pub fn envelope(&self) -> &str {
        &self.envelope
    }

    /// `Cache-Control` value a responder should send.
    pub fn cache_control(&self) -> &'static str {
        RESPONSE_CACHE_CONTROL
    }

    /// `Pragma` value a responder should send.
    pub fn pragma(&self) -> &'static str {
        PRAGMA
    }

    /// `Content-Type` for SOAP 1.1.
    pub fn content_type(&self) -> &'static str {
        CONTENT_TYPE
    }
}

/// One SAML protocol element read from, or placed in, a SOAP 1.1 body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoapProtocolMessage {
    local_name: String,
    namespace: String,
    xml: String,
}

impl SoapProtocolMessage {
    /// Wrap one SAML protocol element in a SOAP 1.1 request.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when `protocol_xml` is not a single element.
    pub fn request(endpoint: EndpointUrl, protocol_xml: &str) -> Result<SoapRequest, SamlError> {
        let element = single_element(protocol_xml)?;
        Ok(SoapRequest {
            endpoint,
            envelope: envelope(&element)?,
        })
    }

    /// Wrap one SAML protocol element in a SOAP 1.1 response envelope.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when `protocol_xml` is not a single element.
    pub fn response_envelope(protocol_xml: &str) -> Result<String, SamlError> {
        envelope(&single_element(protocol_xml)?)
    }

    /// Read the single element in a SOAP 1.1 body.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the envelope is not SOAP 1.1, the body does
    /// not contain exactly one element, or a SOAP header requires processing
    /// this crate does not provide.
    pub fn from_envelope(envelope: &str) -> Result<Self, SamlError> {
        let body = read_soap_body(envelope, XmlLimits::default())?;
        Ok(Self {
            local_name: body.local_name,
            namespace: body.namespace,
            xml: body.xml,
        })
    }

    /// Local name of the SAML element.
    pub fn local_name(&self) -> &str {
        &self.local_name
    }

    /// Namespace URI of the SAML element.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// XML of the SAML element, without the SOAP envelope.
    pub fn xml(&self) -> &str {
        &self.xml
    }
}

/// `Cache-Control` value a SOAP responder should send.
pub fn response_cache_control() -> &'static str {
    RESPONSE_CACHE_CONTROL
}

/// `Pragma` value a SOAP responder should send.
pub fn response_pragma() -> &'static str {
    PRAGMA
}

/// `Content-Type` for a SOAP 1.1 response.
pub fn response_content_type() -> &'static str {
    CONTENT_TYPE
}

pub(crate) struct SoapBody {
    pub(crate) local_name: String,
    pub(crate) namespace: String,
    pub(crate) xml: String,
}

pub(crate) fn read_soap_body(envelope: &str, limits: XmlLimits) -> Result<SoapBody, SamlError> {
    let document = dom::parse_with_limits(envelope, limits)?;
    let child_namespace = soap_body_namespace(envelope)?;
    let body = envelope_parts(&document.root)?.body;
    let child = single_element_child(body)?;
    if child.local_name != child_namespace.local_name {
        return Err(SamlError::Xml(
            "SOAP body element does not match its namespace declaration".into(),
        ));
    }
    Ok(SoapBody {
        local_name: child.local_name.clone(),
        namespace: child_namespace.namespace,
        xml: standalone_element(envelope, child.start, child.end)?,
    })
}

pub(crate) struct EnvelopeParts<'a> {
    pub(crate) header: Option<&'a Node>,
    pub(crate) body: &'a Node,
}

pub(crate) fn envelope_parts(envelope: &Node) -> Result<EnvelopeParts<'_>, SamlError> {
    match envelope.children.as_slice() {
        [body] if body.local_name == "Body" => Ok(EnvelopeParts { header: None, body }),
        [header, body] if header.local_name == "Header" && body.local_name == "Body" => {
            Ok(EnvelopeParts {
                header: Some(header),
                body,
            })
        }
        _ => Err(SamlError::ProtocolProfile(
            "SOAP envelope must contain an optional Header followed by one Body".into(),
        )),
    }
}

fn envelope(element_xml: &str) -> Result<String, SamlError> {
    let mut writer = XmlWriter::new();
    writer.start("soap:Envelope", &[("xmlns:soap", SOAP_NAMESPACE)]);
    writer.start("soap:Body", &[]);
    writer.raw(element_xml);
    writer.end("soap:Body");
    writer.end("soap:Envelope");
    Ok(writer.finish())
}

fn single_element(xml: &str) -> Result<String, SamlError> {
    let document = dom::parse(xml)?;
    if document.root.end < document.root.start || document.root.end > xml.len() {
        return Err(SamlError::Xml("protocol element is incomplete".into()));
    }
    Ok(xml[document.root.start..document.root.end].to_string())
}

struct NamedNamespace {
    local_name: String,
    namespace: String,
}

fn single_element_child(body: &Node) -> Result<&Node, SamlError> {
    let mut children = body.children.iter();
    let child = children
        .next()
        .ok_or_else(|| SamlError::Xml("SOAP body must contain one SAML protocol element".into()))?;
    if children.next().is_some() {
        return Err(SamlError::ProtocolProfile(
            "SOAP body must contain exactly one SAML protocol element".into(),
        ));
    }
    Ok(child)
}

fn soap_body_namespace(xml: &str) -> Result<NamedNamespace, SamlError> {
    let mut reader = NsReader::from_str(xml);
    let mut buf = Vec::new();
    let mut depth = 0usize;
    let mut scan = SoapScan::default();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(element)) => {
                depth += 1;
                observe_start(&reader, &element, depth, &mut scan, false)?;
            }
            Ok(Event::Empty(element)) => {
                observe_start(&reader, &element, depth + 1, &mut scan, true)?;
            }
            Ok(Event::End(_)) => {
                if scan.in_header && depth == scan.header_depth {
                    scan.in_header = false;
                }
                if scan.in_body && depth == scan.body_depth {
                    scan.in_body = false;
                }
                depth = depth.saturating_sub(1);
            }
            Ok(Event::DocType(_)) => {
                return Err(SamlError::Xml("DOCTYPE is not allowed".into()));
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(err) => return Err(SamlError::Xml(err.to_string())),
        }
        buf.clear();
    }

    if !scan.saw_envelope {
        return Err(SamlError::Xml(
            "SOAP message must use the SOAP 1.1 envelope namespace".into(),
        ));
    }
    scan.child
        .ok_or_else(|| SamlError::Xml("SOAP body must contain one SAML protocol element".into()))
}

#[derive(Default)]
struct SoapScan {
    saw_envelope: bool,
    in_header: bool,
    header_depth: usize,
    in_body: bool,
    body_depth: usize,
    body_children: usize,
    child: Option<NamedNamespace>,
}

fn observe_start(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    depth: usize,
    scan: &mut SoapScan,
    empty: bool,
) -> Result<(), SamlError> {
    let (namespace, local_name) = reader.resolver().resolve_element(element.name());
    let local_name = local_name.as_ref().to_string();
    let namespace = bound_namespace(namespace);

    if depth == 1 {
        if local_name != "Envelope" || namespace != Some(SOAP_NAMESPACE) {
            return Err(SamlError::Xml(
                "SOAP message must use the SOAP 1.1 envelope namespace".into(),
            ));
        }
        scan.saw_envelope = true;
        return Ok(());
    }

    if depth == 2 && scan.saw_envelope {
        if namespace != Some(SOAP_NAMESPACE) {
            return Err(SamlError::Xml(
                "SOAP Header and Body must use the SOAP 1.1 namespace".into(),
            ));
        }
        match local_name.as_str() {
            "Header" => {
                scan.in_header = !empty;
                scan.header_depth = depth;
            }
            "Body" => {
                scan.in_body = !empty;
                scan.body_depth = depth;
            }
            _ => {
                return Err(SamlError::Xml(
                    "SOAP envelope contains an element other than Header or Body".into(),
                ));
            }
        }
        return Ok(());
    }

    if scan.in_header && depth == scan.header_depth + 1 {
        reject_must_understand(reader, element)?;
    }

    if scan.in_body && depth == scan.body_depth + 1 {
        scan.body_children += 1;
        if scan.body_children > 1 {
            return Err(SamlError::ProtocolProfile(
                "SOAP body must contain exactly one SAML protocol element".into(),
            ));
        }
        scan.child = Some(NamedNamespace {
            local_name,
            namespace: namespace.unwrap_or("").to_string(),
        });
    }
    Ok(())
}

fn reject_must_understand(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
) -> Result<(), SamlError> {
    for attribute in element.attributes() {
        let attribute = attribute.map_err(|err| SamlError::Xml(err.to_string()))?;
        let (namespace, local_name) = reader.resolver().resolve_attribute(attribute.key);
        if local_name.as_ref() != "mustUnderstand" {
            continue;
        }
        let in_soap = matches!(bound_namespace(namespace), Some(SOAP_NAMESPACE) | None);
        if !in_soap {
            continue;
        }
        let value = attribute
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map_err(|err| SamlError::Xml(err.to_string()))?;
        if matches!(value.trim(), "1" | "true") {
            return Err(SamlError::Xml(
                "SOAP header requires processing this responder does not provide".into(),
            ));
        }
    }
    Ok(())
}

fn bound_namespace(result: ResolveResult<'_>) -> Option<&str> {
    match result {
        ResolveResult::Bound(Namespace(uri)) => Some(uri),
        ResolveResult::Unbound | ResolveResult::Unknown(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soap_channel_round_trips_another_protocol_element() -> Result<(), SamlError> {
        let logout = r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_logout" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"/>"#;
        let endpoint = EndpointUrl::try_new("https://idp.example.com/artifact")?;
        let request = SoapProtocolMessage::request(endpoint, logout)?;
        let message = SoapProtocolMessage::from_envelope(request.envelope())?;

        assert_eq!(message.local_name(), "LogoutRequest");
        assert_eq!(message.namespace(), "urn:oasis:names:tc:SAML:2.0:protocol");
        assert!(message.xml().contains("ID=\"_logout\""));
        assert_eq!(
            request.soap_action(),
            "http://www.oasis-open.org/committees/security"
        );
        Ok(())
    }

    #[test]
    fn soap_body_rejects_a_second_element() {
        let envelope = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><samlp:One xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/><samlp:Two xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/></soap:Body></soap:Envelope>"#;
        assert!(matches!(
            SoapProtocolMessage::from_envelope(envelope),
            Err(SamlError::ProtocolProfile(_))
        ));
    }

    #[test]
    fn soap_header_must_understand_is_rejected() {
        let envelope = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" soap:mustUnderstand="1"/></soap:Header><soap:Body><samlp:ArtifactResolve xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/></soap:Body></soap:Envelope>"#;
        assert!(SoapProtocolMessage::from_envelope(envelope).is_err());
    }

    #[test]
    fn soap_header_padded_must_understand_is_rejected() {
        let envelope = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header><extra soap:mustUnderstand=" 1 ">note</extra></soap:Header><soap:Body><samlp:ArtifactResolve xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/></soap:Body></soap:Envelope>"#;
        assert!(matches!(
            SoapProtocolMessage::from_envelope(envelope),
            Err(SamlError::Xml(_))
        ));
    }

    #[test]
    fn soap_header_must_be_one_element_before_the_body() {
        let body = r#"<soap:Body><samlp:ArtifactResolve xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/></soap:Body>"#;
        for children in [
            format!("{body}<soap:Header/>"),
            format!("<soap:Header/><soap:Header/>{body}"),
        ] {
            let envelope = format!(
                r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">{children}</soap:Envelope>"#
            );
            assert!(
                matches!(
                    SoapProtocolMessage::from_envelope(&envelope),
                    Err(SamlError::ProtocolProfile(_))
                ),
                "{envelope}"
            );
        }
    }

    #[test]
    fn soap_body_keeps_namespaces_declared_on_the_envelope() -> Result<(), SamlError> {
        let envelope = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><soap:Body><samlp:LogoutRequest ID="_logout"/></soap:Body></soap:Envelope>"#;
        let message = SoapProtocolMessage::from_envelope(envelope)?;
        assert_eq!(
            message.xml(),
            r#"<samlp:LogoutRequest xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_logout"/>"#
        );
        Ok(())
    }

    #[test]
    fn soap_header_unprefixed_must_understand_is_rejected() {
        let envelope = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header><extra mustUnderstand="1">note</extra></soap:Header><soap:Body><samlp:ArtifactResolve xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/></soap:Body></soap:Envelope>"#;
        assert!(matches!(
            SoapProtocolMessage::from_envelope(envelope),
            Err(SamlError::Xml(_))
        ));
    }
}
