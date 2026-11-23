//! SOAP 1.1 envelope for one synchronous SAML request and response.
//!
//! The deployment sends the envelope. TLS and HTTP authentication stay there.

use quick_xml::events::{BytesStart, Event};
use quick_xml::name::{Namespace, ResolveResult};
use quick_xml::reader::{NsReader, Reader};

use crate::config::{HmacSecret, XmlSignatureProfile};
use crate::constants::namespace;
#[cfg(crypto)]
use crate::crypto::verify::verify_soap_body_signature;
use crate::error::{xml_err, SamlError};
use crate::http_header::{HttpHeader, CACHE_CONTROL, PRAGMA};
use crate::model::EndpointUrl;
use crate::xml::dom::{self, reader_err, Node};
use crate::xml::fragment::standalone_element;
use crate::xml::protocol_element::{parse_saml_with_limits, SamlElement};
use crate::xml::write::XmlWriter;
use crate::xml::XmlLimits;

pub(crate) const SOAP_NAMESPACE: &str = "http://schemas.xmlsoap.org/soap/envelope/";
pub(crate) const SOAP_ACTOR_NEXT: &str = "http://schemas.xmlsoap.org/soap/actor/next";
const CONTENT_TYPE: HttpHeader = HttpHeader::new("Content-Type", "text/xml; charset=utf-8");
pub(crate) const RESPONSE_CACHE_CONTROL: HttpHeader = HttpHeader::new(
    "Cache-Control",
    "no-cache, no-store, must-revalidate, private",
);
const REQUEST_HEADERS: &[HttpHeader] = &[
    CONTENT_TYPE,
    HttpHeader::new(
        "SOAPAction",
        "http://www.oasis-open.org/committees/security",
    ),
    CACHE_CONTROL,
    PRAGMA,
];
pub(crate) const RESPONSE_HEADERS: &[HttpHeader] = &[CONTENT_TYPE, RESPONSE_CACHE_CONTROL, PRAGMA];

/// The caller's attestation of mutual authentication for a SOAP exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartyAuthentication {
    /// The caller attests that each party authenticated the other.
    Mutual,
    /// The caller did not attest mutual authentication.
    Unattested,
}

/// The caller's attestation of integrity protection for a SOAP exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageIntegrity {
    /// The caller attests that the exchange is protected against modification.
    Protected,
    /// The caller did not attest integrity protection.
    Unattested,
}

/// The caller's attestation of confidentiality for a SOAP exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageConfidentiality {
    /// The caller attests that the exchange is confidential.
    Protected,
    /// The caller did not attest confidentiality.
    Unattested,
}

/// Channel protection attestations for one SOAP exchange.
///
/// The deployment handles TLS and HTTP authentication. Pass the properties
/// the deployment established for this exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoapChannel {
    authentication: PartyAuthentication,
    integrity: MessageIntegrity,
    confidentiality: MessageConfidentiality,
}

impl SoapChannel {
    /// Record the caller's attestations for the exchange.
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

    /// Set all three channel protection attestations to `Unattested`.
    pub fn unattested() -> Self {
        Self::new(
            PartyAuthentication::Unattested,
            MessageIntegrity::Unattested,
            MessageConfidentiality::Unattested,
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

    /// The mutual authentication attestation.
    pub fn authentication(self) -> PartyAuthentication {
        self.authentication
    }

    /// The integrity protection attestation.
    pub fn integrity(self) -> MessageIntegrity {
        self.integrity
    }

    /// The confidentiality attestation.
    pub fn confidentiality(self) -> MessageConfidentiality {
        self.confidentiality
    }

    /// Mutual authentication with integrity protection.
    pub(crate) fn authenticates_peer(self) -> bool {
        self.authentication == PartyAuthentication::Mutual
            && self.integrity == MessageIntegrity::Protected
    }
}

/// Outbound SOAP 1.1 request carrying one XML element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoapRequest {
    endpoint: EndpointUrl,
    envelope: String,
}

impl SoapRequest {
    /// Wrap the XML document element in a SOAP 1.1 request to `endpoint`.
    ///
    /// The payload can use any element name and namespace. Use a typed SAML
    /// operation such as [`crate::ServiceProvider::start_slo`] to construct a
    /// request for its protocol flow.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when `protocol_xml` cannot be parsed as a document
    /// with one root element under the default [`XmlLimits`]. A processing
    /// instruction inside the element returns [`SamlError::Xml`]. The
    /// constructor accepts and omits a leading XML declaration.
    pub fn try_new(endpoint: EndpointUrl, protocol_xml: &str) -> Result<Self, SamlError> {
        Ok(Self {
            endpoint,
            envelope: envelope(outbound_element(protocol_xml)?),
        })
    }

    /// URL the deployment POSTs this envelope to.
    pub fn endpoint(&self) -> &EndpointUrl {
        &self.endpoint
    }

    /// SOAP 1.1 envelope.
    pub fn envelope(&self) -> &str {
        &self.envelope
    }

    /// HTTP headers to send with the POST: `Content-Type`, `SOAPAction`,
    /// `Cache-Control`, and `Pragma`.
    pub fn headers(&self) -> &[HttpHeader] {
        REQUEST_HEADERS
    }
}

/// SOAP 1.1 response carrying one XML element.
///
/// The deployment returns [`Self::envelope`] as the HTTP 200 body of the SOAP
/// request it answers, with [`Self::headers`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoapResponse {
    envelope: String,
}

impl SoapResponse {
    /// Wrap the XML document element in a SOAP 1.1 response.
    ///
    /// The payload can use any element name and namespace. Use a typed SAML
    /// operation such as [`crate::IdentityProvider::respond_slo`] to construct a
    /// response for its protocol flow.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] for the XML input errors described by
    /// [`SoapRequest::try_new`].
    pub fn try_new(protocol_xml: &str) -> Result<Self, SamlError> {
        Ok(Self {
            envelope: envelope(outbound_element(protocol_xml)?),
        })
    }

    /// SOAP 1.1 envelope.
    pub fn envelope(&self) -> &str {
        &self.envelope
    }

    /// HTTP headers to send with the envelope: `Content-Type`,
    /// `Cache-Control`, and `Pragma`.
    pub fn headers(&self) -> &[HttpHeader] {
        RESPONSE_HEADERS
    }
}

/// One XML element read from a SOAP 1.1 body.
///
/// The element exposes its local name, namespace URI, and standalone XML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoapBodyElement {
    local_name: String,
    namespace: String,
    xml: String,
}

impl SoapBodyElement {
    /// Read the single element in a SOAP 1.1 body.
    ///
    /// The payload can use any element name and namespace. Use a typed receive
    /// operation such as [`crate::ServiceProvider::receive_slo`] to validate
    /// the SAML message for its protocol flow.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] for invalid XML under the default [`XmlLimits`],
    /// an envelope other than SOAP 1.1, or an envelope structure other than an
    /// optional `Header` followed by one `Body` with exactly one child element.
    /// A header entry addressed to this receiver with `mustUnderstand` set
    /// also returns an error.
    pub fn from_envelope(envelope: &str) -> Result<Self, SamlError> {
        let body = read_soap_body(envelope, XmlLimits::default())?;
        Ok(Self {
            local_name: body.local_name,
            namespace: body.namespace,
            xml: body.xml,
        })
    }

    /// Local name of the payload element.
    pub fn local_name(&self) -> &str {
        &self.local_name
    }

    /// Resolved namespace URI of the payload element, or an empty string if
    /// no namespace was resolved.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Standalone XML of the payload element with inherited namespace declarations.
    pub fn xml(&self) -> &str {
        &self.xml
    }
}

pub(crate) struct SoapBody {
    pub(crate) local_name: String,
    pub(crate) namespace: String,
    pub(crate) xml: String,
    message_start: usize,
}

impl SoapBody {
    pub(crate) fn verify_signature_if_present(
        &self,
        envelope: &str,
        message: &SamlElement,
        signing_certificates: &[String],
        hmac_secret: Option<&HmacSecret>,
        profile: XmlSignatureProfile,
    ) -> Result<(), SamlError> {
        if message
            .children
            .iter()
            .any(|child| child.is(namespace::DSIG, "Signature"))
        {
            let id = message
                .attr("ID")
                .ok_or(SamlError::SignedReferenceMismatch)?;
            verify_soap_body_signature(
                envelope,
                self.message_start,
                id,
                signing_certificates,
                hmac_secret,
                profile,
            )?;
        }
        Ok(())
    }
}

#[cfg(not(crypto))]
fn verify_soap_body_signature(
    _envelope: &str,
    _message_start: usize,
    _id: &str,
    _signing_certificates: &[String],
    _hmac_secret: Option<&HmacSecret>,
    _profile: XmlSignatureProfile,
) -> Result<(), SamlError> {
    Err(SamlError::Unsupported(
        "signature verification requires a crypto provider feature".into(),
    ))
}

/// Read the single XML element of a SOAP 1.1 body.
///
/// A locally addressed header entry with SOAP `mustUnderstand` set is refused.
pub(crate) fn read_soap_body(envelope: &str, limits: XmlLimits) -> Result<SoapBody, SamlError> {
    let document = dom::parse_document(envelope, limits)?;
    let scan = scan_envelope(envelope)?;
    let child_namespace = scan
        .child
        .ok_or_else(|| SamlError::xml("SOAP body must contain one SAML protocol element"))?;
    let child = single_element_child(envelope_body(&document.root)?)?;
    if child.local_name != child_namespace.local_name {
        return Err(SamlError::xml(
            "SOAP body element does not match its namespace declaration",
        ));
    }
    Ok(SoapBody {
        local_name: child.local_name.clone(),
        namespace: child_namespace.namespace,
        xml: standalone_element(envelope, child.start, child.end)?,
        message_start: child.start,
    })
}

pub(crate) fn read_soap_status_response(
    envelope: &str,
    limits: XmlLimits,
    schema_validator: Option<crate::SchemaValidator>,
    expected_body: &str,
    wrong_body_error: &str,
    request_id: &str,
) -> Result<(SoapBody, SamlElement), SamlError> {
    let body = read_soap_body(envelope, limits)?;
    crate::schema::validate(envelope, schema_validator)?;
    if body.local_name != expected_body || body.namespace != namespace::PROTOCOL {
        return Err(SamlError::ProtocolProfile(wrong_body_error.into()));
    }
    let response = parse_saml_with_limits(&body.xml, limits)?;
    if response.required_attr("Version")? != "2.0" {
        return Err(SamlError::ProtocolProfile(format!(
            "{expected_body} Version must be 2.0"
        )));
    }
    response.required_attr("ID")?;
    response.required_issue_instant()?;
    let in_response_to = response.attr("InResponseTo");
    if in_response_to != Some(request_id) {
        return Err(SamlError::in_response_to_mismatch(
            Some(request_id),
            in_response_to,
        ));
    }
    Ok((body, response))
}

/// The `Body` of an envelope whose children are an optional `Header` and one
/// `Body`.
fn envelope_body(envelope: &Node) -> Result<&Node, SamlError> {
    match envelope.children.as_slice() {
        [body] if body.local_name == "Body" => Ok(body),
        [header, body] if header.local_name == "Header" && body.local_name == "Body" => Ok(body),
        _ => Err(SamlError::ProtocolProfile(
            "SOAP envelope must contain an optional Header followed by one Body".into(),
        )),
    }
}

fn envelope(element_xml: &str) -> String {
    let mut writer = XmlWriter::new();
    writer.start("soap:Envelope", &[("xmlns:soap", SOAP_NAMESPACE)]);
    writer.start("soap:Body", &[]);
    writer.raw(element_xml);
    writer.end("soap:Body");
    writer.end("soap:Envelope");
    writer.finish()
}

fn outbound_element(xml: &str) -> Result<&str, SamlError> {
    let document = dom::parse_document(xml, XmlLimits::default())?;
    let element = xml
        .get(document.root.start..document.root.end)
        .ok_or_else(|| SamlError::xml("protocol element is incomplete"))?;
    reject_processing_instructions(element)?;
    Ok(element)
}

pub(crate) fn reject_processing_instructions(element_xml: &str) -> Result<(), SamlError> {
    let mut reader = Reader::from_str(element_xml);
    loop {
        match reader.read_event().map_err(xml_err)? {
            Event::PI(_) => {
                return Err(SamlError::xml(
                    "processing instructions are not allowed inside a SOAP payload",
                ));
            }
            Event::Eof => return Ok(()),
            Event::Start(_)
            | Event::End(_)
            | Event::Empty(_)
            | Event::Text(_)
            | Event::CData(_)
            | Event::Comment(_)
            | Event::Decl(_)
            | Event::DocType(_)
            | Event::GeneralRef(_) => {}
        }
    }
}

struct NamedNamespace {
    local_name: String,
    namespace: String,
}

fn single_element_child(body: &Node) -> Result<&Node, SamlError> {
    let mut children = body.children.iter();
    let child = children
        .next()
        .ok_or_else(|| SamlError::xml("SOAP body must contain one SAML protocol element"))?;
    if children.next().is_some() {
        return Err(SamlError::ProtocolProfile(
            "SOAP body must contain exactly one SAML protocol element".into(),
        ));
    }
    Ok(child)
}

fn scan_envelope(xml: &str) -> Result<SoapScan, SamlError> {
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
                return Err(SamlError::xml("DOCTYPE is not allowed"));
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(err) => return Err(reader_err(err)),
        }
        buf.clear();
    }

    if !scan.saw_envelope {
        return Err(SamlError::xml(
            "SOAP message must use the SOAP 1.1 envelope namespace",
        ));
    }
    Ok(scan)
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
            return Err(SamlError::xml(
                "SOAP message must use the SOAP 1.1 envelope namespace",
            ));
        }
        scan.saw_envelope = true;
        return Ok(());
    }

    if depth == 2 && scan.saw_envelope {
        if namespace != Some(SOAP_NAMESPACE) {
            return Err(SamlError::xml(
                "SOAP Header and Body must use the SOAP 1.1 namespace",
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
                return Err(SamlError::xml(
                    "SOAP envelope contains an element other than Header or Body",
                ));
            }
        }
        return Ok(());
    }

    if scan.in_header
        && depth == scan.header_depth + 1
        && requires_local_processing(reader, element)?
    {
        return Err(SamlError::xml(
            "SOAP header requires processing this responder does not provide",
        ));
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

/// Whether a header entry is addressed to this receiver, through no SOAP
/// `actor` or the `next` actor, and sets SOAP `mustUnderstand`.
fn requires_local_processing(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
) -> Result<bool, SamlError> {
    let mut must_understand = false;
    for attribute in element.attributes() {
        let attribute = attribute.map_err(xml_err)?;
        let (namespace, local_name) = reader.resolver().resolve_attribute(attribute.key);
        if !matches!(local_name.as_ref(), "actor" | "mustUnderstand") {
            continue;
        }
        let Some(uri) = bound_namespace(namespace) else {
            continue;
        };
        if quick_xml::escape::unescape(uri).map_err(xml_err)? != SOAP_NAMESPACE {
            continue;
        }
        let value = attribute
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map_err(xml_err)?;
        match local_name.as_ref() {
            "actor"
                if !matches!(
                    value.trim_matches([' ', '\t', '\r', '\n']),
                    "" | SOAP_ACTOR_NEXT
                ) =>
            {
                return Ok(false);
            }
            "mustUnderstand" if matches!(value.trim(), "1" | "true") => {
                must_understand = true;
            }
            _ => {}
        }
    }
    Ok(must_understand)
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
        let logout = r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_logout" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><!-- <?example?> --><NameID xmlns="urn:oasis:names:tc:SAML:2.0:assertion">user@example.com</NameID></samlp:LogoutRequest>"#;
        let xml = format!(r#"<?xml version="1.0"?><?before?>{logout}<?after?>"#);
        let endpoint = EndpointUrl::try_new("https://idp.example.com/logout")?;
        let request = SoapRequest::try_new(endpoint, &xml)?;
        let envelope = request.envelope();
        assert!(envelope.contains(logout));
        assert!(!envelope.contains("<?before?>"));
        assert!(!envelope.contains("<?after?>"));
        let message = SoapBodyElement::from_envelope(envelope)?;

        assert_eq!(message.local_name(), "LogoutRequest");
        assert_eq!(message.namespace(), "urn:oasis:names:tc:SAML:2.0:protocol");
        assert!(message.xml().contains("ID=\"_logout\""));
        Ok(())
    }

    #[test]
    fn soap_request_rejects_a_processing_instruction_in_the_payload() -> Result<(), SamlError> {
        let xml = r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_logout" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
            <?trace correlation="request-1"?>
            <NameID xmlns="urn:oasis:names:tc:SAML:2.0:assertion">user@example.com</NameID>
        </samlp:LogoutRequest>"#;
        let endpoint = EndpointUrl::try_new("https://idp.example.com/logout")?;
        let request = SoapRequest::try_new(endpoint, xml);
        assert!(matches!(request, Err(SamlError::Xml { .. })), "{request:?}");
        Ok(())
    }

    #[test]
    fn soap_response_rejects_a_processing_instruction_in_a_nested_element() {
        let xml = r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_response" InResponseTo="_logout" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
            <samlp:Status>
                <?trace correlation="request-1"?>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
            </samlp:Status>
        </samlp:LogoutResponse>"#;
        let response = SoapResponse::try_new(xml);
        assert!(
            matches!(response, Err(SamlError::Xml { .. })),
            "{response:?}"
        );
    }

    #[test]
    fn soap_body_rejects_a_second_element() {
        let envelope = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><samlp:One xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/><samlp:Two xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/></soap:Body></soap:Envelope>"#;
        assert!(matches!(
            SoapBodyElement::from_envelope(envelope),
            Err(SamlError::ProtocolProfile(_))
        ));
    }

    #[test]
    fn soap_header_must_understand_is_rejected() {
        let envelope = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" soap:mustUnderstand="1"/></soap:Header><soap:Body><samlp:ArtifactResolve xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/></soap:Body></soap:Envelope>"#;
        assert!(SoapBodyElement::from_envelope(envelope).is_err());
    }

    #[test]
    fn soap_header_padded_must_understand_is_rejected() {
        let envelope = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header><extra soap:mustUnderstand=" 1 ">note</extra></soap:Header><soap:Body><samlp:ArtifactResolve xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/></soap:Body></soap:Envelope>"#;
        assert!(matches!(
            SoapBodyElement::from_envelope(envelope),
            Err(SamlError::Xml { .. })
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
                    SoapBodyElement::from_envelope(&envelope),
                    Err(SamlError::ProtocolProfile(_))
                ),
                "{envelope}"
            );
        }
    }

    #[test]
    fn soap_body_keeps_namespaces_declared_on_the_envelope() -> Result<(), SamlError> {
        let envelope = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><soap:Body><samlp:LogoutRequest ID="_logout"/></soap:Body></soap:Envelope>"#;
        let message = SoapBodyElement::from_envelope(envelope)?;
        assert_eq!(
            message.xml(),
            r#"<samlp:LogoutRequest xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_logout"/>"#
        );
        Ok(())
    }

    #[test]
    fn soap_header_obligations_use_the_qualified_actor_and_must_understand() -> Result<(), SamlError>
    {
        for (attributes, mandatory_here) in [
            (r#"mustUnderstand="1""#, false),
            (r#"ext:mustUnderstand="1""#, false),
            (r#"s:actor="" s:mustUnderstand="1""#, true),
            (
                r#"xmlns:e="http://schemas.xmlsoap.org/soap/envelope&#47;" e:mustUnderstand="1""#,
                true,
            ),
            (
                r#"s:mustUnderstand="1" s:actor="urn:example:router""#,
                false,
            ),
            (
                r#"actor="urn:example:router" s:mustUnderstand="true""#,
                true,
            ),
            (
                r#"s:actor=" http://schemas.xmlsoap.org/soap/actor/next " s:mustUnderstand="1""#,
                true,
            ),
        ] {
            let envelope = format!(
                r#"<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ext="urn:example:headers"><Header><ext:Trace {attributes}/></Header><Body><LogoutRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol"/></Body></Envelope>"#
            );
            let result = SoapBodyElement::from_envelope(&envelope);
            if mandatory_here {
                assert!(matches!(result, Err(SamlError::Xml { .. })), "{attributes}");
            } else {
                assert_eq!(result?.local_name(), "LogoutRequest", "{attributes}");
            }
        }
        Ok(())
    }
}
