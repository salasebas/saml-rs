//! HTTP-Redirect binding query construction.

use std::borrow::Cow;

use super::deflate::deflate_raw_encode;
use super::encoding::base64_encode;
use crate::constants::namespace;
use crate::constants::ParserType;
use crate::error::SamlError;
use crate::xml::dom::XmlLimits;
use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use quick_xml::NsReader;
use url::form_urlencoded::byte_serialize;

fn url_encode(value: &str) -> String {
    byte_serialize(value.as_bytes()).collect()
}

fn has_query(base_url: &str) -> bool {
    base_url
        .split_once('?')
        .map(|(_, q)| !q.is_empty())
        .unwrap_or(false)
}

/// Build the unsigned query string for the SAML HTTP-Redirect binding.
///
/// `saml_param` is `SAMLRequest` or `SAMLResponse`; `b64_value` is the
/// base64-encoded, raw-DEFLATEd message. For a signed redirect, append
/// `&SigAlg=<uri>&Signature=<b64>` computed over this encoded query (M2).
pub fn redirect_binding_query(
    saml_param: &str,
    b64_value: &str,
    relay_state: Option<&str>,
) -> String {
    let value = url_encode(b64_value);
    let mut query = format!("{saml_param}={value}");
    if let Some(state) = relay_state {
        let state = url_encode(state);
        query.push_str(&format!("&RelayState={state}"));
    }
    query
}

/// Build a full unsigned HTTP-Redirect URL.
///
/// DEFLATE → base64 → url-encode the message, choose `?`/`&` based on whether
/// `base_url` already carries a query, and append an optional `RelayState`.
///
/// Rejects a direct child `ds:Signature` on the protocol root. Bindings §3.4.4.1.
pub fn build_redirect_url(
    base_url: &str,
    parser_type: ParserType,
    xml: &str,
    relay_state: Option<&str>,
) -> Result<String, SamlError> {
    let xml = redirect_message_xml(xml, false)?;
    let deflated = deflate_raw_encode(xml.as_bytes())?;
    let encoded = base64_encode(&deflated);
    let query = redirect_binding_query(parser_type.query_param(), &encoded, relay_state);
    Ok(append_redirect_query(base_url, &query))
}

/// Append an encoded query to `base_url`, after any query it already has.
pub(crate) fn append_redirect_query(base_url: &str, query: &str) -> String {
    let separator = if has_query(base_url) { '&' } else { '?' };
    format!("{base_url}{separator}{query}")
}

/// Build the octet string to sign for a signed HTTP-Redirect message.
///
/// Removes a direct child `ds:Signature` before raw DEFLATE. A nested
/// signature stays. Bindings §3.4.4.1.
pub fn build_redirect_octet(
    parser_type: ParserType,
    xml: &str,
    relay_state: Option<&str>,
    sig_alg: &str,
) -> Result<String, SamlError> {
    let xml = redirect_message_xml(xml, true)?;
    let deflated = deflate_raw_encode(xml.as_bytes())?;
    let encoded = base64_encode(&deflated);
    let mut octet = format!("{}={}", parser_type.query_param(), url_encode(&encoded));
    if let Some(state) = relay_state {
        octet.push_str(&format!("&RelayState={}", url_encode(state)));
    }
    octet.push_str(&format!("&SigAlg={}", url_encode(sig_alg)));
    Ok(octet)
}

fn redirect_message_xml(xml: &str, detach_signature: bool) -> Result<Cow<'_, str>, SamlError> {
    let spans = protocol_signature_spans(xml)?;
    if spans.is_empty() {
        return Ok(Cow::Borrowed(xml));
    }
    if !detach_signature {
        return Err(SamlError::ProtocolProfile(
            "HTTP-Redirect must remove a protocol XML signature and attach a detached signature"
                .into(),
        ));
    }
    Ok(Cow::Owned(remove_spans(xml, &spans)))
}

fn protocol_signature_spans(xml: &str) -> Result<Vec<(usize, usize)>, SamlError> {
    let limits = XmlLimits::default();
    limits.check_input_bytes(xml.len())?;
    let mut reader = NsReader::from_str(xml);
    reader
        .resolver_mut()
        .set_max_namespace_bindings(limits.max_attributes_per_element);
    let mut depth = 0usize;
    let mut nodes = 0usize;
    let mut open_signature = None;
    let mut spans = Vec::new();

    loop {
        let tag = {
            let (resolved, event) = reader
                .read_resolved_event()
                .map_err(|error| SamlError::Xml(error.to_string()))?;
            RedirectTag::from_event(resolved, &event)
        };
        let end = reader.buffer_position() as usize;
        match tag {
            RedirectTag::DocType => {
                return Err(SamlError::Xml("DOCTYPE is not allowed".into()));
            }
            RedirectTag::Start { protocol_signature } => {
                count_element(&mut nodes, limits)?;
                if depth == 1 && protocol_signature {
                    open_signature = Some(element_start(xml, end)?);
                }
                depth = checked_depth(depth, limits)?;
            }
            RedirectTag::Empty { protocol_signature } => {
                count_element(&mut nodes, limits)?;
                if depth == 1 && protocol_signature {
                    let start = element_start(xml, end)?;
                    spans.push((start, end));
                }
            }
            RedirectTag::End => {
                if depth == 0 {
                    return Err(SamlError::Xml(
                        "HTTP-Redirect XML ended an element that was not open".into(),
                    ));
                }
                depth -= 1;
                if depth == 1 {
                    if let Some(start) = open_signature.take() {
                        spans.push((start, end));
                    }
                }
            }
            RedirectTag::Eof => break,
            RedirectTag::Other => {}
        }
    }
    if open_signature.is_some() || depth != 0 {
        return Err(SamlError::Xml(
            "HTTP-Redirect XML ended before its elements closed".into(),
        ));
    }
    Ok(spans)
}

fn is_protocol_signature(resolved: ResolveResult<'_>, local_name: &[u8]) -> bool {
    local_name == b"Signature"
        && matches!(resolved, ResolveResult::Bound(value) if value.into_inner() == namespace::DSIG)
}

enum RedirectTag {
    Start { protocol_signature: bool },
    Empty { protocol_signature: bool },
    End,
    DocType,
    Eof,
    Other,
}

impl RedirectTag {
    fn from_event(resolved: ResolveResult<'_>, event: &Event<'_>) -> Self {
        match event {
            Event::DocType(_) => Self::DocType,
            Event::Start(element) => Self::Start {
                protocol_signature: is_protocol_signature(
                    resolved,
                    element.local_name().into_inner().as_bytes(),
                ),
            },
            Event::Empty(element) => Self::Empty {
                protocol_signature: is_protocol_signature(
                    resolved,
                    element.local_name().into_inner().as_bytes(),
                ),
            },
            Event::End(_) => Self::End,
            Event::Eof => Self::Eof,
            Event::Decl(_)
            | Event::Text(_)
            | Event::CData(_)
            | Event::Comment(_)
            | Event::PI(_)
            | Event::GeneralRef(_) => Self::Other,
        }
    }
}

fn count_element(nodes: &mut usize, limits: XmlLimits) -> Result<(), SamlError> {
    *nodes = nodes
        .checked_add(1)
        .ok_or_else(|| xml_limit("max XML nodes", limits.max_nodes))?;
    if *nodes > limits.max_nodes {
        return Err(xml_limit("max XML nodes", limits.max_nodes));
    }
    Ok(())
}

fn checked_depth(depth: usize, limits: XmlLimits) -> Result<usize, SamlError> {
    let depth = depth
        .checked_add(1)
        .ok_or_else(|| xml_limit("max XML depth", limits.max_depth))?;
    if depth > limits.max_depth {
        return Err(xml_limit("max XML depth", limits.max_depth));
    }
    Ok(depth)
}

fn xml_limit(limit: &str, max: usize) -> SamlError {
    SamlError::Invalid(format!("ERR_XML_LIMIT_EXCEEDED: {limit} exceeded ({max})"))
}

fn element_start(xml: &str, end: usize) -> Result<usize, SamlError> {
    xml.as_bytes()[..end]
        .iter()
        .rposition(|byte| *byte == b'<')
        .ok_or_else(|| SamlError::Xml("HTTP-Redirect XML element has no start tag".into()))
}

fn remove_spans(xml: &str, spans: &[(usize, usize)]) -> String {
    let mut rewritten = String::with_capacity(xml.len());
    let mut cursor = 0usize;
    for &(start, end) in spans {
        rewritten.push_str(&xml[cursor..start]);
        cursor = end;
    }
    rewritten.push_str(&xml[cursor..]);
    rewritten
}

/// Finish a signed HTTP-Redirect URL: `base_url[?&]<octet>&Signature=<enc(sig)>`.
pub fn append_signature(base_url: &str, octet: &str, signature_b64: &str) -> String {
    let separator = if has_query(base_url) { '&' } else { '?' };
    format!(
        "{base_url}{separator}{octet}&Signature={}",
        url_encode(signature_b64)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{base64_decode, deflate_raw_decode, saml_post_binding_form};
    use url::Url;

    const REQUEST: &str = "<samlp:AuthnRequest ID=\"_1\">hi&amp;bye</samlp:AuthnRequest>";

    #[test]
    fn redirect_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let url = build_redirect_url(
            "https://idp.example.com/sso",
            ParserType::SamlRequest,
            REQUEST,
            Some("state 1"),
        )?;
        assert!(url.starts_with("https://idp.example.com/sso?SAMLRequest="));
        let parsed = Url::parse(&url)?;
        let mut pairs = parsed.query_pairs();
        let (k, v) = pairs.next().ok_or("missing SAMLRequest")?;
        assert_eq!(k, "SAMLRequest");
        let inflated = deflate_raw_decode(&base64_decode(&v)?)?;
        assert_eq!(String::from_utf8(inflated)?, REQUEST);
        let relay = parsed
            .query_pairs()
            .find(|(k, _)| k == "RelayState")
            .map(|(_, v)| v.into_owned());
        assert_eq!(relay.as_deref(), Some("state 1"));
        Ok(())
    }

    #[test]
    fn redirect_uses_amp_when_base_has_query() -> Result<(), Box<dyn std::error::Error>> {
        let url = build_redirect_url(
            "http://sp.example.com/acs?x=1",
            ParserType::SamlResponse,
            REQUEST,
            None,
        )?;
        assert!(url.contains("?x=1&SAMLResponse="));
        Ok(())
    }

    #[test]
    fn post_and_simplesign_base64_message() -> Result<(), Box<dyn std::error::Error>> {
        // POST / SimpleSign carry base64(xml) verbatim (no DEFLATE)
        let b64 = base64_encode(REQUEST.as_bytes());
        assert_eq!(String::from_utf8(base64_decode(&b64)?)?, REQUEST);
        let form = saml_post_binding_form(
            "https://idp.example.com/sso",
            ParserType::SamlRequest.query_param(),
            &b64,
            None,
        );
        assert!(form.contains("name=\"SAMLRequest\""));
        assert!(form.contains(&b64));
        Ok(())
    }

    #[test]
    fn redirect_removes_only_a_protocol_signature_before_deflate(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let xml = r#"
            <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:Signature>
                    <ds:SignatureValue>protocol-signature</ds:SignatureValue>
                </ds:Signature>
                <saml:Assertion>
                    <ds:Signature>
                        <ds:SignatureValue>assertion-signature</ds:SignatureValue>
                    </ds:Signature>
                </saml:Assertion>
            </samlp:AuthnRequest>
        "#;
        let unsigned = build_redirect_url(
            "https://idp.example.com/sso",
            ParserType::SamlRequest,
            xml,
            None,
        );
        assert!(
            matches!(unsigned, Err(SamlError::ProtocolProfile(message)) if message.contains("HTTP-Redirect"))
        );

        let octet = build_redirect_octet(ParserType::SamlRequest, xml, Some("state"), "sig-alg")?;
        let encoded = url::form_urlencoded::parse(octet.as_bytes())
            .find(|(name, _)| name == "SAMLRequest")
            .map(|(_, value)| value.into_owned())
            .ok_or("missing encoded request")?;
        let inflated = String::from_utf8(deflate_raw_decode(&base64_decode(&encoded)?)?)?;
        assert!(!inflated.contains("protocol-signature"));
        assert!(inflated.contains("assertion-signature"));
        assert!(octet.contains("&RelayState=state&SigAlg=sig-alg"));

        let with_bom = format!("\u{feff}{xml}");
        let octet =
            build_redirect_octet(ParserType::SamlRequest, &with_bom, Some("state"), "sig-alg")?;
        let encoded = url::form_urlencoded::parse(octet.as_bytes())
            .find(|(name, _)| name == "SAMLRequest")
            .map(|(_, value)| value.into_owned())
            .ok_or("missing encoded request")?;
        let inflated = String::from_utf8(deflate_raw_decode(&base64_decode(&encoded)?)?)?;
        crate::xml::dom::parse(&inflated)?;
        assert!(!inflated.contains("protocol-signature"));
        assert!(inflated.contains("assertion-signature"));
        Ok(())
    }
}
