use std::borrow::Cow;

use super::deflate::deflate_raw_encode;
use super::encoding::encode_base64;
use super::query::ensure_endpoint_query_has_no_saml_parameter;
use crate::constants::namespace;
use crate::constants::ParserType;
use crate::error::SamlError;
use crate::xml::dom::{reader_err, XmlLimits};
use crate::xml::utf8_bom_len;
use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use quick_xml::NsReader;
use url::form_urlencoded::byte_serialize;

pub(crate) fn redirect_binding_query(
    saml_param: &str,
    b64_value: &str,
    relay_state: Option<&str>,
) -> String {
    let mut query = format!("{saml_param}=");
    query.extend(byte_serialize(b64_value.as_bytes()));
    if let Some(state) = relay_state {
        query.push_str("&RelayState=");
        query.extend(byte_serialize(state.as_bytes()));
    }
    query
}

/// Build a full unsigned HTTP-Redirect URL.
///
/// DEFLATE → base64 → url-encode the message and add it, with an optional
/// `RelayState`, to the query of `base_url`, after any existing query and
/// before any fragment.
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
    let encoded = encode_base64(&deflated);
    let query = redirect_binding_query(parser_type.query_param(), &encoded, relay_state);
    append_redirect_query(base_url, &query)
}

pub(crate) fn append_redirect_query(base_url: &str, query: &str) -> Result<String, SamlError> {
    let fragment_start = base_url.find('#').unwrap_or(base_url.len());
    let (before_fragment, fragment) = base_url.split_at(fragment_start);
    let separator = match before_fragment.split_once('?') {
        None => "?",
        Some((_, "")) => "",
        Some((_, endpoint_query)) => {
            ensure_endpoint_query_has_no_saml_parameter(endpoint_query)?;
            "&"
        }
    };
    Ok(format!("{before_fragment}{separator}{query}{fragment}"))
}

/// Build the octet string to sign for a signed HTTP-Redirect message.
///
/// Removes a direct child `ds:Signature` before raw DEFLATE. A nested
/// signature stays. Bindings §3.4.4.1.
#[cfg(any(crypto, test))]
pub(crate) fn build_redirect_octet(
    parser_type: ParserType,
    xml: &str,
    relay_state: Option<&str>,
    sig_alg: &str,
) -> Result<String, SamlError> {
    let xml = redirect_message_xml(xml, true)?;
    let deflated = deflate_raw_encode(xml.as_bytes())?;
    let encoded = encode_base64(&deflated);
    let mut octet = redirect_binding_query(parser_type.query_param(), &encoded, relay_state);
    octet.push_str("&SigAlg=");
    octet.extend(byte_serialize(sig_alg.as_bytes()));
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
    let bom_len = utf8_bom_len(xml);
    reader
        .resolver_mut()
        .set_max_namespace_bindings(limits.max_attributes_per_element);
    let mut depth = 0usize;
    let mut element_count = 0usize;
    let mut open_signature = None;
    let mut spans = Vec::new();

    loop {
        let tag = {
            let (resolved, event) = reader.read_resolved_event().map_err(reader_err)?;
            RedirectTag::from_event(&resolved, &event)
        };
        let end = bom_len + reader.buffer_position() as usize;
        match tag {
            RedirectTag::DocType => {
                return Err(SamlError::xml("DOCTYPE is not allowed"));
            }
            RedirectTag::Start { protocol_signature } => {
                limits.count_element(&mut element_count)?;
                if depth == 1 && protocol_signature {
                    open_signature = Some(element_start(xml, end)?);
                }
                depth = limits.checked_depth(depth)?;
            }
            RedirectTag::Empty { protocol_signature } => {
                limits.count_element(&mut element_count)?;
                if depth == 1 && protocol_signature {
                    let start = element_start(xml, end)?;
                    spans.push((start, end));
                }
            }
            RedirectTag::End => {
                if depth == 0 {
                    return Err(SamlError::xml(
                        "HTTP-Redirect XML ended an element that was not open",
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
        return Err(SamlError::xml(
            "HTTP-Redirect XML ended before its elements closed",
        ));
    }
    Ok(spans)
}

fn is_protocol_signature(resolved: &ResolveResult<'_>, local_name: &[u8]) -> bool {
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
    fn from_event(resolved: &ResolveResult<'_>, event: &Event<'_>) -> Self {
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

fn element_start(xml: &str, end: usize) -> Result<usize, SamlError> {
    xml.as_bytes()[..end]
        .iter()
        .rposition(|byte| *byte == b'<')
        .ok_or_else(|| SamlError::xml("HTTP-Redirect XML element has no start tag"))
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

#[cfg(any(crypto, test))]
pub(crate) fn append_signature(
    base_url: &str,
    octet: &str,
    signature_b64: &str,
) -> Result<String, SamlError> {
    let mut signed = format!("{octet}&Signature=");
    signed.extend(byte_serialize(signature_b64.as_bytes()));
    append_redirect_query(base_url, &signed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{decode_base64, deflate_raw_decode, MAX_DEFLATE_RAW_DECODE_BYTES};
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
        let inflated = deflate_raw_decode(&decode_base64(&v)?, MAX_DEFLATE_RAW_DECODE_BYTES)?;
        assert_eq!(String::from_utf8(inflated)?, REQUEST);
        let relay = parsed
            .query_pairs()
            .find(|(k, _)| k == "RelayState")
            .map(|(_, v)| v.into_owned());
        assert_eq!(relay.as_deref(), Some("state 1"));
        Ok(())
    }

    #[test]
    fn redirect_octet_preserves_encoded_bytes_and_parameter_order(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for (parser_type, param) in [
            (ParserType::SamlRequest, "SAMLRequest"),
            (ParserType::SamlResponse, "SAMLResponse"),
        ] {
            for (relay_state, relay_query) in [
                (None, ""),
                (Some(""), "&RelayState="),
                (Some("a b+c/&=%"), "&RelayState=a+b%2Bc%2F%26%3D%25"),
            ] {
                let octet = build_redirect_octet(
                    parser_type,
                    "<samlp:AuthnRequest/>",
                    relay_state,
                    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                )?;
                assert_eq!(
                    octet,
                    format!("{param}=sylOzM0psHIsLcnIC0otLE0tLtG3AwA%3D{relay_query}&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256")
                );
            }
        }
        Ok(())
    }

    #[test]
    fn redirect_parameters_join_the_query_before_any_fragment(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deflated = deflate_raw_encode(REQUEST.as_bytes())?;
        let query = redirect_binding_query("SAMLResponse", &encode_base64(&deflated), None);
        let octet = build_redirect_octet(ParserType::SamlResponse, REQUEST, None, "sig-alg")?;
        let signed = format!("{octet}&Signature=a%2Bb%3D");
        let acs = "https://sp.example.com/acs";
        let cases = [
            ("", "?", ""),
            ("?", "?", ""),
            ("?x=1", "?x=1&", ""),
            ("#f", "?", "#f"),
            ("?#f", "?", "#f"),
            ("?x=1#f?y", "?x=1&", "#f?y"),
        ];
        for (base_suffix, query_prefix, fragment) in cases {
            let base = format!("{acs}{base_suffix}");
            let before = format!("{acs}{query_prefix}");
            let unsigned = build_redirect_url(&base, ParserType::SamlResponse, REQUEST, None)?;
            assert_eq!(unsigned, format!("{before}{query}{fragment}"), "{base}");
            assert_eq!(
                append_signature(&base, &octet, "a+b=")?,
                format!("{before}{signed}{fragment}"),
                "{base}"
            );
        }
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
        let inflated = String::from_utf8(deflate_raw_decode(
            &decode_base64(&encoded)?,
            MAX_DEFLATE_RAW_DECODE_BYTES,
        )?)?;
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
        let inflated_with_bom = String::from_utf8(deflate_raw_decode(
            &decode_base64(&encoded)?,
            MAX_DEFLATE_RAW_DECODE_BYTES,
        )?)?;
        assert_eq!(inflated_with_bom, format!("\u{feff}{inflated}"));
        Ok(())
    }
}
