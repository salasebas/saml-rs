//! SOAP envelopes and the PAOS HTTP header for Enhanced Client/Proxy SSO.

use crate::error::SamlError;
use crate::model::RelayStateParam;
use crate::soap::{self, HeaderEntry, UnderstoodHeader};
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

/// Header entries the service provider processes on the PAOS response.
pub(super) const SP_UNDERSTOOD_HEADERS: &[UnderstoodHeader] = &[
    UnderstoodHeader {
        namespace: ECP_PROFILE,
        local_name: "RelayState",
    },
    UnderstoodHeader {
        namespace: PAOS_NS,
        local_name: "Response",
    },
];

pub(super) fn read_soap_body(
    envelope_xml: &str,
    element_name: &str,
    limits: XmlLimits,
    understood: &[UnderstoodHeader],
) -> Result<SoapBody, SamlError> {
    let body = soap::read_soap_body(envelope_xml, limits, understood)?;
    if body.local_name != element_name {
        return Err(SamlError::ProtocolProfile(format!(
            "SOAP body must contain one {element_name}"
        )));
    }
    if body.namespace != PROTOCOL_NS {
        return Err(SamlError::ProtocolProfile(format!(
            "SOAP body element must use the {PROTOCOL_NS} namespace"
        )));
    }
    Ok(SoapBody {
        relay_state: relay_state_header(&body.header)?,
        element_xml: body.xml,
    })
}

fn envelope(header_xml: &str, body_xml: &str) -> String {
    format!(
        "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\"><SOAP-ENV:Header>{header_xml}</SOAP-ENV:Header><SOAP-ENV:Body>{body_xml}</SOAP-ENV:Body></SOAP-ENV:Envelope>"
    )
}

fn relay_state_header(header: &[HeaderEntry]) -> Result<RelayStateParam, SamlError> {
    let relay_states: Vec<&HeaderEntry> = header
        .iter()
        .filter(|entry| entry.node.local_name == "RelayState")
        .collect();
    match relay_states.as_slice() {
        [] => Ok(RelayStateParam::absent()),
        [relay_state] if relay_state.namespace == ECP_PROFILE => {
            RelayStateParam::try_from_option(Some(relay_state.node.text.clone()))
        }
        [_] => Err(SamlError::ProtocolProfile(
            "RelayState header must use the ECP profile namespace".into(),
        )),
        _ => Err(SamlError::ProtocolProfile(
            "SOAP header must contain at most one RelayState".into(),
        )),
    }
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
        let ecp_understood = [
            UnderstoodHeader {
                namespace: PAOS_NS,
                local_name: "Request",
            },
            UnderstoodHeader {
                namespace: ECP_PROFILE,
                local_name: "Request",
            },
            UnderstoodHeader {
                namespace: ECP_PROFILE,
                local_name: "RelayState",
            },
        ];
        let body = read_soap_body(
            &envelope,
            "AuthnRequest",
            XmlLimits::default(),
            &ecp_understood,
        )?;
        assert_eq!(
            body.element_xml,
            format!(
                "<samlp:AuthnRequest xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:samlp=\"{PROTOCOL_NS}\" ID=\"_1\"></samlp:AuthnRequest>"
            )
        );
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
        let body = read_soap_body(
            &xml,
            "AuthnRequest",
            XmlLimits::default(),
            SP_UNDERSTOOD_HEADERS,
        )?;
        assert_eq!(body.relay_state.as_deref(), Some("state"));
        Ok(())
    }

    #[test]
    fn relay_state_in_another_namespace_is_rejected() -> Result<(), String> {
        let xml = format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:other=\"urn:example:other\" xmlns:samlp=\"{PROTOCOL_NS}\"><SOAP-ENV:Header><other:RelayState>state</other:RelayState></SOAP-ENV:Header><SOAP-ENV:Body><samlp:AuthnRequest ID=\"_1\"></samlp:AuthnRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>"
        );
        match read_soap_body(
            &xml,
            "AuthnRequest",
            XmlLimits::default(),
            SP_UNDERSTOOD_HEADERS,
        ) {
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
        match read_soap_body(
            &xml,
            "AuthnRequest",
            XmlLimits::default(),
            SP_UNDERSTOOD_HEADERS,
        ) {
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
        match read_soap_body(
            &xml,
            "AuthnRequest",
            XmlLimits::default(),
            SP_UNDERSTOOD_HEADERS,
        ) {
            Err(SamlError::Xml(_)) => Ok(()),
            Err(other) => Err(format!("expected Xml, got {other:?}")),
            Ok(_) => Err("expected Xml, got a SOAP body".into()),
        }
    }

    #[test]
    fn body_element_in_another_namespace_is_rejected() -> Result<(), String> {
        let xml = format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:other=\"urn:example:other\"><SOAP-ENV:Header/><SOAP-ENV:Body><other:Response ID=\"_1\"></other:Response></SOAP-ENV:Body></SOAP-ENV:Envelope>"
        );
        match read_soap_body(
            &xml,
            "Response",
            XmlLimits::default(),
            SP_UNDERSTOOD_HEADERS,
        ) {
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
            let body = read_soap_body(&xml, "Response", XmlLimits::default(), SP_UNDERSTOOD_HEADERS)?;
            assert!(body.element_xml.contains("ID=\"_1\""));
        }
        Ok(())
    }

    #[test]
    fn every_inherited_namespace_is_written_on_the_saml_element() -> Result<(), SamlError> {
        let xml = format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:samlp=\"urn:example:shadowed\" xmlns:unused=\"urn:example:unused\"><SOAP-ENV:Body xmlns:samlp=\"{PROTOCOL_NS}\" xmlns:saml='{ASSERTION_NS}'><samlp:Response ID=\"_1\"><saml:Issuer>idp</saml:Issuer></samlp:Response></SOAP-ENV:Body></SOAP-ENV:Envelope>"
        );
        let body = read_soap_body(
            &xml,
            "Response",
            XmlLimits::default(),
            SP_UNDERSTOOD_HEADERS,
        )?;
        assert_eq!(
            body.element_xml,
            format!(
                "<samlp:Response xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:unused=\"urn:example:unused\" xmlns:samlp=\"{PROTOCOL_NS}\" xmlns:saml=\"{ASSERTION_NS}\" ID=\"_1\"><saml:Issuer>idp</saml:Issuer></samlp:Response>"
            )
        );

        let xml = format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns=\"{PROTOCOL_NS}\"><SOAP-ENV:Body><Response ID=\"_1\"/></SOAP-ENV:Body></SOAP-ENV:Envelope>"
        );
        let body = read_soap_body(
            &xml,
            "Response",
            XmlLimits::default(),
            SP_UNDERSTOOD_HEADERS,
        )?;
        assert_eq!(
            body.element_xml,
            format!(
                "<Response xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns=\"{PROTOCOL_NS}\" ID=\"_1\"/>"
            )
        );
        Ok(())
    }

    #[test]
    fn extra_envelope_child_is_rejected() -> Result<(), String> {
        let xml = format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:samlp=\"{PROTOCOL_NS}\"><SOAP-ENV:Header/><SOAP-ENV:Body><samlp:Response ID=\"_1\"></samlp:Response></SOAP-ENV:Body><SOAP-ENV:Extra/></SOAP-ENV:Envelope>"
        );
        match read_soap_body(
            &xml,
            "Response",
            XmlLimits::default(),
            SP_UNDERSTOOD_HEADERS,
        ) {
            Err(SamlError::Xml(_)) => Ok(()),
            Err(other) => Err(format!("expected Xml, got {other:?}")),
            Ok(_) => Err("expected Xml, got a SOAP body".into()),
        }
    }

    #[test]
    fn duplicate_body_is_rejected() -> Result<(), String> {
        let xml = format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:samlp=\"{PROTOCOL_NS}\"><SOAP-ENV:Body><samlp:Response ID=\"_1\"></samlp:Response></SOAP-ENV:Body><SOAP-ENV:Body><samlp:Response ID=\"_2\"></samlp:Response></SOAP-ENV:Body></SOAP-ENV:Envelope>"
        );
        match read_soap_body(
            &xml,
            "Response",
            XmlLimits::default(),
            SP_UNDERSTOOD_HEADERS,
        ) {
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
        match read_soap_body(
            &xml,
            "Response",
            XmlLimits::default(),
            SP_UNDERSTOOD_HEADERS,
        ) {
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
        match read_soap_body(
            &xml,
            "Response",
            XmlLimits::default(),
            SP_UNDERSTOOD_HEADERS,
        ) {
            Err(SamlError::Xml(_)) => Ok(()),
            Err(other) => Err(format!("expected Xml, got {other:?}")),
            Ok(_) => Err("expected Xml, got a SOAP body".into()),
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
