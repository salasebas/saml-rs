use saml_rs::binding::{
    base64_decode, build_redirect_octet, build_redirect_url, deflate_raw_decode,
};
use saml_rs::constants::ParserType;
use saml_rs::xml::XmlLimits;
use saml_rs::SamlError;

const ENDPOINT: &str = "https://idp.example.com/sso";
const ROOT: &str = "<r xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">";
const SIGNATURE_ERROR: &str =
    "HTTP-Redirect must remove a protocol XML signature and attach a detached signature";

fn assert_limit(result: Result<String, SamlError>, limit: &str, max: usize) {
    let expected = format!("ERR_XML_LIMIT_EXCEEDED: max XML {limit} exceeded ({max})");
    assert!(
        matches!(&result, Err(SamlError::Invalid(message)) if message == &expected),
        "expected Invalid({expected:?}), got {result:?}"
    );
}

fn decode_request(query: &str) -> Result<String, Box<dyn std::error::Error>> {
    let encoded = url::form_urlencoded::parse(query.as_bytes())
        .find(|(name, _)| name == "SAMLRequest")
        .map(|(_, value)| value.into_owned())
        .ok_or("missing SAMLRequest")?;
    Ok(String::from_utf8(deflate_raw_decode(&base64_decode(
        &encoded,
    )?)?)?)
}

#[test]
fn redirect_byte_limit_accepts_boundary_and_precedes_node_depth_and_signature_errors(
) -> Result<(), Box<dyn std::error::Error>> {
    let limits = XmlLimits::default();
    let xml = format!(
        "<r>{}é</r>",
        " ".repeat(limits.max_bytes - "<r>é</r>".len())
    );
    assert_eq!(xml.len(), limits.max_bytes);
    let url = build_redirect_url(ENDPOINT, ParserType::SamlRequest, &xml, None)?;
    let parsed = url::Url::parse(&url)?;
    assert_eq!(decode_request(parsed.query().ok_or("missing query")?)?, xml);
    let octet = build_redirect_octet(ParserType::SamlRequest, &xml, None, "sig-alg")?;
    assert_eq!(decode_request(&octet)?, xml);

    let over_boundary = xml.replacen('é', "é ", 1);
    let competing_limits = format!(
        "{ROOT}<ds:Signature/>{}{}{}</r>",
        "<n/>".repeat(limits.max_nodes),
        "<n>".repeat(limits.max_depth),
        "</n>".repeat(limits.max_depth),
    );
    let competing_limits = format!(
        "{}{}",
        " ".repeat(limits.max_bytes + 1 - competing_limits.len()),
        competing_limits,
    );
    for xml in [over_boundary, competing_limits] {
        assert_eq!(xml.len(), limits.max_bytes + 1);
        for result in [
            build_redirect_url(ENDPOINT, ParserType::SamlRequest, &xml, None),
            build_redirect_octet(ParserType::SamlRequest, &xml, None, "sig-alg"),
        ] {
            assert_limit(result, "bytes", limits.max_bytes);
        }
    }
    Ok(())
}

#[test]
fn redirect_node_limit_counts_start_and_empty_elements() -> Result<(), Box<dyn std::error::Error>> {
    let limits = XmlLimits::default();
    for element in ["<n/>", "<n></n>"] {
        let content = element.repeat(limits.max_nodes - 1);
        let xml = format!("<r>text&amp;<![CDATA[data]]><!--comment--><?p value?>{content}</r>");
        for result in [
            build_redirect_url(ENDPOINT, ParserType::SamlRequest, &xml, None),
            build_redirect_octet(ParserType::SamlRequest, &xml, None, "sig-alg"),
        ] {
            result?;
        }
        let xml = format!("<r>{content}{element}</r>");
        for result in [
            build_redirect_url(ENDPOINT, ParserType::SamlRequest, &xml, None),
            build_redirect_octet(ParserType::SamlRequest, &xml, None, "sig-alg"),
        ] {
            assert_limit(result, "nodes", limits.max_nodes);
        }
    }
    Ok(())
}

#[test]
fn redirect_depth_limit_counts_open_elements_but_not_empty_elements(
) -> Result<(), Box<dyn std::error::Error>> {
    let limits = XmlLimits::default();
    for leaf in ["", "<leaf/>"] {
        let xml = format!(
            "{}{leaf}{}",
            "<n>".repeat(limits.max_depth),
            "</n>".repeat(limits.max_depth),
        );
        for result in [
            build_redirect_url(ENDPOINT, ParserType::SamlRequest, &xml, None),
            build_redirect_octet(ParserType::SamlRequest, &xml, None, "sig-alg"),
        ] {
            result?;
        }
        let xml = format!("<n>{xml}</n>");
        for result in [
            build_redirect_url(ENDPOINT, ParserType::SamlRequest, &xml, None),
            build_redirect_octet(ParserType::SamlRequest, &xml, None, "sig-alg"),
        ] {
            assert_limit(result, "depth", limits.max_depth);
        }
    }
    Ok(())
}

#[test]
fn redirect_node_limit_includes_detached_signature_subtree(
) -> Result<(), Box<dyn std::error::Error>> {
    let limits = XmlLimits::default();
    for element in ["<n/>", "<n></n>"] {
        let content = element.repeat(limits.max_nodes - 2);
        let xml = format!("{ROOT}<ds:Signature>{content}</ds:Signature></r>");
        let octet = build_redirect_octet(ParserType::SamlRequest, &xml, None, "sig-alg")?;
        assert_eq!(decode_request(&octet)?, format!("{ROOT}</r>"));
        let unsigned = build_redirect_url(ENDPOINT, ParserType::SamlRequest, &xml, None);
        assert!(
            matches!(unsigned, Err(SamlError::ProtocolProfile(message)) if message == SIGNATURE_ERROR)
        );

        let xml = format!("{ROOT}<ds:Signature>{content}{element}</ds:Signature></r>");
        for result in [
            build_redirect_url(ENDPOINT, ParserType::SamlRequest, &xml, None),
            build_redirect_octet(ParserType::SamlRequest, &xml, None, "sig-alg"),
        ] {
            assert_limit(result, "nodes", limits.max_nodes);
        }
    }
    Ok(())
}

#[test]
fn redirect_depth_limit_includes_detached_signature_subtree(
) -> Result<(), Box<dyn std::error::Error>> {
    let limits = XmlLimits::default();
    let content = format!(
        "{}<leaf/>{}",
        "<n>".repeat(limits.max_depth - 2),
        "</n>".repeat(limits.max_depth - 2),
    );
    let xml = format!("{ROOT}<ds:Signature>{content}</ds:Signature></r>");
    let octet = build_redirect_octet(ParserType::SamlRequest, &xml, None, "sig-alg")?;
    assert_eq!(decode_request(&octet)?, format!("{ROOT}</r>"));
    let unsigned = build_redirect_url(ENDPOINT, ParserType::SamlRequest, &xml, None);
    assert!(
        matches!(unsigned, Err(SamlError::ProtocolProfile(message)) if message == SIGNATURE_ERROR)
    );

    let xml = format!("{ROOT}<ds:Signature><n>{content}</n></ds:Signature></r>");
    for result in [
        build_redirect_url(ENDPOINT, ParserType::SamlRequest, &xml, None),
        build_redirect_octet(ParserType::SamlRequest, &xml, None, "sig-alg"),
    ] {
        assert_limit(result, "depth", limits.max_depth);
    }
    Ok(())
}

#[test]
fn redirect_node_limit_precedes_depth_limit() {
    let limits = XmlLimits::default();
    let xml = format!(
        "<r>{}{}{}</r>",
        "<n/>".repeat(limits.max_nodes - limits.max_depth),
        "<n>".repeat(limits.max_depth),
        "</n>".repeat(limits.max_depth),
    );
    for result in [
        build_redirect_url(ENDPOINT, ParserType::SamlRequest, &xml, None),
        build_redirect_octet(ParserType::SamlRequest, &xml, None, "sig-alg"),
    ] {
        assert_limit(result, "nodes", limits.max_nodes);
    }
}
