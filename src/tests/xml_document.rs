use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::binding::deflate_raw_encode;
use saml_rs::constants::{Binding, ParserType};
use saml_rs::flow::{FlowOptions, HttpRequest};
use saml_rs::tests::engine::flow;
use saml_rs::tests::engine::redirect_query;
use saml_rs::SamlError;

const AUTHN_REQUEST: &str = concat!(
    "<samlp:AuthnRequest ",
    "xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ",
    "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ",
    "ID=\"_request\" Version=\"2.0\" IssueInstant=\"2026-01-01T00:00:00Z\">",
    "<saml:Issuer>https://sp.example.com/metadata</saml:Issuer>",
    "</samlp:AuthnRequest>",
);

fn options(binding: Binding) -> FlowOptions<'static> {
    FlowOptions::new(binding, ParserType::SamlRequest)
}

fn post_request(xml: &str) -> HttpRequest {
    HttpRequest::post(vec![(
        "SAMLRequest".to_string(),
        STANDARD.encode(xml.as_bytes()),
    )])
}

fn redirect_request(xml: &str) -> Result<HttpRequest, SamlError> {
    let compressed = deflate_raw_encode(xml.as_bytes())?;
    Ok(redirect_query(vec![(
        "SAMLRequest".to_string(),
        STANDARD.encode(&compressed),
    )]))
}

fn assert_multiple_document_elements(error: SamlError) {
    assert!(matches!(
        error,
        SamlError::Xml { message, .. } if message == "multiple document elements"
    ));
}

#[test]
fn post_flow_rejects_multiple_document_elements() -> Result<(), Box<dyn std::error::Error>> {
    let xml = format!("{AUTHN_REQUEST}<garbage/>");
    let error = flow(&options(Binding::Post), &post_request(&xml))
        .err()
        .ok_or("POST flow unexpectedly accepted multiple document elements")?;

    assert_multiple_document_elements(error);
    Ok(())
}

#[test]
fn redirect_flow_rejects_multiple_document_elements() -> Result<(), Box<dyn std::error::Error>> {
    let xml = format!("{AUTHN_REQUEST}<garbage/>");
    let error = flow(&options(Binding::Redirect), &redirect_request(&xml)?)
        .err()
        .ok_or("Redirect flow unexpectedly accepted multiple document elements")?;

    assert_multiple_document_elements(error);
    Ok(())
}

#[test]
fn post_flow_accepts_xml_misc_around_document_element() -> Result<(), Box<dyn std::error::Error>> {
    let xml = format!(
        "<?xml version=\"1.0\"?>\n<!-- before --><?before allowed?>{AUTHN_REQUEST}<?after allowed?><!-- after -->"
    );

    flow(&options(Binding::Post), &post_request(&xml))?;
    Ok(())
}
