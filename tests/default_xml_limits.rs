use saml_rs::constants::ParserType;
use saml_rs::context::{is_valid_xml, is_valid_xml_with_limits};
use saml_rs::validator::{check_status, check_status_with_limits};
use saml_rs::xml::{dom::DEFAULT_XML_MAX_BYTES, extract, extract_with_limits, XmlLimits};
use saml_rs::SamlError;

#[test]
fn raw_conveniences_enforce_default_xml_limits() -> Result<(), Box<dyn std::error::Error>> {
    let xml = format!(
        "<Response><Status><StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></Status>{}</Response>",
        " ".repeat(DEFAULT_XML_MAX_BYTES)
    );
    let raised = XmlLimits {
        max_bytes: xml.len(),
        ..XmlLimits::default()
    };
    let defaults = [
        is_valid_xml(&xml),
        check_status(&xml, ParserType::SamlResponse),
        extract(&xml, &[]).map(drop),
        saml_rs::xml::extract::extract(&xml, &[]).map(drop),
    ];
    for result in defaults {
        assert!(
            matches!(result, Err(SamlError::Invalid(detail)) if detail.contains("ERR_XML_LIMIT_EXCEEDED"))
        );
    }
    is_valid_xml_with_limits(&xml, raised)?;
    check_status_with_limits(&xml, ParserType::SamlResponse, raised)?;
    extract_with_limits(&xml, &[], raised)?;

    #[cfg(crypto)]
    {
        use saml_rs::crypto::{verify_signature, verify_signature_with_limits};

        assert!(
            matches!(verify_signature(&xml, &[]), Err(SamlError::Invalid(detail)) if detail.contains("ERR_XML_LIMIT_EXCEEDED"))
        );
        assert_eq!(
            verify_signature_with_limits(&xml, &[], raised)?,
            (false, None)
        );
    }
    Ok(())
}
