use saml_rs::constants::ParserType;
use saml_rs::context::is_valid_xml_with_limits;
use saml_rs::validator::{check_status, check_status_with_limits};
use saml_rs::xml::{dom::DEFAULT_XML_MAX_BYTES, extract, extract_with_limits};
use saml_rs::SamlError;
use saml_rs::XmlLimits;

#[cfg_attr(
    crypto,
    expect(deprecated, reason = "pins the deprecated signature verifiers")
)]
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
        is_valid_xml_with_limits(&xml, saml_rs::XmlLimits::default()),
        check_status(&xml, ParserType::SamlResponse),
        extract(&xml, &[]).map(drop),
        saml_rs::xml::extract::extract(&xml, &[]).map(drop),
    ];
    for result in defaults {
        assert!(matches!(result, Err(SamlError::LimitExceeded { .. })));
    }
    is_valid_xml_with_limits(&xml, raised)?;
    check_status_with_limits(&xml, ParserType::SamlResponse, raised)?;
    extract_with_limits(&xml, &[], raised)?;

    #[cfg(crypto)]
    {
        use saml_rs::crypto::{verify_signature, verify_signature_with_limits};

        assert!(matches!(
            verify_signature(&xml, &[]),
            Err(SamlError::LimitExceeded { .. })
        ));
        assert_eq!(
            verify_signature_with_limits(&xml, &[], raised)?,
            (false, None)
        );
    }
    Ok(())
}
