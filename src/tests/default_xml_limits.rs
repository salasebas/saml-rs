use saml_rs::constants::ParserType;
use saml_rs::validator::check_status;
use saml_rs::xml::dom::parse_document;
use saml_rs::xml::{extract, extract_with_limits};
use saml_rs::SamlError;
use saml_rs::XmlLimits;

#[test]
fn internal_parsers_enforce_xml_limits() -> Result<(), Box<dyn std::error::Error>> {
    let xml = format!(
        "<Response><Status><StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></Status>{}</Response>",
        " ".repeat(XmlLimits::default().max_bytes)
    );
    let raised = XmlLimits {
        max_bytes: xml.len(),
        ..XmlLimits::default()
    };
    let defaults = [
        parse_document(&xml, saml_rs::XmlLimits::default()).map(drop),
        check_status(&xml, ParserType::SamlResponse, XmlLimits::default()),
        extract(&xml, &[]).map(drop),
    ];
    for result in defaults {
        assert!(matches!(result, Err(SamlError::LimitExceeded { .. })));
    }
    parse_document(&xml, raised)?;
    check_status(&xml, ParserType::SamlResponse, raised)?;
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

#[test]
fn default_limits_are_the_documented_values() {
    assert_eq!(
        XmlLimits::default(),
        XmlLimits {
            max_bytes: 1_048_576,
            max_depth: 1_024,
            max_elements: 50_000,
            max_attributes_per_element: 64,
            max_attribute_value_bytes: 16_384,
            max_element_text_bytes: 1_048_576,
        }
    );
    assert_eq!(
        saml_rs::XmlPolicy::default().redirect_inflate_max_bytes,
        1_048_576
    );
}
