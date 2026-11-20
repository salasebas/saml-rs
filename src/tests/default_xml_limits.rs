use saml_rs::constants::ParserType;
use saml_rs::context::is_valid_xml_with_limits;
use saml_rs::validator::check_status;
use saml_rs::xml::{extract, extract_with_limits};
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
        " ".repeat(XmlLimits::default().max_bytes)
    );
    let raised = XmlLimits {
        max_bytes: xml.len(),
        ..XmlLimits::default()
    };
    let defaults = [
        is_valid_xml_with_limits(&xml, saml_rs::XmlLimits::default()),
        check_status(&xml, ParserType::SamlResponse, XmlLimits::default()),
        extract(&xml, &[]).map(drop),
        saml_rs::xml::extract::extract(&xml, &[]).map(drop),
    ];
    for result in defaults {
        assert!(matches!(result, Err(SamlError::LimitExceeded { .. })));
    }
    is_valid_xml_with_limits(&xml, raised)?;
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
            max_nodes: 50_000,
            max_attributes_per_element: 64,
            max_attribute_value_bytes: 16_384,
            max_text_bytes: 1_048_576,
        }
    );
    assert_eq!(
        saml_rs::XmlPolicy::default().redirect_inflate_max_bytes,
        1_048_576
    );
}
