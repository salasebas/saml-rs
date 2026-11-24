use super::*;

pub(super) fn xml_signature_evidence(
    session: &SsoSession,
) -> Vec<(&str, VerifiedXmlSignatureCoverage)> {
    session
        .verified_xml_signatures()
        .iter()
        .map(|signature| (signature.algorithm_uri(), signature.coverage()))
        .collect()
}

#[test]
fn a_bearer_attribute_assertion_before_authentication_does_not_hide_authentication(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::default(), false)?;
    let original = strip_embedded_signatures(&response_xml(&exchange.response_fields)?)?;
    let with_authentication_last = duplicate_assertion(&original, "_authentication")?;
    let start = with_authentication_last
        .find("<saml:AuthnStatement")
        .ok_or("missing first AuthnStatement")?;
    let close = "</saml:AuthnStatement>";
    let end = with_authentication_last[start..]
        .find(close)
        .ok_or("unterminated AuthnStatement")?;
    let mut xml = with_authentication_last;
    xml.replace_range(
        start..start + end + close.len(),
        concat!(
            r#"<saml:AttributeStatement><saml:Attribute Name="department">"#,
            "<saml:AttributeValue>engineering</saml:AttributeValue>",
            "</saml:Attribute></saml:AttributeStatement>",
        ),
    );
    let attributes_signed = sign_first_assertion(&xml, RSA_SHA384)?;
    let both_signed =
        sign_first_assertion(&move_last_assertion_first(&attributes_signed)?, RSA_SHA512)?;

    let session = accept(&exchange, &move_last_assertion_first(&both_signed)?)?;

    assert_eq!(session.authn_statements().len(), 1);
    assert_eq!(session.assertion_id().as_str(), "_authentication");
    assert_eq!(session.name_id().value(), "alice@example.com");
    assert_eq!(
        xml_signature_evidence(&session),
        [(RSA_SHA512, VerifiedXmlSignatureCoverage::ConsumedAssertion)]
    );
    Ok(())
}

#[test]
fn a_simplesign_response_reports_its_verified_embedded_assertion_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_simple_sign(SpValidationPolicy::default())?;
    let unsigned = strip_embedded_signatures(&response_xml(&exchange.response_fields)?)?;
    let signed = sign_first_assertion(&unsigned, RSA_SHA384)?;

    let session = accept_simple_sign(&exchange, &signed)?;

    assert_eq!(session.binding_signature_algorithm_uri(), Some(RSA_SHA256));
    assert_eq!(
        xml_signature_evidence(&session),
        [(RSA_SHA384, VerifiedXmlSignatureCoverage::ConsumedAssertion)]
    );
    Ok(())
}
