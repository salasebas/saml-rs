use super::*;

#[test]
fn repeated_authn_context_is_rejected_without_a_schema_validator(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::default(), false)?;
    let xml = response_xml(&exchange.response_fields)?.replace(
        "</saml:AuthnContext>",
        "</saml:AuthnContext><saml:AuthnContext><saml:AuthnContextClassRef>urn:example:password</saml:AuthnContextClassRef></saml:AuthnContext>",
    );
    expect_error(accept(&exchange, &resigned(&xml)?), |err| {
        matches!(err, SamlError::ProtocolProfile(_))
    })
}

#[test]
fn browser_sso_rejects_a_statement_missing_authn_context_without_a_schema_validator(
) -> Result<(), Box<dyn std::error::Error>> {
    for unsolicited in [false, true] {
        let exchange = exchange_for(SpValidationPolicy::default(), unsolicited)?;
        let xml = response_xml(&exchange.response_fields)?;
        let start = xml
            .find("<saml:AuthnContext>")
            .ok_or("missing AuthnContext")?;
        let end_tag = "</saml:AuthnContext>";
        let end = xml[start..]
            .find(end_tag)
            .ok_or("unterminated AuthnContext")?
            + start
            + end_tag.len();
        let mut omitted = xml.clone();
        omitted.replace_range(start..end, "");
        expect_error(accept(&exchange, &resigned(&omitted)?), |err| {
            matches!(err, SamlError::ProtocolProfile(_))
        })?;
    }
    Ok(())
}
