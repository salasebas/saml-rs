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
