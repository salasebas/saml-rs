use super::*;
use saml_rs::XmlPolicy;

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

const SCHEMA_REJECTION: &str = "schema rejected repeated SubjectLocality";
const REPEATED_LOCALITY: &str = "AuthnStatement has more than one SubjectLocality";

fn with_repeated_subject_locality(xml: &str) -> String {
    xml.replace(
        "<saml:AuthnContext>",
        r#"<saml:SubjectLocality Address="192.0.2.1"/><saml:SubjectLocality Address="192.0.2.2"/><saml:AuthnContext>"#,
    )
}

#[test]
fn repeated_subject_locality_is_rejected_without_a_schema_validator(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::default(), false)?;
    let xml = with_repeated_subject_locality(&response_xml(&exchange.response_fields)?);
    expect_error(
        accept(&exchange, &resigned(&xml)?),
        |err| matches!(err, SamlError::ProtocolProfile(message) if message == REPEATED_LOCALITY),
    )
}

fn reject_repeated_subject_locality(xml: &str) -> Result<(), String> {
    if xml.matches("<saml:SubjectLocality").count() > 1 {
        return Err(SCHEMA_REJECTION.into());
    }
    Ok(())
}

#[test]
fn schema_validator_rejects_repeated_subject_locality_before_the_statement_reader(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::default(), false)?;
    let exchange = Exchange {
        sp: ServiceProvider::new(
            SpConfig::builder(
                EntityId::try_new(SP_ENTITY_ID)?,
                AcsEndpoint::post(SP_ACS_POST)?.with_default(),
            )
            .credentials(signing_credentials())
            .name_id_format(NameIdFormat::Unspecified)
            .xml(XmlPolicy {
                schema_validator: Some(reject_repeated_subject_locality),
                ..XmlPolicy::default()
            })
            .build()?,
        ),
        ..exchange
    };
    let xml = with_repeated_subject_locality(&response_xml(&exchange.response_fields)?);
    expect_error(
        accept(&exchange, &resigned(&xml)?),
        |err| matches!(err, SamlError::Invalid(reason) if reason == SCHEMA_REJECTION),
    )
}
