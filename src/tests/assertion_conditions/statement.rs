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

fn with_authn_context_content(
    xml: &str,
    content: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let start = xml
        .find("<saml:AuthnContext>")
        .ok_or("missing AuthnContext")?
        + "<saml:AuthnContext>".len();
    let end = xml[start..]
        .find("</saml:AuthnContext>")
        .ok_or("unterminated AuthnContext")?
        + start;
    let mut edited = xml.to_string();
    edited.replace_range(start..end, content);
    Ok(edited)
}

#[test]
fn authn_context_holds_one_class_reference_and_one_declaration_at_most(
) -> Result<(), Box<dyn std::error::Error>> {
    const CLASS: &str =
        "<saml:AuthnContextClassRef>urn:example:password</saml:AuthnContextClassRef>";
    const DECLARATION_REFERENCE: &str =
        "<saml:AuthnContextDeclRef>urn:example:declaration</saml:AuthnContextDeclRef>";
    const DECLARATION: &str = "<saml:AuthnContextDecl/>";
    let exchange = exchange_for(SpValidationPolicy::default(), false)?;
    let xml = response_xml(&exchange.response_fields)?;

    for content in [
        String::new(),
        format!("{CLASS}{CLASS}"),
        format!("{CLASS}{DECLARATION}{DECLARATION_REFERENCE}"),
        format!("{DECLARATION_REFERENCE}{DECLARATION_REFERENCE}"),
    ] {
        let edited = resigned(&with_authn_context_content(&xml, &content)?)?;
        expect_error(accept(&exchange, &edited), |err| {
            matches!(err, SamlError::ProtocolProfile(_))
        })
        .map_err(|error| format!("{content}: {error}"))?;
    }

    for content in [
        DECLARATION_REFERENCE.to_string(),
        format!("{CLASS}{DECLARATION}"),
    ] {
        let edited = resigned(&with_authn_context_content(&xml, &content)?)?;
        accept(&exchange, &edited).map_err(|error| format!("{content}: {error}"))?;
    }
    Ok(())
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

const MISSING_AUTHN_INSTANT: &str =
    "AuthnStatement is missing required unqualified attribute AuthnInstant";
const NON_UTC_AUTHN_INSTANT: &str =
    "AuthnStatement AuthnInstant must use the SAML-conformant UTC xs:dateTime form ending in Z";

fn with_authn_instant_attribute(
    xml: &str,
    attribute: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let statement = xml
        .find("<saml:AuthnStatement ")
        .ok_or("missing AuthnStatement")?;
    let start = xml[statement..]
        .find(" AuthnInstant=\"")
        .ok_or("missing AuthnInstant")?
        + statement;
    let value_start = start + " AuthnInstant=\"".len();
    let end = xml[value_start..]
        .find('"')
        .ok_or("unterminated AuthnInstant")?
        + value_start
        + 1;
    let mut replaced = xml.to_string();
    replaced.replace_range(start..end, attribute);
    Ok(replaced)
}

#[test]
fn browser_sso_rejects_a_statement_missing_authn_instant_without_a_schema_validator(
) -> Result<(), Box<dyn std::error::Error>> {
    for unsolicited in [false, true] {
        let exchange = exchange_for(SpValidationPolicy::default(), unsolicited)?;
        let omitted = with_authn_instant_attribute(&response_xml(&exchange.response_fields)?, "")?;
        expect_error(
            accept(&exchange, &resigned(&omitted)?),
            |err| matches!(err, SamlError::ProtocolProfile(message) if message == MISSING_AUTHN_INSTANT),
        )?;
    }
    Ok(())
}

#[test]
fn browser_sso_rejects_an_authn_instant_that_is_not_a_saml_utc_date_time(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::default(), false)?;
    let xml = response_xml(&exchange.response_fields)?;
    for value in ["not-a-time", "2014-07-17T01:01:48+00:00"] {
        let replaced = with_authn_instant_attribute(&xml, &format!(" AuthnInstant=\"{value}\""))?;
        expect_error(
            accept(&exchange, &resigned(&replaced)?),
            |err| matches!(err, SamlError::ProtocolProfile(message) if message == NON_UTC_AUTHN_INSTANT),
        )?;
    }
    Ok(())
}

#[test]
fn browser_sso_reports_the_collapsed_authn_instant() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::default(), false)?;
    let padded = with_authn_instant_attribute(
        &response_xml(&exchange.response_fields)?,
        " AuthnInstant=\" 2014-07-17T01:01:48Z \"",
    )?;
    let session = accept(&exchange, &resigned(&padded)?)?;
    assert_eq!(
        session
            .authn_statements()
            .iter()
            .map(|statement| statement.authn_instant().as_str())
            .collect::<Vec<_>>(),
        ["2014-07-17T01:01:48Z"]
    );
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
