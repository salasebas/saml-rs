use super::*;
use saml_rs::{OutstandingLogout, SamlInstant};

type ErrorMatches = fn(&SamlError) -> bool;

fn replace_name_id(xml: &str, identifier: &str) -> Result<String, Box<dyn std::error::Error>> {
    let start = xml.find("<saml:NameID").ok_or("missing NameID")?;
    let close = "</saml:NameID>";
    let end = xml[start..].find(close).ok_or("unterminated NameID")? + start + close.len();
    let mut altered = xml.to_string();
    altered.replace_range(start..end, identifier);
    Ok(altered)
}

fn with_department_attribute(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let at = xml
        .rfind("</saml:Assertion>")
        .ok_or("missing assertion end")?;
    let mut altered = xml.to_string();
    altered.insert_str(
        at,
        concat!(
            r#"<saml:AttributeStatement><saml:Attribute Name="department">"#,
            "<saml:AttributeValue>engineering</saml:AttributeValue>",
            "</saml:Attribute></saml:AttributeStatement>",
        ),
    );
    Ok(altered)
}

#[test]
fn a_confirmation_only_subject_signs_in_without_a_logout_subject(
) -> Result<(), Box<dyn std::error::Error>> {
    for unsolicited in [false, true] {
        let exchange = exchange_for(SpValidationPolicy::default(), unsolicited)?;
        let original = response_xml(&exchange.response_fields)?;
        let unsigned = with_department_attribute(&replace_name_id(
            &strip_embedded_signatures(&original)?,
            "",
        )?)?;
        let xml = if unsolicited {
            sign_first_assertion(&unsigned, RSA_SHA256)?
        } else {
            resigned(&unsigned)?
        };

        let session = accept(&exchange, &xml)?;

        assert_eq!(session.name_id(), None, "unsolicited: {unsolicited}");
        assert!(session.logout_subject().is_none());
        assert_eq!(
            session.attributes().first_value("department"),
            Some("engineering")
        );
    }
    Ok(())
}

#[test]
fn an_outstanding_logout_does_not_apply_to_a_confirmation_only_subject(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::default(), false)?;
    let original = response_xml(&exchange.response_fields)?;
    let xml = resigned(&replace_name_id(&original, "")?)?;
    let pending = exchange.pending.as_ref().ok_or("missing pending request")?;
    let logout_everywhere = OutstandingLogout::try_new(
        EntityId::try_new(IDP_ENTITY_ID)?,
        principal(),
        Vec::new(),
        SamlInstant::try_new("9999-12-31T23:59:59Z")?,
    )?;

    let session = exchange.sp.finish_sso_with_outstanding_logout(
        &exchange.idp_descriptor,
        pending,
        Inbound::post(fields_with_xml(exchange.response_fields.clone(), &xml)?),
        post_validation(&mut Default::default()),
        &logout_everywhere,
    )?;

    assert_eq!(session.name_id(), None);
    Ok(())
}

#[test]
fn a_subject_without_a_readable_name_id_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::default(), false)?;
    let original = response_xml(&exchange.response_fields)?;
    let unsupported: ErrorMatches = |error| matches!(error, SamlError::Unsupported(_));
    let protocol_profile: ErrorMatches = |error| matches!(error, SamlError::ProtocolProfile(_));
    let invalid: ErrorMatches = |error| matches!(error, SamlError::Invalid(_));
    let cases = [
        (
            concat!(
                r#"<saml:BaseID xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" "#,
                r#"xmlns:ext="urn:example:ext" xsi:type="ext:ExampleID"/>"#,
            ),
            unsupported,
        ),
        (
            concat!(
                r#"<saml:EncryptedID><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">"#,
                "<xenc:CipherData><xenc:CipherValue>AAAA</xenc:CipherValue></xenc:CipherData>",
                "</xenc:EncryptedData></saml:EncryptedID>",
            ),
            unsupported,
        ),
        (
            concat!(
                r#"<ext:Wrapper xmlns:ext="urn:example:ext">"#,
                "<saml:NameID>alice@example.com</saml:NameID></ext:Wrapper>",
            ),
            protocol_profile,
        ),
        (
            concat!(
                r#"</saml:Subject><saml:Subject><saml:SubjectConfirmation "#,
                r#"Method="urn:oasis:names:tc:SAML:2.0:cm:sender-vouches"/>"#,
            ),
            invalid,
        ),
    ];
    for (identifier, expected) in cases {
        let xml = resigned(&replace_name_id(&original, identifier)?)?;
        match accept(&exchange, &xml) {
            Err(error) => match error.downcast_ref::<SamlError>() {
                Some(error) if expected(error) => {}
                _ => return Err(format!("unexpected error for {identifier}: {error}").into()),
            },
            Ok(session) => {
                return Err(format!(
                    "expected an error for {identifier}, got NameID {:?}",
                    session.name_id()
                )
                .into())
            }
        }
    }
    Ok(())
}

#[test]
fn two_assertions_without_a_name_id_are_not_one_principal() -> Result<(), Box<dyn std::error::Error>>
{
    let exchange = exchange_for(SpValidationPolicy::default(), false)?;
    let original = response_xml(&exchange.response_fields)?;
    let without_name_id = replace_name_id(&strip_embedded_signatures(&original)?, "")?;
    let xml = resigned(&duplicate_assertion(&without_name_id, "_second_assertion")?)?;

    match accept(&exchange, &xml) {
        Err(error) => match error.downcast_ref::<SamlError>() {
            Some(SamlError::PrincipalMismatch) => Ok(()),
            _ => Err(format!("expected PrincipalMismatch, got {error}").into()),
        },
        Ok(_) => Err("expected PrincipalMismatch".into()),
    }
}
