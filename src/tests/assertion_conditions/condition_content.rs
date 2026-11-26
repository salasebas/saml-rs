use super::*;

const EXTENSION: &str = r#" xmlns:ext="urn:example:extension""#;
const XSI: &str = r#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance""#;

fn with_start_tag_attributes(
    xml: &str,
    start_tag: &str,
    attributes: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let at = xml.find(start_tag).ok_or("missing start tag")? + start_tag.len();
    let mut edited = xml.to_string();
    edited.insert_str(at, attributes);
    Ok(edited)
}

fn expect_undeclared_attribute(
    result: Result<SsoSession, Box<dyn std::error::Error>>,
    element: &str,
    attribute: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Err(error) => match error.downcast_ref::<SamlError>() {
            Some(SamlError::UnrecognizedCondition {
                element: actual_element,
                attribute: Some(actual_attribute),
            }) if actual_element == element && actual_attribute == attribute => Ok(()),
            _ => Err(format!("{element} {attribute}: unexpected error {error}").into()),
        },
        Ok(_) => Err(format!("{element} {attribute}: accepted").into()),
    }
}

#[test]
fn selected_conditions_carry_only_their_declared_attributes(
) -> Result<(), Box<dyn std::error::Error>> {
    for unsolicited in [false, true] {
        let exchange = exchange_for(SpValidationPolicy::default(), unsolicited)?;
        let xml = response_xml(&exchange.response_fields)?;
        let refused = [
            (
                with_start_tag_attributes(&xml, "<saml:Conditions", r#" Extra="1""#)?,
                "Conditions",
                "Extra",
            ),
            (
                insert_after_audience_restriction(
                    &xml,
                    r#"<saml:ProxyRestriction Count="0" Extra="1"/>"#,
                )?,
                "ProxyRestriction",
                "Extra",
            ),
            (
                insert_after_audience_restriction(
                    &xml,
                    &format!(r#"<saml:ProxyRestriction{EXTENSION} ext:Count="0"/>"#),
                )?,
                "ProxyRestriction",
                "ext:Count",
            ),
            (
                insert_after_audience_restriction(&xml, r#"<saml:OneTimeUse Count="0"/>"#)?,
                "OneTimeUse",
                "Count",
            ),
        ];
        for (edited, element, attribute) in refused {
            expect_undeclared_attribute(
                accept(&exchange, &resigned(&edited)?),
                element,
                attribute,
            )?;
        }
    }
    Ok(())
}

#[test]
fn schema_instance_attributes_leave_a_known_condition_understood(
) -> Result<(), Box<dyn std::error::Error>> {
    for unsolicited in [false, true] {
        let exchange = exchange_for(SpValidationPolicy::default(), unsolicited)?;
        let xml = response_xml(&exchange.response_fields)?;
        let accepted = [
            with_start_tag_attributes(&xml, "<saml:Conditions", EXTENSION)?,
            with_start_tag_attributes(
                &xml,
                "<saml:Conditions",
                r#" xmlns:i="http://www.w3.org/2001/XMLSchema-instanc&#101;" i:schemaLocation="urn:example:extension extension.xsd""#,
            )?,
            with_start_tag_attributes(
                &xml,
                "<saml:Conditions",
                &format!(
                    r#"{XSI} xsi:schemaLocation="urn:oasis:names:tc:SAML:2.0:assertion saml-schema-assertion-2.0.xsd" xsi:nil="false""#
                ),
            )?,
            with_start_tag_attributes(
                &xml,
                "<saml:AudienceRestriction",
                &format!(r#"{XSI}{EXTENSION} xsi:type="ext:DerivedType""#),
            )?,
            insert_after_audience_restriction(
                &xml,
                &format!(
                    r#"<saml:ProxyRestriction{XSI} xsi:noNamespaceSchemaLocation="proxy.xsd" Count="0"/>"#
                ),
            )?,
        ];
        for edited in accepted {
            let session = accept(&exchange, &resigned(&edited)?)?;
            assert_eq!(audience_groups(&session), [[SP_ENTITY_ID]]);
        }

        let derived = with_start_tag_attributes(
            &xml,
            "<saml:AudienceRestriction",
            &format!(r#"{XSI}{EXTENSION} xsi:type="ext:DerivedType""#),
        )?
        .replacen(
            &format!("<saml:Audience>{SP_ENTITY_ID}</saml:Audience>"),
            &format!("<saml:Audience>{OTHER_AUDIENCE}</saml:Audience>"),
            1,
        );
        expect_error(accept(&exchange, &resigned(&derived)?), |error| {
            matches!(error, SamlError::AudienceMismatch { .. })
        })?;

        let generic = insert_after_audience_restriction(
            &xml,
            &format!(r#"<saml:Condition{XSI}{EXTENSION} xsi:type="ext:DerivedType"/>"#),
        )?;
        expect_unrecognized(accept(&exchange, &resigned(&generic)?))?;
    }
    Ok(())
}

#[test]
fn an_unselected_assertion_keeps_undeclared_conditions_attributes(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::default(), false)?;
    let pair = duplicate_assertion(&response_xml(&exchange.response_fields)?, "_second")?;
    let edited =
        replace_in_last_assertion(&pair, "<saml:Conditions", r#"<saml:Conditions Extra="1""#)?;
    let session = accept(&exchange, &resigned(&edited)?)?;
    assert_ne!(session.assertion_id().as_str(), "_second");
    Ok(())
}
