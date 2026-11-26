use super::*;

const CHILD: &str = r#"<ext:Note xmlns:ext="urn:example:extension"/>"#;

fn insert_in_first_assertion(
    xml: &str,
    before: &str,
    content: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let assertion = xml.find("<saml:Assertion").ok_or("missing assertion")?;
    let at = xml[assertion..]
        .find(before)
        .ok_or("missing text in the first assertion")?
        + assertion;
    let mut edited = xml.to_string();
    edited.insert_str(at, content);
    Ok(edited)
}

#[test]
fn selected_assertion_values_hold_text_without_child_elements(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::default(), false)?;
    let xml = response_xml(&exchange.response_fields)?;
    let authority = format!(
        "<saml:AuthenticatingAuthority>https://upstream.example.com{CHILD}</saml:AuthenticatingAuthority>"
    );
    let refused = [
        ("</saml:Issuer>", CHILD.to_string()),
        ("</saml:NameID>", CHILD.to_string()),
        ("</saml:Audience>", CHILD.to_string()),
        ("</saml:AuthnContextClassRef>", CHILD.to_string()),
        ("</saml:AuthnContext>", authority),
    ];
    for (before, content) in refused {
        let edited = insert_in_first_assertion(&xml, before, &content)?;
        expect_error(accept(&exchange, &resigned(&edited)?), |err| {
            matches!(err, SamlError::ProtocolProfile(_))
        })
        .map_err(|error| format!("{content} before {before}: {error}"))?;
    }

    let commented = xml.replacen(
        "alice@example.com</saml:NameID>",
        "alice@<!-- note -->example.com</saml:NameID>",
        1,
    );
    let session = accept(&exchange, &resigned(&commented)?)?;
    assert_eq!(
        session.name_id().ok_or("missing NameID")?.value(),
        "alice@example.com"
    );
    Ok(())
}

#[test]
fn values_outside_the_selected_assertion_keep_their_text_around_a_child_element(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::default(), false)?;
    let xml = response_xml(&exchange.response_fields)?;
    let pair = duplicate_assertion(&xml, "_second")?;
    let accepted = [
        xml.replacen("</saml:Issuer>", &format!("{CHILD}</saml:Issuer>"), 1),
        replace_in_last_assertion(&pair, "</saml:Issuer>", &format!("{CHILD}</saml:Issuer>"))?,
        replace_in_last_assertion(&pair, "</saml:NameID>", &format!("{CHILD}</saml:NameID>"))?,
    ];
    for edited in accepted {
        let session = accept(&exchange, &resigned(&edited)?)?;
        assert_eq!(session.issuer().as_str(), IDP_ENTITY_ID);
        assert_ne!(session.assertion_id().as_str(), "_second");
    }
    Ok(())
}
