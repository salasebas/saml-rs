use super::*;

fn expire_last_bearer_confirmation(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let assertion = xml.rfind("<saml:Assertion").ok_or("missing assertion")?;
    let data = xml[assertion..]
        .find("<saml:SubjectConfirmationData NotOnOrAfter=\"")
        .ok_or("missing bearer confirmation data")?
        + assertion
        + "<saml:SubjectConfirmationData NotOnOrAfter=\"".len();
    let end = xml[data..].find('"').ok_or("unterminated NotOnOrAfter")? + data;
    let mut expired = xml.to_string();
    expired.replace_range(data..end, "2000-01-01T00:00:00Z");
    Ok(expired)
}

#[test]
fn an_expired_sibling_assertion_is_discarded_without_a_replay_entry(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::default(), false)?;
    let xml = resigned(&expire_last_bearer_confirmation(&duplicate_assertion(
        &response_xml(&exchange.response_fields)?,
        "_second_assertion",
    )?)?)?;
    let mut cache = RecordingReplayCache::default();

    let session = accept_with(
        &exchange,
        &xml,
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(&mut cache)),
    )?;

    assert_ne!(session.assertion_id().as_str(), "_second_assertion");
    let stored: Vec<&str> = cache
        .seen
        .keys()
        .filter_map(|key| key.strip_prefix("assertion_id:"))
        .collect();
    assert_eq!(stored, [session.assertion_id().as_str()]);
    Ok(())
}

#[test]
fn an_unknown_condition_fails_only_the_session_it_supplies(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::default(), false)?;
    let in_sibling = replace_in_last_assertion(
        &duplicate_assertion(
            &response_xml(&exchange.response_fields)?,
            "_second_assertion",
        )?,
        "</saml:AudienceRestriction>",
        "</saml:AudienceRestriction><saml:Condition/>",
    )?;

    let session = accept(&exchange, &resigned(&in_sibling)?)?;
    assert_ne!(session.assertion_id().as_str(), "_second_assertion");

    expect_unrecognized(accept(
        &exchange,
        &resigned(&move_last_assertion_first(&in_sibling)?)?,
    ))
}

#[test]
fn an_unsolicited_assertion_is_confirmed_by_a_bearer_confirmation_without_in_response_to(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::default(), true)?;
    let xml = response_xml(&exchange.response_fields)?;
    let at = xml
        .find("<saml:SubjectConfirmation ")
        .ok_or("missing bearer confirmation")?;
    let mut altered = xml.clone();
    altered.insert_str(
        at,
        &format!(
            "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData NotOnOrAfter=\"2099-01-01T00:00:00Z\" Recipient=\"{SP_ACS_POST}\" InResponseTo=\"_another_request\"/></saml:SubjectConfirmation>"
        ),
    );

    let session = accept(&exchange, &resigned(&altered)?)?;

    assert_eq!(session.in_response_to(), None);
    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}
