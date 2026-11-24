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
fn an_expired_sibling_assertion_is_discarded_and_kept_until_the_session_replay_deadline(
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
    let session_deadline = cache
        .seen
        .get(&format!("assertion_id:{}", session.assertion_id().as_str()))
        .ok_or("the session assertion was not stored")?;
    assert_eq!(
        cache.seen.get("assertion_id:_second_assertion"),
        Some(session_deadline)
    );
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

#[test]
fn assertions_that_share_an_id_are_rejected_without_an_embedded_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_simple_sign(SpValidationPolicy::default())?;
    let xml = strip_embedded_signatures(&response_xml(&exchange.response_fields)?)?;
    let id = assertion_ids(&xml)?
        .into_iter()
        .next()
        .ok_or("missing assertion ID")?;
    let holder_of_key_first = move_last_assertion_first(&replace_in_last_assertion(
        &duplicate_assertion(&xml, &format!(" {id}"))?,
        "urn:oasis:names:tc:SAML:2.0:cm:bearer",
        "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key",
    )?)?;

    expect_error(
        accept_simple_sign(&exchange, &holder_of_key_first),
        |error| matches!(error, SamlError::PotentialWrappingAttack),
    )
}

#[test]
fn assertions_with_distinct_ids_are_accepted_when_each_declares_a_prefix_named_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_simple_sign(SpValidationPolicy::default())?;
    let original = strip_embedded_signatures(&response_xml(&exchange.response_fields)?)?;
    let xml = duplicate_assertion(&original, "_second_assertion")?.replace(
        "<saml:Assertion ",
        "<saml:Assertion xmlns:ID=\"urn:example:shared\" ",
    );
    assert_eq!(xml.matches("xmlns:ID=").count(), 2);

    let mut cache = RecordingReplayCache::default();
    let session = exchange.sp.accept_unsolicited_sso(
        &exchange.idp_descriptor,
        Inbound::simple_sign(simple_sign_fields(&exchange.response_fields, &xml)?),
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(&mut cache)),
    )?;

    let first_id = assertion_ids(&original)?
        .into_iter()
        .next()
        .ok_or("missing assertion ID")?;
    assert_eq!(session.assertion_id().as_str(), first_id);
    let mut stored: Vec<&str> = cache
        .seen
        .keys()
        .filter_map(|key| key.strip_prefix("assertion_id:"))
        .collect();
    stored.sort_unstable();
    let mut expected = vec![first_id.as_str(), "_second_assertion"];
    expected.sort_unstable();
    assert_eq!(stored, expected);
    Ok(())
}
