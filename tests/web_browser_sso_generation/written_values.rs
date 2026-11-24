use super::*;

fn post_response(xml: &str) -> Inbound<SsoResponse> {
    Inbound::post(vec![FormField::new(
        "SAMLResponse",
        STANDARD.encode(xml.as_bytes()),
    )])
}

fn without_signature(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let start = xml.find("<ds:Signature").ok_or("missing ds:Signature")?;
    let end = start
        + xml[start..]
            .find("</ds:Signature>")
            .ok_or("unclosed ds:Signature")?
        + "</ds:Signature>".len();
    Ok(format!("{}{}", &xml[..start], &xml[end..]))
}

#[test]
fn a_forwarded_status_with_a_relative_subordinate_code_is_not_written(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(SpValidationPolicy::default())?;
    let idp = idp_with(IdpValidationPolicy::default(), false)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let upstream = Status::responder().with_subordinate(SubordinateStatusCode::try_new(
        "urn:example:status:upstream",
    )?);
    let sent = idp.initiate_sso(
        &sp_descriptor,
        SsoOutcome::Failure(upstream),
        RespondSso::post(),
    )?;
    let xml = without_signature(&response_xml(&sent)?)?
        .replace("urn:example:status:upstream", "upstream-failure");

    let received =
        match sp.accept_unsolicited_sso(&idp_descriptor, post_response(&xml), validation()) {
            Err(SamlError::StatusNotSuccess { status, .. }) => status,
            other => return Err(format!("expected StatusNotSuccess, got {other:?}").into()),
        };
    assert_eq!(
        received.subordinate().map(SubordinateStatusCode::as_uri),
        Some("upstream-failure")
    );

    let forwarded = idp.initiate_sso(
        &sp_descriptor,
        SsoOutcome::Failure(received),
        RespondSso::post(),
    );
    assert!(
        matches!(forwarded, Err(SamlError::Invalid(_))),
        "{forwarded:?}"
    );
    Ok(())
}

#[test]
fn a_status_message_without_a_non_whitespace_character_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(SpValidationPolicy::default())?;
    let idp = idp_with(IdpValidationPolicy::default(), false)?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    for message in [" ", "\r\n\t"] {
        let response = idp.initiate_sso(
            &sp_descriptor,
            SsoOutcome::Failure(Status::responder()),
            RespondSso::post().status_message(message),
        );
        assert!(
            matches!(response, Err(SamlError::Invalid(_))),
            "{message:?}: {response:?}"
        );
    }
    Ok(())
}
