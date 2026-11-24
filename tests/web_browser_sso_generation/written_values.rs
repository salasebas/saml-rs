use super::*;

const ENTITY_FORMAT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
const PARTNER: &str = "https://partner.example.org/metadata";

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

fn entity_name_id_of_length(length: usize) -> NameId {
    let prefix = "https://partner.example.org/";
    let value = format!("{prefix}{}", "a".repeat(length - prefix.len()));
    NameId::new(value).with_format(NameIdFormat::Entity)
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

#[test]
fn an_entity_name_id_is_a_uri_of_at_most_1024_characters() -> Result<(), Box<dyn std::error::Error>>
{
    let sp = sp_with(SpValidationPolicy::default())?;
    let idp = idp_with(IdpValidationPolicy::default(), false)?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;

    let longest = entity_name_id_of_length(1024);
    let response = idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(longest.clone()),
        RespondSso::post(),
    )?;
    let xml = response_xml(&response)?;
    assert!(
        xml.contains(&format!(
            "<saml:NameID Format=\"{ENTITY_FORMAT}\">{}</saml:NameID>",
            longest.value()
        )),
        "{xml}"
    );

    for name_id in [
        entity_name_id_of_length(1025),
        NameId::new("partner.example.org").with_format(NameIdFormat::Entity),
        NameId::new(format!(" {PARTNER}")).with_format(NameIdFormat::Entity),
    ] {
        let response = idp.initiate_sso(
            &sp_descriptor,
            SsoAssertion::new(name_id.clone()),
            RespondSso::post(),
        );
        assert!(
            matches!(response, Err(SamlError::Invalid(_))),
            "{name_id:?}: {response:?}"
        );
    }
    Ok(())
}

#[test]
fn an_entity_name_id_omits_every_qualifier() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(SpValidationPolicy::default())?;
    let idp = idp_with(IdpValidationPolicy::default(), false)?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    let entity = NameId::new(PARTNER).with_format(NameIdFormat::Entity);
    for name_id in [
        entity.clone().with_name_qualifier(IDP_ENTITY_ID),
        entity.clone().with_sp_name_qualifier(SP_ENTITY_ID),
        entity.with_sp_provided_id("partner-7"),
    ] {
        let response = idp.initiate_sso(
            &sp_descriptor,
            SsoAssertion::new(name_id.clone()),
            RespondSso::post(),
        );
        assert!(
            matches!(response, Err(SamlError::Invalid(_))),
            "{name_id:?}: {response:?}"
        );
    }
    Ok(())
}

#[test]
fn a_name_id_without_a_format_follows_the_configured_entity_format(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(SpValidationPolicy::default())?;
    let idp = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO_POST)?,
        )
        .name_id_format(NameIdFormat::Entity)
        .credentials(signing_credentials())
        .build()?,
    );
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;

    let response = idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(NameId::new(PARTNER)),
        RespondSso::post(),
    )?;
    let xml = response_xml(&response)?;
    assert!(
        xml.contains(&format!(
            "<saml:NameID Format=\"{ENTITY_FORMAT}\">{PARTNER}</saml:NameID>"
        )),
        "{xml}"
    );

    let response = idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(NameId::new("partner")),
        RespondSso::post(),
    );
    assert!(
        matches!(response, Err(SamlError::Invalid(_))),
        "{response:?}"
    );
    Ok(())
}

#[test]
fn a_request_id_that_is_not_an_ncname_is_not_written_as_in_response_to(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(SpValidationPolicy::default())?;
    let idp = idp_with(IdpValidationPolicy::default(), false)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let request_id = started.pending.request_id().as_str();
    let xml = authn_request_xml(&started.outbound)?
        .replace(&format!("ID=\"{request_id}\""), "ID=\"1-not-an-ncname\"");
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(vec![FormField::new(
            "SAMLRequest",
            STANDARD.encode(xml.as_bytes()),
        )]),
        validation(),
    )?;
    assert_eq!(received.message().id().as_str(), "1-not-an-ncname");

    for outcome in [
        SsoOutcome::Success(SsoAssertion::new(principal())),
        SsoOutcome::Failure(Status::responder()),
    ] {
        let response = idp.respond_sso(&sp_descriptor, &received, outcome, RespondSso::post());
        assert!(
            matches!(response, Err(SamlError::Invalid(_))),
            "{response:?}"
        );
    }
    Ok(())
}
