use super::*;
use std::time::SystemTime;

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

fn forward_upstream_status(
    upstream_code: &str,
) -> Result<Result<Outbound<SsoResponse>, SamlError>, Box<dyn std::error::Error>> {
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
        .replace("urn:example:status:upstream", upstream_code);

    let received =
        match sp.accept_unsolicited_sso(&idp_descriptor, post_response(&xml), validation()) {
            Err(SamlError::StatusNotSuccess { status, .. }) => status,
            other => return Err(format!("expected StatusNotSuccess, got {other:?}").into()),
        };
    assert_eq!(
        received.subordinate().map(SubordinateStatusCode::as_uri),
        Some(upstream_code)
    );
    Ok(idp.initiate_sso(
        &sp_descriptor,
        SsoOutcome::Failure(received),
        RespondSso::post(),
    ))
}

#[test]
fn a_forwarded_status_is_written_only_with_an_absolute_subordinate_code(
) -> Result<(), Box<dyn std::error::Error>> {
    let relative = forward_upstream_status("upstream-failure")?;
    assert!(
        matches!(relative, Err(SamlError::Invalid(_))),
        "{relative:?}"
    );

    let with_space = "https://idp.example.com/status/needs review";
    let xml = response_xml(&forward_upstream_status(with_space)??)?;
    assert!(xml.contains(&format!("Value=\"{with_space}\"")), "{xml}");
    Ok(())
}

#[test]
fn a_status_message_needs_a_character_other_than_xml_whitespace(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(SpValidationPolicy::default())?;
    let idp = idp_with(IdpValidationPolicy::default(), false)?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    let respond = |message: &str| {
        idp.initiate_sso(
            &sp_descriptor,
            SsoOutcome::Failure(Status::responder()),
            RespondSso::post().status_message(message),
        )
    };
    for message in [" ", "\r\n\t"] {
        let response = respond(message);
        assert!(
            matches!(response, Err(SamlError::Invalid(_))),
            "{message:?}: {response:?}"
        );
    }
    let no_break_space = "\u{a0}";
    let xml = response_xml(&respond(no_break_space)?)?;
    assert!(
        xml.contains(&format!(
            "<samlp:StatusMessage>{no_break_space}</samlp:StatusMessage>"
        )),
        "{xml}"
    );
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
        SsoAssertion::new(longest.clone(), SystemTime::now()),
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
            SsoAssertion::new(name_id.clone(), SystemTime::now()),
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
            SsoAssertion::new(name_id.clone(), SystemTime::now()),
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
        SsoAssertion::new(NameId::new(PARTNER), SystemTime::now()),
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
        SsoAssertion::new(NameId::new("partner"), SystemTime::now()),
        RespondSso::post(),
    );
    assert!(
        matches!(response, Err(SamlError::Invalid(_))),
        "{response:?}"
    );
    Ok(())
}

fn authn_request_with_id(
    sp: &ServiceProvider,
    idp_descriptor: &IdpDescriptor,
    request_id: &str,
) -> Result<Inbound<AuthnRequest>, Box<dyn std::error::Error>> {
    let started = sp.start_sso(idp_descriptor, StartSso::post())?;
    let generated = started.pending.request_id().as_str();
    let xml = authn_request_xml(&started.outbound)?.replace(
        &format!("ID=\"{generated}\""),
        &format!("ID=\"{request_id}\""),
    );
    Ok(Inbound::post(vec![FormField::new(
        "SAMLRequest",
        STANDARD.encode(xml.as_bytes()),
    )]))
}

#[test]
fn a_request_id_is_written_as_in_response_to_only_as_an_ncname(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(SpValidationPolicy::default())?;
    let idp = idp_with(IdpValidationPolicy::default(), false)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let received = idp.receive_sso(
        &sp_descriptor,
        authn_request_with_id(&sp, &idp_descriptor, "1-not-an-ncname")?,
        validation(),
    )?;
    assert_eq!(received.message().id().as_str(), "1-not-an-ncname");
    for outcome in [
        SsoOutcome::Success(SsoAssertion::new(principal(), SystemTime::now())),
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

#[test]
fn a_padded_request_id_is_one_id_for_correlation() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(SpValidationPolicy::default())?;
    let idp = idp_with(IdpValidationPolicy::default(), false)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let received = idp.receive_sso(
        &sp_descriptor,
        authn_request_with_id(&sp, &idp_descriptor, " _padded ")?,
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache),
    )?;
    assert_eq!(received.message().id().as_str(), "_padded");
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal(), SystemTime::now()),
        RespondSso::post(),
    )?;
    let xml = response_xml(&response)?;
    assert_eq!(xml.matches("InResponseTo=\"_padded\"").count(), 2, "{xml}");

    Ok(())
}
