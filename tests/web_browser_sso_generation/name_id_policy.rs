use super::*;
use saml_rs::NameIdCreationRequest;

const AFFILIATION: &str = "https://federation.example.com/affiliation?group=research&region=west";

#[test]
fn signed_browser_sso_issues_an_affiliation_qualified_persistent_name_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut sp_validation = signing_sp_validation();
    sp_validation.name_id_creation = NameIdCreationPolicy::AllowCreate;
    let sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(SP_ACS)?.with_default(),
        )
        .name_id_format(NameIdFormat::Persistent)
        .credentials(signing_credentials())
        .validation(sp_validation)
        .build()?,
    );
    let idp = idp_with(signed_authn_request_idp_validation(), false)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::post().sp_name_qualifier(EntityId::try_new(AFFILIATION)?),
    )?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let policy = received
        .message()
        .name_id_policy()
        .ok_or("missing NameIDPolicy")?;
    assert_eq!(policy.format(), Some(&NameIdFormat::Persistent));
    assert_eq!(
        policy.creation_request(),
        NameIdCreationRequest::AllowCreate
    );
    assert_eq!(policy.sp_name_qualifier(), Some(AFFILIATION));

    let qualifier = policy
        .sp_name_qualifier()
        .ok_or("missing SPNameQualifier")?;
    let principal = NameId::generate_persistent().with_sp_name_qualifier(qualifier);
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal.clone()),
        RespondSso::post().sign_response(),
    )?;
    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(response.post_form()?.fields().to_vec()),
        post_validation(&mut Default::default()),
    )?;
    assert_eq!(session.name_id(), &principal);
    Ok(())
}

#[test]
fn start_sso_rejects_a_relative_sp_name_qualifier() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(SpValidationPolicy::default())?;
    let idp = idp_with(IdpValidationPolicy::default(), false)?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    let qualifier = EntityId::try_new("federation.example.com/research")?;

    let attempt = sp.start_sso(
        &idp_descriptor,
        StartSso::post().sp_name_qualifier(qualifier),
    );

    assert!(matches!(attempt, Err(SamlError::Invalid(_))));
    Ok(())
}

#[test]
fn start_sso_rejects_a_qualifier_with_entity_format() -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp_with(IdpValidationPolicy::default(), false)?;
    for format in [
        NameIdFormat::Entity,
        NameIdFormat::Custom(format!(" {} ", NameIdFormat::Entity.as_uri())),
    ] {
        let sp = ServiceProvider::new(
            SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?, AcsEndpoint::post(SP_ACS)?)
                .name_id_format(format)
                .build()?,
        );
        let (_, idp_descriptor) = descriptors(&sp, &idp)?;
        sp.start_sso(&idp_descriptor, StartSso::post())?;
        let attempt = sp.start_sso(
            &idp_descriptor,
            StartSso::post().sp_name_qualifier(EntityId::try_new(AFFILIATION)?),
        );
        assert!(
            matches!(attempt, Err(SamlError::Invalid(message)) if message.contains("SPNameQualifier") && message.contains("entity"))
        );
    }
    Ok(())
}
