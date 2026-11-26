use super::{
    descriptors, facades, logout_request_xml, post_fields, receive_crafted_logout_request, subject,
    validation, LocalSloRole, RequestProtection, IDP_ENTITY_ID, SP_ENTITY_ID, SP_SLO_POST,
};
use saml_rs::{
    EntityId, Inbound, LogoutBinding, LogoutSubject, NameId, NameIdFormat, RespondSso,
    SessionIndex, SsoAssertion, StartSlo,
};
use std::time::SystemTime;

#[test]
fn authenticated_idp_logout_selects_the_sessions_named_by_the_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let principal = |value| {
        NameId::new(value)
            .with_name_qualifier(IDP_ENTITY_ID)
            .with_sp_name_qualifier(SP_ENTITY_ID)
            .with_sp_provided_id("alice-at-sp")
    };
    let name_id = principal("alice@example.com");
    let response = idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(name_id.clone(), SystemTime::now()),
        RespondSso::post(),
    )?;
    let session = sp.accept_unsolicited_sso(
        &idp_descriptor,
        Inbound::post(post_fields(&response)?),
        super::validation_with_cache(&mut super::RecordingReplayCache::default()),
    )?;
    let stored_subject = session.logout_subject().ok_or("missing logout subject")?;
    let other_index = SessionIndex::try_new("_another-session")?;
    let foreign_issuer = EntityId::try_new("https://other-idp.example.com/metadata")?;
    let subject_with_indexes = |name_id| {
        LogoutSubject::new(name_id).with_session_indexes(stored_subject.session_indexes().to_vec())
    };

    for (case, request_subject, stored_issuer, expected) in [
        (
            "same session",
            stored_subject.clone(),
            session.issuer(),
            true,
        ),
        (
            "another assertion issuer",
            stored_subject.clone(),
            &foreign_issuer,
            false,
        ),
        (
            "another principal",
            subject_with_indexes(principal("bob@example.com")),
            session.issuer(),
            false,
        ),
        (
            "another NameQualifier",
            subject_with_indexes(
                name_id
                    .clone()
                    .with_name_qualifier("https://other.example.com"),
            ),
            session.issuer(),
            false,
        ),
        (
            "another SPNameQualifier",
            subject_with_indexes(
                name_id
                    .clone()
                    .with_sp_name_qualifier("https://other.example.com"),
            ),
            session.issuer(),
            false,
        ),
        (
            "another SPProvidedID",
            subject_with_indexes(name_id.clone().with_sp_provided_id("another-id")),
            session.issuer(),
            false,
        ),
        (
            "explicit unspecified format",
            subject_with_indexes(name_id.clone().with_format(NameIdFormat::Unspecified)),
            session.issuer(),
            true,
        ),
        (
            "another format",
            subject_with_indexes(name_id.clone().with_format(NameIdFormat::EmailAddress)),
            session.issuer(),
            false,
        ),
        (
            "another session index",
            LogoutSubject::new(name_id.clone()).with_session_index(other_index.clone()),
            session.issuer(),
            false,
        ),
        (
            "one of several indexes matches",
            LogoutSubject::new(name_id.clone())
                .with_session_index(other_index)
                .with_session_indexes(stored_subject.session_indexes().to_vec()),
            session.issuer(),
            true,
        ),
        (
            "no indexes for another qualified principal",
            LogoutSubject::new(name_id.clone().with_sp_provided_id("another-id")),
            session.issuer(),
            false,
        ),
        (
            "the authority omits indexes",
            LogoutSubject::new(name_id),
            session.issuer(),
            true,
        ),
    ] {
        let started = idp.start_slo(&sp_descriptor, request_subject, StartSlo::post())?;
        let received = sp.receive_slo(
            &idp_descriptor,
            Inbound::post(post_fields(&started.outbound)?),
            validation(),
        )?;
        let selected = received.matches_sp_session(stored_issuer, &stored_subject);
        assert_eq!(selected, expected, "{case}");
    }
    Ok(())
}

#[test]
fn a_signed_base_id_cannot_select_a_session_by_index_alone(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = logout_request_xml("_base_id", IDP_ENTITY_ID, Some(SP_SLO_POST)).replace(
        "<saml:NameID>alice@example.com</saml:NameID>",
        r#"<saml:BaseID xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:example="urn:example:identifiers" xsi:type="example:AccountID">alice@example.com</saml:BaseID>"#,
    );
    let received = receive_crafted_logout_request(
        &xml,
        LogoutBinding::Post,
        LocalSloRole::Sp,
        RequestProtection::Signed,
        validation(),
    )?;
    assert!(!received.matches_sp_session(&EntityId::try_new(IDP_ENTITY_ID)?, &subject()?));
    Ok(())
}
