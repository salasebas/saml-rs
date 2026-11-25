#![cfg(crypto)]

mod common;
#[path = "common/unsigned_post.rs"]
mod unsigned_post;
use unsigned_post::unsigned_post_fields;

use common::signing_credentials;

use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::{
    AcsEndpoint, EntityId, FormField, IdentityProvider, IdpConfig, IdpDescriptor,
    IdpValidationPolicy, Inbound, LogoutResponse, LogoutSubject, MetadataTrustPolicy, NameId,
    Outbound, PendingLogoutRequest, ReplayPolicy, RespondSlo, SamlError, SamlValidationContext,
    ServiceProvider, SessionIndex, SloEndpoint, SpConfig, SpDescriptor, SpValidationPolicy,
    SsoEndpoint, StartSlo, Status,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const SP_SLO_HTTPS: &str = "https://sp.example.com/slo/post";
const SP_SLO_HTTP: &str = "http://sp.example.com/slo/post";
const IDP_SSO: &str = "https://idp.example.com/sso/post";
const IDP_SLO_HTTPS: &str = "https://idp.example.com/slo/post";
const IDP_SLO_HTTP: &str = "http://idp.example.com/slo/post";

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache)
}

fn sp(slo: &str, policy: SpValidationPolicy) -> Result<ServiceProvider, SamlError> {
    Ok(ServiceProvider::new(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?, AcsEndpoint::post(SP_ACS)?)
            .slo_endpoint(SloEndpoint::post(slo)?)
            .credentials(signing_credentials())
            .validation(policy)
            .build()?,
    ))
}

fn idp(slo: &str, policy: IdpValidationPolicy) -> Result<saml_rs::IdentityProvider, SamlError> {
    Ok(IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO)?,
        )
        .slo_endpoint(SloEndpoint::post(slo)?)
        .credentials(signing_credentials())
        .validation(policy)
        .build()?,
    ))
}

fn descriptors(
    sp: &saml_rs::ServiceProvider,
    idp: &saml_rs::IdentityProvider,
) -> Result<(SpDescriptor, IdpDescriptor), SamlError> {
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::Unverified,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::Unverified,
    )?;
    Ok((sp_descriptor, idp_descriptor))
}

fn subject_with_session() -> Result<LogoutSubject, SamlError> {
    Ok(LogoutSubject::new(NameId::new("alice@example.com"))
        .with_session_index(SessionIndex::try_new("_session")?))
}

fn subject_without_session() -> LogoutSubject {
    LogoutSubject::new(NameId::new("alice@example.com"))
}

fn post_xml<Message>(outbound: &Outbound<Message>) -> Result<String, Box<dyn std::error::Error>> {
    let form = outbound.post_form()?;
    let message = form
        .value("SAMLRequest")
        .or_else(|| form.value("SAMLResponse"))
        .ok_or("missing SAML message")?;
    Ok(String::from_utf8(STANDARD.decode(message)?)?)
}

fn post_input<Message>(outbound: &Outbound<Message>) -> Result<Vec<FormField>, SamlError> {
    Ok(outbound.post_form()?.fields().to_vec())
}

#[test]
fn session_participant_generation_rules_sign_and_require_session_index(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp(SP_SLO_HTTPS, SpValidationPolicy::default())?;
    let idp = idp(IDP_SLO_HTTPS, IdpValidationPolicy::default())?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject_with_session()?, StartSlo::post())?;
    let xml = post_xml(&started.outbound)?;

    assert!(xml.contains("SessionIndex"));
    assert!(xml.contains("ds:Signature"));
    assert!(xml.contains(&format!("<saml:Issuer>{SP_ENTITY_ID}</saml:Issuer>")));
    assert!(xml.contains(&format!("Destination=\"{IDP_SLO_HTTPS}\"")));
    assert!(!xml.contains("NotOnOrAfter"));

    match sp.start_slo(&idp_descriptor, subject_without_session(), StartSlo::post()) {
        Err(SamlError::ProtocolProfile(message)) if message.contains("SessionIndex") => Ok(()),
        other => Err(format!("expected a SessionIndex rejection, got {other:?}").into()),
    }
}

#[test]
fn logout_request_receipt_requires_a_signature() -> Result<(), Box<dyn std::error::Error>> {
    let service_provider = sp(SP_SLO_HTTPS, SpValidationPolicy::default())?;
    let identity_provider = idp(IDP_SLO_HTTP, IdpValidationPolicy::default())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&service_provider, &identity_provider)?;
    let started = service_provider.start_slo(
        &idp_descriptor,
        subject_with_session()?,
        StartSlo::post().allow_http(),
    )?;
    let input = Inbound::post(unsigned_post_fields(&started.outbound, "SAMLRequest")?);
    match identity_provider.receive_slo(&sp_descriptor, input, validation()) {
        Err(SamlError::SignatureMissing) => Ok(()),
        other => Err(format!(
            "expected the receiver to reject an unsigned LogoutRequest, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn http_logout_request_relaxes_transport_without_dropping_the_other_rules(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp(SP_SLO_HTTPS, SpValidationPolicy::default())?;
    let idp = idp(IDP_SLO_HTTP, IdpValidationPolicy::default())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    match sp.start_slo(&idp_descriptor, subject_with_session()?, StartSlo::post()) {
        Err(SamlError::ProtocolProfile(message)) if message.contains("https") => {}
        other => {
            return Err(format!("expected an https rejection, got {other:?}").into());
        }
    }

    match sp.start_slo(
        &idp_descriptor,
        subject_without_session(),
        StartSlo::post().allow_http(),
    ) {
        Err(SamlError::ProtocolProfile(message)) if message.contains("SessionIndex") => {}
        other => {
            return Err(format!("expected SessionIndex to stay required, got {other:?}").into());
        }
    }

    let started = sp.start_slo(
        &idp_descriptor,
        subject_with_session()?,
        StartSlo::post().allow_http(),
    )?;
    let xml = post_xml(&started.outbound)?;
    assert!(xml.contains("ds:Signature"));
    assert!(xml.contains("SessionIndex"));
    assert!(xml.contains(&format!("Destination=\"{IDP_SLO_HTTP}\"")));
    assert!(!xml.contains("NotOnOrAfter"));

    let received = idp.receive_slo(
        &sp_descriptor,
        Inbound::post(post_input(&started.outbound)?),
        validation(),
    )?;
    assert_eq!(
        received
            .message()
            .destination()
            .map(saml_rs::EndpointUrl::as_str),
        Some(IDP_SLO_HTTP)
    );
    Ok(())
}

#[test]
fn session_authority_keeps_expiration_and_does_not_gain_participant_duties(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp(SP_SLO_HTTP, SpValidationPolicy::default())?;
    let idp = idp(IDP_SLO_HTTPS, IdpValidationPolicy::default())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    let started = idp.start_slo(&sp_descriptor, subject_without_session(), StartSlo::post())?;
    let xml = post_xml(&started.outbound)?;
    assert!(xml.contains("NotOnOrAfter="));
    assert!(xml.contains("ds:Signature"));
    assert!(!xml.contains("SessionIndex"));
    assert!(xml.contains(&format!("Destination=\"{SP_SLO_HTTP}\"")));
    assert!(xml.contains(&format!("<saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>")));

    let received = sp.receive_slo(
        &idp_descriptor,
        Inbound::post(post_input(&started.outbound)?),
        validation(),
    )?;
    assert_eq!(
        received
            .message()
            .destination()
            .map(saml_rs::EndpointUrl::as_str),
        Some(SP_SLO_HTTP)
    );

    let participant_started =
        sp.start_slo(&idp_descriptor, subject_with_session()?, StartSlo::post())?;
    let received_by_authority = idp.receive_slo(
        &sp_descriptor,
        Inbound::post(post_input(&participant_started.outbound)?),
        validation(),
    )?;
    let response = idp.respond_slo(
        &sp_descriptor,
        &received_by_authority,
        &Status::success(),
        RespondSlo::post(),
    )?;
    let response_xml = post_xml(&response)?;
    assert!(response_xml.contains("ds:Signature"));
    assert!(response_xml.contains(&format!("Destination=\"{SP_SLO_HTTP}\"")));

    let completed = sp.finish_slo(
        &idp_descriptor,
        &participant_started.pending,
        Inbound::post(post_input(&response)?),
        validation(),
    )?;
    assert_eq!(completed.peer_entity_id().as_str(), IDP_ENTITY_ID);
    Ok(())
}

#[test]
fn session_participant_response_requires_https_unless_that_recommendation_is_relaxed(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp(SP_SLO_HTTPS, SpValidationPolicy::default())?;
    let idp = idp(IDP_SLO_HTTP, IdpValidationPolicy::default())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = idp.start_slo(&sp_descriptor, subject_with_session()?, StartSlo::post())?;
    let received = sp.receive_slo(
        &idp_descriptor,
        Inbound::post(post_input(&started.outbound)?),
        validation(),
    )?;

    match sp.respond_slo(
        &idp_descriptor,
        &received,
        &Status::success(),
        RespondSlo::post(),
    ) {
        Err(SamlError::ProtocolProfile(message)) if message.contains("https") => {}
        other => {
            return Err(format!("expected an https rejection, got {other:?}").into());
        }
    }

    let response = sp.respond_slo(
        &idp_descriptor,
        &received,
        &Status::success(),
        RespondSlo::post().allow_http(),
    )?;
    let xml = post_xml(&response)?;
    assert!(xml.contains("ds:Signature"));
    assert!(xml.contains(&format!("<saml:Issuer>{SP_ENTITY_ID}</saml:Issuer>")));
    assert!(xml.contains(&format!("Destination=\"{IDP_SLO_HTTP}\"")));

    let completed = idp.finish_slo(
        &sp_descriptor,
        &started.pending,
        Inbound::post(post_input(&response)?),
        validation(),
    )?;
    assert_eq!(completed.peer_entity_id().as_str(), SP_ENTITY_ID);
    Ok(())
}

#[test]
fn session_participant_sends_to_an_https_endpoint_listed_after_an_http_one(
) -> Result<(), Box<dyn std::error::Error>> {
    const POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    const IDP_SLO_RESPONSE_HTTP: &str = "http://idp.example.com/slo/post/response";
    const IDP_SLO_RESPONSE_HTTPS: &str = "https://idp.example.com/slo/post/response";
    let sp = sp(SP_SLO_HTTPS, SpValidationPolicy::default())?;
    let idp = idp(IDP_SLO_HTTPS, IdpValidationPolicy::default())?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    let published =
        format!(r#"<SingleLogoutService Binding="{POST}" Location="{IDP_SLO_HTTPS}"/>"#);
    let idp_metadata = idp.metadata_xml();
    if !idp_metadata.contains(&published) {
        return Err("identity provider metadata does not publish the expected endpoint".into());
    }
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        &idp_metadata.replace(
            &published,
            &format!(
                r#"<SingleLogoutService Binding="{POST}" Location="{IDP_SLO_HTTP}"/><SingleLogoutService Binding="{POST}" Location="{IDP_SLO_HTTPS}" ResponseLocation="{IDP_SLO_RESPONSE_HTTP}"/><SingleLogoutService Binding="{POST}" Location="{IDP_SLO_HTTP}" ResponseLocation="{IDP_SLO_RESPONSE_HTTPS}"/>"#
            ),
        ),
        MetadataTrustPolicy::Unverified,
    )?;

    for (options, expected) in [
        (StartSlo::post(), IDP_SLO_HTTPS),
        (StartSlo::post().allow_http(), IDP_SLO_HTTP),
    ] {
        let started = sp.start_slo(&idp_descriptor, subject_with_session()?, options)?;
        assert_eq!(started.outbound.post_form()?.action().as_str(), expected);
        let xml = post_xml(&started.outbound)?;
        assert!(
            xml.contains(&format!("Destination=\"{expected}\"")),
            "{xml}"
        );
    }

    let started = idp.start_slo(&sp_descriptor, subject_with_session()?, StartSlo::post())?;
    let received = sp.receive_slo(
        &idp_descriptor,
        Inbound::post(post_input(&started.outbound)?),
        validation(),
    )?;
    for (options, expected) in [
        (RespondSlo::post(), IDP_SLO_RESPONSE_HTTPS),
        (RespondSlo::post().allow_http(), IDP_SLO_HTTP),
    ] {
        let response = sp.respond_slo(&idp_descriptor, &received, &Status::success(), options)?;
        assert_eq!(response.post_form()?.action().as_str(), expected);
        let xml = post_xml(&response)?;
        assert!(
            xml.contains(&format!("Destination=\"{expected}\"")),
            "{xml}"
        );
    }
    Ok(())
}

#[test]
fn finish_slo_requires_a_logout_response_signature() -> Result<(), Box<dyn std::error::Error>> {
    finish_rejects_unsigned_response(LocalRole::Sp)?;
    finish_rejects_unsigned_response(LocalRole::Idp)?;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum LocalRole {
    Sp,
    Idp,
}

struct SignedLogoutExchange {
    response: Outbound<LogoutResponse>,
    pending: PendingLogoutRequest,
    service_provider: saml_rs::ServiceProvider,
    identity_provider: saml_rs::IdentityProvider,
    sp_descriptor: SpDescriptor,
    idp_descriptor: IdpDescriptor,
}

fn finish_rejects_unsigned_response(role: LocalRole) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = signed_logout_response(role)?;
    let SignedLogoutExchange {
        response,
        pending,
        service_provider,
        identity_provider,
        sp_descriptor,
        idp_descriptor,
    } = exchange;
    let unsigned = unsigned_post_fields(&response, "SAMLResponse")?;
    let accept_finish = match role {
        LocalRole::Sp => service_provider.finish_slo(
            &idp_descriptor,
            &pending,
            Inbound::post(unsigned),
            validation(),
        ),
        LocalRole::Idp => identity_provider.finish_slo(
            &sp_descriptor,
            &pending,
            Inbound::post(unsigned),
            validation(),
        ),
    };
    match accept_finish {
        Err(SamlError::SignatureMissing) => {}
        other => {
            return Err(format!("expected SignatureMissing for {role:?}, got {other:?}").into());
        }
    }

    Ok(())
}

fn signed_logout_response(
    finishing_role: LocalRole,
) -> Result<SignedLogoutExchange, Box<dyn std::error::Error>> {
    let sp = sp(SP_SLO_HTTPS, SpValidationPolicy::default())?;
    let idp = idp(IDP_SLO_HTTPS, IdpValidationPolicy::default())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let (response, pending) = match finishing_role {
        LocalRole::Sp => {
            let started =
                sp.start_slo(&idp_descriptor, subject_with_session()?, StartSlo::post())?;
            let received = idp.receive_slo(
                &sp_descriptor,
                Inbound::post(post_input(&started.outbound)?),
                validation(),
            )?;
            let response = idp.respond_slo(
                &sp_descriptor,
                &received,
                &Status::success(),
                RespondSlo::post(),
            )?;
            (response, started.pending)
        }
        LocalRole::Idp => {
            let started =
                idp.start_slo(&sp_descriptor, subject_without_session(), StartSlo::post())?;
            let received = sp.receive_slo(
                &idp_descriptor,
                Inbound::post(post_input(&started.outbound)?),
                validation(),
            )?;
            let response = sp.respond_slo(
                &idp_descriptor,
                &received,
                &Status::success(),
                RespondSlo::post(),
            )?;
            (response, started.pending)
        }
    };
    Ok(SignedLogoutExchange {
        response,
        pending,
        service_provider: sp,
        identity_provider: idp,
        sp_descriptor,
        idp_descriptor,
    })
}
