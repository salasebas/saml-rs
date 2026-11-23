//! respond_slo issuer checks and SLO endpoint locations.
#![cfg(crypto)]

mod common;

use common::signing_credentials;

use std::time::SystemTime;

use saml_rs::{
    EntityId, IdentityProvider, IdpConfig, IdpDescriptor, IdpValidationPolicy, Inbound,
    LogoutSubject, MetadataTrustPolicy, NameId, ReplayPolicy, RespondSlo, SamlError,
    SamlValidationContext, ServiceProvider, SessionIndex, SloEndpoint, SpConfig, SpDescriptor,
    SpValidationPolicy, SsoEndpoint, StartSlo, Status,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const OTHER_SP_ENTITY_ID: &str = "https://other.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const SP_SLO: &str = "https://sp.example.com/slo/post";
const SP_SLO_RESPONSE: &str = "https://sp.example.com/slo/response";
const IDP_SSO: &str = "https://idp.example.com/sso/post";
const IDP_SLO: &str = "https://idp.example.com/slo/post";
const IDP_SLO_SECOND: &str = "https://idp.example.com/slo/second";
const IDP_SLO_REQUEST: &str = "https://idp.example.com/slo/request";
const IDP_SLO_RESPONSE: &str = "https://idp.example.com/slo/response";

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache)
}

fn sp(validation_policy: SpValidationPolicy) -> Result<ServiceProvider, SamlError> {
    Ok(ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            saml_rs::AcsEndpoint::post(SP_ACS)?,
        )
        .slo_endpoint(SloEndpoint::post(SP_SLO)?)
        .credentials(signing_credentials())
        .validation(validation_policy)
        .build()?,
    ))
}

fn idp(
    validation_policy: IdpValidationPolicy,
    slo_urls: &[&str],
) -> Result<saml_rs::IdentityProvider, SamlError> {
    let slo_endpoints = slo_urls
        .iter()
        .map(|url| SloEndpoint::post(*url))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO)?,
        )
        .slo_endpoints(slo_endpoints)
        .credentials(signing_credentials())
        .validation(validation_policy)
        .build()?,
    ))
}

fn descriptor_pair(
    sp: &saml_rs::ServiceProvider,
    idp: &saml_rs::IdentityProvider,
) -> Result<(SpDescriptor, IdpDescriptor), SamlError> {
    Ok((
        SpDescriptor::from_metadata_xml(
            EntityId::try_new(SP_ENTITY_ID)?,
            sp.metadata_xml(),
            MetadataTrustPolicy::AllowUnsigned,
        )?,
        IdpDescriptor::from_metadata_xml(
            EntityId::try_new(IDP_ENTITY_ID)?,
            idp.metadata_xml(),
            MetadataTrustPolicy::AllowUnsigned,
        )?,
    ))
}

#[test]
fn respond_slo_rejects_a_logout_request_issuer_from_another_party(
) -> Result<(), Box<dyn std::error::Error>> {
    let service_provider = sp(SpValidationPolicy::default())?;
    let identity_provider = idp(IdpValidationPolicy::default(), &[IDP_SLO])?;
    let (sp_descriptor, idp_descriptor) = descriptor_pair(&service_provider, &identity_provider)?;
    let started = service_provider.start_slo(
        &idp_descriptor,
        LogoutSubject::new(NameId::new("alice@example.com"))
            .with_session_index(SessionIndex::try_new("_session")?),
        StartSlo::post(),
    )?;
    let received = identity_provider.receive_slo(
        &sp_descriptor,
        Inbound::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let other = SpDescriptor::from_metadata_xml(
        EntityId::try_new(OTHER_SP_ENTITY_ID)?,
        &format!(
            r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{OTHER_SP_ENTITY_ID}"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://other.example.com/slo"/><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://other.example.com/acs" index="0"/></SPSSODescriptor></EntityDescriptor>"#
        ),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    match identity_provider.respond_slo(&other, &received, &Status::success(), RespondSlo::post()) {
        Err(SamlError::IssuerMismatch {
            expected, actual, ..
        }) => {
            assert_eq!(expected, SP_ENTITY_ID);
            assert_eq!(actual.as_deref(), Some(OTHER_SP_ENTITY_ID));
        }
        other => return Err(format!("expected IssuerMismatch, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn logout_response_uses_response_location_and_request_uses_location(
) -> Result<(), Box<dyn std::error::Error>> {
    let service_provider = sp(SpValidationPolicy::default())?;
    let identity_provider = idp(IdpValidationPolicy::default(), &[IDP_SLO])?;
    let idp_for_requests = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        &format!(
            r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{IDP_ENTITY_ID}"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{IDP_SSO}"/><SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{IDP_SLO_REQUEST}" ResponseLocation="{IDP_SLO_RESPONSE}"/></IDPSSODescriptor></EntityDescriptor>"#
        ),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let started = service_provider.start_slo(
        &idp_for_requests,
        LogoutSubject::new(NameId::new("alice@example.com"))
            .with_session_index(SessionIndex::try_new("_session")?),
        StartSlo::post(),
    )?;
    assert_eq!(
        started.outbound.post_form()?.action().as_str(),
        IDP_SLO_REQUEST
    );

    let sp_for_responses = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        &service_provider.metadata_xml().replace(
            &format!(r#"Location="{SP_SLO}""#),
            &format!(r#"Location="{SP_SLO}" ResponseLocation="{SP_SLO_RESPONSE}""#),
        ),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let local_idp = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        identity_provider.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let request = service_provider.start_slo(
        &local_idp,
        LogoutSubject::new(NameId::new("alice@example.com"))
            .with_session_index(SessionIndex::try_new("_session")?),
        StartSlo::post(),
    )?;
    let received = identity_provider.receive_slo(
        &sp_for_responses,
        Inbound::post(request.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let response = identity_provider.respond_slo(
        &sp_for_responses,
        &received,
        &Status::success(),
        RespondSlo::post(),
    )?;
    assert_eq!(response.post_form()?.action().as_str(), SP_SLO_RESPONSE);

    for padded_location in [
        format!(" {SP_SLO_RESPONSE} "),
        format!("&#x9;{SP_SLO_RESPONSE}&#xD;&#xA;"),
    ] {
        let padded_metadata = sp_for_responses
            .metadata_xml()
            .replace(SP_SLO_RESPONSE, &padded_location);
        let padded_peer = SpDescriptor::from_metadata_xml(
            EntityId::try_new(SP_ENTITY_ID)?,
            &padded_metadata,
            MetadataTrustPolicy::AllowUnsigned,
        )?;
        let response = identity_provider.respond_slo(
            &padded_peer,
            &received,
            &Status::success(),
            RespondSlo::post(),
        )?;
        assert_eq!(response.post_form()?.action().as_str(), SP_SLO_RESPONSE);
    }

    let extension_metadata = sp_for_responses
        .metadata_xml()
        .replace(
            "<EntityDescriptor ",
            "<EntityDescriptor xmlns:ext=\"urn:example\" ",
        )
        .replace(" ResponseLocation=", " ext:ResponseLocation=");
    let extension_peer = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        &extension_metadata,
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let response = identity_provider.respond_slo(
        &extension_peer,
        &received,
        &Status::success(),
        RespondSlo::post(),
    )?;
    assert_eq!(response.post_form()?.action().as_str(), SP_SLO);
    Ok(())
}

#[test]
fn finish_slo_checks_the_actual_receiving_endpoint() -> Result<(), Box<dyn std::error::Error>> {
    let service_provider = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            saml_rs::AcsEndpoint::post(SP_ACS)?,
        )
        .slo_endpoint(SloEndpoint::post(SP_SLO)?)
        .slo_endpoint(SloEndpoint::post(SP_SLO_RESPONSE)?)
        .credentials(signing_credentials())
        .build()?,
    );
    let identity_provider = idp(IdpValidationPolicy::default(), &[IDP_SLO])?;
    let peer_sp = sp(SpValidationPolicy::default())?;
    let response_metadata = peer_sp.metadata_xml().replace(SP_SLO, SP_SLO_RESPONSE);
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        &response_metadata,
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let (_, idp_descriptor) = descriptor_pair(&service_provider, &identity_provider)?;
    let started = service_provider.start_slo(
        &idp_descriptor,
        LogoutSubject::new(NameId::new("alice@example.com"))
            .with_session_index(SessionIndex::try_new("_session")?),
        StartSlo::post(),
    )?;
    let received = identity_provider.receive_slo(
        &sp_descriptor,
        Inbound::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let response = identity_provider.respond_slo(
        &sp_descriptor,
        &received,
        &Status::success(),
        RespondSlo::post(),
    )?;
    let response_input =
        || -> Result<_, SamlError> { Ok(Inbound::post(response.post_form()?.fields().to_vec())) };
    let wrong_handler = service_provider.finish_slo(
        &idp_descriptor,
        &started.pending,
        response_input()?,
        validation().with_recipient_endpoint(saml_rs::EndpointUrl::try_new(SP_SLO)?),
    );
    assert!(matches!(
        wrong_handler,
        Err(SamlError::DestinationMismatch { .. })
    ));
    let ambiguous = service_provider.finish_slo(
        &idp_descriptor,
        &started.pending,
        response_input()?,
        validation(),
    );
    assert!(matches!(
        ambiguous,
        Err(SamlError::RecipientEndpointAmbiguous)
    ));
    service_provider.finish_slo(
        &idp_descriptor,
        &started.pending,
        response_input()?,
        validation().with_recipient_endpoint(saml_rs::EndpointUrl::try_new(SP_SLO_RESPONSE)?),
    )?;
    Ok(())
}

#[test]
fn slo_destination_matches_the_actual_published_receiving_endpoint(
) -> Result<(), Box<dyn std::error::Error>> {
    let service_provider = sp(SpValidationPolicy::default())?;
    let identity_provider = idp(IdpValidationPolicy::default(), &[IDP_SLO, IDP_SLO_SECOND])?;
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        service_provider.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let input = |destination: &str| -> Result<_, SamlError> {
        let peer = IdpDescriptor::from_metadata_xml(
            EntityId::try_new(IDP_ENTITY_ID)?,
            idp(IdpValidationPolicy::default(), &[destination])?.metadata_xml(),
            MetadataTrustPolicy::AllowUnsigned,
        )?;
        let subject = LogoutSubject::new(NameId::new("alice@example.com"))
            .with_session_index(SessionIndex::try_new("_session")?);
        let started = service_provider.start_slo(&peer, subject, StartSlo::post())?;
        Ok(Inbound::post(
            started.outbound.post_form()?.fields().to_vec(),
        ))
    };

    let accepted = identity_provider.receive_slo(
        &sp_descriptor,
        input(IDP_SLO_SECOND)?,
        validation().with_recipient_endpoint(saml_rs::EndpointUrl::try_new(IDP_SLO_SECOND)?),
    )?;
    assert_eq!(
        accepted.message().destination().map(|url| url.as_str()),
        Some(IDP_SLO_SECOND)
    );

    let rejected = identity_provider.receive_slo(
        &sp_descriptor,
        input("https://idp.example.com/slo/unknown")?,
        validation().with_recipient_endpoint(saml_rs::EndpointUrl::try_new(IDP_SLO)?),
    );
    match rejected {
        Err(SamlError::DestinationMismatch {
            expected, actual, ..
        }) => {
            assert_eq!(expected, IDP_SLO);
            assert_eq!(
                actual.as_deref(),
                Some("https://idp.example.com/slo/unknown")
            );
        }
        other => return Err(format!("expected DestinationMismatch, got {other:?}").into()),
    }

    let wrong_handler = identity_provider.receive_slo(
        &sp_descriptor,
        input(IDP_SLO_SECOND)?,
        validation().with_recipient_endpoint(saml_rs::EndpointUrl::try_new(IDP_SLO)?),
    );
    assert!(matches!(
        wrong_handler,
        Err(SamlError::DestinationMismatch { .. })
    ));

    let ambiguous =
        identity_provider.receive_slo(&sp_descriptor, input(IDP_SLO_SECOND)?, validation());
    assert!(matches!(
        ambiguous,
        Err(SamlError::RecipientEndpointAmbiguous)
    ));
    Ok(())
}

#[test]
fn logout_addresses_the_peer_role_of_a_dual_role_entity() -> Result<(), Box<dyn std::error::Error>>
{
    const SP_ROLE_OF_IDP_SLO: &str = "https://idp.example.com/as-sp/slo";
    const IDP_ROLE_OF_SP_SLO: &str = "https://sp.example.com/as-idp/slo";
    let service_provider = sp(SpValidationPolicy::default())?;
    let identity_provider = idp(IdpValidationPolicy::default(), &[IDP_SLO])?;
    let sp_peer = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        &service_provider.metadata_xml().replace(
            "<SPSSODescriptor ",
            &format!(
                r#"<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{IDP_ROLE_OF_SP_SLO}"/><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/as-idp/sso"/></IDPSSODescriptor><SPSSODescriptor "#
            ),
        ),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let idp_peer = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        &identity_provider.metadata_xml().replace(
            "<IDPSSODescriptor ",
            &format!(
                r#"<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{SP_ROLE_OF_IDP_SLO}"/><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/as-sp/acs" index="0"/></SPSSODescriptor><IDPSSODescriptor "#
            ),
        ),
        MetadataTrustPolicy::AllowUnsigned,
    )?;

    let started = identity_provider.start_slo(
        &sp_peer,
        LogoutSubject::new(NameId::new("alice@example.com"))
            .with_session_index(SessionIndex::try_new("_session")?),
        StartSlo::post(),
    )?;
    let request = started.outbound.post_form()?;
    assert_eq!(request.action().as_str(), SP_SLO);

    let received = service_provider.receive_slo(
        &idp_peer,
        Inbound::post(request.fields().to_vec()),
        validation(),
    )?;
    let response = service_provider.respond_slo(
        &idp_peer,
        &received,
        &Status::success(),
        RespondSlo::post(),
    )?;
    let response = response.post_form()?;
    assert_eq!(response.action().as_str(), IDP_SLO);

    identity_provider.finish_slo(
        &sp_peer,
        &started.pending,
        Inbound::post(response.fields().to_vec()),
        validation(),
    )?;
    Ok(())
}
