//! respond_slo issuer checks and SLO endpoint locations.
#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use std::time::SystemTime;

use saml_rs::binding::base64_encode;
use saml_rs::{
    BrowserInput, CertificatePem, Credentials, EntityId, FormField, IdpConfig, IdpDescriptor,
    IdpValidationPolicy, LogoutRequest, LogoutSigning, LogoutSubject, MetadataTrustPolicy, NameId,
    PrivateKeyPem, ReplayPolicy, RespondSlo, Saml, SamlError, SamlValidationContext, SessionIndex,
    SloEndpoint, SpConfig, SpDescriptor, SpValidationPolicy, SsoEndpoint, StartSlo,
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

const PRIVKEY: &str = include_str!("fixtures/key/sp_privkey.pem");
const CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");

fn credentials() -> Credentials {
    Credentials {
        signing_key: Some(PrivateKeyPem::new(PRIVKEY)),
        signing_certificate: Some(CertificatePem::new(CERT)),
        ..Credentials::default()
    }
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility)
}

fn sp(validation_policy: SpValidationPolicy) -> Result<Saml<saml_rs::Sp>, SamlError> {
    Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(saml_rs::AcsEndpoint::post(SP_ACS)?)
            .slo_endpoint(SloEndpoint::post(SP_SLO)?)
            .credentials(credentials())
            .validation(validation_policy)
            .build()?,
    )
}

fn idp(
    validation_policy: IdpValidationPolicy,
    slo_urls: &[&str],
) -> Result<Saml<saml_rs::Idp>, SamlError> {
    let mut builder = IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::post(IDP_SSO)?);
    for url in slo_urls {
        builder = builder.slo_endpoint(SloEndpoint::post(*url)?);
    }
    Saml::idp(
        builder
            .credentials(credentials())
            .validation(validation_policy)
            .build()?,
    )
}

fn descriptor_pair(
    sp: &Saml<saml_rs::Sp>,
    idp: &Saml<saml_rs::Idp>,
) -> Result<(SpDescriptor, IdpDescriptor), SamlError> {
    Ok((
        SpDescriptor::from_metadata_xml_for(
            EntityId::try_new(SP_ENTITY_ID)?,
            sp.metadata_xml(),
            MetadataTrustPolicy::UnsignedForCompatibility,
        )?,
        IdpDescriptor::from_metadata_xml_for(
            EntityId::try_new(IDP_ENTITY_ID)?,
            idp.metadata_xml(),
            MetadataTrustPolicy::UnsignedForCompatibility,
        )?,
    ))
}

#[test]
fn respond_slo_rejects_a_logout_request_issuer_from_another_party(
) -> Result<(), Box<dyn std::error::Error>> {
    let service_provider = sp(SpValidationPolicy::recommended())?;
    let identity_provider = idp(IdpValidationPolicy::recommended(), &[IDP_SLO])?;
    let (sp_descriptor, idp_descriptor) = descriptor_pair(&service_provider, &identity_provider)?;
    let started = service_provider.start_slo(
        &idp_descriptor,
        LogoutSubject::with_session_index(
            NameId::new("alice@example.com", None),
            SessionIndex::try_new("_session")?,
        ),
        StartSlo::post(),
    )?;
    let received = identity_provider.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let other = SpDescriptor::from_metadata_xml(
        &format!(
            r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{OTHER_SP_ENTITY_ID}"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://other.example.com/slo"/><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://other.example.com/acs" index="0"/></SPSSODescriptor></EntityDescriptor>"#
        ),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    match identity_provider.respond_slo(&other, &received, RespondSlo::post()) {
        Err(SamlError::IssuerMismatch { expected, actual }) => {
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
    let service_provider = sp(SpValidationPolicy::compatibility())?;
    let identity_provider = idp(IdpValidationPolicy::compatibility(), &[IDP_SLO])?;
    let idp_for_requests = IdpDescriptor::from_metadata_xml(
        &format!(
            r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{IDP_ENTITY_ID}"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{IDP_SSO}"/><SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{IDP_SLO_REQUEST}" ResponseLocation="{IDP_SLO_RESPONSE}"/></IDPSSODescriptor></EntityDescriptor>"#
        ),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let started = service_provider.start_slo(
        &idp_for_requests,
        LogoutSubject::with_session_index(
            NameId::new("alice@example.com", None),
            SessionIndex::try_new("_session")?,
        ),
        StartSlo::post().signing(LogoutSigning::DoNotSignForCompatibility),
    )?;
    assert_eq!(
        started.outbound.post_form()?.action().as_str(),
        IDP_SLO_REQUEST
    );

    let sp_for_responses = SpDescriptor::from_metadata_xml(
        &format!(
            r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{SP_ENTITY_ID}"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{SP_SLO}" ResponseLocation="{SP_SLO_RESPONSE}"/><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{SP_ACS}" index="0"/></SPSSODescriptor></EntityDescriptor>"#
        ),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let local_idp = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        identity_provider.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let request = service_provider.start_slo(
        &local_idp,
        LogoutSubject::with_session_index(
            NameId::new("alice@example.com", None),
            SessionIndex::try_new("_session")?,
        ),
        StartSlo::post().signing(LogoutSigning::DoNotSignForCompatibility),
    )?;
    let received = identity_provider.receive_slo(
        &sp_for_responses,
        BrowserInput::<LogoutRequest>::post(request.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let response =
        identity_provider.respond_slo(&sp_for_responses, &received, RespondSlo::post())?;
    assert_eq!(response.post_form()?.action().as_str(), SP_SLO_RESPONSE);

    for padded_location in [
        format!(" {SP_SLO_RESPONSE} "),
        format!("&#x9;{SP_SLO_RESPONSE}&#xD;&#xA;"),
    ] {
        let padded_metadata = sp_for_responses
            .metadata_xml()
            .replace(SP_SLO_RESPONSE, &padded_location);
        let padded_peer = SpDescriptor::from_metadata_xml(
            &padded_metadata,
            MetadataTrustPolicy::UnsignedForCompatibility,
        )?;
        let response =
            identity_provider.respond_slo(&padded_peer, &received, RespondSlo::post())?;
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
        &extension_metadata,
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let response = identity_provider.respond_slo(&extension_peer, &received, RespondSlo::post())?;
    assert_eq!(response.post_form()?.action().as_str(), SP_SLO);
    Ok(())
}

#[test]
fn finish_slo_checks_the_actual_receiving_endpoint() -> Result<(), Box<dyn std::error::Error>> {
    let service_provider = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(saml_rs::AcsEndpoint::post(SP_ACS)?)
            .slo_endpoint(SloEndpoint::post(SP_SLO)?)
            .slo_endpoint(SloEndpoint::post(SP_SLO_RESPONSE)?)
            .credentials(credentials())
            .build()?,
    )?;
    let identity_provider = idp(IdpValidationPolicy::recommended(), &[IDP_SLO])?;
    let peer_sp = sp(SpValidationPolicy::recommended())?;
    let response_metadata = peer_sp.metadata_xml().replace(SP_SLO, SP_SLO_RESPONSE);
    let sp_descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        &response_metadata,
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let (_, idp_descriptor) = descriptor_pair(&service_provider, &identity_provider)?;
    let started = service_provider.start_slo(
        &idp_descriptor,
        LogoutSubject::with_session_index(
            NameId::new("alice@example.com", None),
            SessionIndex::try_new("_session")?,
        ),
        StartSlo::post(),
    )?;
    let received = identity_provider.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let response = identity_provider.respond_slo(&sp_descriptor, &received, RespondSlo::post())?;
    let response_input = || -> Result<_, SamlError> {
        Ok(BrowserInput::<saml_rs::LogoutResponse>::post(
            response.post_form()?.fields().to_vec(),
        ))
    };
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
    assert!(matches!(ambiguous, Err(SamlError::Invalid(_))));
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
    let service_provider = sp(SpValidationPolicy::compatibility())?;
    let identity_provider = idp(
        IdpValidationPolicy::compatibility(),
        &[IDP_SLO, IDP_SLO_SECOND],
    )?;
    let sp_descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        service_provider.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let logout_request = |destination: &str| {
        format!(
            r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_logout" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="{destination}"><saml:Issuer>{SP_ENTITY_ID}</saml:Issuer><saml:NameID>alice@example.com</saml:NameID></samlp:LogoutRequest>"#
        )
    };
    let input = |xml: &str| {
        BrowserInput::<LogoutRequest>::post(vec![FormField::new(
            "SAMLRequest",
            base64_encode(xml.as_bytes()),
        )])
    };

    let accepted = identity_provider.receive_slo(
        &sp_descriptor,
        input(&logout_request(IDP_SLO_SECOND)),
        validation().with_recipient_endpoint(saml_rs::EndpointUrl::try_new(IDP_SLO_SECOND)?),
    )?;
    assert_eq!(
        accepted.message().destination().map(|url| url.as_str()),
        Some(IDP_SLO_SECOND)
    );

    let rejected = identity_provider.receive_slo(
        &sp_descriptor,
        input(&logout_request("https://idp.example.com/slo/unknown")),
        validation().with_recipient_endpoint(saml_rs::EndpointUrl::try_new(IDP_SLO)?),
    );
    match rejected {
        Err(SamlError::DestinationMismatch { expected, actual }) => {
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
        input(&logout_request(IDP_SLO_SECOND)),
        validation().with_recipient_endpoint(saml_rs::EndpointUrl::try_new(IDP_SLO)?),
    );
    assert!(matches!(
        wrong_handler,
        Err(SamlError::DestinationMismatch { .. })
    ));

    let ambiguous = identity_provider.receive_slo(
        &sp_descriptor,
        input(&logout_request(IDP_SLO_SECOND)),
        validation(),
    );
    assert!(matches!(ambiguous, Err(SamlError::Invalid(_))));
    Ok(())
}
