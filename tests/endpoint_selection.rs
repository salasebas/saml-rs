//! Default ACS selection and every published SSO location.
#![cfg(crypto)]

mod common;

use common::signing_credentials;

use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::constants::Binding;
use saml_rs::{
    AcsEndpoint, ArtifactDelivery, ArtifactResolutionService, AuthnRequest, EndpointUrl, EntityId,
    FormField, IdentityProvider, IdpConfig, IdpDescriptor, Inbound, IssuedArtifacts,
    MetadataTrustPolicy, NameId, ReplayPolicy, RespondSso, SamlError, SamlValidationContext,
    ServiceProvider, SpConfig, SpDescriptor, SsoAssertion, SsoEndpoint, SsoResponseBinding,
    StartSso,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const FIRST_ACS: &str = "https://sp.example.com/acs/first";
const DEFAULT_ACS: &str = "https://sp.example.com/acs/default";
const IDP_SSO_FIRST: &str = "https://idp.example.com/sso/first";
const IDP_SSO_SECOND: &str = "https://idp.example.com/sso/second";

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache)
}

fn principal() -> NameId {
    NameId::new("alice@example.com")
}

fn sp_with_default_acs() -> Result<saml_rs::ServiceProvider, SamlError> {
    Ok(ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(FIRST_ACS)?.with_index(0),
        )
        .acs_endpoint(AcsEndpoint::post(DEFAULT_ACS)?.with_index(1).with_default())
        .credentials(signing_credentials())
        .build()?,
    ))
}

fn idp_with_sso(first: &str, more: &[&str]) -> Result<saml_rs::IdentityProvider, SamlError> {
    let more = more
        .iter()
        .map(|url| SsoEndpoint::post(*url))
        .collect::<Result<Vec<_>, _>>()?;
    let builder = IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?, SsoEndpoint::post(first)?)
        .sso_endpoints(more);
    Ok(IdentityProvider::new(
        builder.credentials(signing_credentials()).build()?,
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

fn authn_request(destination: &str) -> String {
    format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_authn" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="{destination}"><saml:Issuer>{SP_ENTITY_ID}</saml:Issuer></samlp:AuthnRequest>"#
    )
}

fn post_authn_request(xml: &str) -> Inbound<AuthnRequest> {
    Inbound::post(vec![FormField::new(
        "SAMLRequest",
        STANDARD.encode(xml.as_bytes()),
    )])
}

#[test]
fn default_assertion_consumer_service_is_selected_when_the_request_names_neither(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with_default_acs()?;
    let idp = idp_with_sso(IDP_SSO_FIRST, &[])?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    assert_eq!(
        received.message().acs_url().map(|url| url.as_str()),
        Some(DEFAULT_ACS)
    );

    let unsolicited = idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    )?;
    assert_eq!(unsolicited.post_form()?.action().as_str(), DEFAULT_ACS);

    let unspecified = idp.receive_sso(
        &sp_descriptor,
        post_authn_request(&authn_request(IDP_SSO_FIRST)),
        validation(),
    )?;
    assert_eq!(unspecified.message().acs_url(), None);
    assert_eq!(unspecified.message().acs_index(), None);
    let response = idp.respond_sso(
        &sp_descriptor,
        &unspecified,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    )?;
    assert_eq!(response.post_form()?.action().as_str(), DEFAULT_ACS);

    let cross_binding_sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(FIRST_ACS)?.with_index(0),
        )
        .acs_endpoint(
            AcsEndpoint::simple_sign(DEFAULT_ACS)?
                .with_index(1)
                .with_default(),
        )
        .credentials(signing_credentials())
        .build()?,
    );
    let (cross_binding_descriptor, _) = descriptors(&cross_binding_sp, &idp)?;
    let unspecified = idp.receive_sso(
        &cross_binding_descriptor,
        post_authn_request(&authn_request(IDP_SSO_FIRST)),
        validation(),
    )?;
    assert_eq!(unspecified.message().protocol_binding(), None);
    assert!(matches!(
        idp.respond_sso(
            &cross_binding_descriptor,
            &unspecified,
            SsoAssertion::new(principal()),
            RespondSso::post()
        ),
        Err(SamlError::Invalid(_))
    ));
    let response = idp.respond_sso(
        &cross_binding_descriptor,
        &unspecified,
        SsoAssertion::new(principal()),
        RespondSso::simple_sign(),
    )?;
    assert_eq!(response.post_form()?.action().as_str(), DEFAULT_ACS);
    assert!(matches!(
        idp.initiate_sso(
            &cross_binding_descriptor,
            SsoAssertion::new(principal()),
            RespondSso::post()
        ),
        Err(SamlError::Invalid(_))
    ));
    let unsolicited = idp.initiate_sso(
        &cross_binding_descriptor,
        SsoAssertion::new(principal()),
        RespondSso::simple_sign(),
    )?;
    assert_eq!(unsolicited.post_form()?.action().as_str(), DEFAULT_ACS);

    let unsupported_metadata = cross_binding_sp.metadata_xml().replace(
        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign",
        "urn:example:unsupported-binding",
    );
    let unsupported_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        &unsupported_metadata,
        MetadataTrustPolicy::Unverified,
    )?;
    let unspecified = idp.receive_sso(
        &unsupported_descriptor,
        post_authn_request(&authn_request(IDP_SSO_FIRST)),
        validation(),
    )?;
    assert!(matches!(
        idp.respond_sso(
            &unsupported_descriptor,
            &unspecified,
            SsoAssertion::new(principal()),
            RespondSso::post()
        ),
        Err(SamlError::Invalid(_))
    ));
    assert!(matches!(
        idp.initiate_sso(
            &unsupported_descriptor,
            SsoAssertion::new(principal()),
            RespondSso::post()
        ),
        Err(SamlError::Invalid(_))
    ));

    let saml2_role = format!(
        r#"<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{FIRST_ACS}" index="0"/></SPSSODescriptor>"#
    );
    let saml1_role = r#"<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol"><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:1.0:profiles:browser-post" Location="https://sp.example.com/saml1/acs" index="0" isDefault="true"/></SPSSODescriptor>"#;
    let second_saml2_role = format!(
        r#"<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{DEFAULT_ACS}" index="1" isDefault="true"/></SPSSODescriptor>"#
    );
    for roles in [
        saml2_role.clone(),
        format!("{saml2_role}{saml1_role}"),
        format!("{saml1_role}{saml2_role}"),
        format!("{saml2_role}{second_saml2_role}"),
    ] {
        let metadata = format!(
            r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{SP_ENTITY_ID}">{roles}</EntityDescriptor>"#
        );
        let descriptor = SpDescriptor::from_metadata_xml(
            EntityId::try_new(SP_ENTITY_ID)?,
            &metadata,
            MetadataTrustPolicy::Unverified,
        )?;
        let unspecified = idp.receive_sso(
            &descriptor,
            post_authn_request(&authn_request(IDP_SSO_FIRST)),
            validation(),
        )?;
        assert_eq!(unspecified.message().acs_url(), None);
        assert_eq!(unspecified.message().acs_index(), None);
        let response = idp.respond_sso(
            &descriptor,
            &unspecified,
            SsoAssertion::new(principal()),
            RespondSso::post(),
        )?;
        assert_eq!(response.post_form()?.action().as_str(), FIRST_ACS);
        let unsolicited = idp.initiate_sso(
            &descriptor,
            SsoAssertion::new(principal()),
            RespondSso::post(),
        )?;
        assert_eq!(unsolicited.post_form()?.action().as_str(), FIRST_ACS);
    }
    Ok(())
}

#[test]
fn protocol_binding_alone_uses_the_binding_default() -> Result<(), Box<dyn std::error::Error>> {
    let idp = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO_FIRST)?,
        )
        .artifact_resolution_service(ArtifactResolutionService::new(
            0,
            EndpointUrl::try_new("https://idp.example.com/artifact")?,
        ))
        .credentials(signing_credentials())
        .build()?,
    );
    for binding in [
        SsoResponseBinding::Post,
        SsoResponseBinding::SimpleSign,
        SsoResponseBinding::Artifact,
    ] {
        let global_binding = match binding {
            SsoResponseBinding::Post => SsoResponseBinding::SimpleSign,
            SsoResponseBinding::SimpleSign | SsoResponseBinding::Artifact => {
                SsoResponseBinding::Post
            }
            _ => return Err("unsupported response binding".into()),
        };
        let sp = ServiceProvider::new(
            SpConfig::builder(
                EntityId::try_new(SP_ENTITY_ID)?,
                AcsEndpoint::new(global_binding, EndpointUrl::try_new(DEFAULT_ACS)?)
                    .with_index(0)
                    .with_default(),
            )
            .acs_endpoint(AcsEndpoint::new(binding, EndpointUrl::try_new(FIRST_ACS)?).with_index(1))
            .credentials(signing_credentials())
            .build()?,
        );
        let (sp_descriptor, _) = descriptors(&sp, &idp)?;
        let xml = authn_request(IDP_SSO_FIRST).replace(
            " Version=",
            &format!(
                " ProtocolBinding=\"{}\" Version=",
                Binding::from(binding).urn()
            ),
        );
        let request = idp.receive_sso(&sp_descriptor, post_authn_request(&xml), validation())?;
        assert_eq!(request.message().acs_url(), None);
        assert_eq!(request.message().acs_index(), None);
        assert_eq!(request.message().protocol_binding(), Some(binding));
        match binding {
            SsoResponseBinding::Post | SsoResponseBinding::SimpleSign => {
                let options = if binding == SsoResponseBinding::Post {
                    RespondSso::post()
                } else {
                    RespondSso::simple_sign()
                };
                let response = idp.respond_sso(
                    &sp_descriptor,
                    &request,
                    SsoAssertion::new(principal()),
                    options,
                )?;
                assert_eq!(response.post_form()?.action().as_str(), FIRST_ACS);
            }
            SsoResponseBinding::Artifact => {
                let mut issued = IssuedArtifacts::expire_after(std::time::Duration::from_secs(60));
                let response = idp.respond_sso_artifact(
                    &sp_descriptor,
                    &request,
                    SsoAssertion::new(principal()),
                    RespondSso::artifact(ArtifactDelivery::redirect(0)),
                    &mut issued,
                )?;
                assert_eq!(
                    url::Url::parse(response.redirect_url()?)?.path(),
                    "/acs/first"
                );
            }
            _ => return Err("unsupported response binding".into()),
        }
    }
    Ok(())
}

#[test]
fn conflicting_request_acs_selectors_are_not_answered() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with_default_acs()?;
    let idp = idp_with_sso(IDP_SSO_FIRST, &[])?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    for (selector, options, expected) in [
        (
            format!(
                " AssertionConsumerServiceURL=\"{DEFAULT_ACS}\" AssertionConsumerServiceIndex=\"0\""
            ),
            RespondSso::post(),
            "AuthnRequest must not specify both ACS URL and ACS index",
        ),
        (
            " AssertionConsumerServiceIndex=\"0\"".to_string(),
            RespondSso::simple_sign(),
            "response binding conflicts with AuthnRequest ACS index",
        ),
    ] {
        let xml =
            authn_request(IDP_SSO_FIRST).replace(" Version=", &format!("{selector} Version="));
        let request = idp.receive_sso(&sp_descriptor, post_authn_request(&xml), validation())?;
        match idp.respond_sso(
            &sp_descriptor,
            &request,
            SsoAssertion::new(principal()),
            options,
        ) {
            Err(SamlError::Invalid(message)) => assert_eq!(message, expected),
            other => return Err(format!("expected Invalid({expected}), got {other:?}").into()),
        }
    }
    Ok(())
}

#[test]
fn a_response_is_not_sent_to_an_unpublished_request_acs() -> Result<(), Box<dyn std::error::Error>>
{
    let sp = sp_with_default_acs()?;
    let idp = idp_with_sso(IDP_SSO_FIRST, &[])?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    let unpublished = "https://sp.example.com/acs/unpublished";
    let xml = authn_request(IDP_SSO_FIRST).replace(
        " Version=",
        &format!(" AssertionConsumerServiceURL=\"{unpublished}\" Version="),
    );
    let request = idp.receive_sso(&sp_descriptor, post_authn_request(&xml), validation())?;
    match idp.respond_sso(
        &sp_descriptor,
        &request,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    ) {
        Err(SamlError::DestinationMismatch {
            expected, actual, ..
        }) => {
            assert_eq!(expected, unpublished);
            assert_eq!(actual.as_deref(), Some(DEFAULT_ACS));
        }
        other => return Err(format!("expected DestinationMismatch, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn sso_destination_matches_the_actual_published_receiving_endpoint(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with_default_acs()?;
    let idp = idp_with_sso(IDP_SSO_FIRST, &[IDP_SSO_SECOND])?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;

    let accepted = idp.receive_sso(
        &sp_descriptor,
        post_authn_request(&authn_request(IDP_SSO_SECOND)),
        validation().with_recipient_endpoint(EndpointUrl::try_new(IDP_SSO_SECOND)?),
    )?;
    assert_eq!(
        accepted.message().destination().map(|url| url.as_str()),
        Some(IDP_SSO_SECOND)
    );

    let rejected = idp.receive_sso(
        &sp_descriptor,
        post_authn_request(&authn_request("https://idp.example.com/sso/unknown")),
        validation().with_recipient_endpoint(EndpointUrl::try_new(IDP_SSO_FIRST)?),
    );
    match rejected {
        Err(SamlError::DestinationMismatch {
            expected, actual, ..
        }) => {
            assert_eq!(expected, IDP_SSO_FIRST);
            assert_eq!(
                actual.as_deref(),
                Some("https://idp.example.com/sso/unknown")
            );
        }
        other => return Err(format!("expected DestinationMismatch, got {other:?}").into()),
    }

    let wrong_handler = idp.receive_sso(
        &sp_descriptor,
        post_authn_request(&authn_request(IDP_SSO_SECOND)),
        validation().with_recipient_endpoint(EndpointUrl::try_new(IDP_SSO_FIRST)?),
    );
    assert!(matches!(
        wrong_handler,
        Err(SamlError::DestinationMismatch { .. })
    ));

    let ambiguous = idp.receive_sso(
        &sp_descriptor,
        post_authn_request(&authn_request(IDP_SSO_SECOND)),
        validation(),
    );
    assert!(matches!(
        ambiguous,
        Err(SamlError::RecipientEndpointAmbiguous)
    ));
    Ok(())
}
