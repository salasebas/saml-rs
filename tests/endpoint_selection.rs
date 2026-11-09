//! Default ACS selection and every published SSO location.
#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use std::time::SystemTime;

use saml_rs::binding::base64_encode;
use saml_rs::{
    AcsEndpoint, AuthnRequest, BrowserInput, CertificatePem, Credentials, EndpointUrl, EntityId,
    FormField, IdpConfig, IdpDescriptor, IdpValidationPolicy, MetadataTrustPolicy, NameId,
    PrivateKeyPem, ReplayPolicy, RespondSso, Saml, SamlError, SamlValidationContext, SpConfig,
    SpDescriptor, SpValidationPolicy, SsoEndpoint, StartSso, Subject,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const FIRST_ACS: &str = "https://sp.example.com/acs/first";
const DEFAULT_ACS: &str = "https://sp.example.com/acs/default";
const IDP_SSO_FIRST: &str = "https://idp.example.com/sso/first";
const IDP_SSO_SECOND: &str = "https://idp.example.com/sso/second";

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

fn subject() -> Subject {
    Subject::new(NameId::new("alice@example.com", None), Vec::new())
}

fn sp_with_default_acs() -> Result<Saml<saml_rs::Sp>, SamlError> {
    Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(FIRST_ACS)?.with_index(0))
            .acs_endpoint(AcsEndpoint::post(DEFAULT_ACS)?.with_index(1).mark_default())
            .credentials(credentials())
            .validation(SpValidationPolicy::compatibility())
            .build()?,
    )
}

fn idp_with_sso(urls: &[&str]) -> Result<Saml<saml_rs::Idp>, SamlError> {
    let mut builder = IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?);
    for url in urls {
        builder = builder.sso_endpoint(SsoEndpoint::post(*url)?);
    }
    Saml::idp(
        builder
            .credentials(credentials())
            .validation(IdpValidationPolicy::compatibility())
            .build()?,
    )
}

fn descriptors(
    sp: &Saml<saml_rs::Sp>,
    idp: &Saml<saml_rs::Idp>,
) -> Result<(SpDescriptor, IdpDescriptor), SamlError> {
    let sp_descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    Ok((sp_descriptor, idp_descriptor))
}

fn authn_request(destination: &str) -> String {
    format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_authn" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="{destination}"><saml:Issuer>{SP_ENTITY_ID}</saml:Issuer></samlp:AuthnRequest>"#
    )
}

fn post_authn_request(xml: &str) -> BrowserInput<AuthnRequest> {
    BrowserInput::<AuthnRequest>::post(vec![FormField::new(
        "SAMLRequest",
        base64_encode(xml.as_bytes()),
    )])
}

#[test]
fn default_assertion_consumer_service_is_selected_when_the_request_names_neither(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with_default_acs()?;
    let idp = idp_with_sso(&[IDP_SSO_FIRST])?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    assert_eq!(
        received.message().acs_url().map(|url| url.as_str()),
        Some(DEFAULT_ACS)
    );

    let unsolicited = idp.initiate_sso(&sp_descriptor, subject(), RespondSso::post())?;
    assert_eq!(unsolicited.post_form()?.action().as_str(), DEFAULT_ACS);

    let unspecified = idp.receive_sso(
        &sp_descriptor,
        post_authn_request(&authn_request(IDP_SSO_FIRST)),
        validation(),
    )?;
    assert_eq!(unspecified.message().acs_url(), None);
    assert_eq!(unspecified.message().acs_index(), None);
    let response = idp.respond_sso(&sp_descriptor, &unspecified, subject(), RespondSso::post())?;
    assert_eq!(response.post_form()?.action().as_str(), DEFAULT_ACS);

    let cross_binding_sp = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(FIRST_ACS)?.with_index(0))
            .acs_endpoint(
                AcsEndpoint::simple_sign(DEFAULT_ACS)?
                    .with_index(1)
                    .mark_default(),
            )
            .credentials(credentials())
            .validation(SpValidationPolicy::compatibility())
            .build()?,
    )?;
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
            subject(),
            RespondSso::post(),
        ),
        Err(SamlError::Invalid(_))
    ));
    let response = idp.respond_sso(
        &cross_binding_descriptor,
        &unspecified,
        subject(),
        RespondSso::simple_sign(),
    )?;
    assert_eq!(response.post_form()?.action().as_str(), DEFAULT_ACS);
    assert!(matches!(
        idp.initiate_sso(&cross_binding_descriptor, subject(), RespondSso::post()),
        Err(SamlError::Invalid(_))
    ));
    let unsolicited = idp.initiate_sso(
        &cross_binding_descriptor,
        subject(),
        RespondSso::simple_sign(),
    )?;
    assert_eq!(unsolicited.post_form()?.action().as_str(), DEFAULT_ACS);

    let unsupported_metadata = cross_binding_sp.metadata_xml().replace(
        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign",
        "urn:example:unsupported-binding",
    );
    let unsupported_descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        &unsupported_metadata,
        MetadataTrustPolicy::UnsignedForCompatibility,
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
            subject(),
            RespondSso::post(),
        ),
        Err(SamlError::Invalid(_))
    ));
    assert!(matches!(
        idp.initiate_sso(&unsupported_descriptor, subject(), RespondSso::post()),
        Err(SamlError::Invalid(_))
    ));

    let saml2_role = format!(
        r#"<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{FIRST_ACS}" index="0"/></SPSSODescriptor>"#
    );
    let saml1_role = r#"<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol"><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:1.0:profiles:browser-post" Location="https://sp.example.com/saml1/acs" index="0" isDefault="true"/></SPSSODescriptor>"#;
    for roles in [
        saml2_role.clone(),
        format!("{saml2_role}{saml1_role}"),
        format!("{saml1_role}{saml2_role}"),
    ] {
        let metadata = format!(
            r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{SP_ENTITY_ID}">{roles}</EntityDescriptor>"#
        );
        let descriptor = SpDescriptor::from_metadata_xml_for(
            EntityId::try_new(SP_ENTITY_ID)?,
            &metadata,
            MetadataTrustPolicy::UnsignedForCompatibility,
        )?;
        let unspecified = idp.receive_sso(
            &descriptor,
            post_authn_request(&authn_request(IDP_SSO_FIRST)),
            validation(),
        )?;
        assert_eq!(unspecified.message().acs_url(), None);
        assert_eq!(unspecified.message().acs_index(), None);
        let response = idp.respond_sso(&descriptor, &unspecified, subject(), RespondSso::post())?;
        assert_eq!(response.post_form()?.action().as_str(), FIRST_ACS);
        let unsolicited = idp.initiate_sso(&descriptor, subject(), RespondSso::post())?;
        assert_eq!(unsolicited.post_form()?.action().as_str(), FIRST_ACS);
    }
    Ok(())
}

#[test]
fn sso_destination_matches_the_actual_published_receiving_endpoint(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with_default_acs()?;
    let idp = idp_with_sso(&[IDP_SSO_FIRST, IDP_SSO_SECOND])?;
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
        Err(SamlError::DestinationMismatch { expected, actual }) => {
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
    assert!(matches!(ambiguous, Err(SamlError::Invalid(_))));
    Ok(())
}
