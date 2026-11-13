#![cfg(crypto)]
use saml_rs::{
    AcsEndpoint, AuthnRequest, CertificatePem, Credentials, EntityId, IdpConfig, IdpConfigBuilder,
    IdpDescriptor, IdpValidationPolicy, LogoutRequest, LogoutSubject, MetadataTrustPolicy, NameId,
    Outbound, PendingAuthnRequest, PendingLogoutRequest, PendingSnapshot, PrivateKeyPem, Saml,
    SamlError, SloEndpoint, SpConfig, SpConfigBuilder, SpValidationPolicy, SsoEndpoint, StartSlo,
    StartSso, Started,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS_POST: &str = "https://sp.example.com/acs/post";
const SP_SLO_POST: &str = "https://sp.example.com/slo/post";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const IDP_SLO_POST: &str = "https://idp.example.com/slo/post";

const PRIVKEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");

fn assert_send_sync<T: Send + Sync>() {}

fn credentials() -> Credentials {
    Credentials {
        signing_key: Some(PrivateKeyPem::new(PRIVKEY)),
        signing_certificate: Some(CertificatePem::new(CERT)),
        ..Credentials::default()
    }
}

fn sp_config() -> Result<SpConfig, SamlError> {
    SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
        .acs_endpoint(AcsEndpoint::post(SP_ACS_POST)?)
        .slo_endpoint(SloEndpoint::post(SP_SLO_POST)?)
        .credentials(credentials())
        .validation(SpValidationPolicy::recommended())
        .build()
}

fn idp_config() -> Result<IdpConfig, SamlError> {
    IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
        .slo_endpoint(SloEndpoint::post(IDP_SLO_POST)?)
        .credentials(credentials())
        .validation(IdpValidationPolicy::recommended())
        .build()
}

#[test]
fn builder_entrypoints_construct_facades_without_raw_mutation(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = Saml::sp(sp_config()?)?;
    let idp = Saml::idp(idp_config()?)?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;

    let sso = sp.start_sso(&idp_descriptor, StartSso::post())?;
    assert_eq!(sso.outbound.post_form()?.action().as_str(), IDP_SSO_POST);
    assert_eq!(sso.pending.request_id(), sso.outbound.id());
    assert_eq!(sso.pending.idp_entity_id().as_str(), IDP_ENTITY_ID);

    let logout_subject = LogoutSubject::from_name_id(NameId::new("alice@example.com", None));
    let slo = sp.start_slo(&idp_descriptor, logout_subject, StartSlo::post())?;
    assert_eq!(slo.outbound.post_form()?.action().as_str(), IDP_SLO_POST);
    assert_eq!(slo.pending.id(), slo.outbound.id());
    assert_eq!(slo.pending.peer_entity_id().as_str(), IDP_ENTITY_ID);
    Ok(())
}

#[test]
fn facade_builder_and_browser_values_are_send_sync() {
    assert_send_sync::<Saml<saml_rs::Sp>>();
    assert_send_sync::<Saml<saml_rs::Idp>>();
    assert_send_sync::<SpConfigBuilder>();
    assert_send_sync::<IdpConfigBuilder>();
    assert_send_sync::<PendingAuthnRequest>();
    assert_send_sync::<PendingSnapshot<AuthnRequest>>();
    assert_send_sync::<PendingLogoutRequest>();
    assert_send_sync::<PendingSnapshot<LogoutRequest>>();
    assert_send_sync::<Outbound<AuthnRequest>>();
    assert_send_sync::<Outbound<LogoutRequest>>();
    assert_send_sync::<Started<AuthnRequest>>();
    assert_send_sync::<Started<LogoutRequest>>();
}
