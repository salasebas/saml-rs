//! Identity-provider receipt of an `AuthnRequest` from a service provider
//! whose metadata sets `AuthnRequestsSigned`.
//!
//! SAML Metadata §2.4.4 as amended by Errata 05 E7.
#![cfg(crypto)]

mod common;

#[path = "common/tag_prefixes.rs"]
mod tag_prefixes;

use common::signing_credentials;

use std::time::SystemTime;

use base64::Engine;
use saml_rs::{
    AcsEndpoint, AuthnRequest, AuthnRequestSigningPolicy, EntityId, IdentityProvider, IdpConfig,
    IdpDescriptor, IdpValidationPolicy, Inbound, MetadataTrustPolicy, Outbound, ReplayPolicy,
    SamlError, SamlValidationContext, ServiceProvider, SpConfig, SpDescriptor, SpValidationPolicy,
    SsoEndpoint, StartSso,
};
use url::Url;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const IDP_SSO_REDIRECT: &str = "https://idp.example.com/sso/redirect";

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache)
}

fn sp(
    authn_request_signing: AuthnRequestSigningPolicy,
) -> Result<saml_rs::ServiceProvider, SamlError> {
    let mut validation = SpValidationPolicy::default();
    validation.authn_request_signing = authn_request_signing;
    Ok(ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(SP_ACS)?.with_default(),
        )
        .templates(tag_prefixes::templates("p", "a"))
        .credentials(signing_credentials())
        .validation(validation)
        .build()?,
    ))
}

fn idp(validation: IdpValidationPolicy) -> Result<saml_rs::IdentityProvider, SamlError> {
    Ok(IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO_POST)?,
        )
        .sso_endpoint(SsoEndpoint::redirect(IDP_SSO_REDIRECT)?)
        .sso_endpoint(SsoEndpoint::simple_sign(IDP_SSO_POST)?)
        .credentials(signing_credentials())
        .validation(validation)
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
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    Ok((sp_descriptor, idp_descriptor))
}

fn post_input(
    outbound: &Outbound<AuthnRequest>,
) -> Result<Inbound<AuthnRequest>, Box<dyn std::error::Error>> {
    Ok(Inbound::post(outbound.post_form()?.fields().to_vec()))
}

fn redirect_input(
    outbound: &Outbound<AuthnRequest>,
) -> Result<Inbound<AuthnRequest>, Box<dyn std::error::Error>> {
    let url = Url::parse(outbound.redirect_url()?)?;
    Ok(Inbound::redirect(url.query().unwrap_or_default()))
}

#[test]
fn unsigned_browser_request_is_rejected_when_sp_metadata_sets_authn_requests_signed(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_sp = sp(AuthnRequestSigningPolicy::Sign)?;
    let unsigned_sp = sp(AuthnRequestSigningPolicy::DoNotSign)?;
    let idp = idp(IdpValidationPolicy::default())?;
    let (signing_descriptor, idp_descriptor) = descriptors(&signing_sp, &idp)?;
    assert!(signing_sp
        .metadata_xml()
        .contains("AuthnRequestsSigned=\"true\""));

    let unsigned_post = unsigned_sp.start_sso(&idp_descriptor, StartSso::post())?;
    let unsigned_redirect = unsigned_sp.start_sso(&idp_descriptor, StartSso::redirect())?;
    for input in [
        post_input(&unsigned_post.outbound)?,
        Inbound::simple_sign(unsigned_post.outbound.post_form()?.fields().to_vec()),
        redirect_input(&unsigned_redirect.outbound)?,
    ] {
        match idp.receive_sso(&signing_descriptor, input, validation()) {
            Err(SamlError::SignatureMissing) => {}
            other => return Err(format!("expected SignatureMissing, got {other:?}").into()),
        }
    }

    let signed_post = signing_sp.start_sso(&idp_descriptor, StartSso::post())?;
    let encoded = signed_post
        .outbound
        .post_form()?
        .value("SAMLRequest")
        .ok_or("missing SAMLRequest")?;
    let xml = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(encoded)?)?;
    assert!(xml.contains("<p:AuthnRequest ") && xml.contains("<a:Issuer>"));
    let signed_redirect = signing_sp.start_sso(&idp_descriptor, StartSso::redirect())?;
    for (started, input) in [
        (&signed_post, post_input(&signed_post.outbound)?),
        (
            &signed_post,
            Inbound::simple_sign(signed_post.outbound.post_form()?.fields().to_vec()),
        ),
        (&signed_redirect, redirect_input(&signed_redirect.outbound)?),
    ] {
        let received = idp.receive_sso(&signing_descriptor, input, validation())?;
        assert_eq!(received.message().id(), started.pending.request_id());
    }

    let (unsigned_descriptor, _) = descriptors(&unsigned_sp, &idp)?;
    let received = idp.receive_sso(
        &unsigned_descriptor,
        Inbound::simple_sign(unsigned_post.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    assert_eq!(received.message().id(), unsigned_post.pending.request_id());
    Ok(())
}
