//! Identity-provider receipt of an `AuthnRequest` from a service provider
//! whose metadata sets `AuthnRequestsSigned`.
//!
//! SAML Metadata §2.4.4 as amended by Errata 05 E7.
#![cfg(crypto)]

mod common;

use common::signing_credentials;

use std::time::SystemTime;

use saml_rs::{
    AcsEndpoint, AuthnRequest, AuthnRequestSigningPolicy, EndpointUrl, EntityId, IdpConfig,
    IdpDescriptor, IdpValidationPolicy, Inbound, MetadataTrustPolicy, Outbound, ReplayPolicy, Saml,
    SamlError, SamlValidationContext, SpConfig, SpDescriptor, SpValidationPolicy, SsoEndpoint,
    StartPaosSso, StartSso,
};
use url::Url;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const IDP_SSO_REDIRECT: &str = "https://idp.example.com/sso/redirect";
const IDP_SOAP: &str = "https://idp.example.com/sso/soap";
const SOAP_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::Disabled)
}

fn sp(authn_requests: AuthnRequestSigningPolicy) -> Result<Saml<saml_rs::Sp>, SamlError> {
    let mut validation = SpValidationPolicy::recommended();
    validation.authn_requests = authn_requests;
    Ok(Saml::sp(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(SP_ACS)?.with_default(),
        )
        .credentials(signing_credentials())
        .validation(validation)
        .build()?,
    ))
}

fn idp(validation: IdpValidationPolicy) -> Result<Saml<saml_rs::Idp>, SamlError> {
    Ok(Saml::idp(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO_POST)?,
        )
        .sso_endpoint(SsoEndpoint::redirect(IDP_SSO_REDIRECT)?)
        .credentials(signing_credentials())
        .validation(validation)
        .build()?,
    ))
}

fn descriptors(
    sp: &Saml<saml_rs::Sp>,
    idp: &Saml<saml_rs::Idp>,
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

fn envelope_for_idp(sp_soap: &str) -> Result<String, Box<dyn std::error::Error>> {
    let document = roxmltree::Document::parse(sp_soap)?;
    let authn = document
        .root_element()
        .children()
        .find(|node| node.has_tag_name("Body"))
        .and_then(|body| {
            body.children()
                .find(|node| node.has_tag_name("AuthnRequest"))
        })
        .ok_or("AuthnRequest missing from the SOAP body")?;
    let authn = sp_soap.get(authn.range()).ok_or("element offsets")?;
    Ok(format!(
        "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_NS}\"><SOAP-ENV:Body>{authn}</SOAP-ENV:Body></SOAP-ENV:Envelope>"
    ))
}

#[test]
fn unsigned_browser_request_is_rejected_when_sp_metadata_sets_authn_requests_signed(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_sp = sp(AuthnRequestSigningPolicy::Sign)?;
    let unsigned_sp = sp(AuthnRequestSigningPolicy::DoNotSign)?;
    let idp = idp(IdpValidationPolicy::recommended())?;
    let (signing_descriptor, idp_descriptor) = descriptors(&signing_sp, &idp)?;
    assert!(signing_sp
        .metadata_xml()
        .contains("AuthnRequestsSigned=\"true\""));

    let unsigned_post = unsigned_sp.start_sso(&idp_descriptor, StartSso::post())?;
    let unsigned_redirect = unsigned_sp.start_sso(&idp_descriptor, StartSso::redirect())?;
    for input in [
        post_input(&unsigned_post.outbound)?,
        redirect_input(&unsigned_redirect.outbound)?,
    ] {
        match idp.receive_sso(&signing_descriptor, input, validation()) {
            Err(SamlError::SignatureMissing) => {}
            other => return Err(format!("expected SignatureMissing, got {other:?}").into()),
        }
    }

    let signed_post = signing_sp.start_sso(&idp_descriptor, StartSso::post())?;
    let signed_redirect = signing_sp.start_sso(&idp_descriptor, StartSso::redirect())?;
    for (started, input) in [
        (&signed_post, post_input(&signed_post.outbound)?),
        (&signed_redirect, redirect_input(&signed_redirect.outbound)?),
    ] {
        let received = idp.receive_sso(&signing_descriptor, input, validation())?;
        assert_eq!(received.message().id(), started.pending.request_id());
    }

    let compatibility = self::idp(IdpValidationPolicy::compatibility())?;
    let received = compatibility.receive_sso(
        &signing_descriptor,
        post_input(&unsigned_post.outbound)?,
        validation(),
    )?;
    assert_eq!(received.message().id(), unsigned_post.pending.request_id());
    Ok(())
}

#[test]
fn unsigned_paos_request_is_rejected_when_sp_metadata_sets_authn_requests_signed(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_sp = sp(AuthnRequestSigningPolicy::Sign)?;
    let idp = idp(IdpValidationPolicy::recommended())?;
    let (signing_descriptor, idp_descriptor) = descriptors(&signing_sp, &idp)?;

    let unsigned = signing_sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?).allow_unsigned_authn_request(),
    )?;
    let unsigned_envelope = envelope_for_idp(unsigned.http_response.envelope())?;
    assert!(!unsigned_envelope.contains("<ds:Signature"));
    match idp.receive_paos_sso(
        &signing_descriptor,
        &unsigned_envelope,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    ) {
        Err(SamlError::SignatureMissing) => {}
        other => return Err(format!("expected SignatureMissing, got {other:?}").into()),
    }

    let signed = signing_sp.start_paos_sso(
        &idp_descriptor,
        StartPaosSso::new(EndpointUrl::try_new(IDP_SOAP)?),
    )?;
    let received = idp.receive_paos_sso(
        &signing_descriptor,
        &envelope_for_idp(signed.http_response.envelope())?,
        &EndpointUrl::try_new(IDP_SOAP)?,
        validation(),
    )?;
    assert_eq!(received.message().id(), signed.pending.request_id());
    Ok(())
}
