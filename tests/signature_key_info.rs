//! The certificate in a signature's `KeyInfo` does not decide trust: a
//! signature verifies when a key in the peer's metadata verifies it.
#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use std::time::SystemTime;

use saml_rs::binding::{base64_decode, base64_encode};
use saml_rs::error::SignatureVerificationReason;
use saml_rs::{
    AcsEndpoint, AuthnRequest, AuthnRequestSigningPolicy, AuthnRequestValidationPolicy,
    BrowserInput, CertificatePem, Credentials, EntityId, FormField, IdpConfig, IdpDescriptor,
    IdpValidationPolicy, MetadataTrustPolicy, PrivateKeyPem, ReplayPolicy, Saml, SamlError,
    SamlValidationContext, SpConfig, SpDescriptor, SpValidationPolicy, SsoEndpoint, StartSso,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";

const SP_KEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const SP_CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const SP_REISSUED_CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.reissued.cer");
const IDP_KEY: &str = include_str!("fixtures/key/idp/provider_matrix_privkey.pkcs8.pem");
const IDP_CERT: &str = include_str!("fixtures/key/idp/cert.cer");

fn credentials(key: &str, cert: &str) -> Credentials {
    Credentials {
        signing_key: Some(PrivateKeyPem::new(key)),
        signing_certificate: Some(CertificatePem::new(cert)),
        ..Credentials::default()
    }
}

fn sp_signing_authn_requests(key: &str, cert: &str) -> Result<Saml<saml_rs::Sp>, SamlError> {
    Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
            .credentials(credentials(key, cert))
            .validation(SpValidationPolicy {
                authn_requests: AuthnRequestSigningPolicy::Sign,
                ..SpValidationPolicy::recommended()
            })
            .build()?,
    )
}

fn idp_requiring_signed_authn_requests() -> Result<Saml<saml_rs::Idp>, SamlError> {
    Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post("https://idp.example.com/sso")?)
            .credentials(credentials(IDP_KEY, IDP_CERT))
            .validation(IdpValidationPolicy {
                authn_requests: AuthnRequestValidationPolicy::RequireSigned,
                ..IdpValidationPolicy::recommended()
            })
            .build()?,
    )
}

fn sp_descriptor_with_signing_cert(cert: &str) -> Result<SpDescriptor, SamlError> {
    SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp_signing_authn_requests(SP_KEY, cert)?.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )
}

fn signed_authn_request_form(
    signer: &Saml<saml_rs::Sp>,
    idp: &Saml<saml_rs::Idp>,
) -> Result<Vec<FormField>, Box<dyn std::error::Error>> {
    let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let started = signer.start_sso(&idp_descriptor, StartSso::post())?;
    Ok(started.outbound.post_form()?.fields().to_vec())
}

fn without_key_info(form: &[FormField]) -> Result<Vec<FormField>, Box<dyn std::error::Error>> {
    form.iter()
        .map(|field| {
            if field.name() != "SAMLRequest" {
                return Ok(field.clone());
            }
            let xml = String::from_utf8(base64_decode(field.value())?)?;
            let start = xml.find("<ds:KeyInfo>").ok_or("signature has no KeyInfo")?;
            let end_tag = "</ds:KeyInfo>";
            let end = xml.find(end_tag).ok_or("KeyInfo is not closed")? + end_tag.len();
            let stripped = format!("{}{}", &xml[..start], &xml[end..]);
            Ok(FormField::new(
                "SAMLRequest",
                base64_encode(stripped.as_bytes()),
            ))
        })
        .collect()
}

fn receive(
    idp: &Saml<saml_rs::Idp>,
    sp_descriptor: &SpDescriptor,
    form: Vec<FormField>,
) -> Result<(), SamlError> {
    idp.receive_sso(
        sp_descriptor,
        BrowserInput::<AuthnRequest>::post(form),
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility),
    )
    .map(drop)
}

#[test]
fn authn_request_whose_key_info_names_a_reissued_certificate_of_the_metadata_key_is_accepted(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp_requiring_signed_authn_requests()?;
    let form = signed_authn_request_form(&sp_signing_authn_requests(SP_KEY, SP_CERT)?, &idp)?;

    receive(
        &idp,
        &sp_descriptor_with_signing_cert(SP_REISSUED_CERT)?,
        form,
    )?;
    Ok(())
}

#[test]
fn authn_request_signed_by_a_key_outside_metadata_is_rejected_with_or_without_key_info(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp_requiring_signed_authn_requests()?;
    let sp_descriptor = sp_descriptor_with_signing_cert(SP_CERT)?;
    let form = signed_authn_request_form(&sp_signing_authn_requests(IDP_KEY, IDP_CERT)?, &idp)?;

    for form in [without_key_info(&form)?, form] {
        let rejected = receive(&idp, &sp_descriptor, form);
        assert!(
            matches!(
                rejected,
                Err(SamlError::SignatureVerification {
                    reason: SignatureVerificationReason::XmlSignature
                })
            ),
            "{rejected:?}"
        );
    }
    Ok(())
}
