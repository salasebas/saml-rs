//! Keys come from the metadata role descriptor of the role a message is from.
#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use std::time::SystemTime;

use saml_rs::util::normalize_cert_string;
use saml_rs::{
    AcsEndpoint, AuthnRequest, BrowserInput, CertificatePem, Credentials, EntityId, IdpConfig,
    IdpDescriptor, IdpValidationPolicy, MetadataTrustPolicy, NameId, PrivateKeyPem, ReplayPolicy,
    RespondSso, Saml, SamlError, SamlValidationContext, SpConfig, SpDescriptor, SpValidationPolicy,
    SsoEndpoint, SsoResponse, StartSso, Subject,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const IDP_SSO: &str = "https://idp.example.com/sso";

const SP_ROLE_KEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const SP_ROLE_CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const IDP_ROLE_KEY: &str = include_str!("fixtures/key/idp/provider_matrix_privkey.pkcs8.pem");
const IDP_ROLE_CERT: &str = include_str!("fixtures/key/idp/cert.cer");

fn credentials(key: &str, cert: &str) -> Credentials {
    Credentials {
        signing_key: Some(PrivateKeyPem::new(key)),
        signing_certificate: Some(CertificatePem::new(cert)),
        ..Credentials::default()
    }
}

fn idp_signing_with(key: &str, cert: &str) -> Result<Saml<saml_rs::Idp>, SamlError> {
    Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post(IDP_SSO)?)
            .credentials(credentials(key, cert))
            .validation(IdpValidationPolicy::recommended())
            .build()?,
    )
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility)
}

fn sso_response_from(
    sp: &Saml<saml_rs::Sp>,
    sp_descriptor: &SpDescriptor,
    idp_descriptor: &IdpDescriptor,
    responder: &Saml<saml_rs::Idp>,
) -> Result<Result<saml_rs::SsoSession, SamlError>, SamlError> {
    let started = sp.start_sso(idp_descriptor, StartSso::post())?;
    let received = responder.receive_sso(
        sp_descriptor,
        BrowserInput::<AuthnRequest>::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let response = responder.respond_sso(
        sp_descriptor,
        &received,
        Subject::new(NameId::new("alice@example.com", None), Vec::new()),
        RespondSso::post(),
    )?;
    Ok(sp.finish_sso(
        idp_descriptor,
        &started.pending,
        BrowserInput::<SsoResponse>::post(response.post_form()?.fields().to_vec()),
        validation(),
    ))
}

#[test]
fn sso_response_signed_with_the_sp_role_key_of_a_dual_role_idp_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS)?)
            .credentials(credentials(SP_ROLE_KEY, SP_ROLE_CERT))
            .validation(SpValidationPolicy::recommended())
            .build()?,
    )?;
    let sp_descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let identity_provider = idp_signing_with(IDP_ROLE_KEY, IDP_ROLE_CERT)?;
    let sp_role_of_idp = format!(
        r#"<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/as-sp/acs" index="0"/></SPSSODescriptor></EntityDescriptor>"#,
        normalize_cert_string(SP_ROLE_CERT)
    );
    let dual_role_idp = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        &identity_provider
            .metadata_xml()
            .replace("</EntityDescriptor>", &sp_role_of_idp),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;

    let session = sso_response_from(&sp, &sp_descriptor, &dual_role_idp, &identity_provider)??;
    assert_eq!(session.issuer().as_str(), IDP_ENTITY_ID);

    let signed_with_sp_role_key = idp_signing_with(SP_ROLE_KEY, SP_ROLE_CERT)?;
    let rejected = sso_response_from(
        &sp,
        &sp_descriptor,
        &dual_role_idp,
        &signed_with_sp_role_key,
    )?;
    assert!(
        matches!(rejected, Err(SamlError::CertificateMismatch)),
        "{rejected:?}"
    );
    Ok(())
}
