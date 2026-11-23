//! A signature that authenticates a received message and contains a
//! `ds:Object` is rejected under the Recommended XML signature profile.
#![cfg(crypto)]

use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::{
    AcsEndpoint, AuthnRequestSigningPolicy, CertificatePem, Credentials, EntityId, FormField,
    IdentityProvider, IdpConfig, IdpDescriptor, IdpValidationPolicy, Inbound, LogoutSubject,
    MetadataTrustPolicy, NameId, NameIdFormat, PrivateKeyPem, ReplayPolicy, RespondSlo, RespondSso,
    SamlError, SamlValidationContext, ServiceProvider, SessionIndex, SloEndpoint, SoapChannel,
    SpConfig, SpDescriptor, SpValidationPolicy, SsoAssertion, SsoEndpoint, StartSlo, StartSso,
    Status, X509Credential, XmlSignatureProfile,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const UNSIGNED_OBJECT: &str = "<ds:Object><Unsigned>evil</Unsigned></ds:Object></ds:Signature>";

const KEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");

struct Parties {
    sp: saml_rs::ServiceProvider,
    idp: saml_rs::IdentityProvider,
    sp_descriptor: SpDescriptor,
    idp_descriptor: IdpDescriptor,
}

fn parties(xml_signatures: XmlSignatureProfile) -> Result<Parties, SamlError> {
    let credentials = Credentials::default().with_signing_credential(X509Credential::new(
        CertificatePem::new(CERT),
        PrivateKeyPem::new(KEY),
    ));
    let mut sp_validation = SpValidationPolicy::default();
    sp_validation.authn_requests = AuthnRequestSigningPolicy::Sign;
    sp_validation.xml_signatures = xml_signatures;
    let mut idp_validation = IdpValidationPolicy::default();
    idp_validation.xml_signatures = xml_signatures;
    let sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post("https://sp.example.com/acs")?.with_default(),
        )
        .slo_endpoint(SloEndpoint::post("https://sp.example.com/slo/post")?)
        .slo_endpoint(SloEndpoint::soap("https://sp.example.com/slo/soap")?)
        .credentials(credentials.clone())
        .validation(sp_validation)
        .build()?,
    );
    let idp = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post("https://idp.example.com/sso/post")?,
        )
        .slo_endpoint(SloEndpoint::post("https://idp.example.com/slo/post")?)
        .slo_endpoint(SloEndpoint::soap("https://idp.example.com/slo/soap")?)
        .credentials(credentials)
        .validation(idp_validation)
        .build()?,
    );
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
    Ok(Parties {
        sp,
        idp,
        sp_descriptor,
        idp_descriptor,
    })
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::Disabled)
}

fn principal() -> NameId {
    NameId::new("alice@example.com").with_format(NameIdFormat::EmailAddress)
}

fn logout_subject() -> Result<LogoutSubject, SamlError> {
    Ok(LogoutSubject::new(NameId::new("alice@example.com"))
        .with_session_index(SessionIndex::try_new("_session123")?))
}

fn with_object(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
    if !xml.contains("</ds:Signature>") {
        return Err("message is not signed".into());
    }
    Ok(xml.replace("</ds:Signature>", UNSIGNED_OBJECT))
}

fn form_with_object(
    fields: &[FormField],
    name: &str,
) -> Result<Vec<FormField>, Box<dyn std::error::Error>> {
    fields
        .iter()
        .map(|field| {
            if field.name() != name {
                return Ok(field.clone());
            }
            let xml = String::from_utf8(STANDARD.decode(field.value())?)?;
            Ok(FormField::new(
                name,
                STANDARD.encode(with_object(&xml)?.as_bytes()),
            ))
        })
        .collect()
}

fn assert_object_rejected<T: std::fmt::Debug>(result: Result<T, SamlError>) {
    assert!(
        matches!(result, Err(SamlError::SignedReferenceMismatch)),
        "{result:?}"
    );
}

fn post_authn_request_with_object(
    parties: &Parties,
) -> Result<Vec<FormField>, Box<dyn std::error::Error>> {
    let started = parties
        .sp
        .start_sso(&parties.idp_descriptor, StartSso::post())?;
    form_with_object(started.outbound.post_form()?.fields(), "SAMLRequest")
}

#[test]
fn post_authn_request_with_object_is_rejected_unless_weak_algorithms_are_allowed(
) -> Result<(), Box<dyn std::error::Error>> {
    for profile in [
        XmlSignatureProfile::ExcludeWeakAlgorithms,
        XmlSignatureProfile::StrictRsaSha2,
    ] {
        let parties = parties(profile)?;
        let form = post_authn_request_with_object(&parties)?;
        assert_object_rejected(parties.idp.receive_sso(
            &parties.sp_descriptor,
            Inbound::post(form),
            validation(),
        ));
    }

    let parties = parties(XmlSignatureProfile::AllowWeakAlgorithms)?;
    let form = post_authn_request_with_object(&parties)?;
    parties
        .idp
        .receive_sso(&parties.sp_descriptor, Inbound::post(form), validation())?;
    Ok(())
}

#[test]
fn post_response_with_object_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties(XmlSignatureProfile::ExcludeWeakAlgorithms)?;
    let started = parties
        .sp
        .start_sso(&parties.idp_descriptor, StartSso::post())?;
    let received = parties.idp.receive_sso(
        &parties.sp_descriptor,
        Inbound::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    for respond in [RespondSso::post(), RespondSso::post().sign_response()] {
        let response = parties.idp.respond_sso(
            &parties.sp_descriptor,
            &received,
            SsoAssertion::new(principal()),
            respond,
        )?;
        let form = form_with_object(response.post_form()?.fields(), "SAMLResponse")?;
        assert_object_rejected(parties.sp.finish_sso(
            &parties.idp_descriptor,
            &started.pending,
            Inbound::post(form),
            validation(),
        ));
    }
    Ok(())
}

#[test]
fn post_logout_request_and_response_with_object_are_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties(XmlSignatureProfile::ExcludeWeakAlgorithms)?;
    let started =
        parties
            .sp
            .start_slo(&parties.idp_descriptor, logout_subject()?, StartSlo::post())?;
    let request = started.outbound.post_form()?.fields().to_vec();
    assert_object_rejected(parties.idp.receive_slo(
        &parties.sp_descriptor,
        Inbound::post(form_with_object(&request, "SAMLRequest")?),
        validation(),
    ));

    let received =
        parties
            .idp
            .receive_slo(&parties.sp_descriptor, Inbound::post(request), validation())?;
    let response = parties.idp.respond_slo(
        &parties.sp_descriptor,
        &received,
        &Status::success(),
        RespondSlo::post(),
    )?;
    assert_object_rejected(parties.sp.finish_slo(
        &parties.idp_descriptor,
        &started.pending,
        Inbound::post(form_with_object(
            response.post_form()?.fields(),
            "SAMLResponse",
        )?),
        validation(),
    ));
    Ok(())
}

#[test]
fn soap_logout_request_and_response_with_object_are_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties(XmlSignatureProfile::ExcludeWeakAlgorithms)?;
    let started =
        parties
            .sp
            .start_slo(&parties.idp_descriptor, logout_subject()?, StartSlo::soap())?;
    let request = started.outbound.soap_request()?.envelope().to_string();
    assert_object_rejected(parties.idp.receive_slo(
        &parties.sp_descriptor,
        Inbound::soap(with_object(&request)?, SoapChannel::unattested()),
        validation(),
    ));

    let received = parties.idp.receive_slo(
        &parties.sp_descriptor,
        Inbound::soap(request, SoapChannel::unattested()),
        validation(),
    )?;
    let response = parties.idp.respond_slo(
        &parties.sp_descriptor,
        &received,
        &Status::success(),
        RespondSlo::soap(),
    )?;
    assert_object_rejected(parties.sp.finish_slo(
        &parties.idp_descriptor,
        &started.pending,
        Inbound::soap(
            with_object(response.soap_response()?.envelope())?,
            SoapChannel::unattested(),
        ),
        validation(),
    ));
    Ok(())
}
