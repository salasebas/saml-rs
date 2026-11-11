//! A signature that authenticates a received message and contains a
//! `ds:Object` is rejected under the Recommended XML signature profile.
#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use std::time::SystemTime;

use saml_rs::binding::{base64_decode, base64_encode};
use saml_rs::{
    AcsEndpoint, AuthnRequest, AuthnRequestSigningPolicy, BrowserInput, CertificatePem,
    Credentials, EntityId, FormField, IdpConfig, IdpDescriptor, IdpValidationPolicy, LogoutRequest,
    LogoutResponse, LogoutSubject, MetadataTrustPolicy, NameId, NameIdFormat, PaosAuthnRequest,
    PaosClientRequest, PaosSsoResponse, PrivateKeyPem, ReplayPolicy, RespondPaosSso, RespondSlo,
    RespondSso, Saml, SamlError, SamlValidationContext, SessionIndex, SloEndpoint, SpConfig,
    SpDescriptor, SpValidationPolicy, SsoEndpoint, SsoResponse, StartPaosSso, StartSlo, StartSso,
    Subject, XmlSignatureProfile,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const IDP_PAOS: &str = "https://idp.example.com/sso/soap";
const SOAP_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const UNSIGNED_OBJECT: &str = "<ds:Object><Unsigned>evil</Unsigned></ds:Object></ds:Signature>";

const KEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");

struct Parties {
    sp: Saml<saml_rs::Sp>,
    idp: Saml<saml_rs::Idp>,
    sp_descriptor: SpDescriptor,
    idp_descriptor: IdpDescriptor,
}

fn parties(xml_signatures: XmlSignatureProfile) -> Result<Parties, SamlError> {
    let credentials = Credentials {
        signing_key: Some(PrivateKeyPem::new(KEY)),
        signing_certificate: Some(CertificatePem::new(CERT)),
        ..Credentials::default()
    };
    let sp = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?.mark_default())
            .slo_endpoint(SloEndpoint::post("https://sp.example.com/slo/post")?)
            .slo_endpoint(SloEndpoint::soap("https://sp.example.com/slo/soap")?)
            .credentials(credentials.clone())
            .validation(SpValidationPolicy {
                authn_requests: AuthnRequestSigningPolicy::Sign,
                xml_signatures,
                ..SpValidationPolicy::recommended()
            })
            .build()?,
    )?;
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post("https://idp.example.com/sso/post")?)
            .slo_endpoint(SloEndpoint::post("https://idp.example.com/slo/post")?)
            .slo_endpoint(SloEndpoint::soap("https://idp.example.com/slo/soap")?)
            .credentials(credentials)
            .validation(IdpValidationPolicy {
                xml_signatures,
                ..IdpValidationPolicy::recommended()
            })
            .build()?,
    )?;
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    Ok(Parties {
        sp,
        idp,
        sp_descriptor,
        idp_descriptor,
    })
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility)
}

fn subject() -> Subject {
    Subject::new(
        NameId::new("alice@example.com", Some(NameIdFormat::EmailAddress)),
        Vec::new(),
    )
}

fn logout_subject() -> Result<LogoutSubject, SamlError> {
    Ok(LogoutSubject::with_session_index(
        NameId::new("alice@example.com", None),
        SessionIndex::try_new("_session123")?,
    ))
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
            let xml = String::from_utf8(base64_decode(field.value())?)?;
            Ok(FormField::new(
                name,
                base64_encode(with_object(&xml)?.as_bytes()),
            ))
        })
        .collect()
}

fn soap_body_element(envelope: &str, element: &str) -> Result<String, Box<dyn std::error::Error>> {
    let start = envelope
        .find(&format!("<samlp:{element}"))
        .ok_or(format!("{element} missing"))?;
    let end_tag = format!("</samlp:{element}>");
    let end = envelope[start..]
        .find(&end_tag)
        .ok_or(format!("{element} is not closed"))?
        + start
        + end_tag.len();
    Ok(format!(
        "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_NS}\"><SOAP-ENV:Body>{}</SOAP-ENV:Body></SOAP-ENV:Envelope>",
        &envelope[start..end]
    ))
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
fn post_authn_request_with_object_is_rejected_unless_the_compatibility_profile_is_selected(
) -> Result<(), Box<dyn std::error::Error>> {
    for profile in [
        XmlSignatureProfile::ExcludeWeakAlgorithms,
        XmlSignatureProfile::StrictRsaSha2,
    ] {
        let parties = parties(profile)?;
        let form = post_authn_request_with_object(&parties)?;
        assert_object_rejected(parties.idp.receive_sso(
            &parties.sp_descriptor,
            BrowserInput::<AuthnRequest>::post(form),
            validation(),
        ));
    }

    let parties = parties(XmlSignatureProfile::AllowProviderSupportedForCompatibility)?;
    let form = post_authn_request_with_object(&parties)?;
    parties.idp.receive_sso(
        &parties.sp_descriptor,
        BrowserInput::<AuthnRequest>::post(form),
        validation(),
    )?;
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
        BrowserInput::<AuthnRequest>::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    for respond in [RespondSso::post(), RespondSso::post().sign_response()] {
        let response =
            parties
                .idp
                .respond_sso(&parties.sp_descriptor, &received, subject(), respond)?;
        let form = form_with_object(response.post_form()?.fields(), "SAMLResponse")?;
        assert_object_rejected(parties.sp.finish_sso(
            &parties.idp_descriptor,
            &started.pending,
            BrowserInput::<SsoResponse>::post(form),
            validation(),
        ));
    }
    Ok(())
}

#[test]
fn paos_authn_request_and_response_with_object_are_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties(XmlSignatureProfile::ExcludeWeakAlgorithms)?;
    let started = parties.sp.start_paos_sso(
        &parties.idp_descriptor,
        PaosClientRequest::headers_checked_by_caller(),
        StartPaosSso::to_soap_endpoint(IDP_PAOS)?,
    )?;
    let request = soap_body_element(started.http_response.envelope(), "AuthnRequest")?;
    assert_object_rejected(parties.idp.receive_paos_sso(
        &parties.sp_descriptor,
        &PaosAuthnRequest::from_envelope(with_object(&request)?, IDP_PAOS)?,
        validation(),
    ));

    let received = parties.idp.receive_paos_sso(
        &parties.sp_descriptor,
        &PaosAuthnRequest::from_envelope(request, IDP_PAOS)?,
        validation(),
    )?;
    let answered = parties.idp.respond_paos_sso(
        &parties.sp_descriptor,
        &received,
        subject(),
        RespondPaosSso::default(),
    )?;
    let response = soap_body_element(answered.envelope(), "Response")?;
    assert_object_rejected(parties.sp.finish_paos_sso(
        &parties.idp_descriptor,
        &started.pending,
        &PaosSsoResponse::from_envelope(with_object(&response)?)?,
        validation(),
    ));
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
        BrowserInput::<LogoutRequest>::post(form_with_object(&request, "SAMLRequest")?),
        validation(),
    ));

    let received = parties.idp.receive_slo(
        &parties.sp_descriptor,
        BrowserInput::<LogoutRequest>::post(request),
        validation(),
    )?;
    let response =
        parties
            .idp
            .respond_slo(&parties.sp_descriptor, &received, RespondSlo::post())?;
    assert_object_rejected(parties.sp.finish_slo(
        &parties.idp_descriptor,
        &started.pending,
        BrowserInput::<LogoutResponse>::post(form_with_object(
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
        BrowserInput::<LogoutRequest>::soap(with_object(&request)?),
        validation(),
    ));

    let received = parties.idp.receive_slo(
        &parties.sp_descriptor,
        BrowserInput::<LogoutRequest>::soap(request),
        validation(),
    )?;
    let response =
        parties
            .idp
            .respond_slo(&parties.sp_descriptor, &received, RespondSlo::soap())?;
    assert_object_rejected(parties.sp.finish_slo(
        &parties.idp_descriptor,
        &started.pending,
        BrowserInput::<LogoutResponse>::soap(with_object(response.soap_response()?.envelope())?),
        validation(),
    ));
    Ok(())
}
