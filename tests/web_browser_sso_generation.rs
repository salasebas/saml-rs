//! `RespondSso::allow_unsigned_encrypted_cbc` relaxes Errata 05 E93 alone.
#![cfg(crypto)]

#[path = "web_browser_sso_generation/assertion_prefix.rs"]
mod assertion_prefix;
mod common;
#[path = "common/tag_prefixes.rs"]
mod tag_prefixes;

#[path = "common/post_validation.rs"]
mod post_validation;
use common::signing_credentials;
use post_validation::post_validation;

use std::time::{Duration, SystemTime};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use flate2::read::DeflateDecoder;
use saml_rs::constants::status_code;
use saml_rs::{
    AcsEndpoint, AssertionSignaturePolicy, AudienceValidationPolicy, AuthnRequest,
    AuthnRequestSigningPolicy, AuthnRequestValidationPolicy, EntityId, ForceAuthn, FormField,
    IdentityProvider, IdpConfig, IdpDescriptor, IdpValidationPolicy, Inbound, MetadataTrustPolicy,
    NameId, NameIdCreationPolicy, NameIdFormat, Outbound, OutboundDelivery, ReplayPolicy,
    RespondSso, SamlError, SamlInstant, SamlValidationContext, ServiceProvider, SloEndpoint,
    SpConfig, SpDescriptor, SpValidationPolicy, SsoAssertion, SsoEndpoint, SsoOutcome, SsoResponse,
    StartSso, Status, SubordinateStatusCode, TemplatePolicy,
};
#[cfg(not(feature = "crypto-fips"))]
use saml_rs::{
    AssertionEncryptionPolicy, CertificatePem, PrivateKeyPem, ResponseSignaturePolicy, XmlPolicy,
};
use url::Url;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const IDP_SSO_REDIRECT: &str = "https://idp.example.com/sso/redirect";
const IDP_SLO: &str = "https://idp.example.com/slo";
const UNSPECIFIED_AUTHN_CONTEXT: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
const NO_CACHE_HEADERS: [(&str, &str); 2] = [
    ("Cache-Control", "no-cache, no-store"),
    ("Pragma", "no-cache"),
];

#[cfg(not(feature = "crypto-fips"))]
const PRIVKEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
#[cfg(not(feature = "crypto-fips"))]
const CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");

fn signing_sp_validation() -> SpValidationPolicy {
    let mut validation = SpValidationPolicy::default();
    validation.assertions = AssertionSignaturePolicy::RequireSigned;
    validation.authn_requests = AuthnRequestSigningPolicy::Sign;
    validation.audience = AudienceValidationPolicy::RequireRestriction;
    validation
}

fn signed_authn_request_idp_validation() -> IdpValidationPolicy {
    let mut validation = IdpValidationPolicy::default();
    validation.authn_requests = AuthnRequestValidationPolicy::RequireSigned;
    validation
}

#[cfg(not(feature = "crypto-fips"))]
fn encrypted_assertions() -> XmlPolicy {
    let mut xml = XmlPolicy::default();
    xml.encryption.assertions = AssertionEncryptionPolicy::EncryptAssertions;
    xml
}

fn principal() -> NameId {
    NameId::new("alice@example.com").with_format(NameIdFormat::EmailAddress)
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::Disabled)
}

fn sp_with(validation: SpValidationPolicy) -> Result<saml_rs::ServiceProvider, SamlError> {
    Ok(ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(SP_ACS)?.with_default(),
        )
        .credentials(signing_credentials())
        .validation(validation)
        .build()?,
    ))
}

fn idp_with(
    validation: IdpValidationPolicy,
    single_logout: bool,
) -> Result<saml_rs::IdentityProvider, SamlError> {
    let mut builder = IdpConfig::builder(
        EntityId::try_new(IDP_ENTITY_ID)?,
        SsoEndpoint::post(IDP_SSO_POST)?,
    )
    .sso_endpoint(SsoEndpoint::redirect(IDP_SSO_REDIRECT)?)
    .credentials(signing_credentials())
    .validation(validation);
    if single_logout {
        builder = builder.slo_endpoint(SloEndpoint::redirect(IDP_SLO)?);
    }
    Ok(IdentityProvider::new(builder.build()?))
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

fn authn_request_xml(
    outbound: &Outbound<AuthnRequest>,
) -> Result<String, Box<dyn std::error::Error>> {
    match outbound.delivery() {
        OutboundDelivery::Redirect(url) => {
            let url = Url::parse(url)?;
            let (_, encoded) = url
                .query_pairs()
                .find(|(key, _)| key == "SAMLRequest")
                .ok_or("missing SAMLRequest")?;
            let compressed = STANDARD.decode(encoded.as_ref())?;
            Ok(std::io::read_to_string(DeflateDecoder::new(
                compressed.as_slice(),
            ))?)
        }
        OutboundDelivery::PostForm(form) => Ok(String::from_utf8(
            STANDARD.decode(form.value("SAMLRequest").ok_or("missing SAMLRequest")?)?,
        )?),
        _ => Err("delivery is unsupported".into()),
    }
}

fn response_xml(outbound: &Outbound<SsoResponse>) -> Result<String, Box<dyn std::error::Error>> {
    let encoded = outbound
        .post_form()?
        .fields()
        .iter()
        .find(|field| field.name() == "SAMLResponse")
        .map(FormField::value)
        .ok_or("missing SAMLResponse")?;
    Ok(String::from_utf8(STANDARD.decode(encoded)?)?)
}

fn assert_generated_instants_have_no_leap_second(
    xml: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for marker in ["IssueInstant=\"", "AuthnInstant=\""] {
        for value in xml.split(marker).skip(1) {
            let instant = value.split('"').next().unwrap_or_default();
            let second = instant
                .trim_end_matches('Z')
                .rsplit(':')
                .next()
                .unwrap_or_default()
                .split('.')
                .next()
                .unwrap_or_default();
            let second: u8 = second.parse()?;
            assert!(second < 60, "{instant}");
        }
    }
    Ok(())
}

fn confirmation_tag(xml: &str) -> String {
    let rest = xml
        .split("<saml:SubjectConfirmationData")
        .nth(1)
        .unwrap_or_default();
    let end = rest.find('>').unwrap_or(rest.len());
    rest[..end].to_string()
}

#[test]
fn typed_sso_response_carries_profile_authentication_statement(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(signing_sp_validation())?;
    let idp = idp_with(signed_authn_request_idp_validation(), false)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    )?;
    let xml = response_xml(&response)?;

    assert!(xml.contains("<saml:AuthnStatement "));
    assert!(!xml.contains("EncryptedAssertion"));
    assert!(xml.contains(&format!(
        "<saml:AuthnContextClassRef>{UNSPECIFIED_AUTHN_CONTEXT}</saml:AuthnContextClassRef>"
    )));
    let issue_instant = xml
        .split("IssueInstant=\"")
        .nth(1)
        .and_then(|value| value.split('"').next())
        .ok_or("missing IssueInstant")?;
    assert!(xml.contains(&format!("AuthnInstant=\"{issue_instant}\"")));
    assert!(xml.contains(&format!("<saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>")));
    assert!(xml.contains(&format!("<saml:Audience>{SP_ENTITY_ID}</saml:Audience>")));
    assert!(xml.contains("ds:Signature"));
    let confirmation = confirmation_tag(&xml);
    assert!(confirmation.contains("NotOnOrAfter="));
    assert!(confirmation.contains(&format!("Recipient=\"{SP_ACS}\"")));
    assert!(!confirmation.contains("NotBefore"));
    assert!(confirmation.contains(&format!(
        "InResponseTo=\"{}\"",
        received.message().id().as_str()
    )));
    assert_generated_instants_have_no_leap_second(&xml)?;

    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(response.post_form()?.fields().to_vec()),
        post_validation(&mut Default::default()),
    )?;
    assert_eq!(session.name_id().value(), "alice@example.com");
    assert_eq!(
        session.in_response_to().map(|id| id.as_str()),
        Some(received.message().id().as_str())
    );
    Ok(())
}

#[test]
fn typed_redirect_and_post_messages_carry_the_no_cache_headers(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(signing_sp_validation())?;
    let idp = idp_with(signed_authn_request_idp_validation(), false)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    let redirect = sp.start_sso(&idp_descriptor, StartSso::redirect())?;
    assert_eq!(header_pairs(&redirect.outbound), NO_CACHE_HEADERS);

    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    assert_eq!(header_pairs(&started.outbound), NO_CACHE_HEADERS);
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    )?;
    assert_eq!(header_pairs(&response), NO_CACHE_HEADERS);
    Ok(())
}

fn header_pairs<Message>(outbound: &Outbound<Message>) -> Vec<(&str, &str)> {
    outbound
        .headers()
        .iter()
        .map(|header| (header.name(), header.value()))
        .collect()
}

#[test]
fn typed_sso_response_writes_the_caller_authentication_instant(
) -> Result<(), Box<dyn std::error::Error>> {
    const AUTHENTICATED: &str = "2026-01-01T08:00:00Z";
    let authenticated = SystemTime::UNIX_EPOCH + Duration::from_millis(1_767_254_400_500);
    let sp = sp_with(signing_sp_validation())?;
    let idp = idp_with(signed_authn_request_idp_validation(), false)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let respond = |authn_instant: SystemTime| {
        idp.respond_sso(
            &sp_descriptor,
            &received,
            SsoAssertion::new(principal()).with_authn_instant(authn_instant),
            RespondSso::post(),
        )
    };

    let response = respond(authenticated)?;
    assert!(response_xml(&response)?.contains(&format!("AuthnInstant=\"{AUTHENTICATED}\"")));
    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(response.post_form()?.fields().to_vec()),
        post_validation(&mut Default::default()),
    )?;
    assert_eq!(
        session
            .authn_statements()
            .first()
            .map(saml_rs::AuthnStatement::authn_instant),
        Some(&SamlInstant::try_new(AUTHENTICATED)?)
    );

    respond(SystemTime::now())?;
    let later = respond(SystemTime::now() + Duration::from_secs(3600));
    assert!(
        matches!(&later, Err(SamlError::Invalid(message)) if message.contains("later than the response IssueInstant")),
        "{later:?}"
    );

    Ok(())
}

#[test]
fn typed_unsolicited_sso_omits_in_response_to() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(signing_sp_validation())?;
    let idp = idp_with(signed_authn_request_idp_validation(), false)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let response = idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    )?;
    let xml = response_xml(&response)?;

    assert!(!xml.contains("InResponseTo"));
    assert!(xml.contains("<saml:AuthnStatement "));
    assert!(xml.contains(&format!("<saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>")));
    assert_generated_instants_have_no_leap_second(&xml)?;

    let session = sp.accept_unsolicited_sso(
        &idp_descriptor,
        Inbound::post(response.post_form()?.fields().to_vec()),
        post_validation(&mut Default::default()),
    )?;
    assert_eq!(session.in_response_to(), None);
    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}

fn name_id_tag(xml: &str) -> String {
    let rest = xml.split("<saml:NameID").nth(1).unwrap_or_default();
    let end = rest.find('>').unwrap_or(rest.len());
    rest[..end].to_string()
}

#[test]
fn typed_sso_assertion_name_id_omits_format_when_none_is_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(signing_sp_validation())?;
    let idp = idp_with(signed_authn_request_idp_validation(), false)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    let response = idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(NameId::new("alice@example.com")),
        RespondSso::post(),
    )?;
    let xml = response_xml(&response)?;
    assert!(xml.contains("<saml:NameID>alice@example.com</saml:NameID>"));

    let session = sp.accept_unsolicited_sso(
        &idp_descriptor,
        Inbound::post(response.post_form()?.fields().to_vec()),
        post_validation(&mut Default::default()),
    )?;
    assert_eq!(session.name_id().format(), None);

    Ok(())
}

#[test]
fn typed_sso_assertion_name_id_keeps_the_configured_format(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(signing_sp_validation())?;
    let idp = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO_POST)?,
        )
        .name_id_format(NameIdFormat::EmailAddress)
        .credentials(signing_credentials())
        .validation(signed_authn_request_idp_validation())
        .build()?,
    );
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;

    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(NameId::new("alice@example.com")),
        RespondSso::post(),
    )?;
    assert_eq!(
        name_id_tag(&response_xml(&response)?),
        format!(" Format=\"{}\"", NameIdFormat::EmailAddress.as_uri()),
    );
    Ok(())
}

#[test]
fn typed_sso_session_index_is_present_only_when_single_logout_is_supported(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(signing_sp_validation())?;
    let idp = idp_with(signed_authn_request_idp_validation(), true)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let response = idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    )?;
    let xml = response_xml(&response)?;
    let assertion = xml
        .split("<saml:Assertion")
        .nth(1)
        .ok_or("missing assertion")?;
    let assertion_id = assertion
        .split("ID=\"")
        .nth(1)
        .and_then(|value| value.split('"').next())
        .ok_or("missing assertion ID")?;
    assert!(assertion.contains(&format!("SessionIndex=\"{assertion_id}\"")));

    let session = sp.accept_unsolicited_sso(
        &idp_descriptor,
        Inbound::post(response.post_form()?.fields().to_vec()),
        post_validation(&mut Default::default()),
    )?;
    let logout_subject = session
        .logout_subject()
        .ok_or("accepted session is missing a logout subject")?;
    let session_index = logout_subject
        .session_indexes()
        .first()
        .ok_or("accepted session dropped SessionIndex")?;
    assert_eq!(session_index.as_str(), session.assertion_id().as_str());
    assert_eq!(session_index.as_str(), assertion_id);
    assert_eq!(response.session_index(), Some(session_index));

    let idp_without_logout = idp_with(signed_authn_request_idp_validation(), false)?;
    let (sp_descriptor, _) = descriptors(&sp, &idp_without_logout)?;
    let response = idp_without_logout.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    )?;
    let xml = response_xml(&response)?;
    assert!(xml.contains("<saml:AuthnStatement "));
    assert!(!xml.contains("SessionIndex="));
    assert_eq!(response.session_index(), None);

    let soap_only_idp = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO_POST)?,
        )
        .slo_endpoint(SloEndpoint::soap(IDP_SLO)?)
        .credentials(signing_credentials())
        .validation(signed_authn_request_idp_validation())
        .build()?,
    );
    let (sp_descriptor, _) = descriptors(&sp, &soap_only_idp)?;
    let response = soap_only_idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    )?;
    let xml = response_xml(&response)?;
    let issued = response
        .session_index()
        .ok_or("SOAP-only logout response did not return its SessionIndex")?;
    assert!(xml.contains(&format!("SessionIndex=\"{}\"", issued.as_str())));
    Ok(())
}

#[test]
fn typed_sso_optional_generation_capabilities_stay_off_until_selected(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(SpValidationPolicy::default())?;
    let idp = idp_with(IdpValidationPolicy::default(), false)?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::redirect())?;
    let request = authn_request_xml(&started.outbound)?;
    let redirect = started.outbound.redirect_url()?;

    assert!(!redirect.contains("Signature="));
    assert!(!request.contains("ForceAuthn="));
    assert!(request.contains("AllowCreate=\"false\""));
    assert!(request.contains("Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\""));
    assert!(!request.contains("Format=\"\""));
    assert!(request.contains(&format!("<saml:Issuer>{SP_ENTITY_ID}</saml:Issuer>")));
    assert!(request.contains(&format!("Destination=\"{IDP_SSO_REDIRECT}\"")));
    assert!(!request.contains("EncryptedAssertion"));

    let forced = sp.start_sso(
        &idp_descriptor,
        StartSso::redirect().force_authn(ForceAuthn::Required),
    )?;
    let forced_xml = authn_request_xml(&forced.outbound)?;
    assert!(forced_xml.contains("ForceAuthn=\"true\""));
    assert!(forced_xml.contains("AllowCreate=\"false\""));

    let mut creating = SpValidationPolicy::default();
    creating.name_id_creation = NameIdCreationPolicy::AllowCreate;
    let sp = sp_with(creating)?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::redirect())?;
    let request = authn_request_xml(&started.outbound)?;
    assert!(request.contains("AllowCreate=\"true\""));
    assert!(!request.contains("ForceAuthn="));
    Ok(())
}

#[test]
fn typed_transient_name_id_omits_allow_create() -> Result<(), Box<dyn std::error::Error>> {
    let mut validation = SpValidationPolicy::default();
    validation.name_id_creation = NameIdCreationPolicy::AllowCreate;
    for format in [
        NameIdFormat::Transient,
        NameIdFormat::Custom(format!(" {} ", NameIdFormat::Transient.as_uri())),
    ] {
        let sp = ServiceProvider::new(
            SpConfig::builder(
                EntityId::try_new(SP_ENTITY_ID)?,
                AcsEndpoint::post(SP_ACS)?.with_default(),
            )
            .name_id_format(format)
            .credentials(signing_credentials())
            .validation(validation.clone())
            .build()?,
        );
        let idp = idp_with(IdpValidationPolicy::default(), false)?;
        let (_, idp_descriptor) = descriptors(&sp, &idp)?;

        let producer = sp.start_sso(&idp_descriptor, StartSso::redirect())?;
        let producer_xml = authn_request_xml(&producer.outbound)?;
        assert!(!producer_xml.contains("AllowCreate="));
        assert!(producer_xml.contains(&format!("<saml:Issuer>{SP_ENTITY_ID}</saml:Issuer>")));
    }
    Ok(())
}

#[test]
fn typed_authn_request_signing_stays_optional_and_does_not_reject_unsigned_requests(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut signed_sp_policy = SpValidationPolicy::default();
    signed_sp_policy.authn_requests = AuthnRequestSigningPolicy::Sign;
    let mut requiring_idp_policy = IdpValidationPolicy::default();
    requiring_idp_policy.authn_requests = AuthnRequestValidationPolicy::RequireSigned;
    let sp = sp_with(signed_sp_policy)?;
    let idp = idp_with(requiring_idp_policy, false)?;
    assert!(idp
        .metadata_xml()
        .contains("WantAuthnRequestsSigned=\"true\""));
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::redirect())?;
    let redirect = started.outbound.redirect_url()?;
    let request = authn_request_xml(&started.outbound)?;
    assert!(redirect.contains("Signature="));
    assert!(redirect.contains("SigAlg="));
    assert!(request.contains(&format!("Destination=\"{IDP_SSO_REDIRECT}\"")));
    assert!(request.contains(&format!("<saml:Issuer>{SP_ENTITY_ID}</saml:Issuer>")));
    assert!(!request.contains("ForceAuthn="));
    assert!(request.contains("AllowCreate=\"false\""));

    let sp = sp_with(SpValidationPolicy::default())?;
    let idp = idp_with(IdpValidationPolicy::default(), false)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::redirect())?;
    assert!(!started.outbound.redirect_url()?.contains("Signature="));
    let url = Url::parse(started.outbound.redirect_url()?)?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::redirect(url.query().unwrap_or_default()),
        validation(),
    )?;
    assert_eq!(received.message().issuer().as_str(), SP_ENTITY_ID);
    Ok(())
}

#[test]
fn typed_signing_sp_starts_sso_against_an_idp_that_does_not_require_signed_requests(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut sp_validation = SpValidationPolicy::default();
    sp_validation.authn_requests = AuthnRequestSigningPolicy::Sign;
    let sp = sp_with(sp_validation)?;
    let idp = idp_with(IdpValidationPolicy::default(), false)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::redirect())?;
    let url = Url::parse(started.outbound.redirect_url()?)?;
    assert!(url.query_pairs().any(|(key, _)| key == "Signature"));
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::redirect(url.query().unwrap_or_default()),
        validation(),
    )?;
    assert_eq!(received.message().issuer().as_str(), SP_ENTITY_ID);
    Ok(())
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn typed_cbc_response_signature_stays_recommended_and_relaxes_alone(
) -> Result<(), Box<dyn std::error::Error>> {
    let encryption = encrypted_assertions();
    let encrypted_credentials = signing_credentials().with_decryption_credential(
        saml_rs::X509Credential::new(CertificatePem::new(CERT), PrivateKeyPem::new(PRIVKEY)),
    );
    let sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(SP_ACS)?.with_default(),
        )
        .credentials(encrypted_credentials.clone())
        .validation(signing_sp_validation())
        .xml(encryption)
        .build()?,
    );
    let idp = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO_POST)?,
        )
        .credentials(signing_credentials())
        .validation(signed_authn_request_idp_validation())
        .xml(encryption)
        .build()?,
    );
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;

    let signed = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    )?;
    let signed_xml = response_xml(&signed)?;
    assert!(signed_xml.contains("<ds:Signature"));
    assert!(signed_xml.contains("<saml:EncryptedAssertion "));
    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(signed.post_form()?.fields().to_vec()),
        post_validation(&mut Default::default()),
    )?;
    assert_eq!(session.name_id().value(), "alice@example.com");

    let unsigned = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal()),
        RespondSso::post().allow_unsigned_encrypted_cbc(),
    )?;
    let unsigned_xml = response_xml(&unsigned)?;
    assert!(!unsigned_xml.contains("<ds:Signature"));
    assert!(unsigned_xml.contains("EncryptedAssertion"));
    let unsigned_fields = unsigned.post_form()?.fields().to_vec();
    match sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(unsigned_fields.clone()),
        post_validation(&mut Default::default()),
    ) {
        Err(SamlError::SignatureMissing) => {}
        other => return Err(format!("expected SignatureMissing, got {other:?}").into()),
    }

    let mut unsigned_cbc = SpValidationPolicy::default();
    unsigned_cbc.responses = ResponseSignaturePolicy::AllowUnsignedEncryptedCbc;
    let permissive = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(SP_ACS)?.with_default(),
        )
        .credentials(encrypted_credentials)
        .validation(unsigned_cbc)
        .xml(encryption)
        .build()?,
    );
    let session = permissive.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(unsigned_fields),
        post_validation(&mut Default::default()),
    )?;
    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}

#[test]
fn typed_plaintext_response_is_accepted() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(signing_sp_validation())?;
    let idp = idp_with(signed_authn_request_idp_validation(), false)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    )?;
    let xml = response_xml(&response)?;
    assert!(xml.contains("AuthnStatement"));
    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(response.post_form()?.fields().to_vec()),
        post_validation(&mut Default::default()),
    )?;
    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}

fn status_element(xml: &str) -> Result<&str, Box<dyn std::error::Error>> {
    let start = xml.find("<samlp:Status>").ok_or("missing Status")?;
    let rest = &xml[start..];
    let end = rest.find("</samlp:Status>").ok_or("missing Status end")?;
    Ok(&rest[..end + "</samlp:Status>".len()])
}

fn assert_error_response_has_no_assertion(xml: &str) -> Result<(), Box<dyn std::error::Error>> {
    if xml.contains("<saml:Assertion")
        || xml.contains("EncryptedAssertion")
        || xml.contains("AuthnStatement")
        || xml.contains("alice@example.com")
    {
        return Err(format!("error Response included an assertion: {xml}").into());
    }
    if xml.matches("<saml:Issuer>").count() != 1 {
        return Err(format!("error Response Issuer count was not 1: {xml}").into());
    }
    Ok(())
}

#[test]
fn typed_sso_error_response_carries_caller_status_and_no_assertions(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(signing_sp_validation())?;
    let idp = idp_with(signed_authn_request_idp_validation(), false)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let request_id = received.message().id().as_str().to_string();

    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoOutcome::Failure(
            Status::responder()
                .with_subordinate(SubordinateStatusCode::try_new(status_code::NO_PASSIVE)?),
        ),
        RespondSso::post(),
    )?;
    let xml = response_xml(&response)?;
    assert_error_response_has_no_assertion(&xml)?;
    assert_eq!(
        status_element(&xml)?,
        concat!(
            "<samlp:Status>",
            "<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Responder\">",
            "<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:NoPassive\"/>",
            "</samlp:StatusCode>",
            "</samlp:Status>"
        )
    );
    assert!(xml.contains(&format!("<saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>")));
    assert!(xml.contains(&format!("Destination=\"{SP_ACS}\"")));
    assert!(xml.contains(&format!("InResponseTo=\"{request_id}\"")));
    assert!(xml.contains("<ds:Signature"));
    assert_generated_instants_have_no_leap_second(&xml)?;

    let requester = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoOutcome::Failure(Status::requester()),
        RespondSso::post(),
    )?;
    let requester_xml = response_xml(&requester)?;
    assert_error_response_has_no_assertion(&requester_xml)?;
    assert_eq!(
        status_element(&requester_xml)?,
        concat!(
            "<samlp:Status>",
            "<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Requester\"/>",
            "</samlp:Status>"
        )
    );
    assert!(requester_xml.contains(&format!("InResponseTo=\"{request_id}\"")));
    assert!(requester_xml.contains(&format!("Destination=\"{SP_ACS}\"")));
    Ok(())
}

#[test]
fn typed_sso_failure_with_a_success_status_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(signing_sp_validation())?;
    let idp = idp_with(signed_authn_request_idp_validation(), false)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;

    match idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoOutcome::Failure(
            Status::success()
                .with_subordinate(SubordinateStatusCode::try_new(status_code::REQUEST_DENIED)?),
        ),
        RespondSso::post(),
    ) {
        Err(SamlError::Invalid(message)) if message.contains("requires an error status") => Ok(()),
        other => Err(format!("expected an error status rejection, got {other:?}").into()),
    }
}

#[test]
fn typed_sso_without_error_status_keeps_success_and_assertions(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(signing_sp_validation())?;
    let idp = idp_with(signed_authn_request_idp_validation(), false)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;

    let solicited = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    )?;
    let solicited_xml = response_xml(&solicited)?;
    assert!(solicited_xml.contains("<saml:Assertion"));
    assert!(solicited_xml.contains("alice@example.com"));
    assert_eq!(
        status_element(&solicited_xml)?,
        concat!(
            "<samlp:Status>",
            "<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>",
            "</samlp:Status>"
        )
    );

    let unsolicited = idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    )?;
    let unsolicited_xml = response_xml(&unsolicited)?;
    assert!(unsolicited_xml.contains("<saml:Assertion"));
    assert_eq!(
        status_element(&unsolicited_xml)?,
        status_element(&solicited_xml)?
    );
    Ok(())
}

#[test]
fn typed_unsolicited_error_response_follows_in_response_to_rules(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(signing_sp_validation())?;
    let idp = idp_with(signed_authn_request_idp_validation(), false)?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;

    let ruled = idp.initiate_sso(
        &sp_descriptor,
        SsoOutcome::Failure(Status::version_mismatch()),
        RespondSso::post(),
    )?;
    let ruled_xml = response_xml(&ruled)?;
    assert_error_response_has_no_assertion(&ruled_xml)?;
    assert!(!ruled_xml.contains("InResponseTo"));
    assert!(ruled_xml.contains(&format!("<saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>")));
    assert!(ruled_xml.contains(&format!("Destination=\"{SP_ACS}\"")));
    assert_eq!(
        status_element(&ruled_xml)?,
        concat!(
            "<samlp:Status>",
            "<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:VersionMismatch\"/>",
            "</samlp:Status>"
        )
    );

    let default_response = idp.initiate_sso(
        &sp_descriptor,
        SsoOutcome::Failure(Status::version_mismatch()),
        RespondSso::post(),
    )?;
    let default_xml = response_xml(&default_response)?;
    assert_error_response_has_no_assertion(&default_xml)?;
    assert!(!default_xml.contains("InResponseTo"));
    assert!(default_xml.contains(&format!("Destination=\"{SP_ACS}\"")));
    assert!(default_xml.contains(&format!("<saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>")));
    Ok(())
}

#[test]
fn typed_error_response_uses_configured_namespace_prefixes(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(signing_sp_validation())?;
    let mut templates = TemplatePolicy::default();
    templates.tag_prefix_protocol = "saml2p".into();
    templates.tag_prefix_assertion = "saml2".into();
    let idp_config = IdpConfig::builder(
        EntityId::try_new(IDP_ENTITY_ID)?,
        SsoEndpoint::post(IDP_SSO_POST)?,
    )
    .credentials(signing_credentials())
    .validation(signed_authn_request_idp_validation())
    .templates(templates)
    .build()?;
    let idp = IdentityProvider::new(idp_config);
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let no_passive = Status::responder()
        .with_subordinate(SubordinateStatusCode::try_new(status_code::NO_PASSIVE)?);

    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let request_id = received.message().id().as_str().to_string();
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoOutcome::Failure(no_passive.clone()),
        RespondSso::post(),
    )?;
    let xml = response_xml(&response)?;
    assert!(xml.starts_with("<saml2p:Response "), "{xml}");
    assert!(xml.contains("<saml2:Issuer>"), "{xml}");
    assert!(!xml.contains("Assertion"), "{xml}");
    assert!(
        xml.contains(&format!("InResponseTo=\"{request_id}\"")),
        "{xml}"
    );
    match sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(response.post_form()?.fields().to_vec()),
        validation(),
    ) {
        Err(SamlError::StatusNotSuccess { status, .. }) => assert_eq!(status, no_passive),
        other => return Err(format!("expected StatusNotSuccess, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn typed_simplesign_error_response_keeps_the_detached_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?, AcsEndpoint::post(SP_ACS)?)
            .acs_endpoint(
                AcsEndpoint::simple_sign("https://sp.example.com/acs/simple-sign")?.with_default(),
            )
            .credentials(signing_credentials())
            .validation(signing_sp_validation())
            .build()?,
    );
    let idp = idp_with(signed_authn_request_idp_validation(), false)?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    let response = idp.initiate_sso(
        &sp_descriptor,
        SsoOutcome::Failure(Status::responder()),
        RespondSso::simple_sign(),
    )?;
    let form = response.post_form()?;
    let xml = response_xml(&response)?;

    assert_error_response_has_no_assertion(&xml)?;
    assert!(xml.contains("Destination=\"https://sp.example.com/acs/simple-sign\""));
    assert!(form.value("Signature").is_some());
    assert!(form.value("SigAlg").is_some());
    assert!(!xml.contains("<ds:Signature"));
    assert_eq!(header_pairs(&response), NO_CACHE_HEADERS);
    Ok(())
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn typed_error_response_stays_plaintext_when_assertion_encryption_is_on(
) -> Result<(), Box<dyn std::error::Error>> {
    let encryption = encrypted_assertions();
    let sp = sp_with(signing_sp_validation())?;
    let idp = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO_POST)?,
        )
        .credentials(signing_credentials())
        .validation(signed_authn_request_idp_validation())
        .xml(encryption)
        .build()?,
    );
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    let response = idp.initiate_sso(
        &sp_descriptor,
        SsoOutcome::Failure(Status::responder()),
        RespondSso::post(),
    )?;
    let xml = response_xml(&response)?;

    assert_error_response_has_no_assertion(&xml)?;
    assert!(!xml.contains("EncryptedData"));
    assert!(xml.contains("<ds:Signature"));
    Ok(())
}
