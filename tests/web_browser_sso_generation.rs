//! Compatibility is the legacy permissive preset.
//! `RespondSso::allow_unsigned_encrypted_cbc` relaxes Errata 05 E93 and is not that preset.
#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use std::time::SystemTime;

use saml_rs::binding::{base64_decode, deflate_raw_decode};
use saml_rs::constants::status_code;
use saml_rs::raw::Binding;
use saml_rs::template::{LoginResponseTemplate, LOGIN_RESPONSE_TEMPLATE};
use saml_rs::{
    AcsEndpoint, AssertionSignaturePolicy, AudienceValidationPolicy, AuthnRequest,
    AuthnRequestSigningPolicy, AuthnRequestValidationPolicy, BrowserInput, CertificatePem,
    Credentials, EntityId, ForceAuthn, FormField, IdpConfig, IdpDescriptor, IdpValidationPolicy,
    MetadataTrustPolicy, NameId, NameIdCreationPolicy, NameIdFormat, Outbound, PrivateKeyPem,
    ReplayPolicy, RespondSso, Saml, SamlError, SamlValidationContext, SloEndpoint, SpConfig,
    SpDescriptor, SpValidationPolicy, SsoEndpoint, SsoResponse, StartSso, Status, Subject,
    SubordinateStatusCode,
};
#[cfg(not(feature = "crypto-fips"))]
use saml_rs::{XmlEncryptionPolicy, XmlPolicy};
use url::Url;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const IDP_SSO_REDIRECT: &str = "https://idp.example.com/sso/redirect";
const IDP_SLO: &str = "https://idp.example.com/slo";
const UNSPECIFIED_AUTHN_CONTEXT: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";

const PRIVKEY: &str = include_str!("fixtures/key/sp_privkey.pem");
const CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");

fn credentials() -> Credentials {
    Credentials {
        signing_key: Some(PrivateKeyPem::new(PRIVKEY)),
        signing_certificate: Some(CertificatePem::new(CERT)),
        ..Credentials::default()
    }
}

fn signing_sp_validation() -> SpValidationPolicy {
    SpValidationPolicy {
        assertions: AssertionSignaturePolicy::RequireSigned,
        authn_requests: AuthnRequestSigningPolicy::Sign,
        audience: AudienceValidationPolicy::Validate,
        ..SpValidationPolicy::recommended()
    }
}

fn signed_authn_request_idp_validation() -> IdpValidationPolicy {
    IdpValidationPolicy {
        authn_requests: AuthnRequestValidationPolicy::RequireSigned,
        ..IdpValidationPolicy::recommended()
    }
}

fn subject() -> Subject {
    Subject::new(NameId::new("alice@example.com", None), Vec::new())
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility)
}

fn sp_with(validation: SpValidationPolicy) -> Result<Saml<saml_rs::Sp>, SamlError> {
    Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS)?.mark_default())
            .credentials(credentials())
            .validation(validation)
            .build()?,
    )
}

fn idp_with(
    validation: IdpValidationPolicy,
    single_logout: bool,
) -> Result<Saml<saml_rs::Idp>, SamlError> {
    let mut builder = IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
        .sso_endpoint(SsoEndpoint::redirect(IDP_SSO_REDIRECT)?)
        .credentials(credentials())
        .validation(validation);
    if single_logout {
        builder = builder.slo_endpoint(SloEndpoint::redirect(IDP_SLO)?);
    }
    Saml::idp(builder.build()?)
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

fn authn_request_xml(
    outbound: &Outbound<AuthnRequest>,
) -> Result<String, Box<dyn std::error::Error>> {
    match outbound.raw_context().binding {
        Binding::Redirect => {
            let url = Url::parse(outbound.redirect_url()?)?;
            let (_, encoded) = url
                .query_pairs()
                .find(|(key, _)| key == "SAMLRequest")
                .ok_or("missing SAMLRequest")?;
            Ok(String::from_utf8(deflate_raw_decode(&base64_decode(
                encoded.as_ref(),
            )?)?)?)
        }
        Binding::Post | Binding::SimpleSign => Ok(String::from_utf8(base64_decode(
            &outbound.raw_context().context,
        )?)?),
        Binding::Artifact => Err("artifact binding is unsupported".into()),
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
    Ok(String::from_utf8(base64_decode(encoded)?)?)
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
        BrowserInput::<AuthnRequest>::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondSso::post().apply_web_browser_sso_generation_rules(),
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
        BrowserInput::<SsoResponse>::post(response.post_form()?.fields().to_vec()),
        validation(),
    )?;
    assert_eq!(session.name_id().value(), "alice@example.com");
    assert_eq!(
        session.in_response_to().map(|id| id.as_str()),
        Some(received.message().id().as_str())
    );
    Ok(())
}

#[test]
fn typed_unsolicited_sso_omits_in_response_to_under_producer_rules(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(signing_sp_validation())?;
    let idp = idp_with(signed_authn_request_idp_validation(), false)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let response = idp.initiate_sso(
        &sp_descriptor,
        subject(),
        RespondSso::post().apply_web_browser_sso_generation_rules(),
    )?;
    let xml = response_xml(&response)?;

    assert!(!xml.contains("InResponseTo"));
    assert!(xml.contains("<saml:AuthnStatement "));
    assert!(xml.contains(&format!("<saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>")));
    assert_generated_instants_have_no_leap_second(&xml)?;

    let session = sp.accept_unsolicited_sso(
        &idp_descriptor,
        BrowserInput::<SsoResponse>::post(response.post_form()?.fields().to_vec()),
        validation(),
    )?;
    assert_eq!(session.in_response_to(), None);
    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}

#[test]
fn typed_sso_compatibility_generation_keeps_todays_response_shape(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(signing_sp_validation())?;
    let idp = idp_with(signed_authn_request_idp_validation(), true)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let response = idp.initiate_sso(&sp_descriptor, subject(), RespondSso::post())?;
    let xml = response_xml(&response)?;

    assert!(xml.contains("InResponseTo=\"\""));
    assert!(!xml.contains("AuthnStatement"));
    assert!(!xml.contains("SessionIndex="));

    let session = sp.accept_unsolicited_sso(
        &idp_descriptor,
        BrowserInput::<SsoResponse>::post(response.post_form()?.fields().to_vec()),
        validation(),
    )?;
    assert_eq!(session.in_response_to(), None);
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

    for options in [
        RespondSso::post(),
        RespondSso::post().apply_web_browser_sso_generation_rules(),
    ] {
        let response = idp.initiate_sso(&sp_descriptor, subject(), options)?;
        let xml = response_xml(&response)?;
        assert!(xml.contains("<saml:NameID>alice@example.com</saml:NameID>"));

        let session = sp.accept_unsolicited_sso(
            &idp_descriptor,
            BrowserInput::<SsoResponse>::post(response.post_form()?.fields().to_vec()),
            validation(),
        )?;
        assert_eq!(session.name_id().format(), None);
    }

    let mut template_config = IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
        .credentials(credentials())
        .validation(signed_authn_request_idp_validation())
        .build()?;
    template_config.templates.login_response_template = Some(LoginResponseTemplate {
        context: Some(LOGIN_RESPONSE_TEMPLATE.to_string()),
        attributes: Vec::new(),
    });
    let template_idp = Saml::idp(template_config)?;
    let (sp_descriptor, _) = descriptors(&sp, &template_idp)?;
    let response = template_idp.initiate_sso(&sp_descriptor, subject(), RespondSso::post())?;
    assert!(response_xml(&response)?.contains("<saml:NameID>alice@example.com</saml:NameID>"));
    Ok(())
}

#[test]
fn typed_sso_assertion_name_id_keeps_the_configured_format(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(signing_sp_validation())?;
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
            .name_id_format(NameIdFormat::EmailAddress)
            .credentials(credentials())
            .validation(signed_authn_request_idp_validation())
            .build()?,
    )?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;

    let response = idp.initiate_sso(&sp_descriptor, subject(), RespondSso::post())?;
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
        subject(),
        RespondSso::post().apply_web_browser_sso_generation_rules(),
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
        BrowserInput::<SsoResponse>::post(response.post_form()?.fields().to_vec()),
        validation(),
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

    let idp_without_logout = idp_with(signed_authn_request_idp_validation(), false)?;
    let (sp_descriptor, _) = descriptors(&sp, &idp_without_logout)?;
    let response = idp_without_logout.initiate_sso(
        &sp_descriptor,
        subject(),
        RespondSso::post().apply_web_browser_sso_generation_rules(),
    )?;
    let xml = response_xml(&response)?;
    assert!(xml.contains("<saml:AuthnStatement "));
    assert!(!xml.contains("SessionIndex="));
    Ok(())
}

#[test]
fn typed_sso_optional_generation_capabilities_stay_off_until_selected(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(SpValidationPolicy::recommended())?;
    let idp = idp_with(IdpValidationPolicy::recommended(), false)?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::redirect().apply_web_browser_sso_generation_rules(),
    )?;
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
        StartSso::redirect()
            .apply_web_browser_sso_generation_rules()
            .force_authn(ForceAuthn::Required),
    )?;
    let forced_xml = authn_request_xml(&forced.outbound)?;
    assert!(forced_xml.contains("ForceAuthn=\"true\""));
    assert!(forced_xml.contains("AllowCreate=\"false\""));

    let mut creating = SpValidationPolicy::recommended();
    creating.name_id_creation = NameIdCreationPolicy::AllowCreate;
    let sp = sp_with(creating)?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::redirect().apply_web_browser_sso_generation_rules(),
    )?;
    let request = authn_request_xml(&started.outbound)?;
    assert!(request.contains("AllowCreate=\"true\""));
    assert!(!request.contains("ForceAuthn="));
    Ok(())
}

#[test]
fn typed_transient_name_id_omits_allow_create_under_producer_rules(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut validation = SpValidationPolicy::compatibility();
    validation.name_id_creation = NameIdCreationPolicy::AllowCreate;
    let sp = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS)?.mark_default())
            .name_id_format(NameIdFormat::Transient)
            .credentials(credentials())
            .validation(validation)
            .build()?,
    )?;
    let idp = idp_with(IdpValidationPolicy::compatibility(), false)?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;

    let compatibility = sp.start_sso(&idp_descriptor, StartSso::redirect())?;
    let compatibility_xml = authn_request_xml(&compatibility.outbound)?;
    assert!(compatibility_xml.contains("AllowCreate=\"true\""));

    let producer = sp.start_sso(
        &idp_descriptor,
        StartSso::redirect().apply_web_browser_sso_generation_rules(),
    )?;
    let producer_xml = authn_request_xml(&producer.outbound)?;
    assert!(!producer_xml.contains("AllowCreate="));
    assert!(producer_xml.contains(&format!("<saml:Issuer>{SP_ENTITY_ID}</saml:Issuer>")));
    Ok(())
}

#[test]
fn typed_authn_request_signing_stays_optional_and_does_not_reject_unsigned_requests(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut signed_sp_policy = SpValidationPolicy::recommended();
    signed_sp_policy.authn_requests = AuthnRequestSigningPolicy::Sign;
    let mut requiring_idp_policy = IdpValidationPolicy::recommended();
    requiring_idp_policy.authn_requests = AuthnRequestValidationPolicy::RequireSigned;
    let sp = sp_with(signed_sp_policy)?;
    let idp = idp_with(requiring_idp_policy, false)?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::redirect().apply_web_browser_sso_generation_rules(),
    )?;
    let redirect = started.outbound.redirect_url()?;
    let request = authn_request_xml(&started.outbound)?;
    assert!(redirect.contains("Signature="));
    assert!(redirect.contains("SigAlg="));
    assert!(request.contains(&format!("Destination=\"{IDP_SSO_REDIRECT}\"")));
    assert!(request.contains(&format!("<saml:Issuer>{SP_ENTITY_ID}</saml:Issuer>")));
    assert!(!request.contains("ForceAuthn="));
    assert!(request.contains("AllowCreate=\"false\""));

    let sp = sp_with(SpValidationPolicy::recommended())?;
    let idp = idp_with(IdpValidationPolicy::recommended(), false)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::redirect().apply_web_browser_sso_generation_rules(),
    )?;
    assert!(!started.outbound.redirect_url()?.contains("Signature="));
    let url = Url::parse(started.outbound.redirect_url()?)?;
    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::redirect(url.query().unwrap_or_default()),
        validation(),
    )?;
    assert_eq!(received.message().issuer().as_str(), SP_ENTITY_ID);
    Ok(())
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn typed_cbc_response_signature_stays_recommended_and_relaxes_alone(
) -> Result<(), Box<dyn std::error::Error>> {
    let encryption = XmlPolicy {
        encryption: XmlEncryptionPolicy::encrypt_assertions()
            .with_insecure_software_rsa_key_transport_decryption_allowed(),
        ..XmlPolicy::default()
    };
    let encrypted_credentials = Credentials {
        encryption_certificate: Some(CertificatePem::new(CERT)),
        decryption_key: Some(PrivateKeyPem::new(PRIVKEY)),
        ..credentials()
    };
    let sp = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS)?.mark_default())
            .credentials(encrypted_credentials.clone())
            .validation(signing_sp_validation())
            .xml(encryption)
            .build()?,
    )?;
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
            .credentials(credentials())
            .validation(signed_authn_request_idp_validation())
            .xml(encryption)
            .build()?,
    )?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;

    let signed = idp.respond_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondSso::post().apply_web_browser_sso_generation_rules(),
    )?;
    let signed_xml = response_xml(&signed)?;
    assert!(signed_xml.contains("<ds:Signature"));
    assert!(signed_xml.contains("EncryptedAssertion"));
    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<SsoResponse>::post(signed.post_form()?.fields().to_vec()),
        validation(),
    )?;
    assert_eq!(session.name_id().value(), "alice@example.com");

    let unsigned = idp.respond_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondSso::post()
            .apply_web_browser_sso_generation_rules()
            .allow_unsigned_encrypted_cbc(),
    )?;
    let unsigned_xml = response_xml(&unsigned)?;
    assert!(!unsigned_xml.contains("<ds:Signature"));
    assert!(unsigned_xml.contains("EncryptedAssertion"));
    let unsigned_fields = unsigned.post_form()?.fields().to_vec();
    match sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<SsoResponse>::post(unsigned_fields.clone()),
        validation(),
    ) {
        Err(SamlError::SignatureMissing) => {}
        other => return Err(format!("expected SignatureMissing, got {other:?}").into()),
    }

    let permissive = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS)?.mark_default())
            .credentials(encrypted_credentials)
            .validation(SpValidationPolicy::compatibility())
            .xml(encryption)
            .build()?,
    )?;
    let session = permissive.finish_sso(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<SsoResponse>::post(unsigned_fields),
        validation(),
    )?;
    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}

#[test]
fn typed_producer_rules_reject_custom_login_templates() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
        .acs_endpoint(AcsEndpoint::post(SP_ACS)?.mark_default())
        .credentials(credentials())
        .validation(SpValidationPolicy::compatibility())
        .build()?;
    config.templates.login_request_template = Some("<samlp:AuthnRequest/>".to_string());
    let sp = Saml::sp(config)?;
    let idp = idp_with(IdpValidationPolicy::compatibility(), false)?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    match sp.start_sso(
        &idp_descriptor,
        StartSso::redirect().apply_web_browser_sso_generation_rules(),
    ) {
        Err(SamlError::Invalid(message)) if message.contains("built-in AuthnRequest renderer") => {}
        other => return Err(format!("expected built-in renderer error, got {other:?}").into()),
    }

    let sp = sp_with(signing_sp_validation())?;
    let mut idp_config = IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
        .credentials(credentials())
        .validation(signed_authn_request_idp_validation())
        .build()?;
    idp_config.templates.login_response_template = Some(LoginResponseTemplate {
        context: Some("<samlp:Response/>".to_string()),
        attributes: Vec::new(),
    });
    let idp = Saml::idp(idp_config)?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    match idp.initiate_sso(
        &sp_descriptor,
        subject(),
        RespondSso::post().apply_web_browser_sso_generation_rules(),
    ) {
        Err(SamlError::Invalid(message))
            if message.contains("built-in login response renderer") =>
        {
            Ok(())
        }
        other => Err(format!("expected built-in renderer error, got {other:?}").into()),
    }
}

#[test]
fn typed_plaintext_response_stays_accepted_without_producer_rules(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(signing_sp_validation())?;
    let idp = idp_with(signed_authn_request_idp_validation(), false)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let response = idp.respond_sso(&sp_descriptor, &received, subject(), RespondSso::post())?;
    let xml = response_xml(&response)?;
    assert!(!xml.contains("AuthnStatement"));
    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<SsoResponse>::post(response.post_form()?.fields().to_vec()),
        validation(),
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
        BrowserInput::<AuthnRequest>::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let request_id = received.message().id().as_str().to_string();

    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondSso::post()
            .apply_web_browser_sso_generation_rules()
            .status(
                Status::responder()
                    .with_subordinate(SubordinateStatusCode::try_new(status_code::NO_PASSIVE)?),
            ),
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
        subject(),
        RespondSso::post().status(Status::requester()),
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
fn typed_sso_without_error_status_keeps_success_and_assertions(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(signing_sp_validation())?;
    let idp = idp_with(signed_authn_request_idp_validation(), false)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;

    let solicited = idp.respond_sso(&sp_descriptor, &received, subject(), RespondSso::post())?;
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

    let explicit_success = idp.respond_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondSso::post().status(Status::success()),
    )?;
    let explicit_xml = response_xml(&explicit_success)?;
    assert!(explicit_xml.contains("<saml:Assertion"));
    assert_eq!(
        status_element(&explicit_xml)?,
        status_element(&solicited_xml)?
    );

    let unsolicited = idp.initiate_sso(&sp_descriptor, subject(), RespondSso::post())?;
    let unsolicited_xml = response_xml(&unsolicited)?;
    assert!(unsolicited_xml.contains("<saml:Assertion"));
    assert_eq!(
        status_element(&unsolicited_xml)?,
        status_element(&solicited_xml)?
    );

    let success_with_detail = idp.respond_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondSso::post().status(
            Status::success()
                .with_subordinate(SubordinateStatusCode::try_new(status_code::REQUEST_DENIED)?),
        ),
    )?;
    let detail_xml = response_xml(&success_with_detail)?;
    assert!(detail_xml.contains("<saml:Assertion"));
    assert!(detail_xml.contains("alice@example.com"));
    assert_eq!(
        status_element(&detail_xml)?,
        concat!(
            "<samlp:Status>",
            "<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\">",
            "<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:RequestDenied\"/>",
            "</samlp:StatusCode>",
            "</samlp:Status>"
        )
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
        subject(),
        RespondSso::post()
            .apply_web_browser_sso_generation_rules()
            .status(Status::version_mismatch()),
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

    let compatibility = idp.initiate_sso(
        &sp_descriptor,
        subject(),
        RespondSso::post().status(Status::version_mismatch()),
    )?;
    let compatibility_xml = response_xml(&compatibility)?;
    assert_error_response_has_no_assertion(&compatibility_xml)?;
    assert!(compatibility_xml.contains("InResponseTo=\"\""));
    assert!(compatibility_xml.contains(&format!("Destination=\"{SP_ACS}\"")));
    assert!(compatibility_xml.contains(&format!("<saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>")));
    Ok(())
}

#[test]
fn typed_error_response_rejects_a_login_response_template() -> Result<(), Box<dyn std::error::Error>>
{
    let sp = sp_with(signing_sp_validation())?;
    let mut idp_config = IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
        .credentials(credentials())
        .validation(signed_authn_request_idp_validation())
        .build()?;
    idp_config.templates.login_response_template = Some(LoginResponseTemplate {
        context: Some(saml_rs::template::LOGIN_RESPONSE_TEMPLATE.to_string()),
        attributes: Vec::new(),
    });
    let idp = Saml::idp(idp_config)?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;

    match idp.initiate_sso(
        &sp_descriptor,
        subject(),
        RespondSso::post().status(Status::responder()),
    ) {
        Err(SamlError::Invalid(message))
            if message.contains("cannot use a login response template") =>
        {
            Ok(())
        }
        other => Err(format!("expected template rejection, got {other:?}").into()),
    }
}

#[test]
fn typed_simplesign_error_response_keeps_the_detached_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS)?)
            .acs_endpoint(
                AcsEndpoint::simple_sign("https://sp.example.com/acs/simple-sign")?.mark_default(),
            )
            .credentials(credentials())
            .validation(signing_sp_validation())
            .build()?,
    )?;
    let idp = idp_with(signed_authn_request_idp_validation(), false)?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    let response = idp.initiate_sso(
        &sp_descriptor,
        subject(),
        RespondSso::simple_sign().status(Status::responder()),
    )?;
    let form = response.post_form()?;
    let xml = response_xml(&response)?;

    assert_error_response_has_no_assertion(&xml)?;
    assert!(xml.contains("Destination=\"https://sp.example.com/acs/simple-sign\""));
    assert!(form.value("Signature").is_some());
    assert!(form.value("SigAlg").is_some());
    assert!(!xml.contains("<ds:Signature"));
    Ok(())
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn typed_error_response_stays_plaintext_when_assertion_encryption_is_on(
) -> Result<(), Box<dyn std::error::Error>> {
    let encryption = XmlPolicy {
        encryption: XmlEncryptionPolicy::encrypt_assertions()
            .with_insecure_software_rsa_key_transport_decryption_allowed(),
        ..XmlPolicy::default()
    };
    let sp = sp_with(signing_sp_validation())?;
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
            .credentials(credentials())
            .validation(signed_authn_request_idp_validation())
            .xml(encryption)
            .build()?,
    )?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    let response = idp.initiate_sso(
        &sp_descriptor,
        subject(),
        RespondSso::post().status(Status::responder()),
    )?;
    let xml = response_xml(&response)?;

    assert_error_response_has_no_assertion(&xml)?;
    assert!(!xml.contains("EncryptedData"));
    assert!(xml.contains("<ds:Signature"));
    Ok(())
}
