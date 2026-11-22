//! Compatibility is the legacy permissive preset.
//! `RespondSso::allow_unsigned_encrypted_cbc` relaxes Errata 05 E93 and is not that preset.
#![cfg(crypto)]

use super::common;
use saml_rs::tests::engine::LogoutUser;
use saml_rs::tests::engine::{IdpMessages, SpMessages};

#[cfg(not(feature = "crypto-fips"))]
#[path = "typed_sso/encryption.rs"]
mod encryption;

use super::replay_cache;

use replay_cache::RecordingReplayCache;

use common::signing_credentials;

use std::time::{Duration, SystemTime};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::binding::{
    append_signature, build_redirect_octet, deflate_raw_decode, MAX_DEFLATE_RAW_DECODE_BYTES,
};
use saml_rs::config::SSO_RESPONSE_TEMPLATE;
use saml_rs::constants::signature_algorithm::{RSA_SHA256, RSA_SHA512};
use saml_rs::constants::Binding;
use saml_rs::constants::{status_code, ParserType};
use saml_rs::crypto::{keys::read_private_key, sign_octet_string, sign_saml_xml};
use saml_rs::entity::{EntitySetting, User};
use saml_rs::error::{SignatureVerificationReason, TimeWindowField};
use saml_rs::idp;
use saml_rs::idp::LoginResponseOptions;
use saml_rs::sp;
use saml_rs::sp::LoginRequestOptions;
use saml_rs::tests::engine::create_logout_request;
use saml_rs::xml::dom::parse_document;
use saml_rs::{
    AcsEndpoint, AssertionSignaturePolicy, AudienceValidationPolicy, AuthnRequest,
    AuthnRequestSigningPolicy, AuthnRequestValidationPolicy, CertificatePem, ClockSkew, EntityId,
    ForceAuthn, FormField, IdentityProvider, IdpConfig, IdpDescriptor, IdpValidationPolicy,
    Inbound, MetadataTrustPolicy, NameId, NameIdFormat, Outbound, OutboundDelivery,
    PendingAuthnRequest, PendingAuthnRequestSnapshot, Received, RelayState, ReplayCache,
    ReplayPolicy, RequestAgePolicy, RespondSso, ResponseSignaturePolicy, SamlError,
    SamlValidationContext, ServiceProvider, SloEndpoint, SpConfig, SpDescriptor,
    SpValidationPolicy, SsoAssertion, SsoEndpoint, SsoOutcome, SsoResponseBinding, StartSso,
    Status, SubordinateStatusCode, VerifiedXmlSignatureCoverage, XmlSignatureProfile,
};
#[cfg(not(feature = "crypto-fips"))]
use saml_rs::{
    AssertionEncryptionPolicy, Credentials, PrivateKeyPem, XmlEncryptionPolicy, XmlPolicy,
};
use saml_rs::{SignatureAction, SignatureConfig};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use url::Url;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS_POST: &str = "https://sp.example.com/acs/post";
const SP_ACS_SIMPLESIGN: &str = "https://sp.example.com/acs/simple-sign";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const IDP_SSO_REDIRECT: &str = "https://idp.example.com/sso/redirect";
const IDP_SSO_SIMPLESIGN: &str = "https://idp.example.com/sso/simple-sign";
const SP_SLO_POST: &str = "https://sp.example.com/slo/post";

const HOSTILE_SP_ENTITY_ID: &str = concat!(
    "https://sp.example.com/metadata",
    "</saml:Issuer>",
    "<evil:Injected>issuer</evil:Injected>",
    "<saml:Issuer>"
);
const HOSTILE_IDP_SSO_DESTINATION: &str = concat!(
    "https://idp.example.com/sso?",
    "continue=%3Cevil:Injected%3Edestination%3C%2Fevil:Injected%3E",
    "&quote=%22"
);
const HOSTILE_ACS_URL: &str = concat!(
    "https://sp.example.com/acs?",
    "continue=%3Cevil:Injected%3Eacs%3C%2Fevil:Injected%3E",
    "&quote=%22"
);
const HOSTILE_NAME_ID_FORMAT: &str = concat!(
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\"/>",
    "<evil:Injected>nameid</evil:Injected>",
    "<samlp:NameIDPolicy Format=\""
);

const PRIVKEY: &str = include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");

fn signing_sp_validation() -> SpValidationPolicy {
    SpValidationPolicy {
        assertions: AssertionSignaturePolicy::RequireSigned,
        authn_requests: AuthnRequestSigningPolicy::Sign,
        audience: AudienceValidationPolicy::RequireRestriction,
        ..SpValidationPolicy::recommended()
    }
}

fn signed_authn_request_idp_validation() -> IdpValidationPolicy {
    IdpValidationPolicy {
        authn_requests: AuthnRequestValidationPolicy::RequireSigned,
        ..IdpValidationPolicy::recommended()
    }
}

#[cfg(not(feature = "crypto-fips"))]
fn encryption_credentials() -> Credentials {
    signing_credentials().with_decryption_credential(saml_rs::X509Credential::new(
        CertificatePem::new(CERT),
        PrivateKeyPem::new(PRIVKEY),
    ))
}

#[cfg(not(feature = "crypto-fips"))]
fn encrypted_xml_policy() -> XmlPolicy {
    XmlPolicy {
        encryption: XmlEncryptionPolicy {
            assertions: AssertionEncryptionPolicy::EncryptAssertions,
            ..XmlEncryptionPolicy::default()
        },
        ..XmlPolicy::default()
    }
}

fn sp_config() -> Result<SpConfig, SamlError> {
    sp_config_with_default_response_binding(SsoResponseBinding::Post)
}

fn sp_config_with_default_response_binding(
    binding: SsoResponseBinding,
) -> Result<SpConfig, SamlError> {
    let post = AcsEndpoint::post(SP_ACS_POST)?;
    let simple_sign = AcsEndpoint::simple_sign(SP_ACS_SIMPLESIGN)?;
    let (post, simple_sign) = match binding {
        SsoResponseBinding::Post => (post.with_default(), simple_sign),
        SsoResponseBinding::SimpleSign => (post, simple_sign.with_default()),
        binding => {
            return Err(SamlError::UnsupportedBinding {
                binding: Binding::from(binding),
            })
        }
    };
    SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?, post)
        .acs_endpoint(simple_sign)
        .credentials(signing_credentials())
        .validation(signing_sp_validation())
        .build()
}

fn response_signature_required_sp_config() -> Result<SpConfig, SamlError> {
    let validation = SpValidationPolicy {
        responses: ResponseSignaturePolicy::RequireSigned,
        ..signing_sp_validation()
    };
    SpConfig::builder(
        EntityId::try_new(SP_ENTITY_ID)?,
        AcsEndpoint::post(SP_ACS_POST)?.with_default(),
    )
    .acs_endpoint(AcsEndpoint::simple_sign(SP_ACS_SIMPLESIGN)?)
    .credentials(signing_credentials())
    .validation(validation)
    .build()
}

fn response_root_only_sp_config() -> Result<SpConfig, SamlError> {
    let validation = SpValidationPolicy {
        assertions: AssertionSignaturePolicy::AllowUnsigned,
        responses: ResponseSignaturePolicy::RequireSigned,
        ..signing_sp_validation()
    };
    SpConfig::builder(
        EntityId::try_new(SP_ENTITY_ID)?,
        AcsEndpoint::post(SP_ACS_POST)?.with_default(),
    )
    .credentials(signing_credentials())
    .validation(validation)
    .build()
}

fn idp_config() -> Result<IdpConfig, SamlError> {
    IdpConfig::builder(
        EntityId::try_new(IDP_ENTITY_ID)?,
        SsoEndpoint::post(IDP_SSO_POST)?,
    )
    .sso_endpoint(SsoEndpoint::redirect(IDP_SSO_REDIRECT)?)
    .sso_endpoint(SsoEndpoint::simple_sign(IDP_SSO_SIMPLESIGN)?)
    .credentials(signing_credentials())
    .validation(signed_authn_request_idp_validation())
    .build()
}

// Field combination exercised by the typed Web Browser SSO accept tests.
fn recommended_sso_accept_validation() -> SpValidationPolicy {
    SpValidationPolicy::recommended()
}

fn recommended_sso_accept_idp_validation() -> IdpValidationPolicy {
    IdpValidationPolicy::recommended()
}

fn signed_idp_metadata() -> Result<String, SamlError> {
    let xml = format!(
        r#"<EntityDescriptor ID="_idp_md1" entityID="{IDP_ENTITY_ID}" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{IDP_SSO_POST}"/></IDPSSODescriptor></EntityDescriptor>"#
    );
    let key = read_private_key(PRIVKEY, None)?;
    let config = SignatureConfig {
        prefix: "ds".into(),
        reference: Some("/*[local-name(.)='EntityDescriptor']".into()),
        action: SignatureAction::Prepend,
    };
    sign_saml_xml(&xml, true, &key, CERT, RSA_SHA256, &[], Some(&config))
}

fn sp_with_validation(validation: SpValidationPolicy) -> Result<SpConfig, SamlError> {
    SpConfig::builder(
        EntityId::try_new(SP_ENTITY_ID)?,
        AcsEndpoint::post(SP_ACS_POST)?.with_default(),
    )
    .credentials(signing_credentials())
    .validation(validation)
    .build()
}

fn idp_with_validation(validation: IdpValidationPolicy) -> Result<IdpConfig, SamlError> {
    IdpConfig::builder(
        EntityId::try_new(IDP_ENTITY_ID)?,
        SsoEndpoint::post(IDP_SSO_POST)?,
    )
    .credentials(signing_credentials())
    .validation(validation)
    .build()
}

#[cfg(not(feature = "crypto-fips"))]
fn encrypted_sp_config() -> Result<SpConfig, SamlError> {
    SpConfig::builder(
        EntityId::try_new(SP_ENTITY_ID)?,
        AcsEndpoint::post(SP_ACS_POST)?.with_default(),
    )
    .credentials(encryption_credentials())
    .validation(signing_sp_validation())
    .xml(encrypted_xml_policy())
    .build()
}

#[cfg(not(feature = "crypto-fips"))]
fn encrypted_idp_config() -> Result<IdpConfig, SamlError> {
    IdpConfig::builder(
        EntityId::try_new(IDP_ENTITY_ID)?,
        SsoEndpoint::post(IDP_SSO_POST)?,
    )
    .credentials(signing_credentials())
    .validation(signed_authn_request_idp_validation())
    .xml(encrypted_xml_policy())
    .build()
}

fn hostile_sp_config() -> Result<SpConfig, SamlError> {
    SpConfig::builder(
        EntityId::try_new(HOSTILE_SP_ENTITY_ID)?,
        AcsEndpoint::post(HOSTILE_ACS_URL)?.with_default(),
    )
    .credentials(signing_credentials())
    .validation(signing_sp_validation())
    .name_id_format(NameIdFormat::Custom(HOSTILE_NAME_ID_FORMAT.to_string()))
    .build()
}

fn hostile_idp_config() -> Result<IdpConfig, SamlError> {
    IdpConfig::builder(
        EntityId::try_new(IDP_ENTITY_ID)?,
        SsoEndpoint::post(HOSTILE_IDP_SSO_DESTINATION)?,
    )
    .sso_endpoint(SsoEndpoint::redirect(HOSTILE_IDP_SSO_DESTINATION)?)
    .sso_endpoint(SsoEndpoint::simple_sign(HOSTILE_IDP_SSO_DESTINATION)?)
    .credentials(signing_credentials())
    .validation(signed_authn_request_idp_validation())
    .build()
}

fn facades() -> Result<(saml_rs::ServiceProvider, saml_rs::IdentityProvider), SamlError> {
    Ok((
        ServiceProvider::new(sp_config()?),
        IdentityProvider::new(idp_config()?),
    ))
}

fn compatibility_facades(
) -> Result<(saml_rs::ServiceProvider, saml_rs::IdentityProvider), SamlError> {
    let sp = SpConfig::builder(
        EntityId::try_new(SP_ENTITY_ID)?,
        AcsEndpoint::post(SP_ACS_POST)?.with_default(),
    )
    .acs_endpoint(AcsEndpoint::simple_sign(SP_ACS_SIMPLESIGN)?)
    .credentials(signing_credentials())
    .validation(SpValidationPolicy::compatibility())
    .build()?;
    let idp = IdpConfig::builder(
        EntityId::try_new(IDP_ENTITY_ID)?,
        SsoEndpoint::post(IDP_SSO_POST)?,
    )
    .sso_endpoint(SsoEndpoint::redirect(IDP_SSO_REDIRECT)?)
    .sso_endpoint(SsoEndpoint::simple_sign(IDP_SSO_SIMPLESIGN)?)
    .credentials(signing_credentials())
    .validation(IdpValidationPolicy::compatibility())
    .build()?;
    Ok((ServiceProvider::new(sp), IdentityProvider::new(idp)))
}

fn hostile_facades() -> Result<(saml_rs::ServiceProvider, saml_rs::IdentityProvider), SamlError> {
    Ok((
        ServiceProvider::new(hostile_sp_config()?),
        IdentityProvider::new(hostile_idp_config()?),
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

fn principal() -> NameId {
    NameId::new("alice@example.com")
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::Disabled)
}

fn validation_with_cache(cache: &mut dyn ReplayCache) -> SamlValidationContext<'_> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(cache))
        .with_replay_retention(Duration::from_secs(5 * 60))
}

fn post_fields<Message>(outbound: &Outbound<Message>) -> Result<Vec<FormField>, SamlError> {
    Ok(outbound.post_form()?.fields().to_vec())
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
            Ok(String::from_utf8(deflate_raw_decode(
                &STANDARD.decode(encoded.as_ref())?,
                MAX_DEFLATE_RAW_DECODE_BYTES,
            )?)?)
        }
        OutboundDelivery::PostForm(form) => Ok(String::from_utf8(
            STANDARD.decode(form.value("SAMLRequest").ok_or("missing SAMLRequest")?)?,
        )?),
        OutboundDelivery::SoapRequest(_) | OutboundDelivery::SoapResponse(_) => {
            Err("an AuthnRequest is not sent over SOAP".into())
        }
    }
}

fn authn_request_input(
    outbound: &Outbound<AuthnRequest>,
) -> Result<Inbound<AuthnRequest>, Box<dyn std::error::Error>> {
    match outbound.delivery() {
        OutboundDelivery::Redirect(url) => {
            let url = Url::parse(url)?;
            Ok(Inbound::redirect(url.query().unwrap_or_default()))
        }
        OutboundDelivery::PostForm(form) if form.value("SigAlg").is_some() => {
            Ok(Inbound::simple_sign(form.fields().to_vec()))
        }
        OutboundDelivery::PostForm(form) => Ok(Inbound::post(form.fields().to_vec())),
        OutboundDelivery::SoapRequest(_) | OutboundDelivery::SoapResponse(_) => {
            Err("an AuthnRequest is not sent over SOAP".into())
        }
    }
}

fn post_authn_request_input_with_xml(xml: &str) -> Inbound<AuthnRequest> {
    Inbound::post(vec![FormField::new(
        "SAMLRequest",
        STANDARD.encode(xml.as_bytes()),
    )])
}

fn replace_issue_instant(
    xml: &str,
    replacement: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let (before, after) = xml
        .split_once(" IssueInstant=\"")
        .ok_or("missing IssueInstant attribute")?;
    let (_, after) = after
        .split_once('"')
        .ok_or("unterminated IssueInstant attribute")?;
    let replacement = replacement
        .map(|value| format!(" IssueInstant=\"{value}\""))
        .unwrap_or_default();
    Ok(format!("{before}{replacement}{after}"))
}

fn response_xml_from_fields(fields: &[FormField]) -> Result<String, Box<dyn std::error::Error>> {
    let encoded = fields
        .iter()
        .find(|field| field.name() == "SAMLResponse")
        .map(FormField::value)
        .ok_or("missing SAMLResponse")?;
    Ok(String::from_utf8(STANDARD.decode(encoded)?)?)
}

fn response_fields_with_xml(
    mut fields: Vec<FormField>,
    xml: &str,
) -> Result<Vec<FormField>, Box<dyn std::error::Error>> {
    let field = fields
        .iter_mut()
        .find(|field| field.name() == "SAMLResponse")
        .ok_or("missing SAMLResponse")?;
    *field = FormField::new("SAMLResponse", STANDARD.encode(xml.as_bytes()));
    Ok(fields)
}

fn replace_element_issue_instant(
    xml: &str,
    element_start: &str,
    replacement: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let start = xml.find(element_start).ok_or("missing SAML element")?;
    let relative_end = xml[start..].find('>').ok_or("unterminated SAML element")?;
    let end = start + relative_end + 1;
    let opening = replace_issue_instant(&xml[start..end], replacement)?;
    Ok(format!("{}{opening}{}", &xml[..start], &xml[end..]))
}

struct SsoExchange {
    sp: saml_rs::ServiceProvider,
    idp: saml_rs::IdentityProvider,
    sp_descriptor: SpDescriptor,
    idp_descriptor: IdpDescriptor,
    pending: PendingAuthnRequest,
    received: Received<AuthnRequest>,
    response_fields: Vec<FormField>,
}

fn start_receive_respond_with(
    start_options: StartSso,
    outcome: impl Into<SsoOutcome>,
    respond_options: RespondSso,
) -> Result<SsoExchange, SamlError> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, start_options)?;

    let request_input = Inbound::post(post_fields(&started.outbound)?);
    let received = idp.receive_sso(&sp_descriptor, request_input, validation())?;
    assert_eq!(received.message().issuer().as_str(), SP_ENTITY_ID);

    let response = idp.respond_sso(&sp_descriptor, &received, outcome, respond_options)?;
    let response_fields = post_fields(&response)?;

    Ok(SsoExchange {
        sp,
        idp,
        sp_descriptor,
        idp_descriptor,
        pending: started.pending,
        received,
        response_fields,
    })
}

fn start_receive_respond() -> Result<SsoExchange, SamlError> {
    let relay_state = RelayState::try_new("state-123")?;
    start_receive_respond_with(
        StartSso::post().relay_state(relay_state),
        SsoAssertion::new(principal()),
        RespondSso::post(),
    )
}

#[test]
fn typed_builder_authn_request_escapes_hostile_values_for_all_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = hostile_facades()?;
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(HOSTILE_SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;

    for start in [
        StartSso::redirect(),
        StartSso::post(),
        StartSso::simple_sign(),
    ] {
        let relay_state = RelayState::try_new("typed-state")?;
        let started = sp.start_sso(
            &idp_descriptor,
            start
                .force_authn(ForceAuthn::Required)
                .relay_state(relay_state),
        )?;
        let xml = authn_request_xml(&started.outbound)?;

        assert_eq!(xml.matches("<samlp:AuthnRequest").count(), 1);
        assert_eq!(xml.matches("<saml:Issuer").count(), 1);
        assert!(!xml.contains("<evil:Injected"));
        assert!(!xml.contains("</evil:Injected"));
        assert!(xml.contains("ForceAuthn=\"true\""));
        assert!(xml.contains("issuer&lt;/evil:Injected"));
        assert!(xml.contains(
            "Destination=\"https://idp.example.com/sso?continue=%3Cevil:Injected%3Edestination%3C%2Fevil:Injected%3E&amp;quote=%22\""
        ));
        assert!(xml.contains(
            "AssertionConsumerServiceURL=\"https://sp.example.com/acs?continue=%3Cevil:Injected%3Eacs%3C%2Fevil:Injected%3E&amp;quote=%22\""
        ));
        assert!(
            xml.contains("Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress&quot;/")
        );
        assert!(xml.contains("nameid&lt;/evil:Injected"));

        let received = idp.receive_sso(
            &sp_descriptor,
            authn_request_input(&started.outbound)?,
            validation(),
        )?;
        assert_eq!(received.message().issuer().as_str(), HOSTILE_SP_ENTITY_ID);
        assert_eq!(
            started.outbound.relay_state().map(|state| state.as_str()),
            Some("typed-state")
        );
    }
    Ok(())
}

#[test]
fn typed_builder_authn_request_options_render_force_authn_and_acs_index(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (_sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    for force_authn in [
        Some(ForceAuthn::Required),
        Some(ForceAuthn::NotRequired),
        None,
    ] {
        let mut options = StartSso::post();
        if let Some(force_authn) = force_authn {
            options = options.force_authn(force_authn);
        }
        let xml = authn_request_xml(&sp.start_sso(&idp_descriptor, options)?.outbound)?;
        match force_authn {
            Some(ForceAuthn::Required) => assert!(xml.contains("ForceAuthn=\"true\"")),
            Some(ForceAuthn::NotRequired) => assert!(xml.contains("ForceAuthn=\"false\"")),
            None => assert!(!xml.contains("ForceAuthn=")),
        }
    }

    let xml = authn_request_xml(
        &sp.start_sso(&idp_descriptor, StartSso::post().acs_index(1))?
            .outbound,
    )?;
    assert!(xml.contains("AssertionConsumerServiceIndex=\"1\""));
    assert!(!xml.contains("AssertionConsumerServiceURL="));
    assert!(!xml.contains("ProtocolBinding="));
    Ok(())
}

#[test]
fn typed_builder_rejects_acs_index_response_binding_mismatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (_sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    match sp.start_sso(
        &idp_descriptor,
        StartSso::post()
            .acs_index(1)
            .response_binding(SsoResponseBinding::Post),
    ) {
        Err(SamlError::Invalid(message)) => {
            assert!(message.contains("AssertionConsumerServiceIndex binding"));
            Ok(())
        }
        other => Err(format!("expected Invalid ACS binding mismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_rejects_unknown_acs_index() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (_sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    match sp.start_sso(&idp_descriptor, StartSso::post().acs_index(99)) {
        Err(SamlError::MissingMetadata(name)) => {
            assert_eq!(name, "AssertionConsumerService");
            Ok(())
        }
        other => Err(format!("expected MissingMetadata, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_honors_custom_acs_index_from_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(SP_ACS_POST)?.with_index(7),
        )
        .credentials(signing_credentials())
        .validation(signing_sp_validation())
        .build()?,
    );
    let idp = IdentityProvider::new(idp_config()?);
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;

    let started = sp.start_sso(&idp_descriptor, StartSso::post().acs_index(7))?;
    let xml = authn_request_xml(&started.outbound)?;

    assert_eq!(started.pending.acs().index(), Some(7));
    assert!(sp.metadata_xml().contains("index=\"7\""));
    assert!(xml.contains("AssertionConsumerServiceIndex=\"7\""));
    Ok(())
}

#[test]
fn typed_detached_authn_requests_parse_with_relay_state() -> Result<(), Box<dyn std::error::Error>>
{
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    for start in [StartSso::redirect(), StartSso::simple_sign()] {
        let relay_state = RelayState::try_new("signed-state")?;
        let started = sp.start_sso(&idp_descriptor, start.relay_state(relay_state))?;
        let received = idp.receive_sso(
            &sp_descriptor,
            authn_request_input(&started.outbound)?,
            validation(),
        )?;

        assert_eq!(received.message().id(), started.pending.request_id());
        assert_eq!(
            started.outbound.relay_state().map(|state| state.as_str()),
            Some("signed-state")
        );
    }
    Ok(())
}

#[test]
fn typed_facade_rejects_missing_authn_request_issue_instant_in_real_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = compatibility_facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let xml = replace_issue_instant(&authn_request_xml(&started.outbound)?, None)?;

    match idp.receive_sso(
        &sp_descriptor,
        post_authn_request_input_with_xml(&xml),
        validation(),
    ) {
        Err(SamlError::ProtocolProfile(message))
            if message.contains("missing required unqualified attribute IssueInstant") =>
        {
            Ok(())
        }
        other => {
            Err(format!("expected missing IssueInstant ProtocolProfile, got {other:?}").into())
        }
    }
}

#[test]
fn typed_facade_rejects_malformed_authn_request_issue_instant_in_real_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = compatibility_facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let xml = replace_issue_instant(
        &authn_request_xml(&started.outbound)?,
        Some("not-an-instant"),
    )?;

    match idp.receive_sso(
        &sp_descriptor,
        post_authn_request_input_with_xml(&xml),
        validation(),
    ) {
        Err(SamlError::ProtocolProfile(message))
            if message.contains(
                "IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z",
            ) =>
        {
            Ok(())
        }
        other => {
            Err(format!("expected malformed IssueInstant ProtocolProfile, got {other:?}").into())
        }
    }
}

#[test]
fn typed_facade_accepts_old_normalized_authn_request_issue_instant_in_real_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = compatibility_facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let xml = replace_issue_instant(
        &authn_request_xml(&started.outbound)?,
        Some(" &#x9;2001-01-01T00:00:00Z&#xA; "),
    )?;
    let received = idp.receive_sso(
        &sp_descriptor,
        post_authn_request_input_with_xml(&xml),
        validation(),
    )?;

    assert_eq!(
        received.message().issue_instant().as_str(),
        "2001-01-01T00:00:00Z"
    );
    Ok(())
}

const AUTHN_REQUEST_AGE_NOW: &str = "2024-06-15T12:00:00Z";

fn authn_request_age_now() -> Result<SystemTime, time::error::Parse> {
    OffsetDateTime::parse(AUTHN_REQUEST_AGE_NOW, &Rfc3339).map(SystemTime::from)
}

fn bounded_authn_request_age(
    now: SystemTime,
    max_age: Duration,
    skew: ClockSkew,
) -> SamlValidationContext<'static> {
    SamlValidationContext::new(now, ReplayPolicy::Disabled)
        .with_clock_skew(skew)
        .with_authn_request_age(RequestAgePolicy::Bounded { max_age })
}

fn bounded_authn_request_age_with_cache(
    now: SystemTime,
    cache: &mut RecordingReplayCache,
) -> SamlValidationContext<'_> {
    SamlValidationContext::new(now, ReplayPolicy::RequireCache(cache))
        .with_clock_skew(ClockSkew::strict())
        .with_authn_request_age(RequestAgePolicy::Bounded {
            max_age: Duration::from_secs(60 * 60),
        })
        .with_replay_retention(Duration::from_secs(5 * 60))
}

struct IssuedAuthnRequest {
    idp: saml_rs::IdentityProvider,
    sp_descriptor: SpDescriptor,
    xml: String,
}

fn issued_authn_request_for_recommended_idp(
) -> Result<IssuedAuthnRequest, Box<dyn std::error::Error>> {
    let (sp, _) = compatibility_facades()?;
    let idp = IdentityProvider::new(idp_with_validation(IdpValidationPolicy::recommended())?);
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let xml = authn_request_xml(&started.outbound)?;
    Ok(IssuedAuthnRequest {
        idp,
        sp_descriptor,
        xml,
    })
}

fn receive_issued(
    issued: &IssuedAuthnRequest,
    instant: &str,
    validation: SamlValidationContext<'_>,
) -> Result<Received<AuthnRequest>, Box<dyn std::error::Error>> {
    let xml = replace_issue_instant(&issued.xml, Some(instant))?;
    issued
        .idp
        .receive_sso(
            &issued.sp_descriptor,
            post_authn_request_input_with_xml(&xml),
            validation,
        )
        .map_err(Into::into)
}

fn assert_authn_request_age_rejected(
    result: Result<Received<AuthnRequest>, Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let error = match result {
        Ok(_) => return Err("expected AuthnRequest IssueInstant age error".into()),
        Err(error) => error,
    };
    let error = error
        .downcast::<SamlError>()
        .map_err(|error| format!("expected SamlError, got {error}"))?;
    match *error {
        SamlError::TimeWindowInvalid { field } => {
            assert_eq!(field, TimeWindowField::AuthnRequestIssueInstant);
            Ok(())
        }
        other => Err(format!("expected AuthnRequest IssueInstant age error, got {other:?}").into()),
    }
}

#[test]
fn disabled_authn_request_age_ignores_clock_skew_at_a_fixed_clock(
) -> Result<(), Box<dyn std::error::Error>> {
    let now = authn_request_age_now()?;
    let validation = SamlValidationContext::new(now, ReplayPolicy::Disabled);
    assert_eq!(validation.authn_request_age(), RequestAgePolicy::Disabled);
    assert_eq!(validation.clock_skew(), ClockSkew::five_minutes());

    let issued = issued_authn_request_for_recommended_idp()?;
    for instant in [
        "2001-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        "2024-06-15T10:54:59Z",
        "2024-06-15T12:00:60Z",
    ] {
        let received = receive_issued(&issued, instant, validation_at_disabled(now))?;
        assert_eq!(received.message().issue_instant().as_str(), instant);
    }
    Ok(())
}

fn validation_at_disabled(now: SystemTime) -> SamlValidationContext<'static> {
    SamlValidationContext::new(now, ReplayPolicy::Disabled)
}

#[test]
fn bounded_authn_request_age_rejects_outside_the_inclusive_window(
) -> Result<(), Box<dyn std::error::Error>> {
    let now = authn_request_age_now()?;
    let issued = issued_authn_request_for_recommended_idp()?;
    let max_age = Duration::from_secs(60 * 60);

    for instant in ["2024-06-15T11:00:00Z", AUTHN_REQUEST_AGE_NOW] {
        let received = receive_issued(
            &issued,
            instant,
            bounded_authn_request_age(now, max_age, ClockSkew::strict()),
        )?;
        assert_eq!(received.message().issue_instant().as_str(), instant);
    }
    for instant in ["2024-06-15T10:59:59Z", "2024-06-15T12:00:01Z"] {
        assert_authn_request_age_rejected(receive_issued(
            &issued,
            instant,
            bounded_authn_request_age(now, max_age, ClockSkew::strict()),
        ))?;
    }
    Ok(())
}

#[test]
fn five_minute_skew_widens_only_a_bounded_authn_request_age(
) -> Result<(), Box<dyn std::error::Error>> {
    let now = authn_request_age_now()?;
    let issued = issued_authn_request_for_recommended_idp()?;
    let max_age = Duration::from_secs(60 * 60);

    let outside_widened_window =
        receive_issued(&issued, "2024-06-15T10:54:59Z", validation_at_disabled(now))?;
    assert_eq!(
        outside_widened_window.message().issue_instant().as_str(),
        "2024-06-15T10:54:59Z"
    );

    for instant in ["2024-06-15T10:55:00Z", "2024-06-15T12:05:00Z"] {
        let received = receive_issued(
            &issued,
            instant,
            bounded_authn_request_age(now, max_age, ClockSkew::five_minutes()),
        )?;
        assert_eq!(received.message().issue_instant().as_str(), instant);
        assert_authn_request_age_rejected(receive_issued(
            &issued,
            instant,
            bounded_authn_request_age(now, max_age, ClockSkew::strict()),
        ))?;
    }
    for instant in ["2024-06-15T10:54:59Z", "2024-06-15T12:05:01Z"] {
        assert_authn_request_age_rejected(receive_issued(
            &issued,
            instant,
            bounded_authn_request_age(now, max_age, ClockSkew::five_minutes()),
        ))?;
    }
    Ok(())
}

#[test]
fn zero_authn_request_max_age_leaves_the_skew_neighborhood(
) -> Result<(), Box<dyn std::error::Error>> {
    let now = authn_request_age_now()?;
    let issued = issued_authn_request_for_recommended_idp()?;

    let received = receive_issued(
        &issued,
        AUTHN_REQUEST_AGE_NOW,
        bounded_authn_request_age(now, Duration::ZERO, ClockSkew::strict()),
    )?;
    assert_eq!(
        received.message().issue_instant().as_str(),
        AUTHN_REQUEST_AGE_NOW
    );
    for instant in ["2024-06-15T11:59:59Z", "2024-06-15T12:00:01Z"] {
        assert_authn_request_age_rejected(receive_issued(
            &issued,
            instant,
            bounded_authn_request_age(now, Duration::ZERO, ClockSkew::strict()),
        ))?;
    }

    for instant in ["2024-06-15T11:55:00Z", "2024-06-15T12:05:00Z"] {
        let received = receive_issued(
            &issued,
            instant,
            bounded_authn_request_age(now, Duration::ZERO, ClockSkew::five_minutes()),
        )?;
        assert_eq!(received.message().issue_instant().as_str(), instant);
    }
    for instant in ["2024-06-15T11:54:59Z", "2024-06-15T12:05:01Z"] {
        assert_authn_request_age_rejected(receive_issued(
            &issued,
            instant,
            bounded_authn_request_age(now, Duration::ZERO, ClockSkew::five_minutes()),
        ))?;
    }
    Ok(())
}

#[test]
fn inverted_clock_skew_does_not_shrink_authn_request_max_age(
) -> Result<(), Box<dyn std::error::Error>> {
    let now = authn_request_age_now()?;
    let issued = issued_authn_request_for_recommended_idp()?;
    let max_age = Duration::from_secs(60 * 60);
    let inverted = ClockSkew::from_millis(5 * 60 * 1_000, -5 * 60 * 1_000);

    for instant in ["2024-06-15T11:00:00Z", AUTHN_REQUEST_AGE_NOW] {
        let received = receive_issued(
            &issued,
            instant,
            bounded_authn_request_age(now, max_age, inverted),
        )?;
        assert_eq!(received.message().issue_instant().as_str(), instant);
    }
    for instant in ["2024-06-15T10:55:00Z", "2024-06-15T12:05:00Z"] {
        assert_authn_request_age_rejected(receive_issued(
            &issued,
            instant,
            bounded_authn_request_age(now, max_age, inverted),
        ))?;
    }
    Ok(())
}

#[test]
fn bounded_authn_request_age_handles_a_large_duration_and_overflow(
) -> Result<(), Box<dyn std::error::Error>> {
    let now = authn_request_age_now()?;
    let issued = issued_authn_request_for_recommended_idp()?;
    let large_age = Duration::from_secs(200 * 365 * 24 * 60 * 60);

    let received = receive_issued(
        &issued,
        "1900-01-01T00:00:00Z",
        bounded_authn_request_age(now, large_age, ClockSkew::strict()),
    )?;
    assert_eq!(
        received.message().issue_instant().as_str(),
        "1900-01-01T00:00:00Z"
    );
    assert_authn_request_age_rejected(receive_issued(
        &issued,
        "1700-01-01T00:00:00Z",
        bounded_authn_request_age(now, large_age, ClockSkew::strict()),
    ))?;
    assert_authn_request_age_rejected(receive_issued(
        &issued,
        AUTHN_REQUEST_AGE_NOW,
        bounded_authn_request_age(now, Duration::MAX, ClockSkew::strict()),
    ))?;
    assert_authn_request_age_rejected(receive_issued(
        &issued,
        "2024-06-15T12:00:60Z",
        bounded_authn_request_age(now, Duration::from_secs(60 * 60), ClockSkew::five_minutes()),
    ))?;
    Ok(())
}

#[test]
fn rejected_authn_request_age_does_not_occupy_a_replay_key(
) -> Result<(), Box<dyn std::error::Error>> {
    let now = authn_request_age_now()?;
    let issued = issued_authn_request_for_recommended_idp()?;
    let mut cache = RecordingReplayCache::default();
    let stale = replace_issue_instant(&issued.xml, Some("2001-01-01T00:00:00Z"))?;
    let fresh = replace_issue_instant(&issued.xml, Some(AUTHN_REQUEST_AGE_NOW))?;
    let misdirected = stale.replace(
        "Destination=\"https://idp.example.com/sso/post\"",
        "Destination=\"https://idp.example.com/sso/other\"",
    );

    match issued.idp.receive_sso(
        &issued.sp_descriptor,
        post_authn_request_input_with_xml(&misdirected),
        bounded_authn_request_age_with_cache(now, &mut cache),
    ) {
        Err(SamlError::DestinationMismatch { .. }) => {}
        other => return Err(format!("expected DestinationMismatch, got {other:?}").into()),
    }
    assert!(cache.seen.is_empty());

    assert_authn_request_age_rejected(
        issued
            .idp
            .receive_sso(
                &issued.sp_descriptor,
                post_authn_request_input_with_xml(&stale),
                bounded_authn_request_age_with_cache(now, &mut cache),
            )
            .map_err(Into::into),
    )?;
    assert!(cache.seen.is_empty());

    let received = issued.idp.receive_sso(
        &issued.sp_descriptor,
        post_authn_request_input_with_xml(&fresh),
        bounded_authn_request_age_with_cache(now, &mut cache),
    )?;
    let replay_key = format!("authn_request_id:{}", received.message().id().as_str());
    assert!(cache.seen.contains_key(&replay_key));

    let mut disabled_cache = RecordingReplayCache::default();
    issued.idp.receive_sso(
        &issued.sp_descriptor,
        post_authn_request_input_with_xml(&stale),
        SamlValidationContext::new(now, ReplayPolicy::RequireCache(&mut disabled_cache))
            .with_replay_retention(Duration::from_secs(5 * 60)),
    )?;
    assert!(disabled_cache.seen.contains_key(&replay_key));
    Ok(())
}

#[test]
fn signed_authn_request_age_check_does_not_replace_signature_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let xml = replace_issue_instant(
        &authn_request_xml(&started.outbound)?,
        Some("2001-01-01T00:00:00Z"),
    )?;
    let mut cache = RecordingReplayCache::default();
    let validation = SamlValidationContext::new(
        authn_request_age_now()?,
        ReplayPolicy::RequireCache(&mut cache),
    )
    .with_clock_skew(ClockSkew::strict())
    .with_authn_request_age(RequestAgePolicy::Bounded {
        max_age: Duration::from_secs(60),
    })
    .with_replay_retention(Duration::from_secs(5 * 60));

    match idp.receive_sso(
        &sp_descriptor,
        post_authn_request_input_with_xml(&xml),
        validation,
    ) {
        Err(SamlError::SignatureVerification {
            reason: saml_rs::error::SignatureVerificationReason::XmlSignature,
        }) => {
            assert!(cache.seen.is_empty());
            Ok(())
        }
        other => Err(
            format!("expected XML signature failure before the age check, got {other:?}").into(),
        ),
    }
}

#[test]
fn typed_facade_receive_sso_checks_authn_request_replay() -> Result<(), Box<dyn std::error::Error>>
{
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let request_fields = post_fields(&started.outbound)?;
    let mut cache = RecordingReplayCache::default();

    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(request_fields.clone()),
        validation_with_cache(&mut cache),
    )?;
    let replay_key = format!("authn_request_id:{}", received.message().id().as_str());
    assert!(cache.seen.contains_key(&replay_key));

    match idp.receive_sso(
        &sp_descriptor,
        Inbound::post(request_fields),
        validation_with_cache(&mut cache),
    ) {
        Err(SamlError::ReplayDetected { key }) => {
            assert_eq!(key.cache_key(), replay_key);
            Ok(())
        }
        other => Err(format!("expected AuthnRequest ReplayDetected, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_receive_sso_requires_replay_retention_for_authn_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let mut cache = RecordingReplayCache::default();
    let validation =
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(&mut cache));

    match idp.receive_sso(
        &sp_descriptor,
        Inbound::post(post_fields(&started.outbound)?),
        validation,
    ) {
        Err(SamlError::TimeWindowInvalid { field }) => {
            assert_eq!(field, TimeWindowField::ReplayExpiration);
            Ok(())
        }
        other => Err(format!("expected ReplayExpiration error, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_start_sso_redirect_returns_url() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (_sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::redirect())?;

    let redirect_url = started.outbound.redirect_url()?;
    assert!(redirect_url.starts_with(IDP_SSO_REDIRECT));
    assert_eq!(started.pending.request_id(), started.outbound.id());
    Ok(())
}

#[test]
fn typed_facade_runs_sp_initiated_sso() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = start_receive_respond()?;

    assert_eq!(
        exchange.received.relay_state(),
        Some(&RelayState::try_new("state-123")?)
    );

    let session = exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::post(exchange.response_fields),
        validation(),
    )?;

    assert_eq!(session.issuer().as_str(), IDP_ENTITY_ID);
    assert_eq!(
        session.in_response_to(),
        Some(exchange.pending.request_id())
    );
    assert_eq!(session.relay_state(), exchange.pending.relay_state());
    assert_eq!(
        session.response_issue_instant(),
        session.assertion_issue_instant()
    );
    assert!(session.response_issue_instant().as_str().ends_with('Z'));
    assert_eq!(session.name_id().value(), "alice@example.com");
    assert_eq!(
        exchange.received.message().id(),
        exchange.pending.request_id()
    );
    assert_eq!(
        exchange.idp.engine().metadata.as_metadata().entity_id(),
        Some(IDP_ENTITY_ID)
    );
    assert_eq!(exchange.sp_descriptor.entity_id().as_str(), SP_ENTITY_ID);
    Ok(())
}

#[test]
fn typed_http_post_exposes_verified_assertion_signature_evidence(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = start_receive_respond()?;
    let session = exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::post(exchange.response_fields),
        validation(),
    )?;

    let [signature] = session.verified_xml_signatures() else {
        return Err("expected one verified embedded XML signature".into());
    };
    assert_eq!(signature.algorithm_uri(), RSA_SHA256);
    assert_eq!(
        signature.coverage(),
        VerifiedXmlSignatureCoverage::ConsumedAssertion
    );
    assert_eq!(session.binding_signature_algorithm_uri(), None);
    Ok(())
}

#[test]
fn typed_http_post_exposes_verified_response_root_signature_evidence(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(response_root_only_sp_config()?);
    let idp = IdentityProvider::new(idp_config()?);
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(post_fields(&started.outbound)?),
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal()),
        RespondSso::post().sign_response(),
    )?;
    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(post_fields(&response)?),
        validation(),
    )?;

    let [signature] = session.verified_xml_signatures() else {
        return Err("expected one verified embedded XML signature".into());
    };
    assert_eq!(signature.algorithm_uri(), RSA_SHA256);
    assert_eq!(
        signature.coverage(),
        VerifiedXmlSignatureCoverage::ResponseRoot
    );
    assert_eq!(session.binding_signature_algorithm_uri(), None);
    Ok(())
}

#[test]
fn typed_http_post_preserves_distinct_response_and_assertion_signature_evidence(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = start_receive_respond()?;
    let response_xml = response_xml_from_fields(&exchange.response_fields)?;
    let key = read_private_key(PRIVKEY, None)?;
    let response_and_assertion_signed =
        sign_saml_xml(&response_xml, true, &key, CERT, RSA_SHA512, &[], None)?;
    let response_fields =
        response_fields_with_xml(exchange.response_fields, &response_and_assertion_signed)?;
    let session = exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::post(response_fields),
        validation(),
    )?;

    assert_eq!(session.verified_xml_signatures().len(), 2);
    assert!(session.verified_xml_signatures().iter().any(|signature| {
        signature.algorithm_uri() == RSA_SHA512
            && signature.coverage() == VerifiedXmlSignatureCoverage::ResponseRoot
    }));
    assert!(session.verified_xml_signatures().iter().any(|signature| {
        signature.algorithm_uri() == RSA_SHA256
            && signature.coverage() == VerifiedXmlSignatureCoverage::ConsumedAssertion
    }));
    assert_eq!(session.binding_signature_algorithm_uri(), None);
    Ok(())
}

#[test]
fn typed_required_response_signature_rejects_assertion_only_post(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(response_signature_required_sp_config()?);
    let idp = IdentityProvider::new(idp_config()?);
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(post_fields(&started.outbound)?),
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    )?;

    match sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(post_fields(&response)?),
        validation(),
    ) {
        Err(SamlError::SignedReferenceMismatch) => Ok(()),
        other => Err(format!("expected SignedReferenceMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_sign_response_satisfies_required_response_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(response_signature_required_sp_config()?);
    let idp = IdentityProvider::new(idp_config()?);
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(post_fields(&started.outbound)?),
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal()),
        RespondSso::post().sign_response(),
    )?;
    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(post_fields(&response)?),
        validation(),
    )?;

    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}

/// Move the `EncryptedKey` from the `KeyInfo` of `EncryptedData` to after
/// `EncryptedData`, named by a `RetrievalMethod`: the SAML Core Errata 05 E43
/// placement that OpenSAML's `Encrypter` writes by default.
#[cfg(not(feature = "crypto-fips"))]
fn with_peer_encrypted_key(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
    const ENC: &str = "http://www.w3.org/2001/04/xmlenc#";
    let start = xml
        .find("<xenc:EncryptedKey>")
        .ok_or("missing EncryptedKey")?;
    let key_end_tag = "</xenc:EncryptedKey>";
    let end = xml.find(key_end_tag).ok_or("missing EncryptedKey end")? + key_end_tag.len();
    let key = xml[start..end].replacen(
        "<xenc:EncryptedKey>",
        &format!("<xenc:EncryptedKey xmlns:xenc=\"{ENC}\" Id=\"_peer_key\">"),
        1,
    );
    let retrieval = format!("<ds:RetrievalMethod URI=\"#_peer_key\" Type=\"{ENC}EncryptedKey\"/>");
    let data_end_tag = "</xenc:EncryptedData>";
    let data_end = xml.find(data_end_tag).ok_or("missing EncryptedData end")? + data_end_tag.len();
    Ok(format!(
        "{}{retrieval}{}{key}{}",
        &xml[..start],
        &xml[end..data_end],
        &xml[data_end..]
    ))
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn typed_sp_decrypts_an_assertion_whose_key_is_beside_encrypted_data(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(encrypted_sp_config()?);
    let idp = IdentityProvider::new(encrypted_idp_config()?);
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(post_fields(&started.outbound)?),
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    )?;
    let fields = post_fields(&response)?;
    let peer = resign_response(&with_peer_encrypted_key(&response_xml_from_fields(
        &fields,
    )?)?)?;
    assert!(peer.contains("</xenc:EncryptedData><xenc:EncryptedKey"));

    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(response_fields_with_xml(fields, &peer)?),
        validation(),
    )?;
    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn typed_sp_rejects_explicit_unsigned_encrypted_cbc() -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(encrypted_sp_config()?);
    let idp = IdentityProvider::new(encrypted_idp_config()?);
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(post_fields(&started.outbound)?),
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal()),
        RespondSso::post().allow_unsigned_encrypted_cbc(),
    )?;

    match sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(post_fields(&response)?),
        validation(),
    ) {
        Err(SamlError::SignatureMissing) => Ok(()),
        other => Err(format!("expected SignatureMissing, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_runs_simplesign_sso_response_binding() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::post().response_binding(SsoResponseBinding::SimpleSign),
    )?;
    let request_input = Inbound::post(post_fields(&started.outbound)?);
    let received = idp.receive_sso(&sp_descriptor, request_input, validation())?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal()),
        RespondSso::simple_sign(),
    )?;
    let response_form = response.post_form()?;
    assert_eq!(response_form.action().as_str(), SP_ACS_SIMPLESIGN);
    assert!(response_form.value("SigAlg").is_some());
    assert!(response_form.value("Signature").is_some());

    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::simple_sign(response_form.fields().to_vec()),
        validation(),
    )?;

    assert_eq!(session.in_response_to(), Some(started.pending.request_id()));
    assert_eq!(
        session.response_issue_instant(),
        session.assertion_issue_instant()
    );
    assert_eq!(session.name_id().value(), "alice@example.com");
    assert_eq!(session.binding_signature_algorithm_uri(), Some(RSA_SHA256));
    let [signature] = session.verified_xml_signatures() else {
        return Err("expected one verified embedded XML signature".into());
    };
    assert_eq!(signature.algorithm_uri(), RSA_SHA256);
    assert_eq!(
        signature.coverage(),
        VerifiedXmlSignatureCoverage::ConsumedAssertion
    );
    Ok(())
}

#[test]
fn typed_facade_finish_sso_post_rejects_missing_response_issue_instant(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = start_receive_respond()?;
    let xml = replace_element_issue_instant(
        &response_xml_from_fields(&exchange.response_fields)?,
        "<samlp:Response",
        None,
    )?;
    let fields = response_fields_with_xml(exchange.response_fields, &xml)?;

    match exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::post(fields),
        validation(),
    ) {
        Err(SamlError::ProtocolProfile(message))
            if message
                .contains("Response is missing required unqualified attribute IssueInstant") =>
        {
            Ok(())
        }
        other => Err(format!(
            "expected Response IssueInstant ProtocolProfile from finish_sso POST, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn typed_facade_finish_sso_simplesign_rejects_malformed_assertion_issue_instant(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = start_receive_respond_with(
        StartSso::post().response_binding(SsoResponseBinding::SimpleSign),
        SsoAssertion::new(principal()),
        RespondSso::simple_sign(),
    )?;
    let xml = replace_element_issue_instant(
        &response_xml_from_fields(&exchange.response_fields)?,
        "<saml:Assertion",
        Some("not-an-instant"),
    )?;
    let fields = response_fields_with_xml(exchange.response_fields, &xml)?;

    match exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::simple_sign(fields),
        validation(),
    ) {
        Err(SamlError::ProtocolProfile(message))
            if message.contains(
                "Assertion IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z",
            ) =>
        {
            Ok(())
        }
        other => Err(format!(
            "expected Assertion IssueInstant ProtocolProfile from finish_sso SimpleSign, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn typed_facade_persists_indexed_acs_for_response_validation(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post().acs_index(1))?;

    assert_eq!(
        started.pending.acs().binding(),
        SsoResponseBinding::SimpleSign
    );
    assert_eq!(started.pending.acs().index(), Some(1));
    assert_eq!(started.pending.acs().location().as_str(), SP_ACS_SIMPLESIGN);
    let snapshot = started.pending.snapshot();
    assert_eq!(snapshot.acs_index, Some(1));
    let restored = PendingAuthnRequest::from_snapshot(snapshot)?;
    assert_eq!(restored, started.pending);

    let request_input = Inbound::post(post_fields(&started.outbound)?);
    let received = idp.receive_sso(&sp_descriptor, request_input, validation())?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal()),
        RespondSso::simple_sign(),
    )?;
    let session = sp.finish_sso(
        &idp_descriptor,
        &restored,
        Inbound::simple_sign(post_fields(&response)?),
        validation(),
    )?;

    assert_eq!(session.in_response_to(), Some(restored.request_id()));
    Ok(())
}

#[test]
fn typed_facades_accept_a_peer_entity_id_that_is_not_a_uri(
) -> Result<(), Box<dyn std::error::Error>> {
    const PEER_IDP_ENTITY_ID: &str = "idp.example.com";
    const PEER_SP_ENTITY_ID: &str = "sp.example.org";
    let sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(SP_ACS_POST)?.with_default(),
        )
        .slo_endpoint(SloEndpoint::post(SP_SLO_POST)?)
        .credentials(signing_credentials())
        .validation(signing_sp_validation())
        .build()?,
    );
    let idp = IdentityProvider::new(idp_config()?);
    let peer_idp_metadata = idp
        .metadata_xml()
        .replace(IDP_ENTITY_ID, PEER_IDP_ENTITY_ID);
    let peer_sp_metadata = sp.metadata_xml().replace(SP_ENTITY_ID, PEER_SP_ENTITY_ID);
    let peer_idp_descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(PEER_IDP_ENTITY_ID)?,
        &peer_idp_metadata,
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let peer_sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(PEER_SP_ENTITY_ID)?,
        &peer_sp_metadata,
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let signing_setting = EntitySetting {
        private_key: Some(PRIVKEY.to_string()),
        signing_cert: Some(CERT.to_string()),
        want_assertions_signed: true,
        ..EntitySetting::default()
    };
    let peer_idp = idp::Engine::from_metadata(&peer_idp_metadata, signing_setting.clone())?;
    let peer_sp = sp::Engine::from_metadata(&peer_sp_metadata, signing_setting)?;
    let local_idp = idp::Engine::from_metadata(idp.metadata_xml(), EntitySetting::default())?;
    let local_sp = sp::Engine::from_metadata(sp.metadata_xml(), EntitySetting::default())?;

    let request =
        peer_sp.create_login_request(&local_idp, Binding::Post, &LoginRequestOptions::default())?;
    let received = idp.receive_sso(
        &peer_sp_descriptor,
        Inbound::post(vec![FormField::new("SAMLRequest", request.context)]),
        validation(),
    )?;
    assert_eq!(received.message().issuer().as_str(), PEER_SP_ENTITY_ID);

    let started = sp.start_sso(&peer_idp_descriptor, StartSso::post())?;
    let pending = PendingAuthnRequest::from_snapshot(started.pending.snapshot())?;
    assert_eq!(pending.idp_entity_id().as_str(), PEER_IDP_ENTITY_ID);
    let response = peer_idp.create_login_response(
        &local_sp,
        Binding::Post,
        &User::new("alice@example.com"),
        &LoginResponseOptions {
            in_response_to: Some(pending.request_id().as_str()),
            ..LoginResponseOptions::default()
        },
    )?;
    let session = sp.finish_sso(
        &peer_idp_descriptor,
        &pending,
        Inbound::post(vec![FormField::new("SAMLResponse", response.context)]),
        validation(),
    )?;
    assert_eq!(session.issuer().as_str(), PEER_IDP_ENTITY_ID);

    let logout = create_logout_request(
        &peer_idp.setting,
        peer_idp.metadata.as_metadata(),
        local_sp.metadata.as_metadata(),
        Binding::Post,
        &LogoutUser::new("alice@example.com"),
        None,
        true,
    )?;
    let received_logout = sp.receive_slo(
        &peer_idp_descriptor,
        Inbound::post(vec![FormField::new("SAMLRequest", logout.context)]),
        validation(),
    )?;
    assert_eq!(
        received_logout.message().issuer().as_str(),
        PEER_IDP_ENTITY_ID
    );
    Ok(())
}

#[test]
fn typed_facade_rejects_pending_peer_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = start_receive_respond()?;
    let other_idp = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new("https://other-idp.example.com/metadata")?,
            SsoEndpoint::post(IDP_SSO_POST)?,
        )
        .credentials(signing_credentials())
        .validation(signed_authn_request_idp_validation())
        .build()?,
    );
    let other_descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new("https://other-idp.example.com/metadata")?,
        other_idp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;

    match exchange.sp.finish_sso(
        &other_descriptor,
        &exchange.pending,
        Inbound::post(exchange.response_fields),
        validation(),
    ) {
        Err(SamlError::IssuerMismatch { expected, actual }) => {
            assert_eq!(expected, IDP_ENTITY_ID);
            assert_eq!(
                actual.as_deref(),
                Some("https://other-idp.example.com/metadata")
            );
            Ok(())
        }
        other => Err(format!("expected IssuerMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_rejects_response_with_wrong_sp_descriptor() -> Result<(), Box<dyn std::error::Error>>
{
    let exchange = start_receive_respond()?;
    let other_sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new("https://other-sp.example.com/metadata")?,
            AcsEndpoint::post(SP_ACS_POST)?,
        )
        .credentials(signing_credentials())
        .validation(signing_sp_validation())
        .build()?,
    );
    let other_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new("https://other-sp.example.com/metadata")?,
        other_sp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;

    match exchange.idp.respond_sso(
        &other_descriptor,
        &exchange.received,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    ) {
        Err(SamlError::IssuerMismatch { expected, actual }) => {
            assert_eq!(expected, SP_ENTITY_ID);
            assert_eq!(
                actual.as_deref(),
                Some("https://other-sp.example.com/metadata")
            );
            Ok(())
        }
        other => Err(format!("expected IssuerMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_rejects_response_binding_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = start_receive_respond()?;
    let mut snapshot = exchange.pending.snapshot();
    snapshot.acs_binding = "simpleSign".to_string();
    snapshot.acs_url = SP_ACS_SIMPLESIGN.to_string();
    let pending = PendingAuthnRequest::from_snapshot(snapshot)?;

    match exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &pending,
        Inbound::post(exchange.response_fields),
        validation(),
    ) {
        Err(SamlError::UnsupportedBinding { binding }) => {
            assert_eq!(binding, saml_rs::constants::Binding::Post);
            Ok(())
        }
        other => Err(format!("expected UnsupportedBinding, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_rejects_relay_state_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let mut exchange = start_receive_respond()?;
    for field in &mut exchange.response_fields {
        if field.name() == "RelayState" {
            *field = FormField::new("RelayState", "other-state");
        }
    }

    match exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::post(exchange.response_fields),
        validation(),
    ) {
        Err(SamlError::RelayStateMismatch { expected, actual }) => {
            assert_eq!(expected, Some(RelayState::try_new("state-123")?));
            assert_eq!(actual, Some(RelayState::try_new("other-state")?));
            Ok(())
        }
        other => Err(format!("expected RelayStateMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_rejects_a_response_without_the_relay_state_the_request_carried(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut exchange = start_receive_respond()?;
    exchange
        .response_fields
        .retain(|field| field.name() != "RelayState");

    match exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::post(exchange.response_fields),
        validation(),
    ) {
        Err(SamlError::RelayStateMismatch { expected, actual }) => {
            assert_eq!(expected, Some(RelayState::try_new("state-123")?));
            assert_eq!(actual, None);
            Ok(())
        }
        other => Err(format!("expected RelayStateMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_accepts_relay_state_the_idp_adds_to_a_request_without_one(
) -> Result<(), Box<dyn std::error::Error>> {
    for added in [RelayState::try_new("added")?, RelayState::try_new("")?] {
        let exchange = start_receive_respond_with(
            StartSso::post(),
            SsoAssertion::new(principal()),
            RespondSso::post().relay_state(added.clone()),
        )?;

        let session = exchange.sp.finish_sso(
            &exchange.idp_descriptor,
            &exchange.pending,
            Inbound::post(exchange.response_fields),
            validation(),
        )?;

        assert_eq!(session.relay_state(), Some(&added));
    }
    Ok(())
}

#[test]
fn respond_sso_returns_the_relay_state_the_request_carried(
) -> Result<(), Box<dyn std::error::Error>> {
    for received in ["state-123", ""] {
        let exchange = start_receive_respond_with(
            StartSso::post().relay_state(RelayState::try_new(received)?),
            SsoAssertion::new(principal()),
            RespondSso::post(),
        )?;
        let echoed: Vec<&str> = exchange
            .response_fields
            .iter()
            .filter(|field| field.name() == "RelayState")
            .map(FormField::value)
            .collect();
        assert_eq!(echoed, [received]);

        let result = exchange.idp.respond_sso(
            &exchange.sp_descriptor,
            &exchange.received,
            SsoAssertion::new(principal()),
            RespondSso::post().relay_state(RelayState::try_new("override")?),
        );

        assert!(
            matches!(result, Err(SamlError::ProtocolProfile(_))),
            "received {received:?}: {:?}",
            result.map(|outbound| outbound.relay_state().cloned())
        );
    }
    Ok(())
}

#[test]
fn typed_facade_rejects_wrong_pending_request_id() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = start_receive_respond()?;
    let mut snapshot: PendingAuthnRequestSnapshot = exchange.pending.snapshot();
    snapshot.request_id = "_different_request".to_string();
    let wrong_pending = PendingAuthnRequest::from_snapshot(snapshot)?;

    match exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &wrong_pending,
        Inbound::post(exchange.response_fields),
        validation(),
    ) {
        Err(SamlError::InResponseToMismatch { expected, actual }) => {
            assert_eq!(expected.as_deref(), Some("_different_request"));
            assert_eq!(
                actual.as_deref(),
                Some(exchange.pending.request_id().as_str())
            );
            Ok(())
        }
        other => Err(format!("expected InResponseToMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_rejects_solicited_response_as_unsolicited() -> Result<(), Box<dyn std::error::Error>>
{
    let exchange = start_receive_respond()?;

    match exchange.sp.accept_unsolicited_sso(
        &exchange.idp_descriptor,
        Inbound::post(exchange.response_fields),
        validation(),
    ) {
        Err(SamlError::InResponseToMismatch { expected, actual }) => {
            assert_eq!(expected, None);
            assert_eq!(
                actual.as_deref(),
                Some(exchange.pending.request_id().as_str())
            );
            Ok(())
        }
        other => Err(format!("expected InResponseToMismatch, got {other:?}").into()),
    }
}

fn auth_failed_status() -> Result<Status, SamlError> {
    Ok(Status::responder()
        .with_subordinate(SubordinateStatusCode::try_new(status_code::AUTHN_FAILED)?))
}

fn error_response_exchange() -> Result<SsoExchange, SamlError> {
    start_receive_respond_with(
        StartSso::post(),
        SsoOutcome::Failure(auth_failed_status()?),
        RespondSso::post(),
    )
}

fn finish_sso_with_response_xml(
    exchange: &SsoExchange,
    xml: &str,
) -> Result<saml_rs::SsoSession, SamlError> {
    exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::post(vec![FormField::new(
            "SAMLResponse",
            STANDARD.encode(xml.as_bytes()),
        )]),
        validation(),
    )
}

#[test]
fn typed_finish_sso_reports_an_unsigned_correlated_error_status(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = error_response_exchange()?;
    let xml = strip_embedded_signatures(&response_xml_from_fields(&exchange.response_fields)?)?;

    match finish_sso_with_response_xml(&exchange, &xml) {
        Err(SamlError::StatusNotSuccess { status }) => {
            assert_eq!(status, auth_failed_status()?);
            Ok(())
        }
        other => Err(format!("expected StatusNotSuccess, got {other:?}").into()),
    }
}

#[test]
fn typed_finish_sso_rejects_a_top_level_status_outside_the_four_saml_values(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = error_response_exchange()?;
    let xml = strip_embedded_signatures(&response_xml_from_fields(&exchange.response_fields)?)?
        .replacen(
            &format!("Value=\"{}\"", status_code::RESPONDER),
            "Value=\"urn:example:status:Unknown\"",
            1,
        );

    match finish_sso_with_response_xml(&exchange, &xml) {
        Err(SamlError::ProtocolProfile(message))
            if message.contains("urn:example:status:Unknown") =>
        {
            Ok(())
        }
        other => Err(format!("expected ProtocolProfile, got {other:?}").into()),
    }
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn typed_finish_sso_reports_a_signed_error_status_when_assertions_are_encrypted(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(encrypted_sp_config()?);
    let idp = IdentityProvider::new(encrypted_idp_config()?);
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(post_fields(&started.outbound)?),
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoOutcome::Failure(auth_failed_status()?),
        RespondSso::post(),
    )?;
    let response_fields = post_fields(&response)?;
    assert!(response_xml_from_fields(&response_fields)?.contains("<ds:Signature"));

    match sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(response_fields.clone()),
        validation(),
    ) {
        Err(SamlError::StatusNotSuccess { status }) => assert_eq!(status, auth_failed_status()?),
        other => return Err(format!("expected StatusNotSuccess, got {other:?}").into()),
    }

    let mut snapshot: PendingAuthnRequestSnapshot = started.pending.snapshot();
    snapshot.request_id = "_different_request".to_string();
    match sp.finish_sso(
        &idp_descriptor,
        &PendingAuthnRequest::from_snapshot(snapshot)?,
        Inbound::post(response_fields),
        validation(),
    ) {
        Err(SamlError::InResponseToMismatch { .. }) => Ok(()),
        other => Err(format!("expected InResponseToMismatch, got {other:?}").into()),
    }
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn typed_finish_sso_requiring_encrypted_assertions_reports_a_response_without_any_assertion(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(encrypted_sp_config()?);
    let idp = IdentityProvider::new(idp_config()?);
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(post_fields(&started.outbound)?),
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    )?;
    let xml = strip_embedded_signatures(&response_xml_from_fields(&post_fields(&response)?)?)?;
    let start = xml.find("<saml:Assertion").ok_or("missing assertion")?;
    let end = xml
        .find("</saml:Assertion>")
        .ok_or("unterminated assertion")?
        + "</saml:Assertion>".len();
    let mut without_assertion = xml.clone();
    without_assertion.replace_range(start..end, "");
    let fields = vec![FormField::new(
        "SAMLResponse",
        STANDARD.encode(resign_response(&without_assertion)?.as_bytes()),
    )];

    match sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(fields),
        validation(),
    ) {
        Err(SamlError::AssertionMissing) => Ok(()),
        other => Err(format!("expected AssertionMissing, got {other:?}").into()),
    }
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn typed_finish_sso_does_not_decrypt_an_assertion_in_a_signed_error_response(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(SP_ACS_POST)?.with_default(),
        )
        .credentials(encryption_credentials())
        .validation(signing_sp_validation())
        .build()?,
    );
    let idp = IdentityProvider::new(idp_config()?);
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(post_fields(&started.outbound)?),
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoOutcome::Failure(auth_failed_status()?),
        RespondSso::post(),
    )?;
    let undecryptable = concat!(
        "</samlp:Status><saml:EncryptedAssertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">",
        "<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">",
        "<xenc:CipherData><xenc:CipherValue>AAAA</xenc:CipherValue></xenc:CipherData>",
        "</xenc:EncryptedData></saml:EncryptedAssertion>",
    );
    let xml = resign_response(
        &response_xml_from_fields(&post_fields(&response)?)?.replacen(
            "</samlp:Status>",
            undecryptable,
            1,
        ),
    )?;
    assert!(xml.contains("<saml:EncryptedAssertion"));
    let fields = vec![FormField::new(
        "SAMLResponse",
        STANDARD.encode(xml.as_bytes()),
    )];

    let mut snapshot: PendingAuthnRequestSnapshot = started.pending.snapshot();
    snapshot.request_id = "_different_request".to_string();
    match sp.finish_sso(
        &idp_descriptor,
        &PendingAuthnRequest::from_snapshot(snapshot)?,
        Inbound::post(fields.clone()),
        validation(),
    ) {
        Err(SamlError::InResponseToMismatch { .. }) => {}
        other => return Err(format!("expected InResponseToMismatch, got {other:?}").into()),
    }
    match sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(fields),
        validation(),
    ) {
        Err(SamlError::StatusNotSuccess { status }) => {
            assert_eq!(status, auth_failed_status()?);
            Ok(())
        }
        other => Err(format!("expected StatusNotSuccess, got {other:?}").into()),
    }
}

#[test]
fn typed_finish_sso_checks_in_response_to_before_error_status(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = error_response_exchange()?;
    let mut snapshot: PendingAuthnRequestSnapshot = exchange.pending.snapshot();
    snapshot.request_id = "_different_request".to_string();
    let wrong_pending = PendingAuthnRequest::from_snapshot(snapshot)?;

    match exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &wrong_pending,
        Inbound::post(exchange.response_fields),
        validation(),
    ) {
        Err(SamlError::InResponseToMismatch { expected, actual }) => {
            assert_eq!(expected.as_deref(), Some("_different_request"));
            assert_eq!(
                actual.as_deref(),
                Some(exchange.pending.request_id().as_str())
            );
            Ok(())
        }
        other => Err(format!("expected InResponseToMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_finish_sso_checks_issuer_before_error_status() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = error_response_exchange()?;
    let xml = strip_embedded_signatures(&response_xml_from_fields(&exchange.response_fields)?)?
        .replacen(
            &format!(">{IDP_ENTITY_ID}<"),
            ">https://other-idp.example.com/metadata<",
            1,
        );

    match finish_sso_with_response_xml(&exchange, &xml) {
        Err(SamlError::IssuerMismatch { expected, actual }) => {
            assert_eq!(expected, IDP_ENTITY_ID);
            assert_eq!(
                actual.as_deref(),
                Some("https://other-idp.example.com/metadata")
            );
            Ok(())
        }
        other => Err(format!("expected IssuerMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_finish_sso_checks_destination_before_error_status(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = error_response_exchange()?;
    let xml = strip_embedded_signatures(&response_xml_from_fields(&exchange.response_fields)?)?
        .replacen(
            &format!("Destination=\"{SP_ACS_POST}\""),
            "Destination=\"https://other-sp.example.com/acs\"",
            1,
        );

    match finish_sso_with_response_xml(&exchange, &xml) {
        Err(SamlError::DestinationMismatch { expected, actual }) => {
            assert_eq!(expected, SP_ACS_POST);
            assert_eq!(actual.as_deref(), Some("https://other-sp.example.com/acs"));
            Ok(())
        }
        other => Err(format!("expected DestinationMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_finish_sso_verifies_a_present_signature_before_error_status(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = error_response_exchange()?;
    let xml = corrupt_signature_value(&response_xml_from_fields(&exchange.response_fields)?)?;

    match finish_sso_with_response_xml(&exchange, &xml) {
        Err(SamlError::SignatureVerification { .. }) => Ok(()),
        other => Err(format!("expected SignatureVerification, got {other:?}").into()),
    }
}

#[test]
fn typed_finish_sso_rejects_an_error_status_with_two_issuers(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = error_response_exchange()?;
    let other_issuer = "https://other-idp.example.com/metadata";
    let xml = strip_embedded_signatures(&response_xml_from_fields(&exchange.response_fields)?)?
        .replacen(
            &format!(">{IDP_ENTITY_ID}</saml:Issuer>"),
            &format!(">{other_issuer}</saml:Issuer><saml:Issuer>{other_issuer}</saml:Issuer>"),
            1,
        );

    match finish_sso_with_response_xml(&exchange, &xml) {
        Err(SamlError::IssuerMismatch { expected, actual }) => {
            assert_eq!(expected, IDP_ENTITY_ID);
            assert_eq!(actual, None);
            Ok(())
        }
        other => Err(format!("expected IssuerMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_finish_sso_verifies_a_simplesign_signature_before_error_status(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = start_receive_respond_with(
        StartSso::post().response_binding(SsoResponseBinding::SimpleSign),
        SsoOutcome::Failure(auth_failed_status()?),
        RespondSso::simple_sign(),
    )?;
    let finish = |fields: Vec<FormField>| {
        exchange.sp.finish_sso(
            &exchange.idp_descriptor,
            &exchange.pending,
            Inbound::simple_sign(fields),
            validation(),
        )
    };

    match finish(exchange.response_fields.clone()) {
        Err(SamlError::StatusNotSuccess { status }) => {
            assert_eq!(status.top_level().as_uri(), status_code::RESPONDER);
            assert_eq!(
                status
                    .subordinate()
                    .map(saml_rs::SubordinateStatusCode::as_uri),
                Some(status_code::AUTHN_FAILED)
            );
        }
        other => return Err(format!("expected StatusNotSuccess, got {other:?}").into()),
    }

    let mut tampered = exchange.response_fields.clone();
    let signature = tampered
        .iter_mut()
        .find(|field| field.name() == "Signature")
        .ok_or("missing Signature")?;
    let mut signature_bytes = STANDARD.decode(signature.value())?;
    let first = signature_bytes.first_mut().ok_or("empty Signature")?;
    *first ^= 0x01;
    *signature = FormField::new("Signature", STANDARD.encode(&signature_bytes));

    match finish(tampered) {
        Err(SamlError::SignatureVerification { reason }) => {
            assert_eq!(reason, SignatureVerificationReason::BindingSignature);
        }
        other => return Err(format!("expected SignatureVerification, got {other:?}").into()),
    }

    let key = read_private_key(PRIVKEY, None)?;
    let xml = corrupt_signature_value(&sign_saml_xml(
        &response_xml_from_fields(&exchange.response_fields)?,
        true,
        &key,
        CERT,
        RSA_SHA256,
        &[],
        None,
    )?)?;
    let octet = format!("SAMLResponse={xml}&SigAlg={RSA_SHA256}");
    let embedded_signature_corrupted = vec![
        FormField::new("SAMLResponse", STANDARD.encode(xml.as_bytes())),
        FormField::new("SigAlg", RSA_SHA256),
        FormField::new("Signature", sign_octet_string(&octet, &key, RSA_SHA256)?),
    ];
    match finish(embedded_signature_corrupted) {
        Err(SamlError::SignatureVerification { reason }) => {
            assert_eq!(reason, SignatureVerificationReason::XmlSignature);
            Ok(())
        }
        other => Err(format!("expected SignatureVerification, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_rejects_an_empty_in_response_to_as_unsolicited(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let ruled = idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(principal()),
        RespondSso::post().apply_producer_rules(),
    )?;
    let ruled_fields = post_fields(&ruled)?;
    let ruled_xml = response_xml_from_fields(&ruled_fields)?;
    let empty_on_response =
        ruled_xml.replacen("<samlp:Response ", "<samlp:Response InResponseTo=\"\" ", 1);
    let empty_on_bearer = sign_saml_xml(
        &strip_embedded_signatures(&ruled_xml.replacen(
            "<saml:SubjectConfirmationData ",
            "<saml:SubjectConfirmationData InResponseTo=\"\" ",
            1,
        ))?,
        false,
        &read_private_key(PRIVKEY, None)?,
        CERT,
        RSA_SHA256,
        &[],
        None,
    )?;
    let cases = [
        (
            "Response",
            response_fields_with_xml(ruled_fields.clone(), &empty_on_response)?,
        ),
        (
            "bearer SubjectConfirmationData",
            response_fields_with_xml(ruled_fields, &empty_on_bearer)?,
        ),
    ];

    for (case, fields) in cases {
        match sp.accept_unsolicited_sso(&idp_descriptor, Inbound::post(fields), validation()) {
            Err(SamlError::InResponseToMismatch { expected, actual }) => {
                assert_eq!(expected, None, "{case}");
                assert_eq!(actual.as_deref(), Some(""), "{case}");
            }
            other => {
                return Err(format!("{case}: expected InResponseToMismatch, got {other:?}").into())
            }
        }
    }
    Ok(())
}

#[test]
fn typed_facade_checks_replay_cache() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = start_receive_respond()?;
    let mut cache = RecordingReplayCache::default();

    exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::post(exchange.response_fields.clone()),
        validation_with_cache(&mut cache),
    )?;
    let replay_keys: Vec<String> = cache.seen.keys().cloned().collect();
    assert!(replay_keys
        .iter()
        .any(|key| key.starts_with("response_id:")));
    assert!(replay_keys
        .iter()
        .any(|key| key.starts_with("assertion_id:")));

    match exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::post(exchange.response_fields),
        validation_with_cache(&mut cache),
    ) {
        Err(SamlError::ReplayDetected { key }) => {
            assert!(replay_keys.contains(&key.cache_key()));
            Ok(())
        }
        other => Err(format!("expected ReplayDetected, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_accepts_unsolicited_sso_explicitly() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let response = idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(principal()),
        RespondSso::post().relay_state(RelayState::try_new("")?),
    )?;
    let session = sp.accept_unsolicited_sso(
        &idp_descriptor,
        Inbound::post(post_fields(&response)?),
        validation(),
    )?;

    assert_eq!(session.issuer().as_str(), IDP_ENTITY_ID);
    assert_eq!(session.in_response_to(), None);
    assert_eq!(
        session.response_issue_instant(),
        session.assertion_issue_instant()
    );
    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}

#[test]
fn typed_facade_accept_unsolicited_sso_post_rejects_missing_assertion_issue_instant(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let response = idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    )?;
    let fields = post_fields(&response)?;
    let xml = replace_element_issue_instant(
        &response_xml_from_fields(&fields)?,
        "<saml:Assertion",
        None,
    )?;
    let fields = response_fields_with_xml(fields, &xml)?;

    match sp.accept_unsolicited_sso(&idp_descriptor, Inbound::post(fields), validation()) {
        Err(SamlError::ProtocolProfile(message))
            if message
                .contains("Assertion is missing required unqualified attribute IssueInstant") =>
        {
            Ok(())
        }
        other => Err(format!(
            "expected Assertion IssueInstant ProtocolProfile from unsolicited POST, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn typed_facade_accept_unsolicited_sso_simplesign_rejects_non_utc_response_issue_instant(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_, idp) = facades()?;
    let sp = ServiceProvider::new(sp_config_with_default_response_binding(
        SsoResponseBinding::SimpleSign,
    )?);
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let response = idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(principal()),
        RespondSso::simple_sign(),
    )?;
    let fields = post_fields(&response)?;
    let xml = replace_element_issue_instant(
        &response_xml_from_fields(&fields)?,
        "<samlp:Response",
        Some("2024-01-01T00:00:00+00:00"),
    )?;
    let fields = response_fields_with_xml(fields, &xml)?;

    match sp.accept_unsolicited_sso(
        &idp_descriptor,
        Inbound::simple_sign(fields),
        validation(),
    ) {
        Err(SamlError::ProtocolProfile(message))
            if message.contains(
                "Response IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z",
            ) =>
        {
            Ok(())
        }
        other => Err(format!(
            "expected Response IssueInstant ProtocolProfile from unsolicited SimpleSign, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn typed_idp_issuance_lifetime_drives_both_sso_expirations_for_default_and_template_renderers(
) -> Result<(), Box<dyn std::error::Error>> {
    let lifetime = Duration::from_secs(11 * 60);
    for (template, binding) in [
        (None, SsoResponseBinding::Post),
        (Some(SSO_RESPONSE_TEMPLATE), SsoResponseBinding::SimpleSign),
    ] {
        let sp = ServiceProvider::new(sp_config_with_default_response_binding(binding)?);
        let idp_config = IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO_POST)?,
        )
        .sso_endpoint(SsoEndpoint::simple_sign(IDP_SSO_SIMPLESIGN)?)
        .credentials(signing_credentials())
        .issuance_lifetime(lifetime)
        .validation(signed_authn_request_idp_validation());
        let idp_config = match template {
            Some(template) => idp_config.sso_response_template(template),
            None => idp_config,
        };
        let idp = IdentityProvider::new(idp_config.build()?);
        let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
        let options = match binding {
            SsoResponseBinding::Post => RespondSso::post(),
            SsoResponseBinding::SimpleSign => RespondSso::simple_sign(),
            _ => return Err("not a posted response binding".into()),
        };
        let response = idp.initiate_sso(&sp_descriptor, SsoAssertion::new(principal()), options)?;
        let fields = post_fields(&response)?;
        let xml = response_xml_from_fields(&fields)?;
        let document = parse_document(&xml, saml_rs::XmlLimits::default())?;
        let issue_instant = document
            .root
            .attr("IssueInstant")
            .ok_or("missing Response IssueInstant")?;
        let assertion = document
            .root
            .children
            .iter()
            .find(|node| node.local_name == "Assertion")
            .ok_or("missing Assertion")?;
        let conditions = assertion
            .children
            .iter()
            .find(|node| node.local_name == "Conditions")
            .and_then(|node| node.attr("NotOnOrAfter"))
            .ok_or("missing Conditions NotOnOrAfter")?;
        let subject = assertion
            .children
            .iter()
            .find(|node| node.local_name == "Subject")
            .ok_or("missing Subject")?;
        let subject_confirmation = subject
            .children
            .iter()
            .find(|node| node.local_name == "SubjectConfirmation")
            .ok_or("missing SubjectConfirmation")?;
        let bearer = subject_confirmation
            .children
            .iter()
            .find(|node| node.local_name == "SubjectConfirmationData")
            .and_then(|node| node.attr("NotOnOrAfter"))
            .ok_or("missing SubjectConfirmationData NotOnOrAfter")?;
        let issue_instant = OffsetDateTime::parse(issue_instant, &Rfc3339)?;
        let expiration = OffsetDateTime::parse(conditions, &Rfc3339)?;
        assert_eq!(conditions, bearer);
        assert_eq!(expiration - issue_instant, time::Duration::minutes(11));

        let input = match binding {
            SsoResponseBinding::Post => Inbound::post(fields),
            SsoResponseBinding::SimpleSign => Inbound::simple_sign(fields),
            _ => return Err("not a posted response binding".into()),
        };
        let session = sp.accept_unsolicited_sso(&idp_descriptor, input, validation())?;
        assert_eq!(
            session.not_on_or_after().map(|value| value.as_str()),
            Some(conditions)
        );
    }
    Ok(())
}

#[test]
fn typed_idp_sso_reports_issuance_expiration_overflow() -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(sp_config()?);
    let idp = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO_POST)?,
        )
        .credentials(signing_credentials())
        .issuance_lifetime(Duration::from_secs(i64::MAX as u64))
        .validation(signed_authn_request_idp_validation())
        .build()?,
    );
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;

    match idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    ) {
        Err(SamlError::TimeWindowInvalid { field }) => {
            assert_eq!(field, TimeWindowField::IdpIssuanceExpiration);
            Ok(())
        }
        other => Err(format!("expected IdpIssuanceExpiration error, got {other:?}").into()),
    }
}

fn strip_embedded_signatures(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut rest = xml;
    let mut stripped = String::new();
    while let Some(start) = rest.find("<ds:Signature") {
        stripped.push_str(&rest[..start]);
        let after = &rest[start..];
        let end = after
            .find("</ds:Signature>")
            .ok_or("unterminated XML signature")?;
        rest = &after[end + "</ds:Signature>".len()..];
    }
    stripped.push_str(rest);
    Ok(stripped)
}

fn resign_response(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let key = read_private_key(PRIVKEY, None)?;
    Ok(sign_saml_xml(
        &strip_embedded_signatures(xml)?,
        true,
        &key,
        CERT,
        RSA_SHA256,
        &[],
        None,
    )?)
}

fn recommended_post_exchange() -> Result<SsoExchange, Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(sp_with_validation(recommended_sso_accept_validation())?);
    let idp = IdentityProvider::new(idp_with_validation(recommended_sso_accept_idp_validation())?);
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(post_fields(&started.outbound)?),
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    )?;
    Ok(SsoExchange {
        sp,
        idp,
        sp_descriptor,
        idp_descriptor,
        pending: started.pending,
        received,
        response_fields: post_fields(&response)?,
    })
}

fn assert_response_root_signature(
    session: &saml_rs::SsoSession,
) -> Result<(), Box<dyn std::error::Error>> {
    let [signature] = session.verified_xml_signatures() else {
        return Err("expected one verified embedded XML signature".into());
    };
    if signature.algorithm_uri() != RSA_SHA256
        || signature.coverage() != VerifiedXmlSignatureCoverage::ResponseRoot
    {
        return Err("expected a response signature and no direct assertion signature".into());
    }
    Ok(())
}

#[test]
fn recommended_sso_trusts_signed_metadata_only_with_pinned_certificates(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(sp_with_validation(recommended_sso_accept_validation())?);
    let signed = signed_idp_metadata()?;
    if !signed.contains("<ds:X509Certificate>") {
        return Err("expected the metadata signature to carry its own certificate".into());
    }

    let empty: [CertificatePem; 0] = [];
    match IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        &signed,
        MetadataTrustPolicy::RequireSignature {
            trusted_certificates: &empty,
        },
    ) {
        Err(SamlError::NoTrustedCertificate | SamlError::SignatureVerification { .. }) => {}
        other => {
            return Err(format!(
                "expected signed metadata without pinned certificates to be rejected, got {other:?}"
            )
            .into());
        }
    }

    let pinned = [CertificatePem::new(CERT)];
    let verified = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        &signed,
        MetadataTrustPolicy::RequireSignature {
            trusted_certificates: &pinned,
        },
    )?;
    assert!(verified.signed_metadata_xml().is_some());
    let started = sp.start_sso(&verified, StartSso::post())?;
    assert!(!started.outbound.id().as_str().is_empty());

    let unverified = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        &signed,
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    assert!(!unverified.signed_metadata_xml().is_some());
    Ok(())
}

#[test]
fn recommended_sso_accept_does_not_store_replay_without_a_caller_cache(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = recommended_post_exchange()?;
    let fields = exchange.response_fields;
    exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::post(fields.clone()),
        validation(),
    )?;
    exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::post(fields.clone()),
        validation(),
    )?;

    let mut cache = RecordingReplayCache::default();
    exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::post(fields.clone()),
        validation_with_cache(&mut cache),
    )?;
    let stored: Vec<_> = cache.seen.keys().cloned().collect();
    if !stored.iter().any(|key| key.starts_with("assertion_id:")) {
        return Err("expected the caller cache to store the assertion id".into());
    }
    match exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::post(fields),
        validation_with_cache(&mut cache),
    ) {
        Err(SamlError::ReplayDetected { .. }) => Ok(()),
        other => {
            Err(format!("expected ReplayDetected from the caller cache, got {other:?}").into())
        }
    }
}

#[test]
fn recommended_sso_receive_does_not_store_replay_without_a_caller_cache(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(sp_with_validation(recommended_sso_accept_validation())?);
    let idp = IdentityProvider::new(idp_with_validation(recommended_sso_accept_idp_validation())?);
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    assert!(!idp_descriptor.signed_metadata_xml().is_some());
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let fields = post_fields(&started.outbound)?;

    idp.receive_sso(&sp_descriptor, Inbound::post(fields.clone()), validation())?;
    idp.receive_sso(&sp_descriptor, Inbound::post(fields.clone()), validation())?;

    let mut cache = RecordingReplayCache::default();
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(fields.clone()),
        validation_with_cache(&mut cache),
    )?;
    let replay_key = format!("authn_request_id:{}", received.message().id().as_str());
    assert!(cache.seen.contains_key(&replay_key));
    match idp.receive_sso(
        &sp_descriptor,
        Inbound::post(fields),
        validation_with_cache(&mut cache),
    ) {
        Err(SamlError::ReplayDetected { key }) => {
            assert_eq!(key.cache_key(), replay_key);
            Ok(())
        }
        other => Err(format!(
            "expected AuthnRequest ReplayDetected from the caller cache, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn recommended_sso_accept_accepts_response_signature_without_assertion_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = recommended_post_exchange()?;
    let xml = response_xml_from_fields(&exchange.response_fields)?;
    if xml.matches("</ds:Signature>").count() != 1 {
        return Err("expected the response signature to be the only embedded signature".into());
    }

    let session = exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::post(exchange.response_fields.clone()),
        validation(),
    )?;
    assert_response_root_signature(&session)?;
    assert_eq!(session.name_id().value(), "alice@example.com");

    let unsolicited = exchange.idp.initiate_sso(
        &exchange.sp_descriptor,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    )?;
    let unsolicited_fields = post_fields(&unsolicited)?;
    let unsolicited_xml = response_xml_from_fields(&unsolicited_fields)?;
    if unsolicited_xml.matches("</ds:Signature>").count() != 1 {
        return Err("expected an unsolicited response signed only on the Response".into());
    }
    let session = exchange.sp.accept_unsolicited_sso(
        &exchange.idp_descriptor,
        Inbound::post(unsolicited_fields),
        validation(),
    )?;
    assert_response_root_signature(&session)?;
    assert_eq!(session.in_response_to(), None);
    Ok(())
}

#[test]
fn recommended_sso_accept_rejects_response_only_signature_only_with_assertion_hardening(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = recommended_post_exchange()?;
    let fields = exchange.response_fields;
    let hardening = ServiceProvider::new(sp_with_validation(SpValidationPolicy {
        assertions: AssertionSignaturePolicy::RequireSigned,
        ..recommended_sso_accept_validation()
    })?);
    match hardening.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::post(fields.clone()),
        validation(),
    ) {
        Err(SamlError::AssertionSignatureRequired) => {}
        other => {
            return Err(format!(
                "expected AssertionSignatureRequired for assertion hardening, got {other:?}"
            )
            .into());
        }
    }

    let sha2_only = ServiceProvider::new(sp_with_validation(SpValidationPolicy {
        xml_signatures: XmlSignatureProfile::StrictRsaSha2,
        ..recommended_sso_accept_validation()
    })?);
    let session = sha2_only.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::post(fields),
        validation(),
    )?;
    assert_response_root_signature(&session)?;
    Ok(())
}

#[test]
fn recommended_sso_accept_rejects_messages_a_receiver_must_reject(
) -> Result<(), Box<dyn std::error::Error>> {
    let first = recommended_post_exchange()?;
    let second = recommended_post_exchange()?;
    match first.sp.finish_sso(
        &first.idp_descriptor,
        &second.pending,
        Inbound::post(first.response_fields.clone()),
        validation(),
    ) {
        Err(SamlError::InResponseToMismatch { .. }) => {}
        other => {
            return Err(
                format!("expected InResponseToMismatch from finish_sso, got {other:?}").into(),
            );
        }
    }

    match first.sp.accept_unsolicited_sso(
        &first.idp_descriptor,
        Inbound::post(first.response_fields.clone()),
        validation(),
    ) {
        Err(SamlError::InResponseToMismatch { .. }) => {}
        other => {
            return Err(format!(
                "expected InResponseToMismatch from accept_unsolicited_sso, got {other:?}"
            )
            .into());
        }
    }

    let xml = response_xml_from_fields(&first.response_fields)?;
    let wrong_audience = resign_response(&xml.replace(
        &format!("<saml:Audience>{SP_ENTITY_ID}</saml:Audience>"),
        "<saml:Audience>https://other.example/metadata</saml:Audience>",
    ))?;
    if !xml.contains(&format!("<saml:Audience>{SP_ENTITY_ID}</saml:Audience>")) {
        return Err("expected the bearer assertion to name the service provider".into());
    }
    match first.sp.finish_sso(
        &first.idp_descriptor,
        &first.pending,
        Inbound::post(response_fields_with_xml(
            first.response_fields,
            &wrong_audience,
        )?),
        validation(),
    ) {
        Err(SamlError::AudienceMismatch { .. }) => {}
        other => return Err(format!("expected AudienceMismatch, got {other:?}").into()),
    }

    let started = first
        .sp
        .start_sso(&first.idp_descriptor, StartSso::post())?;
    let request_xml = authn_request_xml(&started.outbound)?
        .replace(IDP_SSO_POST, "https://idp.example.com/sso/wrong");
    match first.idp.receive_sso(
        &first.sp_descriptor,
        post_authn_request_input_with_xml(&request_xml),
        validation(),
    ) {
        Err(SamlError::DestinationMismatch { .. }) => Ok(()),
        other => Err(format!("expected DestinationMismatch, got {other:?}").into()),
    }
}

#[test]
fn recommended_sso_accept_requires_issue_instant_and_accepts_leap_seconds(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = recommended_post_exchange()?;
    let missing = replace_element_issue_instant(
        &response_xml_from_fields(&exchange.response_fields)?,
        "<samlp:Response",
        None,
    )?;
    match exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::post(response_fields_with_xml(
            exchange.response_fields.clone(),
            &missing,
        )?),
        validation(),
    ) {
        Err(SamlError::ProtocolProfile(message))
            if message
                .contains("Response is missing required unqualified attribute IssueInstant") => {}
        other => {
            return Err(format!("expected missing Response IssueInstant, got {other:?}").into());
        }
    }

    let leap_second = "2016-12-31T23:59:60Z";
    let leap_xml = resign_response(&replace_element_issue_instant(
        &response_xml_from_fields(&exchange.response_fields)?,
        "<samlp:Response",
        Some(leap_second),
    )?)?;
    let session = exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::post(response_fields_with_xml(
            exchange.response_fields,
            &leap_xml,
        )?),
        validation(),
    )?;
    assert_eq!(session.response_issue_instant().as_str(), leap_second);

    let unsolicited = exchange.idp.initiate_sso(
        &exchange.sp_descriptor,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    )?;
    let unsolicited_fields = post_fields(&unsolicited)?;
    let unsolicited_leap = resign_response(&replace_element_issue_instant(
        &response_xml_from_fields(&unsolicited_fields)?,
        "<samlp:Response",
        Some(leap_second),
    )?)?;
    let session = exchange.sp.accept_unsolicited_sso(
        &exchange.idp_descriptor,
        Inbound::post(response_fields_with_xml(
            unsolicited_fields,
            &unsolicited_leap,
        )?),
        validation(),
    )?;
    assert_eq!(session.response_issue_instant().as_str(), leap_second);

    let started = exchange
        .sp
        .start_sso(&exchange.idp_descriptor, StartSso::post())?;
    let missing_request = replace_issue_instant(&authn_request_xml(&started.outbound)?, None)?;
    match exchange.idp.receive_sso(
        &exchange.sp_descriptor,
        post_authn_request_input_with_xml(&missing_request),
        validation(),
    ) {
        Err(SamlError::ProtocolProfile(message))
            if message.contains("missing required unqualified attribute IssueInstant") => {}
        other => {
            return Err(
                format!("expected missing AuthnRequest IssueInstant, got {other:?}").into(),
            );
        }
    }
    let leap_request =
        replace_issue_instant(&authn_request_xml(&started.outbound)?, Some(leap_second))?;
    let received = exchange.idp.receive_sso(
        &exchange.sp_descriptor,
        post_authn_request_input_with_xml(&leap_request),
        validation(),
    )?;
    assert_eq!(received.message().issue_instant().as_str(), leap_second);
    Ok(())
}

#[test]
fn cbc_relaxation_does_not_disable_other_accept_rules() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = recommended_post_exchange()?;
    let relaxed = ServiceProvider::new(sp_with_validation(SpValidationPolicy {
        responses: ResponseSignaturePolicy::AllowUnsignedEncryptedCbc,
        ..recommended_sso_accept_validation()
    })?);
    let unsigned =
        strip_embedded_signatures(&response_xml_from_fields(&exchange.response_fields)?)?;
    match relaxed.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::post(response_fields_with_xml(
            exchange.response_fields.clone(),
            &unsigned,
        )?),
        validation(),
    ) {
        Err(SamlError::SignatureMissing) => {}
        other => {
            return Err(format!(
                "expected SignatureMissing for an unsigned POST response, got {other:?}"
            )
            .into());
        }
    }

    let wrong_audience = resign_response(
        &response_xml_from_fields(&exchange.response_fields)?.replace(
            &format!("<saml:Audience>{SP_ENTITY_ID}</saml:Audience>"),
            "<saml:Audience>https://other.example/metadata</saml:Audience>",
        ),
    )?;
    match relaxed.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::post(response_fields_with_xml(
            exchange.response_fields,
            &wrong_audience,
        )?),
        validation(),
    ) {
        Err(SamlError::AudienceMismatch { .. }) => Ok(()),
        other => Err(format!(
            "expected AudienceMismatch after relaxing only the CBC recommendation, got {other:?}"
        )
        .into()),
    }
}

#[cfg(not(feature = "crypto-fips"))]
fn sp_with_validation_and_xml(
    validation: SpValidationPolicy,
) -> Result<saml_rs::SpConfigBuilder, SamlError> {
    Ok(SpConfig::builder(
        EntityId::try_new(SP_ENTITY_ID)?,
        AcsEndpoint::post(SP_ACS_POST)?.with_default(),
    )
    .credentials(encryption_credentials())
    .validation(validation)
    .xml(encrypted_xml_policy()))
}

#[cfg(not(feature = "crypto-fips"))]
fn idp_with_validation_and_xml(
    validation: IdpValidationPolicy,
) -> Result<saml_rs::IdpConfigBuilder, SamlError> {
    Ok(IdpConfig::builder(
        EntityId::try_new(IDP_ENTITY_ID)?,
        SsoEndpoint::post(IDP_SSO_POST)?,
    )
    .credentials(signing_credentials())
    .validation(validation)
    .xml(encrypted_xml_policy()))
}

fn response_without_audience_restriction(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let start = xml
        .find("<saml:AudienceRestriction")
        .ok_or("missing AudienceRestriction")?;
    let closer = "</saml:AudienceRestriction>";
    let relative_end = xml[start..]
        .find(closer)
        .ok_or("unterminated AudienceRestriction")?;
    let end = start + relative_end + closer.len();
    resign_response(&format!("{}{}", &xml[..start], &xml[end..]))
}

fn corrupt_signature_value(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let marker = "<ds:SignatureValue>";
    let start = xml.find(marker).ok_or("missing signature value")? + marker.len();
    let mut bytes = xml.as_bytes().to_vec();
    let byte = *bytes.get(start).ok_or("empty signature value")?;
    bytes[start] = if byte == b'A' { b'B' } else { b'A' };
    Ok(String::from_utf8(bytes)?)
}

#[test]
fn recommended_sso_accept_does_not_require_an_audience_restriction(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = recommended_post_exchange()?;
    let fields = response_fields_with_xml(
        exchange.response_fields.clone(),
        &response_without_audience_restriction(&response_xml_from_fields(
            &exchange.response_fields,
        )?)?,
    )?;
    let session = exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::post(fields.clone()),
        validation(),
    )?;
    assert_eq!(session.name_id().value(), "alice@example.com");
    assert!(session.audience_restrictions().is_empty());

    let validate_omission = ServiceProvider::new(sp_with_validation(SpValidationPolicy {
        audience: AudienceValidationPolicy::RequireRestriction,
        ..recommended_sso_accept_validation()
    })?);
    match validate_omission.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::post(fields),
        validation(),
    ) {
        Err(SamlError::AudienceMismatch { .. }) => Ok(()),
        other => Err(format!(
            "expected AudienceMismatch when omission hardening is selected, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn recommended_idp_receive_verifies_a_present_authn_request_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_sp = ServiceProvider::new(sp_config()?);
    let strict_idp = IdentityProvider::new(idp_config()?);
    let recommended_idp =
        IdentityProvider::new(idp_with_validation(recommended_sso_accept_idp_validation())?);
    let compatibility_idp =
        IdentityProvider::new(idp_with_validation(IdpValidationPolicy::compatibility())?);
    let (sp_descriptor, idp_descriptor) = descriptors(&signing_sp, &strict_idp)?;
    let started = signing_sp.start_sso(&idp_descriptor, StartSso::post())?;
    let signed = authn_request_input(&started.outbound)?;
    recommended_idp.receive_sso(&sp_descriptor, signed, validation())?;

    let corrupted = corrupt_signature_value(&authn_request_xml(&started.outbound)?)?;
    match recommended_idp.receive_sso(
        &sp_descriptor,
        post_authn_request_input_with_xml(&corrupted),
        validation(),
    ) {
        Err(SamlError::SignatureVerification { .. }) => {}
        other => {
            return Err(format!(
                "expected SignatureVerification for a present invalid signature, got {other:?}"
            )
            .into());
        }
    }

    compatibility_idp.receive_sso(
        &sp_descriptor,
        post_authn_request_input_with_xml(&corrupted),
        validation(),
    )?;
    Ok(())
}

#[test]
fn compatibility_sso_accept_keeps_unsigned_request_and_response_signature_outcomes(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = recommended_post_exchange()?;
    let compatibility =
        ServiceProvider::new(sp_with_validation(SpValidationPolicy::compatibility())?);
    let session = compatibility.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::post(exchange.response_fields.clone()),
        validation(),
    )?;
    assert_response_root_signature(&session)?;

    let wrong_audience = resign_response(
        &response_xml_from_fields(&exchange.response_fields)?.replace(
            &format!("<saml:Audience>{SP_ENTITY_ID}</saml:Audience>"),
            "<saml:Audience>https://other.example/metadata</saml:Audience>",
        ),
    )?;
    let session = compatibility.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::post(response_fields_with_xml(
            exchange.response_fields,
            &wrong_audience,
        )?),
        validation(),
    )?;
    assert_eq!(session.name_id().value(), "alice@example.com");

    let (compatibility_sp, compatibility_idp) = compatibility_facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&compatibility_sp, &compatibility_idp)?;
    let started = compatibility_sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = compatibility_idp.receive_sso(
        &sp_descriptor,
        Inbound::post(post_fields(&started.outbound)?),
        validation(),
    )?;
    assert_eq!(received.message().id(), started.pending.request_id());

    let wrong_destination = authn_request_xml(&started.outbound)?
        .replace(IDP_SSO_POST, "https://idp.example.com/sso/wrong");
    match compatibility_idp.receive_sso(
        &sp_descriptor,
        post_authn_request_input_with_xml(&wrong_destination),
        validation(),
    ) {
        Err(SamlError::DestinationMismatch { .. }) => {}
        other => {
            return Err(format!(
                "expected DestinationMismatch from compatibility receive, got {other:?}"
            )
            .into());
        }
    }

    let strict_idp = IdentityProvider::new(idp_config()?);
    match strict_idp.receive_sso(
        &sp_descriptor,
        Inbound::post(post_fields(&started.outbound)?),
        validation(),
    ) {
        Err(SamlError::SignatureMissing) => Ok(()),
        other => Err(format!(
            "expected a required AuthnRequest signature to reject an unsigned request, got {other:?}"
        )
        .into()),
    }
}

fn without_destination(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let marker = " Destination=\"";
    let start = xml.find(marker).ok_or("missing Destination")?;
    let value_start = start + marker.len();
    let end_quote = xml[value_start..]
        .find('"')
        .ok_or("unterminated Destination")?;
    let end = value_start + end_quote + 1;
    Ok(format!("{}{}", &xml[..start], &xml[end..]))
}

fn signed_redirect_query_without_destination(
    xml: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let unsigned = strip_embedded_signatures(&without_destination(xml)?)?;
    let octet = build_redirect_octet(ParserType::SamlRequest, &unsigned, None, RSA_SHA256)?;
    let key = read_private_key(PRIVKEY, None)?;
    let signature = sign_octet_string(&octet, &key, RSA_SHA256)?;
    let url = append_signature(IDP_SSO_REDIRECT, &octet, &signature);
    Ok(url
        .split_once('?')
        .ok_or("missing redirect query")?
        .1
        .to_string())
}

#[test]
fn recommended_idp_receive_ignores_a_spurious_post_signature_field(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(sp_with_validation(recommended_sso_accept_validation())?);
    let idp = IdentityProvider::new(idp_with_validation(recommended_sso_accept_idp_validation())?);
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let mut fields = post_fields(&started.outbound)?;
    fields.push(FormField::new("Signature", "bm90LWEgc2ln"));

    let received = idp.receive_sso(&sp_descriptor, Inbound::post(fields), validation())?;
    assert_eq!(received.message().id(), started.pending.request_id());
    Ok(())
}

#[test]
fn idp_receive_rejects_authenticated_request_without_destination(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_sp = ServiceProvider::new(sp_config()?);
    let strict_idp = IdentityProvider::new(idp_config()?);
    let recommended_idp = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO_POST)?,
        )
        .sso_endpoint(SsoEndpoint::redirect(IDP_SSO_REDIRECT)?)
        .credentials(signing_credentials())
        .validation(recommended_sso_accept_idp_validation())
        .build()?,
    );
    let (sp_descriptor, idp_descriptor) = descriptors(&signing_sp, &strict_idp)?;

    let started = signing_sp.start_sso(&idp_descriptor, StartSso::post())?;
    let xml = without_destination(&authn_request_xml(&started.outbound)?)?;
    let resigned = resign_response(&xml)?;
    let redirect = signing_sp.start_sso(&idp_descriptor, StartSso::redirect())?;
    let query = signed_redirect_query_without_destination(&authn_request_xml(&redirect.outbound)?)?;
    for (policy, idp) in [
        ("RequireSigned", &strict_idp),
        ("recommended", &recommended_idp),
    ] {
        match idp.receive_sso(
            &sp_descriptor,
            post_authn_request_input_with_xml(&resigned),
            validation(),
        ) {
            Err(SamlError::DestinationMismatch { actual, .. }) if actual.is_none() => {}
            other => {
                return Err(format!(
                    "expected missing Destination on a signed POST AuthnRequest under {policy}, got {other:?}"
                )
                .into());
            }
        }
        match idp.receive_sso(&sp_descriptor, Inbound::redirect(&query), validation()) {
            Err(SamlError::DestinationMismatch { actual, .. }) if actual.is_none() => {}
            other => {
                return Err(format!(
                    "expected missing Destination on a signed Redirect AuthnRequest under {policy}, got {other:?}"
                )
                .into());
            }
        }
    }

    let unsigned_sp =
        ServiceProvider::new(sp_with_validation(recommended_sso_accept_validation())?);
    let (unsigned_descriptor, recommended_descriptor) =
        descriptors(&unsigned_sp, &recommended_idp)?;
    let unsigned = unsigned_sp.start_sso(&recommended_descriptor, StartSso::post())?;
    let omitted = without_destination(&authn_request_xml(&unsigned.outbound)?)?;
    let received = recommended_idp.receive_sso(
        &unsigned_descriptor,
        post_authn_request_input_with_xml(&omitted),
        validation(),
    )?;
    assert_eq!(received.message().destination(), None);
    Ok(())
}

#[test]
fn typed_facade_accepts_metadata_and_response_that_start_with_a_byte_order_mark(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = start_receive_respond()?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        &format!("\u{feff}{}", exchange.idp.metadata_xml()),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let xml = format!(
        "\u{feff}{}",
        response_xml_from_fields(&exchange.response_fields)?
    );
    let fields = response_fields_with_xml(exchange.response_fields, &xml)?;

    let session = exchange.sp.finish_sso(
        &idp_descriptor,
        &exchange.pending,
        Inbound::post(fields),
        validation(),
    )?;

    assert_eq!(session.issuer().as_str(), IDP_ENTITY_ID);
    assert_eq!(
        session.in_response_to(),
        Some(exchange.pending.request_id())
    );
    Ok(())
}
