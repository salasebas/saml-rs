#![cfg(not(crypto))]

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::binding::{deflate_raw_decode, MAX_DEFLATE_RAW_DECODE_BYTES};
use saml_rs::constants::{Binding, ParserType};
use saml_rs::entity::{EntitySetting, User};
use saml_rs::flow::{FlowOptions, HttpRequest, SignatureCheck};
use saml_rs::idp;
use saml_rs::idp::LoginResponseOptions;
use saml_rs::metadata::{Endpoint, IdpMetadata, IdpMetadataInput, SpMetadataInput};
use saml_rs::sp;
use saml_rs::sp::LoginRequestOptions;
use saml_rs::tests::engine::flow;
use saml_rs::tests::engine::{create_logout_request, create_logout_response, LogoutUser};
use saml_rs::tests::engine::{IdpMessages, SpMessages};
use saml_rs::tests::policies_without_crypto::{
    idp_validation_without_crypto, sp_validation_without_crypto,
};
use saml_rs::xml::{extract, ExtractorField};
use saml_rs::{
    AcsEndpoint, AssertionEncryptionPolicy, AssertionSignaturePolicy, AuthnRequestSigningPolicy,
    AuthnRequestValidationPolicy, CertificatePem, EntityId, IdentityProvider, IdpConfig,
    IdpDescriptor, Inbound, LogoutSignaturePolicy, LogoutSigning, LogoutSubject,
    MetadataTrustPolicy, NameId, RelayState, ReplayPolicy, ResponseSignaturePolicy, SamlError,
    SamlValidationContext, ServiceProvider, SloEndpoint, SpConfig, SpDescriptor, SsoEndpoint,
    StartSlo, StartSso, XmlPolicy,
};
use std::time::SystemTime;

fn idp_config(want_authn_requests_signed: bool) -> IdpMetadataInput {
    IdpMetadataInput {
        entity_id: "https://idp.example.com/metadata".into(),
        want_authn_requests_signed,
        single_sign_on_service: vec![
            Endpoint::new(Binding::Post, "https://idp.example.com/sso"),
            Endpoint::new(Binding::Redirect, "https://idp.example.com/sso"),
        ],
        single_logout_service: vec![Endpoint::new(Binding::Post, "https://idp.example.com/slo")],
        ..IdpMetadataInput::default()
    }
}

fn sp_config(authn_requests_signed: bool) -> SpMetadataInput {
    SpMetadataInput {
        entity_id: "https://sp.example.com/metadata".into(),
        authn_requests_signed,
        assertion_consumer_service: vec![Endpoint::new(
            Binding::Post,
            "https://sp.example.com/acs",
        )],
        single_logout_service: vec![Endpoint::new(Binding::Post, "https://sp.example.com/slo")],
        ..SpMetadataInput::default()
    }
}

fn idp(want_authn_requests_signed: bool) -> Result<idp::Engine, SamlError> {
    idp::Engine::from_config(
        &idp_config(want_authn_requests_signed),
        EntitySetting::default(),
    )
}

fn sp(authn_requests_signed: bool) -> Result<sp::Engine, SamlError> {
    sp::Engine::from_config(&sp_config(authn_requests_signed), EntitySetting::default())
}

fn assert_unsupported(result: Result<impl Sized, SamlError>) {
    assert!(matches!(result, Err(SamlError::Unsupported(_))));
}

fn sp_config_builder() -> Result<saml_rs::SpConfigBuilder, SamlError> {
    Ok(SpConfig::builder(
        EntityId::try_new("https://sp.example.com/metadata")?,
        AcsEndpoint::post("https://sp.example.com/acs")?,
    )
    .validation(sp_validation_without_crypto()))
}

fn idp_config_builder() -> Result<saml_rs::IdpConfigBuilder, SamlError> {
    Ok(IdpConfig::builder(
        EntityId::try_new("https://idp.example.com/metadata")?,
        SsoEndpoint::redirect("https://idp.example.com/sso")?,
    )
    .validation(idp_validation_without_crypto()))
}

fn typed_sp_config() -> Result<SpConfig, SamlError> {
    SpConfig::builder(
        EntityId::try_new("https://sp.example.com/metadata")?,
        AcsEndpoint::post("https://sp.example.com/acs")?,
    )
    .slo_endpoint(SloEndpoint::post("https://sp.example.com/slo")?)
    .validation(sp_validation_without_crypto())
    .build()
}

fn typed_idp_config() -> Result<IdpConfig, SamlError> {
    IdpConfig::builder(
        EntityId::try_new("https://idp.example.com/metadata")?,
        SsoEndpoint::post("https://idp.example.com/sso")?,
    )
    .slo_endpoint(SloEndpoint::post("https://idp.example.com/slo")?)
    .validation(idp_validation_without_crypto())
    .build()
}

fn typed_protocol_facades() -> Result<
    (
        saml_rs::ServiceProvider,
        saml_rs::IdentityProvider,
        SpDescriptor,
        IdpDescriptor,
    ),
    SamlError,
> {
    let sp = ServiceProvider::new(typed_sp_config()?);
    let idp = IdentityProvider::new(typed_idp_config()?);
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new("https://sp.example.com/metadata")?,
        sp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new("https://idp.example.com/metadata")?,
        idp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    Ok((sp, idp, sp_descriptor, idp_descriptor))
}

fn typed_validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::Disabled)
}

#[test]
fn unsigned_metadata_parsing_and_xml_extraction_still_work(
) -> Result<(), Box<dyn std::error::Error>> {
    let metadata_xml = idp(false)?.metadata_xml().to_string();
    let metadata = IdpMetadata::from_xml(&metadata_xml)?;
    assert_eq!(
        metadata.as_metadata().entity_id(),
        Some("https://idp.example.com/metadata")
    );

    let extracted = extract(
        r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject></saml:Assertion>"#,
        &[ExtractorField::new(
            "nameID",
            &["Assertion", "Subject", "NameID"],
        )],
    )?;
    assert_eq!(extracted.get_str("nameID"), Some("user@example.com"));
    Ok(())
}

#[test]
fn typed_metadata_descriptors_parse_unsigned_metadata_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp_metadata_xml = idp(false)?.metadata_xml().to_string();
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new("https://idp.example.com/metadata")?,
        &idp_metadata_xml,
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    assert_eq!(
        idp_descriptor.entity_id().as_str(),
        "https://idp.example.com/metadata"
    );

    let sp_metadata_xml = sp(false)?.metadata_xml().to_string();
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new("https://sp.example.com/metadata")?,
        &sp_metadata_xml,
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    assert_eq!(
        sp_descriptor.entity_id().as_str(),
        "https://sp.example.com/metadata"
    );
    Ok(())
}

#[test]
fn typed_metadata_require_signature_is_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp_metadata_xml = idp(false)?.metadata_xml().to_string();
    let cert = CertificatePem::new("placeholder");

    assert_unsupported(IdpDescriptor::from_metadata_xml(
        EntityId::try_new("https://idp.example.com/metadata")?,
        &idp_metadata_xml,
        MetadataTrustPolicy::RequireSignature {
            trusted_certificates: std::slice::from_ref(&cert),
        },
    ));
    Ok(())
}

#[test]
fn typed_config_builders_construct_protocol_only_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp_config = SpConfig::builder(
        EntityId::try_new("https://sp.example.com/metadata")?,
        AcsEndpoint::post("https://sp.example.com/acs")?,
    )
    .validation(sp_validation_without_crypto())
    .build()?;
    let idp_config = IdpConfig::builder(
        EntityId::try_new("https://idp.example.com/metadata")?,
        SsoEndpoint::redirect("https://idp.example.com/sso")?,
    )
    .validation(idp_validation_without_crypto())
    .build()?;

    assert_eq!(
        sp_config.entity_id().as_str(),
        "https://sp.example.com/metadata"
    );
    assert_eq!(
        idp_config.entity_id().as_str(),
        "https://idp.example.com/metadata"
    );
    assert_eq!(sp_config.validation(), &sp_validation_without_crypto());
    assert_eq!(idp_config.validation(), &idp_validation_without_crypto());
    Ok(())
}

#[test]
fn typed_facade_creates_and_receives_unsigned_protocol_sso_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = typed_protocol_facades()?;
    let relay_state = RelayState::try_new("protocol-only")?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post().relay_state(relay_state))?;

    let form = started.outbound.post_form()?;
    assert_eq!(form.action().as_str(), "https://idp.example.com/sso");
    assert!(form.value("SAMLRequest").is_some());
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(form.fields().to_vec()),
        typed_validation(),
    )?;

    assert_eq!(
        received.message().issuer().as_str(),
        "https://sp.example.com/metadata"
    );
    assert_eq!(received.message().id(), started.pending.request_id());
    Ok(())
}

#[test]
fn typed_config_builders_return_unsupported_for_crypto_required_policy_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_unsupported(
        SpConfig::builder(
            EntityId::try_new("https://sp.example.com/metadata")?,
            AcsEndpoint::post("https://sp.example.com/acs")?,
        )
        .build(),
    );
    assert_unsupported(
        IdpConfig::builder(
            EntityId::try_new("https://idp.example.com/metadata")?,
            SsoEndpoint::redirect("https://idp.example.com/sso")?,
        )
        .build(),
    );
    Ok(())
}

#[test]
fn sp_required_assertion_signatures_return_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut validation = sp_validation_without_crypto();
    validation.assertions = AssertionSignaturePolicy::RequireSigned;

    assert_unsupported(sp_config_builder()?.validation(validation).build());
    Ok(())
}

#[test]
fn sp_required_response_signatures_return_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut validation = sp_validation_without_crypto();
    validation.responses = ResponseSignaturePolicy::RequireSigned;

    assert_unsupported(sp_config_builder()?.validation(validation).build());
    Ok(())
}

#[test]
fn sp_signed_authn_requests_return_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut validation = sp_validation_without_crypto();
    validation.authn_requests = AuthnRequestSigningPolicy::Sign;

    assert_unsupported(sp_config_builder()?.validation(validation).build());
    Ok(())
}

#[test]
fn sp_signed_logout_policy_returns_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut validation = sp_validation_without_crypto();
    validation.logout.requests = LogoutSignaturePolicy::RequireSigned;

    assert_unsupported(sp_config_builder()?.validation(validation).build());
    Ok(())
}

#[test]
fn sp_encrypted_assertions_return_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut xml = XmlPolicy::default();
    xml.encryption.assertions = AssertionEncryptionPolicy::EncryptAssertions;

    assert_unsupported(sp_config_builder()?.xml(xml).build());
    Ok(())
}

#[test]
fn idp_required_authn_request_signatures_return_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut validation = idp_validation_without_crypto();
    validation.authn_requests = AuthnRequestValidationPolicy::RequireSigned;

    assert_unsupported(idp_config_builder()?.validation(validation).build());
    Ok(())
}

#[test]
fn idp_signed_logout_policy_returns_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut validation = idp_validation_without_crypto();
    validation.logout.responses = LogoutSignaturePolicy::RequireSigned;

    assert_unsupported(idp_config_builder()?.validation(validation).build());
    Ok(())
}

#[test]
fn idp_encrypted_assertions_return_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut xml = XmlPolicy::default();
    xml.encryption.assertions = AssertionEncryptionPolicy::EncryptAssertions;

    assert_unsupported(idp_config_builder()?.xml(xml).build());
    Ok(())
}

#[test]
fn typed_facade_crypto_required_paths_return_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, _idp, _sp_descriptor, idp_descriptor) = typed_protocol_facades()?;

    assert_unsupported(sp.start_slo(
        &idp_descriptor,
        LogoutSubject::new(NameId::new("alice@example.com")),
        StartSlo::post().signing(LogoutSigning::Sign),
    ));
    Ok(())
}

#[test]
fn unsigned_login_request_creation_still_works() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = sp(false)?.create_login_request(
        &idp(false)?,
        Binding::Post,
        &LoginRequestOptions::default(),
    )?;
    let xml = String::from_utf8(STANDARD.decode(&ctx.context)?)?;
    assert!(xml.contains("<samlp:AuthnRequest"));
    assert!(ctx.signature.is_none());
    Ok(())
}

#[test]
fn unsigned_login_request_redirect_decoding_still_works() -> Result<(), Box<dyn std::error::Error>>
{
    let ctx = sp(false)?.create_login_request(
        &idp(false)?,
        Binding::Redirect,
        &LoginRequestOptions::default(),
    )?;
    let url = url::Url::parse(&ctx.context)?;
    let (_, encoded) = url
        .query_pairs()
        .find(|(key, _)| key == "SAMLRequest")
        .ok_or("missing SAMLRequest")?;
    let xml = String::from_utf8(deflate_raw_decode(
        &STANDARD.decode(encoded.as_ref())?,
        MAX_DEFLATE_RAW_DECODE_BYTES,
    )?)?;
    assert!(xml.contains("AssertionConsumerServiceURL=\"https://sp.example.com/acs\""));
    Ok(())
}

#[test]
fn signing_login_request_returns_unsupported() -> Result<(), Box<dyn std::error::Error>> {
    assert_unsupported(sp(true)?.create_login_request(
        &idp(true)?,
        Binding::Post,
        &LoginRequestOptions::default(),
    ));
    Ok(())
}

#[test]
fn signed_login_response_creation_returns_unsupported() -> Result<(), Box<dyn std::error::Error>> {
    assert_unsupported(idp(false)?.create_login_response(
        &sp(false)?,
        Binding::Post,
        &User::new("user@example.com"),
        &LoginResponseOptions::default(),
    ));
    Ok(())
}

#[test]
fn encrypted_assertion_parse_path_returns_unsupported() {
    let request = HttpRequest::post(vec![(
        "SAMLResponse".into(),
        STANDARD.encode(
            br#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_encrypted_response" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com/metadata</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/></samlp:Response>"#,
        ),
    )]);
    let options = FlowOptions {
        binding: Some(Binding::Post),
        parser_type: Some(ParserType::SamlResponse),
        signature_check: SignatureCheck::Require,
        decrypt_key: Some("private key is unavailable without crypto feature"),
        ..FlowOptions::default()
    };

    assert_unsupported(flow(&options, &request));
}

#[test]
fn signed_logout_request_returns_unsupported() -> Result<(), Box<dyn std::error::Error>> {
    assert_unsupported(create_logout_request(
        &EntitySetting::default(),
        sp(false)?.metadata.as_metadata(),
        idp(false)?.metadata.as_metadata(),
        Binding::Post,
        &LogoutUser::new("user@example.com"),
        None,
        true,
    ));
    Ok(())
}

#[test]
fn signed_logout_response_returns_unsupported() -> Result<(), Box<dyn std::error::Error>> {
    assert_unsupported(create_logout_response(
        &EntitySetting::default(),
        idp(false)?.metadata.as_metadata(),
        sp(false)?.metadata.as_metadata(),
        Binding::Post,
        Some("_logout_request"),
        None,
        true,
    ));
    Ok(())
}
