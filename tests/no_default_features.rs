#![cfg(not(crypto))]

use saml_rs::binding::{base64_decode, base64_encode, deflate_raw_decode};
use saml_rs::constants::{Binding, ParserType};
use saml_rs::entity::{EntitySetting, User};
use saml_rs::flow::{flow, FlowOptions, HttpRequest};
use saml_rs::idp::LoginResponseOptions;
use saml_rs::logout::{create_logout_request, create_logout_response};
use saml_rs::metadata::{Endpoint, IdpMetadata, IdpMetadataConfig, SpMetadataConfig};
use saml_rs::xml::{extract, ExtractorField};
use saml_rs::{
    AcsEndpoint, AssertionSignaturePolicy, AuthnRequest, AuthnRequestSigningPolicy,
    AuthnRequestValidationPolicy, BrowserInput, CertificatePem, EntityId, IdentityProvider,
    IdpConfig, IdpDescriptor, IdpValidationPolicy, LogoutSignaturePolicy, LogoutSigning,
    LogoutSubject, MetadataTrustPolicy, NameId, RelayStateParam, ReplayPolicy,
    ResponseSignaturePolicy, Saml, SamlError, SamlValidationContext, ServiceProvider, SloEndpoint,
    SpConfig, SpDescriptor, SpValidationPolicy, SsoEndpoint, StartSlo, StartSso,
    XmlEncryptionPolicy, XmlPolicy,
};
use std::time::SystemTime;

fn idp_config(want_authn_requests_signed: bool) -> IdpMetadataConfig {
    IdpMetadataConfig {
        entity_id: "https://idp.example.com/metadata".into(),
        want_authn_requests_signed,
        single_sign_on_service: vec![
            Endpoint::new(Binding::Post, "https://idp.example.com/sso"),
            Endpoint::new(Binding::Redirect, "https://idp.example.com/sso"),
        ],
        single_logout_service: vec![Endpoint::new(Binding::Post, "https://idp.example.com/slo")],
        ..Default::default()
    }
}

fn sp_config(authn_requests_signed: bool) -> SpMetadataConfig {
    SpMetadataConfig {
        entity_id: "https://sp.example.com/metadata".into(),
        authn_requests_signed,
        assertion_consumer_service: vec![Endpoint::new(
            Binding::Post,
            "https://sp.example.com/acs",
        )],
        single_logout_service: vec![Endpoint::new(Binding::Post, "https://sp.example.com/slo")],
        ..Default::default()
    }
}

fn idp(want_authn_requests_signed: bool) -> Result<IdentityProvider, SamlError> {
    IdentityProvider::from_config(
        &idp_config(want_authn_requests_signed),
        EntitySetting::default(),
    )
}

fn sp(authn_requests_signed: bool) -> Result<ServiceProvider, SamlError> {
    ServiceProvider::from_config(&sp_config(authn_requests_signed), EntitySetting::default())
}

fn assert_unsupported(result: Result<impl Sized, SamlError>) {
    assert!(matches!(result, Err(SamlError::Unsupported(_))));
}

fn sp_config_builder() -> Result<saml_rs::SpConfigBuilder, SamlError> {
    Ok(
        SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
            .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
            .validation(SpValidationPolicy::compatibility()),
    )
}

fn idp_config_builder() -> Result<saml_rs::IdpConfigBuilder, SamlError> {
    Ok(
        IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
            .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso")?)
            .validation(IdpValidationPolicy::compatibility()),
    )
}

fn typed_sp_config() -> Result<SpConfig, SamlError> {
    SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
        .slo_endpoint(SloEndpoint::post("https://sp.example.com/slo")?)
        .validation(SpValidationPolicy::compatibility())
        .build()
}

fn typed_idp_config() -> Result<IdpConfig, SamlError> {
    IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
        .sso_endpoint(SsoEndpoint::post("https://idp.example.com/sso")?)
        .slo_endpoint(SloEndpoint::post("https://idp.example.com/slo")?)
        .validation(IdpValidationPolicy::compatibility())
        .build()
}

fn typed_protocol_facades() -> Result<
    (
        Saml<saml_rs::Sp>,
        Saml<saml_rs::Idp>,
        SpDescriptor,
        IdpDescriptor,
    ),
    SamlError,
> {
    let sp = Saml::sp(typed_sp_config()?)?;
    let idp = Saml::idp(typed_idp_config()?)?;
    let sp_descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new("https://sp.example.com/metadata")?,
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new("https://idp.example.com/metadata")?,
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    Ok((sp, idp, sp_descriptor, idp_descriptor))
}

fn typed_validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility)
}

#[test]
fn unsigned_metadata_parsing_and_xml_extraction_still_work(
) -> Result<(), Box<dyn std::error::Error>> {
    let metadata_xml = idp(false)?.metadata_xml().to_string();
    let metadata = IdpMetadata::from_xml(&metadata_xml)?;
    assert_eq!(
        metadata.get_entity_id(),
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
    let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new("https://idp.example.com/metadata")?,
        &idp_metadata_xml,
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    assert_eq!(
        idp_descriptor.entity_id().as_str(),
        "https://idp.example.com/metadata"
    );

    let sp_metadata_xml = sp(false)?.metadata_xml().to_string();
    let sp_descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new("https://sp.example.com/metadata")?,
        &sp_metadata_xml,
        MetadataTrustPolicy::UnsignedForCompatibility,
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

    assert_unsupported(IdpDescriptor::from_metadata_xml_for(
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
    let sp_config = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
        .validation(SpValidationPolicy::compatibility())
        .build()?;
    let idp_config = IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
        .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso")?)
        .validation(IdpValidationPolicy::compatibility())
        .build()?;

    assert_eq!(
        sp_config.entity_id.as_str(),
        "https://sp.example.com/metadata"
    );
    assert_eq!(
        idp_config.entity_id.as_str(),
        "https://idp.example.com/metadata"
    );
    assert_eq!(sp_config.validation, SpValidationPolicy::compatibility());
    assert_eq!(idp_config.validation, IdpValidationPolicy::compatibility());
    Ok(())
}

#[test]
fn typed_facade_creates_and_receives_unsigned_protocol_sso_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp, sp_descriptor, idp_descriptor) = typed_protocol_facades()?;
    let relay_state = RelayStateParam::try_from_option(Some("protocol-only".to_string()))?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post().relay_state(relay_state))?;

    let form = started.outbound.post_form()?;
    assert_eq!(form.action().as_str(), "https://idp.example.com/sso");
    assert!(form.value("SAMLRequest").is_some());
    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(form.fields().to_vec()),
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
        SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
            .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
            .build(),
    );
    assert_unsupported(
        IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
            .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso")?)
            .build(),
    );
    Ok(())
}

#[test]
fn sp_required_assertion_signatures_return_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut validation = SpValidationPolicy::compatibility();
    validation.assertions = AssertionSignaturePolicy::RequireSigned;

    assert_unsupported(sp_config_builder()?.validation(validation).build());
    Ok(())
}

#[test]
fn sp_required_response_signatures_return_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut validation = SpValidationPolicy::compatibility();
    validation.responses = ResponseSignaturePolicy::RequireSigned;

    assert_unsupported(sp_config_builder()?.validation(validation).build());
    Ok(())
}

#[test]
fn sp_signed_authn_requests_return_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut validation = SpValidationPolicy::compatibility();
    validation.authn_requests = AuthnRequestSigningPolicy::Sign;

    assert_unsupported(sp_config_builder()?.validation(validation).build());
    Ok(())
}

#[test]
fn sp_signed_logout_policy_returns_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut validation = SpValidationPolicy::compatibility();
    validation.logout.requests = LogoutSignaturePolicy::RequireSigned;

    assert_unsupported(sp_config_builder()?.validation(validation).build());
    Ok(())
}

#[test]
fn sp_encrypted_assertions_return_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = XmlPolicy {
        encryption: XmlEncryptionPolicy::encrypt_assertions(),
        ..XmlPolicy::default()
    };

    assert_unsupported(sp_config_builder()?.xml(xml).build());
    Ok(())
}

#[test]
fn idp_required_authn_request_signatures_return_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut validation = IdpValidationPolicy::compatibility();
    validation.authn_requests = AuthnRequestValidationPolicy::RequireSigned;

    assert_unsupported(idp_config_builder()?.validation(validation).build());
    Ok(())
}

#[test]
fn idp_signed_logout_policy_returns_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut validation = IdpValidationPolicy::compatibility();
    validation.logout.responses = LogoutSignaturePolicy::RequireSigned;

    assert_unsupported(idp_config_builder()?.validation(validation).build());
    Ok(())
}

#[test]
fn idp_encrypted_assertions_return_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = XmlPolicy {
        encryption: XmlEncryptionPolicy::encrypt_assertions(),
        ..XmlPolicy::default()
    };

    assert_unsupported(idp_config_builder()?.xml(xml).build());
    Ok(())
}

#[test]
fn typed_facade_crypto_required_paths_return_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, _idp, _sp_descriptor, idp_descriptor) = typed_protocol_facades()?;

    assert_unsupported(sp.start_slo(
        &idp_descriptor,
        LogoutSubject::from_name_id(NameId::new("alice@example.com", None)),
        StartSlo::post().signing(LogoutSigning::Sign),
    ));
    Ok(())
}

#[test]
fn unsigned_login_request_creation_still_works() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = sp(false)?.create_login_request(&idp(false)?, Binding::Post, None)?;
    let xml = String::from_utf8(base64_decode(&ctx.context)?)?;
    assert!(xml.contains("<samlp:AuthnRequest"));
    assert!(ctx.signature.is_none());
    Ok(())
}

#[test]
fn unsigned_login_request_redirect_decoding_still_works() -> Result<(), Box<dyn std::error::Error>>
{
    let ctx = sp(false)?.create_login_request(&idp(false)?, Binding::Redirect, None)?;
    let url = url::Url::parse(&ctx.context)?;
    let (_, encoded) = url
        .query_pairs()
        .find(|(key, _)| key == "SAMLRequest")
        .ok_or("missing SAMLRequest")?;
    let xml = String::from_utf8(deflate_raw_decode(&base64_decode(encoded.as_ref())?)?)?;
    assert!(xml.contains("AssertionConsumerServiceURL=\"https://sp.example.com/acs\""));
    Ok(())
}

#[test]
fn signing_login_request_returns_unsupported() -> Result<(), Box<dyn std::error::Error>> {
    assert_unsupported(sp(true)?.create_login_request(&idp(true)?, Binding::Post, None));
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
        base64_encode(
            br#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_encrypted_response" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com/metadata</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/></samlp:Response>"#,
        ),
    )]);
    let mut options = FlowOptions::default();
    options.binding = Some(Binding::Post);
    options.parser_type = Some(ParserType::SamlResponse);
    options.check_signature = true;
    options.decrypt_key = Some("private key is unavailable without crypto feature");

    assert_unsupported(flow(&options, &request));
}

#[test]
fn signed_logout_request_returns_unsupported() -> Result<(), Box<dyn std::error::Error>> {
    assert_unsupported(create_logout_request(
        &EntitySetting::default(),
        &sp(false)?.metadata,
        &idp(false)?.metadata,
        Binding::Post,
        &User::new("user@example.com"),
        None,
        true,
    ));
    Ok(())
}

#[test]
fn signed_logout_response_returns_unsupported() -> Result<(), Box<dyn std::error::Error>> {
    assert_unsupported(create_logout_response(
        &EntitySetting::default(),
        &idp(false)?.metadata,
        &sp(false)?.metadata,
        Binding::Post,
        Some("_logout_request"),
        None,
        true,
    ));
    Ok(())
}
