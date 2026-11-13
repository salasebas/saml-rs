//! HTTP-POST-SimpleSign messages are decoded under the configured XML limits.
#![cfg(crypto)]

mod common;

use common::signing_credentials;

use std::time::SystemTime;

use saml_rs::binding::{base64_decode, base64_encode};
use saml_rs::crypto::{construct_message_signature, keys::load_private_key};
use saml_rs::xml::{dom::DEFAULT_XML_MAX_BYTES, XmlLimits};
use saml_rs::{
    AcsEndpoint, AssertionSignaturePolicy, AudienceValidationPolicy, AuthnRequest,
    AuthnRequestSigningPolicy, AuthnRequestValidationPolicy, BrowserInput, EntityId, FormField,
    IdpConfig, IdpDescriptor, IdpValidationPolicy, LogoutRequest, LogoutSubject,
    MetadataTrustPolicy, NameId, ReplayPolicy, RespondSso, Saml, SamlError, SamlValidationContext,
    SessionIndex, SloEndpoint, SpConfig, SpDescriptor, SpValidationPolicy, SsoEndpoint,
    SsoResponse, SsoResponseBinding, StartSlo, StartSso, Subject, XmlPolicy,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const PRIVKEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");

const CONFIGURED_MAX_BYTES: usize = 2 * 1024 * 1024;
const PADDING_ABOVE_DEFAULT_LIMIT: usize = DEFAULT_XML_MAX_BYTES + 1;
const PADDING_ABOVE_CONFIGURED_LIMIT: usize = CONFIGURED_MAX_BYTES + 1;

struct Parties {
    sp: Saml<saml_rs::Sp>,
    idp: Saml<saml_rs::Idp>,
    sp_descriptor: SpDescriptor,
    idp_descriptor: IdpDescriptor,
}

fn raised_xml_policy() -> XmlPolicy {
    XmlPolicy {
        limits: XmlLimits {
            max_bytes: CONFIGURED_MAX_BYTES,
            max_text_bytes: CONFIGURED_MAX_BYTES,
            ..XmlLimits::default()
        },
        ..XmlPolicy::default()
    }
}

fn parties() -> TestResult<Parties> {
    let sp = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::simple_sign(
                "https://sp.example.com/acs/simple",
            )?)
            .slo_endpoint(SloEndpoint::simple_sign(
                "https://sp.example.com/slo/simple",
            )?)
            .credentials(signing_credentials())
            .validation(SpValidationPolicy {
                assertions: AssertionSignaturePolicy::RequireSigned,
                authn_requests: AuthnRequestSigningPolicy::Sign,
                audience: AudienceValidationPolicy::Validate,
                ..SpValidationPolicy::recommended()
            })
            .xml(raised_xml_policy())
            .build()?,
    )?;
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::simple_sign(
                "https://idp.example.com/sso/simple",
            )?)
            .slo_endpoint(SloEndpoint::simple_sign(
                "https://idp.example.com/slo/simple",
            )?)
            .credentials(signing_credentials())
            .validation(IdpValidationPolicy {
                authn_requests: AuthnRequestValidationPolicy::RequireSigned,
                ..IdpValidationPolicy::recommended()
            })
            .xml(raised_xml_policy())
            .build()?,
    )?;
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

fn field<'a>(fields: &'a [FormField], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|field| field.name() == name)
        .map(FormField::value)
}

/// Pads the message with whitespace before its closing root tag and signs
/// the SimpleSign octet string again.
fn padded(fields: &[FormField], message: &str, padding: usize) -> TestResult<Vec<FormField>> {
    let encoded = field(fields, message).ok_or("missing SimpleSign message field")?;
    let mut xml = String::from_utf8(base64_decode(encoded)?)?;
    let closing_tag = xml.rfind("</").ok_or("message has no closing root tag")?;
    xml.insert_str(closing_tag, &" ".repeat(padding));

    let sig_alg = field(fields, "SigAlg").ok_or("missing SigAlg")?;
    let relay_state = field(fields, "RelayState");
    let octet = match relay_state {
        Some(relay_state) => format!("{message}={xml}&RelayState={relay_state}&SigAlg={sig_alg}"),
        None => format!("{message}={xml}&SigAlg={sig_alg}"),
    };
    let key = load_private_key(PRIVKEY, None)?;
    let signature = construct_message_signature(&octet, &key, sig_alg)?;

    let mut padded = vec![
        FormField::new(message, base64_encode(xml.as_bytes())),
        FormField::new("SigAlg", sig_alg),
        FormField::new("Signature", signature),
    ];
    if let Some(relay_state) = relay_state {
        padded.push(FormField::new("RelayState", relay_state));
    }
    Ok(padded)
}

fn receive_padded_authn_request(padding: usize) -> TestResult<Result<(), SamlError>> {
    let parties = parties()?;
    let started = parties.sp.start_sso(
        &parties.idp_descriptor,
        StartSso::simple_sign().response_binding(SsoResponseBinding::SimpleSign),
    )?;
    let fields = padded(
        started.outbound.post_form()?.fields(),
        "SAMLRequest",
        padding,
    )?;
    Ok(parties
        .idp
        .receive_sso(
            &parties.sp_descriptor,
            BrowserInput::<AuthnRequest>::simple_sign(fields),
            validation(),
        )
        .map(drop))
}

fn finish_padded_sso_response(padding: usize) -> TestResult<Result<(), SamlError>> {
    let parties = parties()?;
    let started = parties.sp.start_sso(
        &parties.idp_descriptor,
        StartSso::simple_sign().response_binding(SsoResponseBinding::SimpleSign),
    )?;
    let received = parties.idp.receive_sso(
        &parties.sp_descriptor,
        BrowserInput::<AuthnRequest>::simple_sign(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let response = parties.idp.respond_sso(
        &parties.sp_descriptor,
        &received,
        Subject::new(NameId::new("alice@example.com", None), Vec::new()),
        RespondSso::simple_sign(),
    )?;
    let fields = padded(response.post_form()?.fields(), "SAMLResponse", padding)?;
    Ok(parties
        .sp
        .finish_sso(
            &parties.idp_descriptor,
            &started.pending,
            BrowserInput::<SsoResponse>::simple_sign(fields),
            validation(),
        )
        .map(drop))
}

fn receive_padded_logout_request(padding: usize) -> TestResult<Result<(), SamlError>> {
    let parties = parties()?;
    let started = parties.sp.start_slo(
        &parties.idp_descriptor,
        LogoutSubject::with_session_index(
            NameId::new("alice@example.com", None),
            SessionIndex::try_new("_session123")?,
        ),
        StartSlo::simple_sign(),
    )?;
    let fields = padded(
        started.outbound.post_form()?.fields(),
        "SAMLRequest",
        padding,
    )?;
    Ok(parties
        .idp
        .receive_slo(
            &parties.sp_descriptor,
            BrowserInput::<LogoutRequest>::simple_sign(fields),
            validation(),
        )
        .map(drop))
}

fn is_base64_output_limit(result: &Result<(), SamlError>) -> bool {
    matches!(result, Err(SamlError::Invalid(reason)) if reason == "ERR_BASE64_OUTPUT_LIMIT_EXCEEDED")
}

#[test]
fn simplesign_authn_request_is_decoded_under_the_configured_limit() -> TestResult {
    receive_padded_authn_request(PADDING_ABOVE_DEFAULT_LIMIT)??;
    let over_limit = receive_padded_authn_request(PADDING_ABOVE_CONFIGURED_LIMIT)?;
    assert!(is_base64_output_limit(&over_limit), "{over_limit:?}");
    Ok(())
}

#[test]
fn simplesign_sso_response_is_decoded_under_the_configured_limit() -> TestResult {
    finish_padded_sso_response(PADDING_ABOVE_DEFAULT_LIMIT)??;
    let over_limit = finish_padded_sso_response(PADDING_ABOVE_CONFIGURED_LIMIT)?;
    assert!(is_base64_output_limit(&over_limit), "{over_limit:?}");
    Ok(())
}

#[test]
fn simplesign_logout_request_is_decoded_under_the_configured_limit() -> TestResult {
    receive_padded_logout_request(PADDING_ABOVE_DEFAULT_LIMIT)??;
    let over_limit = receive_padded_logout_request(PADDING_ABOVE_CONFIGURED_LIMIT)?;
    assert!(is_base64_output_limit(&over_limit), "{over_limit:?}");
    Ok(())
}
