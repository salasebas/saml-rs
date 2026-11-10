#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use saml_rs::binding::{base64_decode, base64_encode};
use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::constants::{status_code, Binding, ParserType};
use saml_rs::entity::{iso8601_offset, EntitySetting, User};
use saml_rs::error::{SignatureVerificationReason, TimeWindowField};
use saml_rs::flow::HttpRequest;
use saml_rs::idp::LoginResponseOptions;
use saml_rs::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
use saml_rs::template::{replace_tags_by_value, LOGIN_RESPONSE_TEMPLATE};
use saml_rs::validator::check_status;
use saml_rs::{IdentityProvider, SamlError, ServiceProvider};

const PRIVKEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const FAILED: &str = include_str!("fixtures/misc/failed_response.xml");

#[derive(Debug, Clone)]
struct ResponseShape {
    issuer: String,
    destination: String,
    audience: String,
    response_in_response_to: String,
    subject_in_response_to: String,
    subject_confirmation_not_on_or_after: String,
    conditions_not_before: String,
    conditions_not_on_or_after: String,
    additional_conditions: String,
    authn_statement: String,
}

impl Default for ResponseShape {
    fn default() -> Self {
        let now = iso8601_offset(-60);
        let later = iso8601_offset(300);
        Self {
            issuer: "https://idp.example.com/metadata".into(),
            destination: "https://sp.example.com/acs".into(),
            audience: "https://sp.example.com/metadata".into(),
            response_in_response_to: "_request123".into(),
            subject_in_response_to: "_request123".into(),
            subject_confirmation_not_on_or_after: later.clone(),
            conditions_not_before: now,
            conditions_not_on_or_after: later,
            additional_conditions: String::new(),
            authn_statement: String::new(),
        }
    }
}

fn signing() -> EntitySetting {
    let mut setting = EntitySetting::default();
    setting.private_key = Some(PRIVKEY.into());
    setting.signing_cert = Some(CERT.into());
    setting.request_signature_algorithm = RSA_SHA256.into();
    setting
}

fn idp() -> Result<IdentityProvider, SamlError> {
    IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec![CERT.into()],
            single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
            ..Default::default()
        },
        signing(),
    )
}

fn sp() -> Result<ServiceProvider, SamlError> {
    ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            want_assertions_signed: true,
            signing_certs: vec![CERT.into()],
            assertion_consumer_service: vec![Endpoint::new(
                Binding::Post,
                "https://sp.example.com/acs",
            )],
            ..Default::default()
        },
        signing(),
    )
}

fn unsigned_response_template() -> String {
    LOGIN_RESPONSE_TEMPLATE.replacen("{AttributeStatement}", "", 1)
}

fn response_xml(template: &str, shape: &ResponseShape) -> String {
    let id = "_response_taxonomy".to_string();
    let issue_instant = iso8601_offset(-60);
    let prepared = template.replacen(
        "Recipient=\"{SubjectRecipient}\" InResponseTo=\"{InResponseTo}\"",
        "Recipient=\"{SubjectRecipient}\" InResponseTo=\"{SubjectInResponseTo}\"",
        1,
    );
    let prepared = prepared.replacen(
        "{AuthnStatement}",
        &format!("{}{}", shape.additional_conditions, shape.authn_statement),
        1,
    );
    replace_tags_by_value(
        &prepared,
        &[
            ("ID", id),
            ("AssertionID", "_assertion_taxonomy".into()),
            ("Destination", shape.destination.clone()),
            ("SubjectRecipient", "https://sp.example.com/acs".into()),
            (
                "AssertionConsumerServiceURL",
                "https://sp.example.com/acs".into(),
            ),
            ("Audience", shape.audience.clone()),
            ("Issuer", shape.issuer.clone()),
            ("IssueInstant", issue_instant),
            ("StatusCode", status_code::SUCCESS.into()),
            ("ConditionsNotBefore", shape.conditions_not_before.clone()),
            (
                "ConditionsNotOnOrAfter",
                shape.conditions_not_on_or_after.clone(),
            ),
            (
                "SubjectConfirmationDataNotOnOrAfter",
                shape.subject_confirmation_not_on_or_after.clone(),
            ),
            (
                "NameIDFormat",
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".into(),
            ),
            ("NameID", "user@example.com".into()),
            ("InResponseTo", shape.response_in_response_to.clone()),
            ("SubjectInResponseTo", shape.subject_in_response_to.clone()),
        ],
    )
}

fn signed_response(shape: &ResponseShape) -> Result<String, SamlError> {
    let idp = idp()?;
    let sp = sp()?;
    let custom = |template: &str| {
        let id = "_response_taxonomy".to_string();
        (id, response_xml(template, shape))
    };
    Ok(idp
        .create_login_response(
            &sp,
            Binding::Post,
            &User::new("user@example.com"),
            &LoginResponseOptions {
                in_response_to: Some(shape.response_in_response_to.as_str()),
                custom: Some(&custom),
                ..Default::default()
            },
        )?
        .context)
}

fn parse_response(response: String, request_id: &str) -> Result<(), SamlError> {
    let sp = sp()?;
    let idp = idp()?;
    let request = HttpRequest::post(vec![("SAMLResponse".into(), response)]);
    sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, request_id)?;
    Ok(())
}

fn parse_raw_response(response: String, request_id: &str) -> Result<(), SamlError> {
    let sp = sp()?;
    let idp = idp()?;
    let request = HttpRequest::post(vec![(
        "SAMLResponse".into(),
        base64_encode(response.as_bytes()),
    )]);
    sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, request_id)?;
    Ok(())
}

#[test]
fn error_taxonomy_bad_issuer_returns_issuer_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let response = signed_response(&ResponseShape {
        issuer: "https://attacker.example.com/metadata".into(),
        ..Default::default()
    })?;

    match parse_response(response, "_request123") {
        Err(SamlError::IssuerMismatch { expected, actual }) => {
            assert_eq!(expected, "https://idp.example.com/metadata");
            assert_eq!(
                actual.as_deref(),
                Some("https://attacker.example.com/metadata")
            );
            Ok(())
        }
        other => Err(format!("expected IssuerMismatch, got {other:?}").into()),
    }
}

#[test]
fn error_taxonomy_bad_destination_returns_destination_mismatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let response = signed_response(&ResponseShape {
        destination: "https://evil.example.com/acs".into(),
        ..Default::default()
    })?;

    match parse_response(response, "_request123") {
        Err(SamlError::DestinationMismatch { expected, actual }) => {
            assert_eq!(expected, "https://sp.example.com/acs");
            assert_eq!(actual.as_deref(), Some("https://evil.example.com/acs"));
            Ok(())
        }
        other => Err(format!("expected DestinationMismatch, got {other:?}").into()),
    }
}

#[test]
fn error_taxonomy_bad_audience_returns_audience_mismatch() -> Result<(), Box<dyn std::error::Error>>
{
    let response = signed_response(&ResponseShape {
        audience: "https://evil.example.com/metadata".into(),
        ..Default::default()
    })?;

    match parse_response(response, "_request123") {
        Err(SamlError::AudienceMismatch { expected }) => {
            assert_eq!(expected, "https://sp.example.com/metadata");
            Ok(())
        }
        other => Err(format!("expected AudienceMismatch, got {other:?}").into()),
    }
}

#[test]
fn error_taxonomy_bad_in_response_to_returns_in_response_to_mismatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let response = signed_response(&ResponseShape::default())?;

    match parse_response(response, "_different") {
        Err(SamlError::InResponseToMismatch { expected, actual }) => {
            assert_eq!(expected.as_deref(), Some("_different"));
            assert_eq!(actual.as_deref(), Some("_request123"));
            Ok(())
        }
        other => Err(format!("expected InResponseToMismatch, got {other:?}").into()),
    }
}

#[test]
fn error_taxonomy_unsigned_post_response_returns_signature_missing(
) -> Result<(), Box<dyn std::error::Error>> {
    let response = response_xml(&unsigned_response_template(), &ResponseShape::default());

    match parse_raw_response(response, "_request123") {
        Err(SamlError::SignatureMissing) => Ok(()),
        other => Err(format!("expected SignatureMissing, got {other:?}").into()),
    }
}

#[test]
fn error_taxonomy_invalid_xml_signature_returns_xml_signature_reason(
) -> Result<(), Box<dyn std::error::Error>> {
    let response = signed_response(&ResponseShape::default())?;
    let xml = String::from_utf8(base64_decode(&response)?)?.replacen(
        "user@example.com",
        "evil@example.com",
        1,
    );
    let response = base64_encode(xml.as_bytes());

    match parse_response(response, "_request123") {
        Err(SamlError::SignatureVerification {
            reason: SignatureVerificationReason::XmlSignature,
        }) => Ok(()),
        other => Err(format!("expected XML signature verification failure, got {other:?}").into()),
    }
}

#[test]
fn error_taxonomy_expired_session_returns_session_not_on_or_after_time_window(
) -> Result<(), Box<dyn std::error::Error>> {
    let now = iso8601_offset(-60);
    let expired = iso8601_offset(-300);
    let response = signed_response(&ResponseShape {
        authn_statement: format!(
            "<saml:AuthnStatement AuthnInstant=\"{now}\" SessionNotOnOrAfter=\"{expired}\" SessionIndex=\"_expired\"/>"
        ),
        ..Default::default()
    })?;

    match parse_response(response, "_request123") {
        Err(SamlError::TimeWindowInvalid {
            field: TimeWindowField::SessionNotOnOrAfter,
        }) => Ok(()),
        other => {
            Err(format!("expected SessionNotOnOrAfter time window failure, got {other:?}").into())
        }
    }
}

#[test]
fn error_taxonomy_repeated_session_uses_earliest_expiration(
) -> Result<(), Box<dyn std::error::Error>> {
    let now = iso8601_offset(-60);
    let expired = iso8601_offset(-300);
    let future = iso8601_offset(300);
    let response = signed_response(&ResponseShape {
        authn_statement: format!(
            "<saml:AuthnStatement AuthnInstant=\"{now}\" SessionNotOnOrAfter=\"{future}\" SessionIndex=\"_future\"/><saml:AuthnStatement AuthnInstant=\"{now}\" SessionNotOnOrAfter=\"{expired}\" SessionIndex=\"_expired\"/>"
        ),
        ..Default::default()
    })?;

    match parse_response(response, "_request123") {
        Err(SamlError::TimeWindowInvalid {
            field: TimeWindowField::SessionNotOnOrAfter,
        }) => Ok(()),
        other => Err(format!(
            "expected earliest repeated SessionNotOnOrAfter to fail, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn error_taxonomy_repeated_future_sessions_are_accepted() -> Result<(), Box<dyn std::error::Error>>
{
    let now = iso8601_offset(-60);
    let first_future = iso8601_offset(300);
    let second_future = iso8601_offset(600);
    let response = signed_response(&ResponseShape {
        authn_statement: format!(
            "<saml:AuthnStatement AuthnInstant=\"{now}\" SessionNotOnOrAfter=\"{first_future}\" SessionIndex=\"_first\"/><saml:AuthnStatement AuthnInstant=\"{now}\" SessionNotOnOrAfter=\"{second_future}\" SessionIndex=\"_second\"/>"
        ),
        ..Default::default()
    })?;

    parse_response(response, "_request123")?;
    Ok(())
}

#[test]
fn error_taxonomy_repeated_session_malformed_expiration_fails_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let now = iso8601_offset(-60);
    let future = iso8601_offset(300);
    let response = signed_response(&ResponseShape {
        authn_statement: format!(
            "<saml:AuthnStatement AuthnInstant=\"{now}\" SessionNotOnOrAfter=\"{future}\" SessionIndex=\"_valid\"/><saml:AuthnStatement AuthnInstant=\"{now}\" SessionNotOnOrAfter=\"not-a-time\" SessionIndex=\"_malformed\"/>"
        ),
        ..Default::default()
    })?;

    match parse_response(response, "_request123") {
        Err(SamlError::TimeWindowInvalid {
            field: TimeWindowField::SessionNotOnOrAfter,
        }) => Ok(()),
        other => Err(format!(
            "expected malformed repeated SessionNotOnOrAfter to fail, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn error_taxonomy_expired_conditions_return_conditions_time_window(
) -> Result<(), Box<dyn std::error::Error>> {
    let response = signed_response(&ResponseShape {
        conditions_not_on_or_after: iso8601_offset(-300),
        ..Default::default()
    })?;

    match parse_response(response, "_request123") {
        Err(SamlError::TimeWindowInvalid {
            field: TimeWindowField::Conditions,
        }) => Ok(()),
        other => Err(format!("expected Conditions time window failure, got {other:?}").into()),
    }
}

#[test]
fn error_taxonomy_signed_repeated_conditions_are_rejected() -> Result<(), Box<dyn std::error::Error>>
{
    let response = signed_response(&ResponseShape {
        additional_conditions: format!(
            "<saml:Conditions NotOnOrAfter=\"{}\"/>",
            iso8601_offset(-300)
        ),
        ..Default::default()
    })?;

    match parse_response(response, "_request123") {
        Err(SamlError::Invalid(message)) if message.contains("Conditions") => Ok(()),
        other => Err(format!("expected repeated Conditions rejection, got {other:?}").into()),
    }
}

#[test]
fn error_taxonomy_non_success_status_returns_status_not_success(
) -> Result<(), Box<dyn std::error::Error>> {
    match check_status(FAILED, ParserType::SamlResponse) {
        Err(SamlError::StatusNotSuccess { top, second }) => {
            assert_eq!(top, status_code::REQUESTER);
            assert_eq!(second.as_deref(), Some(status_code::INVALID_NAME_ID_POLICY));
            Ok(())
        }
        other => Err(format!("expected StatusNotSuccess, got {other:?}").into()),
    }
}
