//! Historical regression cases derived from npm `samlify` flow tests.
//!
//! Upstream uses IdP/SP private keys whose PEM format `bergshamra` cannot
//! auto-detect, so entities are built from config with the project's working
//! RSA keypair. Redirect/SimpleSign responses are parsed by reconstructing the
//! signed octet string the way the bindings produce it.
#![cfg(crypto)]
#![allow(clippy::unwrap_used)]

use crate::tests::template::fill_template;
use crate::tests::template::LoginResponseAttribute;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::binding::{deflate_raw_decode, deflate_raw_encode, MAX_DEFLATE_RAW_DECODE_BYTES};
use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::constants::Binding;
use saml_rs::entity::{iso8601_offset, BindingContext, EntitySetting, User};
use saml_rs::error::SignatureVerificationReason;
use saml_rs::flow::{FlowResult, HttpRequest};
use saml_rs::idp;
use saml_rs::idp::LoginResponseOptions;
use saml_rs::metadata::{Endpoint, IdpMetadataInput, SpMetadataInput};
use saml_rs::sp;
use saml_rs::sp::LoginRequestOptions;
use saml_rs::tests::engine::redirect_query;
use saml_rs::tests::engine::LogoutUser;
use saml_rs::tests::engine::{
    create_logout_request, create_logout_response, parse_logout_request, parse_logout_response,
};
use saml_rs::tests::engine::{IdpMessages, SpMessages};
use saml_rs::RelayState;
use saml_rs::{Inbound, Outbound, SamlError, SsoResponse, XmlLimits};

const PRIVKEY: &str = include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const FAILED: &str = include_str!("../../tests/fixtures/misc/failed_response.xml");

fn signing() -> EntitySetting {
    EntitySetting {
        private_key: Some(PRIVKEY.into()),
        signing_cert: Some(CERT.into()),
        request_signature_algorithm: RSA_SHA256.into(),
        ..EntitySetting::default()
    }
}

fn idp_config(want_authn_signed: bool) -> IdpMetadataInput {
    IdpMetadataInput {
        entity_id: "https://idp.example.com/metadata".into(),
        signing_certs: vec![CERT.into()],
        want_authn_requests_signed: want_authn_signed,
        single_sign_on_service: vec![
            Endpoint::new(Binding::Post, "https://idp/sso"),
            Endpoint::new(Binding::Redirect, "https://idp/sso"),
            Endpoint::new(Binding::SimpleSign, "https://idp/sso"),
        ],
        single_logout_service: vec![
            Endpoint::new(Binding::Post, "https://idp/slo"),
            Endpoint::new(Binding::Redirect, "https://idp/slo"),
            Endpoint::new(Binding::SimpleSign, "https://idp/slo"),
        ],
        ..IdpMetadataInput::default()
    }
}

fn sp_config(authn_signed: bool, want_assertions_signed: bool, enc: bool) -> SpMetadataInput {
    SpMetadataInput {
        entity_id: "https://sp.example.com/metadata".into(),
        authn_requests_signed: authn_signed,
        want_assertions_signed,
        signing_certs: vec![CERT.into()],
        encrypt_certs: if enc { vec![CERT.into()] } else { Vec::new() },
        single_logout_service: vec![
            Endpoint::new(Binding::Post, "https://sp/slo"),
            Endpoint::new(Binding::Redirect, "https://sp/slo"),
            Endpoint::new(Binding::SimpleSign, "https://sp/slo"),
        ],
        assertion_consumer_service: vec![
            Endpoint::new(Binding::Post, "https://sp/acs"),
            Endpoint::new(Binding::Redirect, "https://sp/acs"),
            Endpoint::new(Binding::SimpleSign, "https://sp/acs"),
        ],
        ..SpMetadataInput::default()
    }
}

fn idp(want_authn_signed: bool) -> idp::Engine {
    idp::Engine::from_config(&idp_config(want_authn_signed), signing()).unwrap()
}

fn sp(want_assertions_signed: bool, enc: bool) -> sp::Engine {
    let mut setting = signing();
    if enc {
        setting.is_assertion_encrypted = true;
        setting.enc_private_key = Some(PRIVKEY.into());
    }
    sp::Engine::from_config(&sp_config(false, want_assertions_signed, enc), setting).unwrap()
}

fn unsigned_idp() -> idp::Engine {
    idp::Engine::from_config(&idp_config(false), EntitySetting::default()).unwrap()
}

fn unsigned_sp() -> sp::Engine {
    sp::Engine::from_config(&sp_config(false, false, false), EntitySetting::default()).unwrap()
}

/// Rebuild the SP-side HTTP request for a response over `binding`.
fn response_request(binding: Binding, ctx: &BindingContext) -> Result<HttpRequest, SamlError> {
    Ok(match binding {
        Binding::Post => HttpRequest::post(vec![("SAMLResponse".into(), ctx.context.clone())]),
        Binding::Redirect => redirect_request(&ctx.context)?,
        Binding::SimpleSign => simplesign_request("SAMLResponse", ctx)?,
        binding => {
            return Err(SamlError::Invalid(format!(
                "test helper has no {binding:?} case"
            )))
        }
    })
}

fn parse_response_with_request_id(
    sp: &sp::Engine,
    idp: &idp::Engine,
    binding: Binding,
    ctx: &BindingContext,
    request_id: &str,
) -> Result<FlowResult, SamlError> {
    let request = response_request(binding, ctx)?;
    sp.parse_login_response_with_request_id(idp, binding, &request, request_id)
}

fn redirect_request(url: &str) -> Result<HttpRequest, SamlError> {
    let parsed = url::Url::parse(url).map_err(|e| SamlError::Invalid(e.to_string()))?;
    let raw = parsed.query().unwrap_or("");
    let octet = raw.split("&Signature=").next().unwrap_or("").to_string();
    let query = parsed
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    Ok(HttpRequest {
        query,
        octet_string: Some(octet),
        ..Default::default()
    })
}

fn simplesign_request(param: &str, ctx: &BindingContext) -> Result<HttpRequest, SamlError> {
    let decoded = STANDARD
        .decode(&ctx.context)
        .map_err(|e| SamlError::Invalid(e.to_string()))?;
    let raw_xml = String::from_utf8(decoded).map_err(|e| SamlError::Invalid(e.to_string()))?;
    let sig_alg = ctx.sig_alg.clone().unwrap_or_default();
    let octet = match ctx.relay_state.as_deref() {
        Some(relay_state) => format!("{param}={raw_xml}&RelayState={relay_state}&SigAlg={sig_alg}"),
        None => format!("{param}={raw_xml}&SigAlg={sig_alg}"),
    };
    let mut body = vec![(param.to_string(), ctx.context.clone())];
    if let Some(relay_state) = &ctx.relay_state {
        body.push(("RelayState".into(), relay_state.clone()));
    }
    body.push(("SigAlg".into(), sig_alg));
    body.push((
        "Signature".into(),
        ctx.signature.clone().unwrap_or_default(),
    ));
    Ok(HttpRequest {
        body,
        octet_string: Some(octet),
        ..Default::default()
    })
}

/// A `customTagReplacement` that renders our default template + attributes.
fn fill_response(template: &str, idp_id: &str, email: &str) -> Result<(String, String), SamlError> {
    let id = "_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6".to_string();
    let now = iso8601_offset(-60);
    let later = iso8601_offset(300);
    let attributes = crate::tests::template::build_attribute_statement(
        &[attr("mail", "user.email"), attr("name", "user.name")],
        crate::tests::template::ATTRIBUTE_TEMPLATE,
        crate::tests::template::ATTRIBUTE_STATEMENT_TEMPLATE,
    );
    let template = template.replacen("{AttributeStatement}", &attributes, 1);
    let xml = fill_template(
        &template,
        &[
            ("ID", id.clone()),
            ("AssertionID", "_assertion0123456789".into()),
            ("Destination", "https://sp/acs".into()),
            ("SubjectRecipient", "https://sp/acs".into()),
            ("AssertionConsumerServiceURL", "https://sp/acs".into()),
            ("Audience", "https://sp.example.com/metadata".into()),
            ("Issuer", idp_id.to_string()),
            ("IssueInstant", now.clone()),
            (
                "StatusCode",
                "urn:oasis:names:tc:SAML:2.0:status:Success".into(),
            ),
            ("ConditionsNotBefore", now),
            ("ConditionsNotOnOrAfter", later.clone()),
            ("SubjectConfirmationDataNotOnOrAfter", later),
            (
                "NameIDFormat",
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".into(),
            ),
            ("NameID", email.to_string()),
            ("InResponseTo", "_req".into()),
            ("AuthnStatement", String::new()),
            ("attrUserEmail", email.to_string()),
            ("attrUserName", "user name".into()),
        ],
    );
    Ok((id, xml))
}

fn custom_idp() -> Result<idp::Engine, SamlError> {
    idp::Engine::from_config(&idp_config(false), signing())
}

fn attr(name: &str, tag: &str) -> LoginResponseAttribute {
    LoginResponseAttribute {
        name: name.into(),
        value_tag: tag.into(),
        name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".into(),
        value_xsi_type: "xs:string".into(),
        value_xmlns_xs: None,
        value_xmlns_xsi: None,
    }
}

fn opts(in_response_to: &str) -> LoginResponseOptions<'_> {
    LoginResponseOptions {
        in_response_to: Some(in_response_to),
        ..Default::default()
    }
}

fn attacker_authn_request() -> &'static str {
    "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_attacker_req\" Version=\"2.0\" IssueInstant=\"2026-06-27T19:15:08Z\" Destination=\"https://idp/sso\" AssertionConsumerServiceURL=\"https://evil.example/acs\"><saml:Issuer>https://evil.example/metadata</saml:Issuer></samlp:AuthnRequest>"
}

fn assert_failed_message_signature(
    result: Result<saml_rs::flow::FlowResult, SamlError>,
) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Err(SamlError::SignatureVerification {
            reason: SignatureVerificationReason::BindingSignature,
            ..
        }) => Ok(()),
        other => {
            Err(format!("expected detached signature verification failure, got {other:?}").into())
        }
    }
}

// ----- create login request (1-3): default template round-trip -----

fn login_request_round_trip(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    let sp = unsigned_sp();
    let idp = unsigned_idp();
    let ctx = sp.create_login_request(&idp, binding, &LoginRequestOptions::default())?;
    let request = match binding {
        Binding::Redirect => redirect_request(&ctx.context)?,
        _ => HttpRequest::post(vec![("SAMLRequest".into(), ctx.context.clone())]),
    };
    let parsed = idp.parse_login_request(&sp, binding, &request)?;
    assert_eq!(parsed.extract.get_str("request.id"), Some(ctx.id.as_str()));
    Ok(())
}

#[test]
fn flow_conformance_login_request_redirect_default() -> Result<(), Box<dyn std::error::Error>> {
    login_request_round_trip(Binding::Redirect)
}
#[test]
fn flow_conformance_login_request_simplesign_default() -> Result<(), Box<dyn std::error::Error>> {
    login_request_round_trip(Binding::SimpleSign)
}
#[test]
fn flow_conformance_login_request_post_default() -> Result<(), Box<dyn std::error::Error>> {
    login_request_round_trip(Binding::Post)
}

// ----- AuthnRequest signing flags (4-6) -----

fn signing_sp_against_idp_without_requirement(
    binding: Binding,
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp::Engine::from_config(&sp_config(true, false, false), signing())?;
    let ctx = sp.create_login_request(&idp(false), binding, &LoginRequestOptions::default())?;
    let request = match binding {
        Binding::Post => HttpRequest::post(vec![("SAMLRequest".into(), ctx.context.clone())]),
        Binding::Redirect => redirect_request(&ctx.context)?,
        Binding::SimpleSign => simplesign_request("SAMLRequest", &ctx)?,
        _ => return Err("unsupported binding".into()),
    };
    let parsed = idp(true).parse_login_request(&sp, binding, &request)?;
    assert_eq!(parsed.extract.get_str("request.id"), Some(ctx.id.as_str()));
    Ok(())
}

#[test]
fn flow_conformance_signing_sp_without_idp_requirement_post(
) -> Result<(), Box<dyn std::error::Error>> {
    signing_sp_against_idp_without_requirement(Binding::Post)
}
#[test]
fn flow_conformance_signing_sp_without_idp_requirement_redirect(
) -> Result<(), Box<dyn std::error::Error>> {
    signing_sp_against_idp_without_requirement(Binding::Redirect)
}
#[test]
fn flow_conformance_signing_sp_without_idp_requirement_simplesign(
) -> Result<(), Box<dyn std::error::Error>> {
    signing_sp_against_idp_without_requirement(Binding::SimpleSign)
}
#[test]
fn flow_conformance_unsigned_sp_against_requiring_idp() -> Result<(), Box<dyn std::error::Error>> {
    match sp(false, false).create_login_request(
        &idp(true),
        Binding::Redirect,
        &LoginRequestOptions::default(),
    ) {
        Err(SamlError::AuthnRequestSigningRequired) => Ok(()),
        other => Err(format!("expected conflict, got {other:?}").into()),
    }
}

// ----- detached message signature binding -----

fn detached_signature_rejects_mismatched_login_request(
    binding: Binding,
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp::Engine::from_config(&sp_config(true, false, false), signing())?;
    let idp = idp(true);
    let ctx = sp.create_login_request(&idp, binding, &LoginRequestOptions::default())?;
    let mut request = match binding {
        Binding::Redirect => redirect_request(&ctx.context)?,
        Binding::SimpleSign => simplesign_request("SAMLRequest", &ctx)?,
        _ => return Err("unsupported binding for detached regression".into()),
    };

    let parsed = idp.parse_login_request(&sp, binding, &request)?;
    assert_eq!(parsed.extract.get_str("request.id"), Some(ctx.id.as_str()));

    match binding {
        Binding::Redirect => {
            let attacker =
                STANDARD.encode(&deflate_raw_encode(attacker_authn_request().as_bytes())?);
            let (_, saml_request) = request
                .query
                .iter_mut()
                .find(|(key, _)| key == "SAMLRequest")
                .ok_or("missing SAMLRequest")?;
            *saml_request = attacker;
        }
        Binding::SimpleSign => {
            let attacker = STANDARD.encode(attacker_authn_request().as_bytes());
            let (_, saml_request) = request
                .body
                .iter_mut()
                .find(|(key, _)| key == "SAMLRequest")
                .ok_or("missing SAMLRequest")?;
            *saml_request = attacker;
        }
        _ => return Err("unsupported binding for detached regression".into()),
    }

    assert_failed_message_signature(idp.parse_login_request(&sp, binding, &request))
}

#[test]
fn flow_conformance_redirect_signature_rejects_mismatched_consumed_request(
) -> Result<(), Box<dyn std::error::Error>> {
    detached_signature_rejects_mismatched_login_request(Binding::Redirect)
}

#[test]
fn flow_conformance_simplesign_signature_rejects_mismatched_consumed_request(
) -> Result<(), Box<dyn std::error::Error>> {
    detached_signature_rejects_mismatched_login_request(Binding::SimpleSign)
}

#[test]
fn flow_conformance_redirect_signature_rejects_mismatched_relay_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp::Engine::from_config(&sp_config(true, false, false), signing())?;
    let idp = idp(true);
    let ctx = sp.create_login_request(
        &idp,
        Binding::Redirect,
        &LoginRequestOptions {
            relay_state: Some("relay-expected"),
            ..Default::default()
        },
    )?;
    let mut request = redirect_request(&ctx.context)?;
    let relay_index = request
        .query
        .iter()
        .position(|(key, _)| key == "RelayState")
        .ok_or("missing RelayState")?;
    request.query[relay_index].1 = "x".repeat(saml_rs::MAX_RECEIVED_RELAY_STATE_BYTES + 1);
    let oversized = idp.parse_login_request(&sp, Binding::Redirect, &request);
    assert!(
        matches!(
            oversized,
            Err(SamlError::LimitExceeded {
                limit: saml_rs::ResourceLimit::RelayStateBytes,
                maximum: saml_rs::MAX_RECEIVED_RELAY_STATE_BYTES,
                ..
            })
        ),
        "{oversized:?}"
    );

    let received = "x".repeat(saml_rs::MAX_RELAY_STATE_BYTES + 1);
    request.query[relay_index].1.clone_from(&received);
    match idp.parse_login_request(&sp, Binding::Redirect, &request) {
        Err(SamlError::RelayStateMismatch {
            expected, actual, ..
        }) => {
            assert_eq!(
                expected.as_ref().map(RelayState::as_str),
                Some("relay-expected")
            );
            assert_eq!(
                actual.as_ref().map(RelayState::as_str),
                Some(received.as_str())
            );
            Ok(())
        }
        other => Err(format!("expected RelayStateMismatch, got {other:?}").into()),
    }
}

// ----- create login request signed with PKCS#8 keys (8,9) -----

fn signed_request_with_key(
    key: &str,
    pass: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let setting = EntitySetting {
        private_key: Some(key.into()),
        private_key_pass: pass.map(str::to_string),
        signing_cert: Some(CERT.into()),
        request_signature_algorithm: RSA_SHA256.into(),
        ..EntitySetting::default()
    };
    let sp = sp::Engine::from_config(&sp_config(true, false, false), setting)?;
    let idp = idp(true);
    let ctx = sp.create_login_request(&idp, Binding::Redirect, &LoginRequestOptions::default())?;
    assert!(ctx.context.contains("&Signature="));
    Ok(())
}

#[test]
fn flow_conformance_login_request_redirect_signed_unencrypted_pkcs8(
) -> Result<(), Box<dyn std::error::Error>> {
    signed_request_with_key(
        include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem"),
        None,
    )
}
#[test]
#[cfg(feature = "crypto-rustcrypto")]
fn flow_conformance_login_request_redirect_signed_encrypted_pkcs8(
) -> Result<(), Box<dyn std::error::Error>> {
    signed_request_with_key(
        include_str!("../../tests/fixtures/key/sp/privkey.encrypted.pkcs8.pem"),
        Some("VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px"),
    )
}

// ----- create login response (12-15) -----

#[test]
fn flow_conformance_login_response_undefined_binding() -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let sp = sp(true, false);
    match idp.create_login_response(&sp, Binding::Artifact, &User::new("a@e.com"), &opts("_r")) {
        Err(SamlError::UnsupportedBinding {
            binding: Binding::Artifact,
            ..
        }) => Ok(()),
        other => Err(format!("expected UnsupportedBinding(Artifact), got {other:?}").into()),
    }
}

fn create_login_response(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let sp = sp(true, false);
    let ctx = idp.create_login_response(&sp, binding, &User::new("a@e.com"), &opts("_r"))?;
    assert!(!ctx.context.is_empty());
    Ok(())
}

#[test]
fn flow_conformance_create_redirect_login_response() -> Result<(), Box<dyn std::error::Error>> {
    create_login_response(Binding::Redirect)
}
#[test]
fn flow_conformance_create_simplesign_login_response() -> Result<(), Box<dyn std::error::Error>> {
    create_login_response(Binding::SimpleSign)
}
#[test]
fn flow_conformance_create_post_login_response() -> Result<(), Box<dyn std::error::Error>> {
    create_login_response(Binding::Post)
}

#[test]
fn flow_conformance_simplesign_login_response_post_form_round_trips_to_parser(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let sp = sp(false, false);
    let ctx = idp.create_login_response(
        &sp,
        Binding::SimpleSign,
        &User::new("form@example.com"),
        &LoginResponseOptions {
            in_response_to: Some("_r"),
            relay_state: Some("relay-123"),
        },
    )?;

    let outbound = Outbound::<SsoResponse>::echoing_received_relay_state(ctx.clone())?;
    let request = Inbound::<SsoResponse>::simple_sign(outbound.post_form()?.fields().to_vec())
        .into_http_request(XmlLimits::default())?;

    assert_eq!(body_param(&request, "RelayState")?, "relay-123");
    assert_eq!(
        body_param(&request, "SigAlg")?,
        ctx.sig_alg.as_deref().ok_or("missing SigAlg")?
    );
    assert_eq!(
        body_param(&request, "Signature")?,
        ctx.signature.as_deref().ok_or("missing Signature")?
    );
    let parsed =
        sp.parse_login_response_with_request_id(&idp, Binding::SimpleSign, &request, "_r")?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("form@example.com"));
    Ok(())
}

// ----- create logout request (16-18) -----

fn logout_request(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let sp = sp(false, false);
    let ctx = create_logout_request(
        &idp.setting,
        idp.metadata.as_metadata(),
        sp.metadata.as_metadata(),
        binding,
        &LogoutUser::new("a@e.com"),
        None,
        false,
    )?;
    assert!(!ctx.context.is_empty());
    Ok(())
}

#[test]
fn flow_conformance_logout_request_redirect() -> Result<(), Box<dyn std::error::Error>> {
    logout_request(Binding::Redirect)
}
#[test]
fn flow_conformance_logout_request_post() -> Result<(), Box<dyn std::error::Error>> {
    logout_request(Binding::Post)
}
#[test]
fn flow_conformance_logout_request_one_binding() -> Result<(), Box<dyn std::error::Error>> {
    // IdP target exposes a single SLO binding.
    let idp = idp(false);
    let sp_config = SpMetadataInput {
        entity_id: "https://sp.example.com/metadata".into(),
        single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://sp/slo")],
        assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
        ..SpMetadataInput::default()
    };
    let sp = sp::Engine::from_config(&sp_config, EntitySetting::default())?;
    let ctx = create_logout_request(
        &idp.setting,
        idp.metadata.as_metadata(),
        sp.metadata.as_metadata(),
        Binding::Redirect,
        &LogoutUser::new("a@e.com"),
        None,
        false,
    )?;
    assert_eq!(ctx.entity_endpoint, "https://sp/slo");
    Ok(())
}

// ----- create logout response (19-21) -----

#[test]
fn flow_conformance_logout_response_undefined_binding() -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let sp = sp(false, false);
    match create_logout_response(
        &idp.setting,
        idp.metadata.as_metadata(),
        sp.metadata.as_metadata(),
        Binding::Artifact,
        Some("_r"),
        None,
        false,
    ) {
        Err(SamlError::UnsupportedBinding {
            binding: Binding::Artifact,
            ..
        }) => Ok(()),
        other => Err(format!("expected UnsupportedBinding(Artifact), got {other:?}").into()),
    }
}

fn logout_response(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let sp = sp(false, false);
    let ctx = create_logout_response(
        &idp.setting,
        idp.metadata.as_metadata(),
        sp.metadata.as_metadata(),
        binding,
        Some("_r"),
        None,
        false,
    )?;
    assert!(!ctx.context.is_empty());
    Ok(())
}

#[test]
fn flow_conformance_logout_response_redirect() -> Result<(), Box<dyn std::error::Error>> {
    logout_response(Binding::Redirect)
}
#[test]
fn flow_conformance_logout_response_post() -> Result<(), Box<dyn std::error::Error>> {
    logout_response(Binding::Post)
}

// ----- send response: signed assertion (22-24) -----

fn send_signed_assertion(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let sp = sp(true, false);
    let ctx = idp.create_login_response(&sp, binding, &User::new("a@example.com"), &opts("_r"))?;
    let parsed = parse_response_with_request_id(&sp, &idp, binding, &ctx, "_r")?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("a@example.com"));
    Ok(())
}

#[test]
fn flow_conformance_send_signed_assertion_post() -> Result<(), Box<dyn std::error::Error>> {
    send_signed_assertion(Binding::Post)
}

#[test]
fn flow_conformance_required_response_signature_rejects_assertion_only_post(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let assertion_only_sp = sp(true, false);
    let mut required_setting = signing();
    required_setting.want_message_signed = true;
    let required_sp = sp::Engine::from_config(&sp_config(false, true, false), required_setting)?;
    let ctx = idp.create_login_response(
        &assertion_only_sp,
        Binding::Post,
        &User::new("assertion-only@example.com"),
        &opts("_r"),
    )?;

    match parse_response_with_request_id(&required_sp, &idp, Binding::Post, &ctx, "_r") {
        Err(SamlError::SignedReferenceMismatch) => Ok(()),
        other => Err(format!("expected SignedReferenceMismatch, got {other:?}").into()),
    }
}
#[test]
fn flow_conformance_send_signed_assertion_redirect() -> Result<(), Box<dyn std::error::Error>> {
    send_signed_assertion(Binding::Redirect)
}
#[test]
fn flow_conformance_send_signed_assertion_simplesign() -> Result<(), Box<dyn std::error::Error>> {
    send_signed_assertion(Binding::SimpleSign)
}

// ----- signed assertion + custom transformation algorithms (25-27) -----

fn send_signed_assertion_custom_transforms(
    binding: Binding,
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let mut sp_setting = signing();
    sp_setting.transformation_algorithms = vec![
        saml_rs::constants::transform_algorithm::ENVELOPED_SIGNATURE.into(),
        saml_rs::constants::transform_algorithm::EXC_C14N.into(),
    ];
    let sp = sp::Engine::from_config(&sp_config(false, true, false), sp_setting)?;
    let ctx = idp.create_login_response(&sp, binding, &User::new("a@example.com"), &opts("_r"))?;
    let parsed = parse_response_with_request_id(&sp, &idp, binding, &ctx, "_r")?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("a@example.com"));
    Ok(())
}

#[test]
fn flow_conformance_send_signed_assertion_custom_transforms_post(
) -> Result<(), Box<dyn std::error::Error>> {
    send_signed_assertion_custom_transforms(Binding::Post)
}
#[test]
fn flow_conformance_send_signed_assertion_custom_transforms_redirect(
) -> Result<(), Box<dyn std::error::Error>> {
    send_signed_assertion_custom_transforms(Binding::Redirect)
}
#[test]
fn flow_conformance_send_signed_assertion_custom_transforms_simplesign(
) -> Result<(), Box<dyn std::error::Error>> {
    send_signed_assertion_custom_transforms(Binding::SimpleSign)
}

// ----- [custom template] signed assertion (28-30) -----

fn send_custom_signed_assertion(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    let idp = custom_idp()?;
    let sp = sp(true, false);
    let idp_id = "https://idp.example.com/metadata";
    let cb = |t: &str| fill_response(t, idp_id, "custom@example.com");
    let ctx = idp.create_rendered_login_response(&sp, binding, &cb)?;
    let parsed = parse_response_with_request_id(&sp, &idp, binding, &ctx, "_req")?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("custom@example.com"));
    assert_eq!(
        parsed.extract.get_str("attributes.mail"),
        Some("custom@example.com")
    );
    Ok(())
}

#[test]
fn flow_conformance_send_custom_signed_assertion_post() -> Result<(), Box<dyn std::error::Error>> {
    send_custom_signed_assertion(Binding::Post)
}
#[test]
fn flow_conformance_send_custom_signed_assertion_redirect() -> Result<(), Box<dyn std::error::Error>>
{
    send_custom_signed_assertion(Binding::Redirect)
}
#[test]
fn flow_conformance_send_custom_signed_assertion_simplesign(
) -> Result<(), Box<dyn std::error::Error>> {
    send_custom_signed_assertion(Binding::SimpleSign)
}

// ----- signed message (31-33) -----

fn send_signed_message(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let sp = sp(false, false); // not assertion-signed → message is signed (POST)
    let ctx = idp.create_login_response(&sp, binding, &User::new("a@example.com"), &opts("_r"))?;
    let parsed = parse_response_with_request_id(&sp, &idp, binding, &ctx, "_r")?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("a@example.com"));
    Ok(())
}

#[test]
fn flow_conformance_required_response_signature_accepts_response_root_signed_post(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let response_signed_sp = sp(false, false);
    let mut required_setting = signing();
    required_setting.want_message_signed = true;
    let required_sp = sp::Engine::from_config(&sp_config(false, false, false), required_setting)?;
    let ctx = idp.create_login_response(
        &response_signed_sp,
        Binding::Post,
        &User::new("response-signed@example.com"),
        &opts("_r"),
    )?;

    let parsed = parse_response_with_request_id(&required_sp, &idp, Binding::Post, &ctx, "_r")?;
    assert_eq!(
        parsed.extract.get_str("nameID"),
        Some("response-signed@example.com")
    );
    Ok(())
}

#[test]
fn flow_conformance_strict_assertion_signature_rejects_response_only_post(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let sp_allowing_unsigned_assertions = sp(false, false);
    let strict_sp = sp(true, false);
    let ctx = idp.create_login_response(
        &sp_allowing_unsigned_assertions,
        Binding::Post,
        &User::new("response-only@example.com"),
        &opts("_r"),
    )?;

    match parse_response_with_request_id(&strict_sp, &idp, Binding::Post, &ctx, "_r") {
        Err(SamlError::AssertionSignatureRequired) => Ok(()),
        other => Err(format!("expected AssertionSignatureRequired, got {other:?}").into()),
    }
}

#[test]
fn flow_conformance_compatible_assertion_signature_accepts_response_only_post(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let sp = sp(false, false);
    let ctx = idp.create_login_response(
        &sp,
        Binding::Post,
        &User::new("response-only@example.com"),
        &opts("_r"),
    )?;

    let parsed = parse_response_with_request_id(&sp, &idp, Binding::Post, &ctx, "_r")?;
    assert_eq!(
        parsed.extract.get_str("nameID"),
        Some("response-only@example.com")
    );
    Ok(())
}

#[test]
fn flow_conformance_send_signed_message_redirect() -> Result<(), Box<dyn std::error::Error>> {
    send_signed_message(Binding::Redirect)
}
#[test]
fn flow_conformance_send_signed_message_simplesign() -> Result<(), Box<dyn std::error::Error>> {
    send_signed_message(Binding::SimpleSign)
}

fn signed_response_without_destination_is_rejected(
    binding: Binding,
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp::Engine::from_config(&idp_config(false), signing())?;
    let sp = sp(false, false);
    let callback = |template: &str| {
        fill_response(
            &template.replacen(" Destination=\"{Destination}\"", "", 1),
            "https://idp.example.com/metadata",
            "missing-destination@example.com",
        )
    };
    let context = idp.create_rendered_login_response(&sp, binding, &callback)?;

    match parse_response_with_request_id(&sp, &idp, binding, &context, "_req") {
        Err(SamlError::DestinationMismatch {
            expected,
            actual: None,
            ..
        }) if expected == "https://sp/acs" => Ok(()),
        other => Err(format!("expected missing Destination error, got {other:?}").into()),
    }
}

#[test]
fn flow_conformance_signed_post_response_requires_destination(
) -> Result<(), Box<dyn std::error::Error>> {
    signed_response_without_destination_is_rejected(Binding::Post)
}

#[test]
fn flow_conformance_signed_redirect_response_requires_destination(
) -> Result<(), Box<dyn std::error::Error>> {
    signed_response_without_destination_is_rejected(Binding::Redirect)
}

#[test]
fn flow_conformance_signed_simplesign_response_requires_destination(
) -> Result<(), Box<dyn std::error::Error>> {
    signed_response_without_destination_is_rejected(Binding::SimpleSign)
}

#[test]
fn flow_conformance_assertion_only_signed_post_allows_omitted_response_destination(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp::Engine::from_config(&idp_config(false), signing())?;
    let sp = sp(true, false);
    let callback = |template: &str| {
        fill_response(
            &template.replacen(" Destination=\"{Destination}\"", "", 1),
            "https://idp.example.com/metadata",
            "assertion-only@example.com",
        )
    };
    let context = idp.create_rendered_login_response(&sp, Binding::Post, &callback)?;
    let parsed = parse_response_with_request_id(&sp, &idp, Binding::Post, &context, "_req")?;

    assert_eq!(
        parsed.extract.get_str("nameID"),
        Some("assertion-only@example.com")
    );
    Ok(())
}

fn required_response_signature_accepts_detached_without_embedded_signature(
    binding: Binding,
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let detached_signed_sp = sp(false, false);
    let mut required_setting = signing();
    required_setting.want_message_signed = true;
    let required_sp = sp::Engine::from_config(&sp_config(false, false, false), required_setting)?;
    let ctx = idp.create_login_response(
        &detached_signed_sp,
        binding,
        &User::new("detached@example.com"),
        &opts("_r"),
    )?;
    let request = response_request(binding, &ctx)?;
    let params = match binding {
        Binding::Redirect => &request.query,
        Binding::SimpleSign => &request.body,
        _ => return Err("expected detached binding".into()),
    };
    let encoded = params
        .iter()
        .find(|(name, _)| name == "SAMLResponse")
        .map(|(_, value)| value.as_str())
        .ok_or("missing bound SAMLResponse")?;
    let decoded = STANDARD.decode(encoded)?;
    let xml = match binding {
        Binding::Redirect => deflate_raw_decode(&decoded, MAX_DEFLATE_RAW_DECODE_BYTES)?,
        Binding::SimpleSign => decoded,
        _ => return Err("expected detached binding".into()),
    };
    let xml = String::from_utf8(xml)?;
    if xml.contains("<ds:Signature") {
        return Err("expected detached-only response fixture".into());
    }

    let parsed = parse_response_with_request_id(&required_sp, &idp, binding, &ctx, "_r")?;
    assert_eq!(
        parsed.extract.get_str("nameID"),
        Some("detached@example.com")
    );
    Ok(())
}

#[test]
fn flow_conformance_required_response_signature_accepts_redirect_detached_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    required_response_signature_accepts_detached_without_embedded_signature(Binding::Redirect)
}

#[test]
fn flow_conformance_required_response_signature_accepts_simplesign_detached_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    required_response_signature_accepts_detached_without_embedded_signature(Binding::SimpleSign)
}

// ----- [custom template] signed message (34-36) -----

fn send_custom_signed_message(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    let idp = custom_idp()?;
    let sp = sp(false, false);
    let idp_id = "https://idp.example.com/metadata";
    let cb = |t: &str| fill_response(t, idp_id, "cm@example.com");
    let ctx = idp.create_rendered_login_response(&sp, binding, &cb)?;
    let parsed = parse_response_with_request_id(&sp, &idp, binding, &ctx, "_req")?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("cm@example.com"));
    Ok(())
}

#[test]
fn flow_conformance_send_custom_signed_message_post() -> Result<(), Box<dyn std::error::Error>> {
    send_custom_signed_message(Binding::Post)
}
#[test]
fn flow_conformance_send_custom_signed_message_redirect() -> Result<(), Box<dyn std::error::Error>>
{
    send_custom_signed_message(Binding::Redirect)
}
#[test]
fn flow_conformance_send_custom_signed_message_simplesign() -> Result<(), Box<dyn std::error::Error>>
{
    send_custom_signed_message(Binding::SimpleSign)
}

// ----- signed assertion + signed message (37-39) -----

fn send_assertion_and_message(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let mut sp_setting = signing();
    sp_setting.want_message_signed = true;
    let sp = sp::Engine::from_config(&sp_config(false, true, false), sp_setting)?;
    let ctx = idp.create_login_response(&sp, binding, &User::new("a@example.com"), &opts("_r"))?;
    let parsed = parse_response_with_request_id(&sp, &idp, binding, &ctx, "_r")?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("a@example.com"));
    Ok(())
}

#[test]
fn flow_conformance_send_assertion_and_message_post() -> Result<(), Box<dyn std::error::Error>> {
    send_assertion_and_message(Binding::Post)
}
#[test]
fn flow_conformance_send_assertion_and_message_redirect() -> Result<(), Box<dyn std::error::Error>>
{
    send_assertion_and_message(Binding::Redirect)
}
#[test]
fn flow_conformance_send_assertion_and_message_simplesign() -> Result<(), Box<dyn std::error::Error>>
{
    send_assertion_and_message(Binding::SimpleSign)
}

// ----- [custom template] signed assertion + signed message (40-42) -----

fn send_custom_assertion_and_message(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    let idp = custom_idp()?;
    let mut sp_setting = signing();
    sp_setting.want_message_signed = true;
    let sp = sp::Engine::from_config(&sp_config(false, true, false), sp_setting)?;
    let idp_id = "https://idp.example.com/metadata";
    let cb = |t: &str| fill_response(t, idp_id, "cam@example.com");
    let ctx = idp.create_rendered_login_response(&sp, binding, &cb)?;
    let parsed = parse_response_with_request_id(&sp, &idp, binding, &ctx, "_req")?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("cam@example.com"));
    Ok(())
}

#[test]
fn flow_conformance_send_custom_assertion_and_message_post(
) -> Result<(), Box<dyn std::error::Error>> {
    send_custom_assertion_and_message(Binding::Post)
}
#[test]
fn flow_conformance_send_custom_assertion_and_message_redirect(
) -> Result<(), Box<dyn std::error::Error>> {
    send_custom_assertion_and_message(Binding::Redirect)
}
#[test]
fn flow_conformance_send_custom_assertion_and_message_simplesign(
) -> Result<(), Box<dyn std::error::Error>> {
    send_custom_assertion_and_message(Binding::SimpleSign)
}

// ----- encrypted assertion variants (43-47, 54) -----

#[cfg(not(feature = "crypto-fips"))]
fn encrypted_signed(custom: bool, with_message: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut idp_setting = signing();
    idp_setting.is_assertion_encrypted = true;
    let idp = idp::Engine::from_config(&idp_config(false), idp_setting)?;
    let mut sp_setting = signing();
    sp_setting.is_assertion_encrypted = true;
    sp_setting.enc_private_key = Some(PRIVKEY.into());
    sp_setting.want_message_signed = with_message;
    let sp = sp::Engine::from_config(&sp_config(false, true, true), sp_setting)?;
    let idp_id = "https://idp.example.com/metadata";
    let cb = |t: &str| fill_response(t, idp_id, "es@example.com");
    let options = LoginResponseOptions {
        in_response_to: Some("_r"),
        ..Default::default()
    };
    let user = User::new("es@example.com");
    let ctx = if custom {
        idp.create_rendered_login_response(&sp, Binding::Post, &cb)?
    } else {
        idp.create_login_response(&sp, Binding::Post, &user, &options)?
    };
    let request_id = if custom { "_req" } else { "_r" };
    let parsed = parse_response_with_request_id(&sp, &idp, Binding::Post, &ctx, request_id)?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("es@example.com"));
    Ok(())
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn flow_conformance_encrypted_signed_assertion() -> Result<(), Box<dyn std::error::Error>> {
    encrypted_signed(false, false)
}
#[cfg(not(feature = "crypto-fips"))]
#[test]
fn flow_conformance_encrypted_custom_signed_assertion() -> Result<(), Box<dyn std::error::Error>> {
    encrypted_signed(true, false)
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn flow_conformance_required_response_signature_rejects_encrypted_assertion_only_post(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut idp_setting = signing();
    idp_setting.is_assertion_encrypted = true;
    let idp = idp::Engine::from_config(&idp_config(false), idp_setting)?;
    let assertion_only_sp = sp(true, true);
    let mut required_setting = signing();
    required_setting.is_assertion_encrypted = true;
    required_setting.enc_private_key = Some(PRIVKEY.into());
    required_setting.want_message_signed = true;
    let required_sp = sp::Engine::from_config(&sp_config(false, true, true), required_setting)?;
    let ctx = idp.create_login_response(
        &assertion_only_sp,
        Binding::Post,
        &User::new("encrypted-assertion-only@example.com"),
        &opts("_r"),
    )?;

    match parse_response_with_request_id(&required_sp, &idp, Binding::Post, &ctx, "_r") {
        Err(SamlError::SignatureMissing) => Ok(()),
        other => Err(format!("expected SignatureMissing, got {other:?}").into()),
    }
}
#[cfg(not(feature = "crypto-fips"))]
#[test]
fn flow_conformance_encrypted_signed_assertion_and_message(
) -> Result<(), Box<dyn std::error::Error>> {
    encrypted_signed(false, true)
}
#[cfg(not(feature = "crypto-fips"))]
#[test]
fn flow_conformance_encrypted_custom_signed_assertion_and_message(
) -> Result<(), Box<dyn std::error::Error>> {
    encrypted_signed(true, true)
}

// ----- logout request/response with & without signature (48-53) -----

fn logout_request_flow(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let sp = sp(false, false);
    let ctx = create_logout_request(
        &idp.setting,
        idp.metadata.as_metadata(),
        sp.metadata.as_metadata(),
        binding,
        &LogoutUser::new("a@e.com"),
        None,
        true,
    )?;
    let request = logout_request_to_http(binding, &ctx)?;
    let parsed = parse_logout_request(&sp.setting, idp.metadata.as_metadata(), binding, &request)?;
    assert_eq!(
        parsed.extract.get_str("issuer"),
        Some("https://idp.example.com/metadata")
    );
    Ok(())
}

fn logout_request_to_http(
    binding: Binding,
    ctx: &BindingContext,
) -> Result<HttpRequest, Box<dyn std::error::Error>> {
    Ok(match binding {
        Binding::Redirect => redirect_request(&ctx.context)?,
        Binding::Post => HttpRequest::post(vec![("SAMLRequest".into(), ctx.context.clone())]),
        Binding::SimpleSign => simplesign_request("SAMLRequest", ctx)?,
        binding => return Err(format!("test helper has no {binding:?} case").into()),
    })
}

fn logout_response_to_http(
    binding: Binding,
    ctx: &BindingContext,
) -> Result<HttpRequest, Box<dyn std::error::Error>> {
    Ok(match binding {
        Binding::Redirect => redirect_request(&ctx.context)?,
        Binding::Post => HttpRequest::post(vec![("SAMLResponse".into(), ctx.context.clone())]),
        Binding::SimpleSign => simplesign_request("SAMLResponse", ctx)?,
        binding => return Err(format!("test helper has no {binding:?} case").into()),
    })
}

fn body_param<'a>(request: &'a HttpRequest, param: &str) -> Result<&'a str, SamlError> {
    request
        .body
        .iter()
        .find(|(key, _)| key == param)
        .map(|(_, value)| value.as_str())
        .ok_or_else(|| SamlError::Invalid(format!("missing {param}")))
}

fn body_param_mut<'a>(
    request: &'a mut HttpRequest,
    param: &str,
) -> Result<&'a mut String, SamlError> {
    request
        .body
        .iter_mut()
        .find(|(key, _)| key == param)
        .map(|(_, value)| value)
        .ok_or_else(|| SamlError::Invalid(format!("missing {param}")))
}

fn tamper_body_message(
    request: &mut HttpRequest,
    param: &str,
    from: &str,
    to: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let encoded = body_param_mut(request, param)?;
    let xml = String::from_utf8(STANDARD.decode(encoded.as_str())?)?;
    let tampered = xml.replace(from, to);
    if tampered == xml {
        return Err("tamper target not found".into());
    }
    *encoded = STANDARD.encode(tampered.as_bytes());
    Ok(())
}

#[test]
fn flow_conformance_idp_redirect_logout_request_signed() -> Result<(), Box<dyn std::error::Error>> {
    logout_request_flow(Binding::Redirect)
}
#[test]
fn flow_conformance_idp_post_logout_request_signed() -> Result<(), Box<dyn std::error::Error>> {
    logout_request_flow(Binding::Post)
}

#[test]
fn flow_conformance_signed_simplesign_logout_request_returns_detached_signature_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let sp = sp(false, false);
    let ctx = create_logout_request(
        &idp.setting,
        idp.metadata.as_metadata(),
        sp.metadata.as_metadata(),
        Binding::SimpleSign,
        &LogoutUser::new("a@e.com"),
        None,
        true,
    )?;
    assert!(
        matches!((&ctx.signature, &ctx.sig_alg), (Some(_), Some(_))),
        "expected detached Signature and SigAlg"
    );
    Ok(())
}

#[test]
fn flow_conformance_signed_simplesign_logout_request_parses_when_required(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let sp = sp(false, false);
    let ctx = create_logout_request(
        &idp.setting,
        idp.metadata.as_metadata(),
        sp.metadata.as_metadata(),
        Binding::SimpleSign,
        &LogoutUser::new("a@e.com"),
        None,
        true,
    )?;
    let request = logout_request_to_http(Binding::SimpleSign, &ctx)?;
    let parsed = parse_logout_request(
        &sp.setting,
        idp.metadata.as_metadata(),
        Binding::SimpleSign,
        &request,
    )?;
    assert_eq!(
        parsed.extract.get_str("issuer"),
        Some("https://idp.example.com/metadata")
    );
    Ok(())
}

#[test]
fn flow_conformance_tampered_simplesign_logout_request_body_fails_signature_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let sp = sp(false, false);
    let ctx = create_logout_request(
        &idp.setting,
        idp.metadata.as_metadata(),
        sp.metadata.as_metadata(),
        Binding::SimpleSign,
        &LogoutUser::new("a@e.com"),
        None,
        true,
    )?;
    let mut request = logout_request_to_http(Binding::SimpleSign, &ctx)?;
    tamper_body_message(
        &mut request,
        "SAMLRequest",
        "https://idp.example.com/metadata",
        "https://attacker.example.com/metadata",
    )?;
    assert_failed_message_signature(parse_logout_request(
        &sp.setting,
        idp.metadata.as_metadata(),
        Binding::SimpleSign,
        &request,
    ))
}

#[test]
fn flow_conformance_signed_simplesign_logout_request_with_relay_state_includes_body_and_octet(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let sp = sp(false, false);
    let ctx = create_logout_request(
        &idp.setting,
        idp.metadata.as_metadata(),
        sp.metadata.as_metadata(),
        Binding::SimpleSign,
        &LogoutUser::new("a@e.com"),
        Some("relay-123"),
        true,
    )?;
    let request = logout_request_to_http(Binding::SimpleSign, &ctx)?;
    let octet = request
        .octet_string
        .as_deref()
        .ok_or_else(|| SamlError::Invalid("missing octet".into()))?;
    assert_eq!(body_param(&request, "RelayState")?, "relay-123");
    assert!(
        octet.contains("&RelayState=relay-123&SigAlg="),
        "expected RelayState in signed octet"
    );
    Ok(())
}

fn logout_response_flow(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let sp = sp(false, false);
    let ctx = create_logout_response(
        &sp.setting,
        sp.metadata.as_metadata(),
        idp.metadata.as_metadata(),
        binding,
        Some("_r"),
        None,
        true,
    )?;
    let request = logout_response_to_http(binding, &ctx)?;
    let parsed = parse_logout_response(
        &idp.setting,
        sp.metadata.as_metadata(),
        binding,
        &request,
        "_r",
    )?;
    assert_eq!(
        parsed.extract.get_str("issuer"),
        Some("https://sp.example.com/metadata")
    );
    Ok(())
}

#[test]
fn flow_conformance_sp_post_logout_response_signed() -> Result<(), Box<dyn std::error::Error>> {
    logout_response_flow(Binding::Post)
}

#[test]
fn flow_conformance_sp_redirect_logout_response_signed() -> Result<(), Box<dyn std::error::Error>> {
    logout_response_flow(Binding::Redirect)
}

#[test]
fn flow_conformance_signed_simplesign_logout_response_returns_detached_signature_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let sp = sp(false, false);
    let ctx = create_logout_response(
        &sp.setting,
        sp.metadata.as_metadata(),
        idp.metadata.as_metadata(),
        Binding::SimpleSign,
        Some("_r"),
        None,
        true,
    )?;
    assert!(
        matches!((&ctx.signature, &ctx.sig_alg), (Some(_), Some(_))),
        "expected detached Signature and SigAlg"
    );
    Ok(())
}

#[test]
fn flow_conformance_signed_simplesign_logout_response_parses_when_required(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp_recv = idp(false);
    let sp = sp(false, false);
    let ctx = create_logout_response(
        &sp.setting,
        sp.metadata.as_metadata(),
        idp_recv.metadata.as_metadata(),
        Binding::SimpleSign,
        Some("_r"),
        None,
        true,
    )?;
    let request = logout_response_to_http(Binding::SimpleSign, &ctx)?;
    let parsed = parse_logout_response(
        &idp_recv.setting,
        sp.metadata.as_metadata(),
        Binding::SimpleSign,
        &request,
        "_r",
    )?;
    assert_eq!(
        parsed.extract.get_str("issuer"),
        Some("https://sp.example.com/metadata")
    );
    Ok(())
}

#[test]
fn flow_conformance_tampered_simplesign_logout_response_body_fails_signature_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp_recv = idp(false);
    let sp = sp(false, false);
    let ctx = create_logout_response(
        &sp.setting,
        sp.metadata.as_metadata(),
        idp_recv.metadata.as_metadata(),
        Binding::SimpleSign,
        Some("_r"),
        None,
        true,
    )?;
    let mut request = logout_response_to_http(Binding::SimpleSign, &ctx)?;
    tamper_body_message(
        &mut request,
        "SAMLResponse",
        "https://sp.example.com/metadata",
        "https://attacker.example.com/metadata",
    )?;
    assert_failed_message_signature(parse_logout_response(
        &idp_recv.setting,
        sp.metadata.as_metadata(),
        Binding::SimpleSign,
        &request,
        "_r",
    ))
}

#[test]
fn flow_conformance_signed_simplesign_logout_response_with_relay_state_includes_body_and_octet(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let sp = sp(false, false);
    let ctx = create_logout_response(
        &sp.setting,
        sp.metadata.as_metadata(),
        idp.metadata.as_metadata(),
        Binding::SimpleSign,
        Some("_r"),
        Some("relay-456"),
        true,
    )?;
    let request = logout_response_to_http(Binding::SimpleSign, &ctx)?;
    let octet = request
        .octet_string
        .as_deref()
        .ok_or_else(|| SamlError::Invalid("missing octet".into()))?;
    assert_eq!(body_param(&request, "RelayState")?, "relay-456");
    assert!(
        octet.contains("&RelayState=relay-456&SigAlg="),
        "expected RelayState in signed octet"
    );
    Ok(())
}

#[test]
fn flow_conformance_signed_logout_response_wrong_request_id_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp_recv = idp(false);
    let sp = sp(false, false);
    let ctx = create_logout_response(
        &sp.setting,
        sp.metadata.as_metadata(),
        idp_recv.metadata.as_metadata(),
        Binding::Post,
        Some("_wrong"),
        None,
        true,
    )?;
    let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);

    assert!(matches!(
        parse_logout_response(
            &idp_recv.setting,
            sp.metadata.as_metadata(),
            Binding::Post,
            &request,
            "_r"
        ),
        Err(SamlError::InResponseToMismatch { .. })
    ));
    Ok(())
}

// ----- malformed response (57-59) -----

fn malformed(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let idp = idp(false);
    let sp = sp(true, false);
    let bad = STANDARD.encode(b"<<<not-xml");
    let request = match binding {
        Binding::Redirect => redirect_query(vec![("SAMLResponse".into(), bad)]),
        _ => HttpRequest::post(vec![("SAMLResponse".into(), bad)]),
    };
    assert!(sp
        .parse_unsolicited_login_response(&idp, binding, &request)
        .is_err());
    Ok(())
}

#[test]
fn flow_conformance_malformed_response_post() -> Result<(), Box<dyn std::error::Error>> {
    malformed(Binding::Post)
}
#[test]
fn flow_conformance_malformed_response_redirect() -> Result<(), Box<dyn std::error::Error>> {
    malformed(Binding::Redirect)
}
#[test]
fn flow_conformance_malformed_response_simplesign() -> Result<(), Box<dyn std::error::Error>> {
    malformed(Binding::SimpleSign)
}

// ----- signature wrapping (60-61) -----

const ATTACK: &str = include_str!("../../tests/fixtures/misc/attack_response_signed.xml");

#[test]
fn flow_conformance_reject_signature_wrapped_response_case_1(
) -> Result<(), Box<dyn std::error::Error>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let idp = idp(false);
    let sp = sp(true, false);
    let request = HttpRequest::post(vec![(
        "SAMLResponse".into(),
        STANDARD.encode(ATTACK.as_bytes()),
    )]);
    assert!(sp
        .parse_unsolicited_login_response(&idp, Binding::Post, &request)
        .is_err());
    Ok(())
}

#[test]
fn flow_conformance_use_signed_contents_in_wrapped_response_case_2(
) -> Result<(), Box<dyn std::error::Error>> {
    // A correctly signed response yields only the cryptographically signed
    // assertion contents (no wrapping injection survives).
    let idp = idp(false);
    let sp = sp(true, false);
    let ctx = idp.create_login_response(
        &sp,
        Binding::Post,
        &User::new("safe@example.com"),
        &opts("_r"),
    )?;
    let parsed = parse_response_with_request_id(&sp, &idp, Binding::Post, &ctx, "_r")?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("safe@example.com"));
    Ok(())
}

// ----- two-tier status error (62-64) -----

fn two_tier_status(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let idp = idp(false);
    let sp = sp(true, false);
    let failed = FAILED.replace(
        "http://sp.example.com/demo1/index.php?acs",
        "https://sp/acs",
    );
    let request = match binding {
        Binding::Redirect => {
            use saml_rs::binding::deflate_raw_encode;
            let enc = STANDARD.encode(&deflate_raw_encode(failed.as_bytes())?);
            redirect_query(vec![("SAMLResponse".into(), enc)])
        }
        _ => HttpRequest::post(vec![(
            "SAMLResponse".into(),
            STANDARD.encode(failed.as_bytes()),
        )]),
    };
    match sp.parse_unsolicited_login_response(&idp, binding, &request) {
        Err(SamlError::StatusNotSuccess { .. }) => Ok(()),
        other => Err(format!("expected StatusNotSuccess, got {other:?}").into()),
    }
}

#[test]
fn flow_conformance_two_tier_status_post() -> Result<(), Box<dyn std::error::Error>> {
    two_tier_status(Binding::Post)
}
#[test]
fn flow_conformance_two_tier_status_redirect() -> Result<(), Box<dyn std::error::Error>> {
    two_tier_status(Binding::Redirect)
}
#[test]
fn flow_conformance_two_tier_status_simplesign() -> Result<(), Box<dyn std::error::Error>> {
    two_tier_status(Binding::SimpleSign)
}
