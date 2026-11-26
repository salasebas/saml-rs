//! Typed HTTP-Redirect and HTTP-POST-SimpleSign binding rules.
//!
//! Bindings §3.4.3 and §3.5.3, and HTTP-POST-SimpleSign CD-04 §2.3, prohibit
//! the entity creating a message from sending a RelayState longer than 80
//! bytes, and require a responder to return the exact RelayState it received.
//! Bindings §3.4.4.1 requires HTTP-Redirect to remove a protocol XML signature
//! before DEFLATE, recommends against encoding a message with other signed
//! content, and requires verifying the detached signature over parameters in
//! a fixed order. CD-04 §2.5 and §2.6 require
//! SimpleSign to sign the raw XML octets, including RelayState when present.
#![cfg(crypto)]

#[path = "common/post_validation.rs"]
mod post_validation;
use post_validation::post_validation;
use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::constants::Binding;
use saml_rs::{
    AcsEndpoint, AssertionSignaturePolicy, AudienceValidationPolicy, AuthnRequestSigningPolicy,
    AuthnRequestValidationPolicy, Credentials, DeliveredArtifact, EntityId, ExtensionElement,
    FormField, IdentityProvider, IdpConfig, IdpDescriptor, IdpValidationPolicy, Inbound,
    MetadataTrustPolicy, NameId, NameIdFormat, PrivateKeyPem, RelayState, ReplayPolicy, RespondSso,
    SamlError, SamlValidationContext, ServiceProvider, SpConfig, SpConfigBuilder, SpDescriptor,
    SpValidationPolicy, SsoAssertion, SsoEndpoint, StartSso, X509Credential,
    MAX_RECEIVED_RELAY_STATE_BYTES, MAX_RELAY_STATE_BYTES,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS_POST: &str = "https://sp.example.com/acs/post";
const SP_ACS_SIMPLESIGN: &str = "https://sp.example.com/acs/simple-sign";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const IDP_SSO_REDIRECT: &str = "https://idp.example.com/sso/redirect";
const IDP_SSO_SIMPLESIGN: &str = "https://idp.example.com/sso/simple-sign";

const PRIVKEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");

fn credentials() -> Credentials {
    Credentials::default().with_signing_credential(X509Credential::new(
        saml_rs::CertificatePem::new(CERT),
        PrivateKeyPem::new(PRIVKEY),
    ))
}

fn signing_sp_validation() -> SpValidationPolicy {
    let mut validation = SpValidationPolicy::default();
    validation.assertion_signatures = AssertionSignaturePolicy::RequireSigned;
    validation.authn_request_signing = AuthnRequestSigningPolicy::Sign;
    validation.audience = AudienceValidationPolicy::RequireRestriction;
    validation
}

fn signed_authn_request_idp_validation() -> IdpValidationPolicy {
    let mut validation = IdpValidationPolicy::default();
    validation.authn_request_signatures = AuthnRequestValidationPolicy::RequireSigned;
    validation
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache)
}

fn principal() -> NameId {
    NameId::new("alice@example.com").with_format(NameIdFormat::EmailAddress)
}

fn sp_config(validation: SpValidationPolicy) -> Result<SpConfigBuilder, SamlError> {
    Ok(SpConfig::builder(
        EntityId::try_new(SP_ENTITY_ID)?,
        AcsEndpoint::post(SP_ACS_POST)?.with_default(),
    )
    .acs_endpoint(AcsEndpoint::simple_sign(SP_ACS_SIMPLESIGN)?)
    .credentials(credentials())
    .validation(validation))
}

fn sp_with(validation: SpValidationPolicy) -> Result<saml_rs::ServiceProvider, SamlError> {
    Ok(ServiceProvider::new(sp_config(validation)?.build()?))
}

fn idp_with(validation: IdpValidationPolicy) -> Result<saml_rs::IdentityProvider, SamlError> {
    idp_with_redirect_endpoint(validation, IDP_SSO_REDIRECT)
}

fn idp_with_redirect_endpoint(
    validation: IdpValidationPolicy,
    redirect_endpoint: &str,
) -> Result<saml_rs::IdentityProvider, SamlError> {
    Ok(IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO_POST)?,
        )
        .sso_endpoint(SsoEndpoint::redirect(redirect_endpoint)?)
        .sso_endpoint(SsoEndpoint::simple_sign(IDP_SSO_SIMPLESIGN)?)
        .credentials(credentials())
        .validation(validation)
        .build()?,
    ))
}

fn descriptors(
    sp: &saml_rs::ServiceProvider,
    idp: &saml_rs::IdentityProvider,
) -> Result<(SpDescriptor, IdpDescriptor), SamlError> {
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::Unverified,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::Unverified,
    )?;
    Ok((sp_descriptor, idp_descriptor))
}

fn query_names(url: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let query = url.split_once('?').ok_or("missing query")?.1;
    Ok(query
        .split('&')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            segment
                .split_once('=')
                .map(|(name, _)| name)
                .unwrap_or(segment)
        })
        .map(str::to_string)
        .collect())
}

#[test]
fn typed_send_rejects_relay_state_longer_than_80_bytes() -> Result<(), Box<dyn std::error::Error>> {
    assert!(RelayState::try_new("a".repeat(MAX_RELAY_STATE_BYTES + 1)).is_err());
    let relay_state = RelayState::try_new("a".repeat(MAX_RELAY_STATE_BYTES))?;

    let sp = sp_with(SpValidationPolicy::default())?;
    let idp = idp_with(IdpValidationPolicy::default())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::redirect().relay_state(relay_state),
    )?;

    let query = started
        .outbound
        .redirect_url()?
        .split_once('?')
        .ok_or("missing query")?
        .1
        .replace(&"a".repeat(MAX_RELAY_STATE_BYTES), &"a".repeat(200));
    let received = idp.receive_sso(&sp_descriptor, Inbound::redirect(query), validation())?;
    let reused = received
        .relay_state()
        .cloned()
        .ok_or("missing RelayState")?;
    match idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(principal(), SystemTime::now()),
        RespondSso::post().relay_state(reused.clone()),
    ) {
        Err(SamlError::Invalid(message)) if message.contains("80") => {}
        other => {
            return Err(
                format!("expected the 80-byte RelayState prohibition, got {other:?}").into(),
            )
        }
    }
    match sp.start_sso(&idp_descriptor, StartSso::post().relay_state(reused)) {
        Err(SamlError::Invalid(message)) if message.contains("80") => {}
        other => {
            return Err(
                format!("expected the 80-byte RelayState prohibition, got {other:?}").into(),
            )
        }
    }

    Ok(())
}

#[test]
fn typed_sso_request_without_relay_state_sends_and_records_none(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(SpValidationPolicy::default())?;
    let idp = idp_with(IdpValidationPolicy::default())?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;

    let redirect = sp.start_sso(&idp_descriptor, StartSso::redirect())?;
    let names = query_names(redirect.outbound.redirect_url()?)?;
    assert!(!names.iter().any(|name| name == "RelayState"), "{names:?}");
    assert_eq!(redirect.pending.relay_state(), None);

    let post = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let form = post.outbound.post_form()?;
    assert!(form
        .fields()
        .iter()
        .all(|field| field.name() != "RelayState"));
    assert_eq!(post.pending.relay_state(), None);
    Ok(())
}

#[test]
fn typed_sso_accepts_and_echoes_received_relay_state_up_to_the_receive_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    let long = "c".repeat(200);
    let sp = sp_with(SpValidationPolicy::default())?;
    let idp = idp_with(IdpValidationPolicy::default())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::redirect())?;
    let request_query = |relay_state: &str| -> Result<String, Box<dyn std::error::Error>> {
        let query = started
            .outbound
            .redirect_url()?
            .split_once('?')
            .ok_or("missing query")?
            .1;
        Ok(format!("{query}&RelayState={relay_state}"))
    };

    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::redirect(request_query(&long)?),
        validation(),
    )?;
    assert_eq!(
        received.relay_state().map(RelayState::as_str),
        Some(long.as_str())
    );

    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal(), SystemTime::now()),
        RespondSso::post(),
    )?;
    assert_eq!(
        response.relay_state().map(RelayState::as_str),
        Some(long.as_str())
    );
    let response_fields = response.post_form()?.fields().to_vec();
    assert_eq!(
        response.post_form()?.value("RelayState"),
        Some(long.as_str())
    );

    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(response_fields),
        post_validation(&mut Default::default()),
    )?;
    assert_eq!(
        session.relay_state().map(RelayState::as_str),
        Some(long.as_str())
    );

    let unsolicited = idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(principal(), SystemTime::now()),
        RespondSso::post(),
    )?;
    let mut fields = unsolicited.post_form()?.fields().to_vec();
    fields.push(FormField::new("RelayState", long.as_str()));
    let session = sp.accept_unsolicited_sso(
        &idp_descriptor,
        Inbound::post(fields),
        post_validation(&mut Default::default()),
    )?;
    assert_eq!(
        session.relay_state().map(RelayState::as_str),
        Some(long.as_str())
    );
    Ok(())
}

#[test]
fn typed_sso_rejects_received_relay_state_above_the_receive_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    let too_long = "d".repeat(MAX_RECEIVED_RELAY_STATE_BYTES + 1);
    let sp = sp_with(SpValidationPolicy::default())?;
    let idp = idp_with(IdpValidationPolicy::default())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::redirect())?;
    let query = started
        .outbound
        .redirect_url()?
        .split_once('?')
        .ok_or("missing query")?
        .1;

    match idp.receive_sso(
        &sp_descriptor,
        Inbound::redirect(format!("{query}&RelayState={too_long}")),
        validation(),
    ) {
        Err(SamlError::LimitExceeded {
            limit: saml_rs::ResourceLimit::RelayStateBytes,
            ..
        }) => {}
        other => {
            return Err(format!("expected the RelayState receive limit, got {other:?}").into())
        }
    }

    let response = idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(principal(), SystemTime::now()),
        RespondSso::post(),
    )?;
    let mut fields = response.post_form()?.fields().to_vec();
    fields.push(FormField::new("RelayState", too_long));
    match sp.accept_unsolicited_sso(&idp_descriptor, Inbound::post(fields), validation()) {
        Err(SamlError::LimitExceeded {
            limit: saml_rs::ResourceLimit::RelayStateBytes,
            maximum: saml_rs::MAX_RECEIVED_RELAY_STATE_BYTES,
            ..
        }) => Ok(()),
        other => Err(format!("expected the RelayState receive limit, got {other:?}").into()),
    }
}

fn expect_ambiguous_relay_state<T: std::fmt::Debug>(
    entry_point: &str,
    result: Result<T, SamlError>,
) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Err(SamlError::DuplicateBindingParameter {
            name: "RelayState", ..
        }) => Ok(()),
        other => Err(format!(
            "expected {entry_point} to refuse a repeated RelayState, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn typed_sso_rejects_a_repeated_relay_state() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(SpValidationPolicy::default())?;
    let idp = idp_with(IdpValidationPolicy::default())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let relay_state = RelayState::try_new("state")?;

    let started = sp.start_sso(&idp_descriptor, StartSso::post().relay_state(relay_state))?;
    let mut request_fields = started.outbound.post_form()?.fields().to_vec();
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(request_fields.clone()),
        validation(),
    )?;
    request_fields.push(FormField::new("RelayState", "https://evil.example/"));
    expect_ambiguous_relay_state(
        "receive_sso over HTTP-POST",
        idp.receive_sso(&sp_descriptor, Inbound::post(request_fields), validation()),
    )?;

    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal(), SystemTime::now()),
        RespondSso::post(),
    )?;
    let mut response_fields = response.post_form()?.fields().to_vec();
    response_fields.push(FormField::new("RelayState", "https://evil.example/"));
    expect_ambiguous_relay_state(
        "finish_sso",
        sp.finish_sso(
            &idp_descriptor,
            &started.pending,
            Inbound::post(response_fields),
            validation(),
        ),
    )?;

    let unsolicited = idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(principal(), SystemTime::now()),
        RespondSso::post(),
    )?;
    let mut unsolicited_fields = unsolicited.post_form()?.fields().to_vec();
    unsolicited_fields.push(FormField::new("RelayState", "a"));
    unsolicited_fields.push(FormField::new("RelayState", "b"));
    expect_ambiguous_relay_state(
        "accept_unsolicited_sso",
        sp.accept_unsolicited_sso(
            &idp_descriptor,
            Inbound::post(unsolicited_fields),
            validation(),
        ),
    )?;

    let started = sp.start_sso(&idp_descriptor, StartSso::redirect())?;
    let request_url = started.outbound.redirect_url()?;
    let query = request_url.split_once('?').ok_or("missing query")?.1;
    for repeated in ["RelayState=a&RelayState=b", "RelayState=a&Rel%61yState=b"] {
        expect_ambiguous_relay_state(
            "receive_sso over unsigned HTTP-Redirect",
            idp.receive_sso(
                &sp_descriptor,
                Inbound::redirect(format!("{query}&{repeated}")),
                validation(),
            ),
        )?;
    }
    Ok(())
}

#[test]
fn typed_redirect_signs_in_binding_order_and_verifies_reordered_parameters(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp_with(signed_authn_request_idp_validation())?;
    let sp = sp_with(signing_sp_validation())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let relay_state = RelayState::try_new("ordered-state")?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::redirect().relay_state(relay_state),
    )?;
    assert_eq!(
        query_names(started.outbound.redirect_url()?)?,
        ["SAMLRequest", "RelayState", "SigAlg", "Signature"]
    );
    let query = started
        .outbound
        .redirect_url()?
        .split_once('?')
        .ok_or("missing query")?
        .1
        .to_string();
    let mut segments: Vec<&str> = query.split('&').collect();
    segments.rotate_left(1);
    let reordered = segments.join("&");
    let received = idp.receive_sso(&sp_descriptor, Inbound::redirect(reordered), validation())?;
    assert_eq!(received.message().id(), started.pending.request_id());
    assert_eq!(
        received.relay_state().map(RelayState::as_str),
        Some("ordered-state")
    );
    Ok(())
}

#[test]
fn typed_redirect_refuses_an_authn_request_with_signed_content(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp_with(IdpValidationPolicy::default())?;
    let signed = ExtensionElement::from_xml(
        r#"<app:Ticket xmlns:app="urn:example:app" ID="ticket-1"><sig:Signature xmlns:sig="http://www.w3.org/2000/09/xmldsig#"><sig:SignatureValue>AA==</sig:SignatureValue></sig:Signature></app:Ticket>"#,
    )?;
    let named_signature = ExtensionElement::from_xml(
        r#"<app:Signature xmlns:app="urn:example:app">approved</app:Signature>"#,
    )?;
    for validation in [SpValidationPolicy::default(), signing_sp_validation()] {
        let sp = sp_with(validation)?;
        let (_, idp_descriptor) = descriptors(&sp, &idp)?;
        let refused = sp.start_sso(
            &idp_descriptor,
            StartSso::redirect().extension(signed.clone()),
        );
        assert!(
            matches!(refused, Err(SamlError::SignedContentOnRedirect)),
            "{refused:?}"
        );
        sp.start_sso(
            &idp_descriptor,
            StartSso::redirect().extension(named_signature.clone()),
        )?;
        let post = sp.start_sso(&idp_descriptor, StartSso::post().extension(signed.clone()))?;
        let request = post
            .outbound
            .post_form()?
            .value("SAMLRequest")
            .ok_or("missing SAMLRequest")?;
        let xml = String::from_utf8(STANDARD.decode(request)?)?;
        assert!(xml.contains("<sig:SignatureValue>AA==</sig:SignatureValue>"));
    }
    Ok(())
}

#[test]
fn typed_simplesign_binds_relay_state_to_the_raw_xml_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(signing_sp_validation())?;
    let idp = idp_with(signed_authn_request_idp_validation())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let relay_state = RelayState::try_new("signed-state")?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::simple_sign().relay_state(relay_state),
    )?;
    let fields = started.outbound.post_form()?.fields().to_vec();
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::simple_sign(fields.clone()),
        validation(),
    )?;
    assert_eq!(
        received.relay_state().map(RelayState::as_str),
        Some("signed-state")
    );

    let mut tampered = fields;
    let relay = tampered
        .iter_mut()
        .find(|field| field.name() == "RelayState")
        .ok_or("missing RelayState")?;
    *relay = FormField::new("RelayState", "other-state");
    match idp.receive_sso(
        &sp_descriptor,
        Inbound::simple_sign(tampered),
        validation(),
    ) {
        Err(SamlError::SignatureVerification { .. }) => Ok(()),
        other => Err(format!(
            "expected SimpleSign to reject a RelayState the octet string did not cover, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn typed_simplesign_requires_the_sig_alg_field() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(signing_sp_validation())?;
    let idp = idp_with(signed_authn_request_idp_validation())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::simple_sign())?;
    let fields: Vec<FormField> = started
        .outbound
        .post_form()?
        .fields()
        .iter()
        .filter(|field| field.name() != "SigAlg")
        .cloned()
        .collect();
    let result = idp.receive_sso(&sp_descriptor, Inbound::simple_sign(fields), validation());
    assert!(
        matches!(
            result,
            Err(SamlError::MissingBindingParameter { name: "SigAlg", .. })
        ),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn typed_simplesign_reads_a_wrapped_unpadded_signature_and_reports_a_malformed_one(
) -> Result<(), Box<dyn std::error::Error>> {
    const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let sp = sp_with(signing_sp_validation())?;
    let idp = idp_with(signed_authn_request_idp_validation())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::simple_sign())?;
    let fields = started.outbound.post_form()?.fields().to_vec();
    let signature = fields
        .iter()
        .find(|field| field.name() == "Signature")
        .ok_or("missing Signature")?
        .value()
        .to_string();
    let unpadded = signature.trim_end_matches('=');
    assert_ne!(unpadded, signature, "an RSA-2048 signature is padded");
    let (head, tail) = unpadded.split_at(76);
    let (data, last) = unpadded.split_at(unpadded.len() - 1);
    let last_index = ALPHABET
        .find(last)
        .ok_or("Signature outside the alphabet")?;
    let pad_bit_set = ALPHABET
        .chars()
        .nth(last_index ^ 1)
        .ok_or("no such character")?;
    let nonzero_pad_bits = format!("{data}{pad_bit_set}{}", &signature[unpadded.len()..]);
    let with_signature = |value: &str| {
        fields
            .iter()
            .map(|field| match field.name() {
                "Signature" => FormField::new("Signature", value),
                _ => field.clone(),
            })
            .collect::<Vec<_>>()
    };

    idp.receive_sso(
        &sp_descriptor,
        Inbound::simple_sign(with_signature(&format!("{head}\r\n{tail}"))),
        validation(),
    )?;
    for malformed in ["invalid base64!", nonzero_pad_bits.as_str()] {
        let result = idp.receive_sso(
            &sp_descriptor,
            Inbound::simple_sign(with_signature(malformed)),
            validation(),
        );
        assert!(
            matches!(result, Err(SamlError::Base64 { .. })),
            "{malformed}: {result:?}"
        );
    }
    Ok(())
}

fn redirect_query(url: &str) -> Result<&str, Box<dyn std::error::Error>> {
    Ok(url.split_once('?').ok_or("missing query")?.1)
}

fn expect_unrepresentable<T: std::fmt::Debug>(
    result: Result<T, SamlError>,
    expected: Binding,
) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Err(SamlError::RelayStateNotRepresentable { binding, .. }) if binding == expected => Ok(()),
        other => Err(format!(
            "expected a {expected:?} form to refuse the RelayState, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn typed_form_refuses_a_relay_state_it_cannot_send_unchanged(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(signing_sp_validation())?;
    let idp = idp_with(signed_authn_request_idp_validation())?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;

    for value in ["line\nbreak", "line\rbreak", "line\n\rbreak"] {
        let relay_state = RelayState::try_new(value)?;
        expect_unrepresentable(
            sp.start_sso(
                &idp_descriptor,
                StartSso::post().relay_state(relay_state.clone()),
            ),
            Binding::Post,
        )?;
        expect_unrepresentable(
            sp.start_sso(
                &idp_descriptor,
                StartSso::simple_sign().relay_state(relay_state),
            ),
            Binding::SimpleSign,
        )?;
    }

    let crlf = RelayState::try_new("line\r\nbreak")?;
    let started = sp.start_sso(&idp_descriptor, StartSso::simple_sign().relay_state(crlf))?;
    assert_eq!(
        started.outbound.post_form()?.value("RelayState"),
        Some("line\r\nbreak")
    );

    let sp = sp_with(SpValidationPolicy::default())?;
    let idp = idp_with(IdpValidationPolicy::default())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::redirect())?;
    let query = format!(
        "{}&RelayState=line%0Abreak",
        redirect_query(started.outbound.redirect_url()?)?
    );
    let received = idp.receive_sso(&sp_descriptor, Inbound::redirect(query), validation())?;
    assert_eq!(
        received.relay_state().map(RelayState::as_str),
        Some("line\nbreak")
    );
    expect_unrepresentable(
        idp.respond_sso(
            &sp_descriptor,
            &received,
            SsoAssertion::new(principal(), SystemTime::now()),
            RespondSso::post(),
        ),
        Binding::Post,
    )?;

    let query = format!(
        "{}&RelayState=null%00byte",
        redirect_query(started.outbound.redirect_url()?)?
    );
    let received = idp.receive_sso(&sp_descriptor, Inbound::redirect(query), validation())?;
    expect_unrepresentable(
        idp.respond_sso(
            &sp_descriptor,
            &received,
            SsoAssertion::new(principal(), SystemTime::now()),
            RespondSso::post(),
        ),
        Binding::Post,
    )
}

#[test]
fn typed_redirect_refuses_a_relay_state_that_is_not_utf8() -> Result<(), Box<dyn std::error::Error>>
{
    let sp = sp_with(SpValidationPolicy::default())?;
    let idp = idp_with(IdpValidationPolicy::default())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::redirect())?;
    let query = redirect_query(started.outbound.redirect_url()?)?;

    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::redirect(format!("{query}&RelayState=caf%C3%A9")),
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        SsoAssertion::new(principal(), SystemTime::now()),
        RespondSso::post(),
    )?;
    assert_eq!(response.post_form()?.value("RelayState"), Some("café"));

    let result = idp.receive_sso(
        &sp_descriptor,
        Inbound::redirect(format!("{query}&RelayState=caf%E9")),
        validation(),
    );
    assert!(
        matches!(&result, Err(SamlError::Invalid(message)) if message.contains("RelayState") && message.contains("UTF-8")),
        "{result:?}"
    );

    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::redirect(format!("{query}&SAMLart=caf%E9")),
        validation(),
    )?;
    assert_eq!(received.message().id(), started.pending.request_id());

    let artifact = "AAQAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJyg%3D";
    let delivered = DeliveredArtifact::from_query(&format!("SAMLart={artifact}&Signature=caf%E9"))?;
    assert_eq!(delivered.relay_state(), None);
    let result = DeliveredArtifact::from_query(&format!("SAMLart={artifact}&RelayState=caf%E9"));
    assert!(
        matches!(&result, Err(SamlError::Invalid(message)) if message.contains("RelayState") && message.contains("UTF-8")),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn typed_redirect_keeps_an_ordinary_endpoint_query_and_refuses_saml_parameters(
) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = format!("{IDP_SSO_REDIRECT}?tenant=a%20b");
    let sp = sp_with(signing_sp_validation())?;
    let idp = idp_with_redirect_endpoint(signed_authn_request_idp_validation(), &endpoint)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let relay_state = RelayState::try_new("endpoint-state")?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::redirect().relay_state(relay_state),
    )?;
    let url = started.outbound.redirect_url()?;
    assert_eq!(
        query_names(url)?,
        ["tenant", "SAMLRequest", "RelayState", "SigAlg", "Signature"]
    );
    assert!(
        url.starts_with(&format!("{endpoint}&SAMLRequest=")),
        "{url}"
    );
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::redirect(redirect_query(url)?),
        validation(),
    )?;
    assert_eq!(
        received.relay_state().map(RelayState::as_str),
        Some("endpoint-state")
    );

    let literal = format!("{IDP_SSO_REDIRECT}?%3FRelayState=x");
    let idp = idp_with_redirect_endpoint(IdpValidationPolicy::default(), &literal)?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::redirect())?;
    assert!(
        started
            .outbound
            .redirect_url()?
            .starts_with(&format!("{literal}&SAMLRequest=")),
        "{literal}"
    );

    for (endpoint, name) in [
        (format!("{IDP_SSO_REDIRECT}??RelayState=x"), "RelayState"),
        (
            format!("{IDP_SSO_REDIRECT}?tenant=a&SAMLRequest=x"),
            "SAMLRequest",
        ),
        (
            format!("{IDP_SSO_REDIRECT}?tenant=a&SAMLResponse=x"),
            "SAMLResponse",
        ),
        (format!("{IDP_SSO_REDIRECT}?tenant=a&SAMLart=x"), "SAMLart"),
        (
            format!("{IDP_SSO_REDIRECT}?tenant=a&RelayState=x"),
            "RelayState",
        ),
        (
            format!("{IDP_SSO_REDIRECT}?tenant=a&Relay%53tate=x"),
            "RelayState",
        ),
        (format!("{IDP_SSO_REDIRECT}?tenant=a&SigAlg=x"), "SigAlg"),
        (
            format!("{IDP_SSO_REDIRECT}?tenant=a&Signature=x"),
            "Signature",
        ),
        (
            format!("{IDP_SSO_REDIRECT}?tenant=a&SAMLEncoding=x"),
            "SAMLEncoding",
        ),
    ] {
        let idp = idp_with_redirect_endpoint(IdpValidationPolicy::default(), &endpoint)?;
        let (_, idp_descriptor) = descriptors(&sp, &idp)?;
        let result = sp.start_sso(&idp_descriptor, StartSso::redirect());
        assert!(
            matches!(&result, Err(SamlError::Invalid(message)) if message.contains(name) && message.contains("endpoint")),
            "{endpoint}: {result:?}"
        );
    }
    Ok(())
}

#[test]
fn typed_redirect_inflates_only_the_deflate_saml_encoding() -> Result<(), Box<dyn std::error::Error>>
{
    let sp = sp_with(SpValidationPolicy::default())?;
    let idp = idp_with(IdpValidationPolicy::default())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::redirect())?;
    let query = redirect_query(started.outbound.redirect_url()?)?;

    let deflate = "urn%3Aoasis%3Anames%3Atc%3ASAML%3A2.0%3Abindings%3AURL-Encoding%3ADEFLATE";
    let received = idp.receive_sso(
        &sp_descriptor,
        Inbound::redirect(format!("{query}&SAMLEncoding={deflate}")),
        validation(),
    )?;
    assert_eq!(received.message().id(), started.pending.request_id());

    for custom in [
        "SAMLEncoding=urn%3Aexample%3Acustom&payload=abc",
        "SAMLEncoding=urn%3Aexample%3Acustom&SAMLRequest=%FF",
    ] {
        let result = idp.receive_sso(&sp_descriptor, Inbound::redirect(custom), validation());
        assert!(
            matches!(&result, Err(SamlError::Unsupported(message)) if message.contains("SAMLEncoding")),
            "{custom}: {result:?}"
        );
    }
    for encoding in ["urn%3Aexample%3Aother-encoding", ""] {
        let result = idp.receive_sso(
            &sp_descriptor,
            Inbound::redirect(format!("{query}&SAMLEncoding={encoding}")),
            validation(),
        );
        assert!(
            matches!(&result, Err(SamlError::Unsupported(message)) if message.contains("SAMLEncoding")),
            "{encoding}: {result:?}"
        );
    }
    let result = idp.receive_sso(
        &sp_descriptor,
        Inbound::redirect(format!(
            "{query}&SAMLEncoding={deflate}&SAMLEncoding={deflate}"
        )),
        validation(),
    );
    assert!(
        matches!(
            result,
            Err(SamlError::DuplicateBindingParameter {
                name: "SAMLEncoding",
                ..
            })
        ),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn typed_redirect_matches_percent_encoded_parameter_names() -> Result<(), Box<dyn std::error::Error>>
{
    let sp = sp_with(signing_sp_validation())?;
    let idp = idp_with(signed_authn_request_idp_validation())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let relay_state = RelayState::try_new("encoded-names")?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::redirect().relay_state(relay_state),
    )?;
    let query = redirect_query(started.outbound.redirect_url()?)?
        .replace("SigAlg=", "Sig%41lg=")
        .replace("RelayState=", "Relay%53tate=");

    let received = idp.receive_sso(&sp_descriptor, Inbound::redirect(query), validation())?;
    assert_eq!(received.message().id(), started.pending.request_id());
    assert_eq!(
        received.relay_state().map(RelayState::as_str),
        Some("encoded-names")
    );
    Ok(())
}
