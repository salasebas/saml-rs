//! Typed HTTP-Redirect and HTTP-POST-SimpleSign binding rules.
//!
//! Bindings §3.4.3 and §3.5.3, and HTTP-POST-SimpleSign CD-04 §2.3, prohibit
//! the entity creating a message from sending a RelayState longer than 80
//! bytes, and require a responder to return the exact RelayState it received.
//! Bindings §3.4.4.1 requires HTTP-Redirect to remove a protocol XML signature
//! before DEFLATE and to verify the detached signature over parameters in a
//! fixed order. CD-04 §2.5 and §2.6 require
//! SimpleSign to sign the raw XML octets, including RelayState when present.
#![cfg(crypto)]

use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::binding::{deflate_raw_decode, MAX_DEFLATE_RAW_DECODE_BYTES};
use saml_rs::{
    AcsEndpoint, AssertionSignaturePolicy, AudienceValidationPolicy, AuthnRequestSigningPolicy,
    AuthnRequestValidationPolicy, Credentials, EntityId, FormField, IdentityProvider, IdpConfig,
    IdpDescriptor, IdpValidationPolicy, Inbound, MetadataTrustPolicy, NameId, PrivateKeyPem,
    RelayState, ReplayPolicy, RespondSso, SamlError, SamlValidationContext, ServiceProvider,
    SpConfig, SpConfigBuilder, SpDescriptor, SpValidationPolicy, SsoAssertion, SsoEndpoint,
    StartSso, X509Credential, MAX_RECEIVED_RELAY_STATE_BYTES, MAX_RELAY_STATE_BYTES,
};
use url::Url;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS_POST: &str = "https://sp.example.com/acs/post";
const SP_ACS_SIMPLESIGN: &str = "https://sp.example.com/acs/simple-sign";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const IDP_SSO_REDIRECT: &str = "https://idp.example.com/sso/redirect";
const IDP_SSO_SIMPLESIGN: &str = "https://idp.example.com/sso/simple-sign";

const PRIVKEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");

const SIGNED_AUTHN_REQUEST_TEMPLATE: &str = r#"
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}">
    <saml:Issuer>{Issuer}</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignatureValue>protocol-signature</ds:SignatureValue>
    </ds:Signature>
    <saml:Assertion>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignatureValue>assertion-signature</ds:SignatureValue>
        </ds:Signature>
    </saml:Assertion>
</samlp:AuthnRequest>
"#;

fn credentials() -> Credentials {
    Credentials::default().with_signing_credential(X509Credential::new(
        saml_rs::CertificatePem::new(CERT),
        PrivateKeyPem::new(PRIVKEY),
    ))
}

fn signing_sp_validation() -> SpValidationPolicy {
    let mut validation = SpValidationPolicy::recommended();
    validation.assertions = AssertionSignaturePolicy::RequireSigned;
    validation.authn_requests = AuthnRequestSigningPolicy::Sign;
    validation.audience = AudienceValidationPolicy::RequireRestriction;
    validation
}

fn signed_authn_request_idp_validation() -> IdpValidationPolicy {
    let mut validation = IdpValidationPolicy::recommended();
    validation.authn_requests = AuthnRequestValidationPolicy::RequireSigned;
    validation
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::Disabled)
}

fn principal() -> NameId {
    NameId::new("alice@example.com")
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
    Ok(IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO_POST)?,
        )
        .sso_endpoint(SsoEndpoint::redirect(IDP_SSO_REDIRECT)?)
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
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    Ok((sp_descriptor, idp_descriptor))
}

fn redirect_xml(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let parsed = Url::parse(url)?;
    let encoded = parsed
        .query_pairs()
        .find(|(name, _)| name == "SAMLRequest")
        .map(|(_, value)| value.into_owned())
        .ok_or("missing SAMLRequest")?;
    Ok(String::from_utf8(deflate_raw_decode(
        &STANDARD.decode(&encoded)?,
        MAX_DEFLATE_RAW_DECODE_BYTES,
    )?)?)
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

    let sp = sp_with(SpValidationPolicy::recommended())?;
    let idp = idp_with(IdpValidationPolicy::recommended())?;
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
        SsoAssertion::new(principal()),
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
    let sp = sp_with(SpValidationPolicy::recommended())?;
    let idp = idp_with(IdpValidationPolicy::recommended())?;
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
    let sp = sp_with(SpValidationPolicy::recommended())?;
    let idp = idp_with(IdpValidationPolicy::recommended())?;
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
        SsoAssertion::new(principal()),
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
        validation(),
    )?;
    assert_eq!(
        session.relay_state().map(RelayState::as_str),
        Some(long.as_str())
    );

    let unsolicited = idp.initiate_sso(
        &sp_descriptor,
        SsoAssertion::new(principal()),
        RespondSso::post(),
    )?;
    let mut fields = unsolicited.post_form()?.fields().to_vec();
    fields.push(FormField::new("RelayState", long.as_str()));
    let session =
        sp.accept_unsolicited_sso(&idp_descriptor, Inbound::post(fields), validation())?;
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
    let sp = sp_with(SpValidationPolicy::recommended())?;
    let idp = idp_with(IdpValidationPolicy::recommended())?;
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
        SsoAssertion::new(principal()),
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
    let sp = sp_with(SpValidationPolicy::recommended())?;
    let idp = idp_with(IdpValidationPolicy::recommended())?;
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
        SsoAssertion::new(principal()),
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
        SsoAssertion::new(principal()),
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
fn typed_redirect_removes_protocol_signature_and_verifies_parameter_order(
) -> Result<(), Box<dyn std::error::Error>> {
    let unsigned_sp = ServiceProvider::new(
        sp_config(SpValidationPolicy::recommended())?
            .authn_request_template(SIGNED_AUTHN_REQUEST_TEMPLATE)
            .build()?,
    );
    let recommended_idp = idp_with(IdpValidationPolicy::recommended())?;
    let (_, idp_descriptor) = descriptors(&unsigned_sp, &recommended_idp)?;
    match unsigned_sp.start_sso(&idp_descriptor, StartSso::redirect()) {
        Err(SamlError::ProtocolProfile(message)) if message.contains("HTTP-Redirect") => {}
        other => {
            return Err(format!(
                "expected unsigned HTTP-Redirect to reject a protocol XML signature, got {other:?}"
            )
            .into())
        }
    }

    let sp = ServiceProvider::new(
        sp_config(signing_sp_validation())?
            .authn_request_template(SIGNED_AUTHN_REQUEST_TEMPLATE)
            .build()?,
    );
    let idp = idp_with(signed_authn_request_idp_validation())?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    let relay_state = RelayState::try_new("ordered-state")?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::redirect().relay_state(relay_state),
    )?;
    let url = started.outbound.redirect_url()?.to_string();
    let xml = redirect_xml(&url)?;
    roxmltree::Document::parse(&xml)?;
    if xml.contains("protocol-signature") || !xml.contains("assertion-signature") {
        return Err(
            "HTTP-Redirect must drop the protocol signature and keep an assertion signature".into(),
        );
    }
    assert_eq!(
        query_names(&url)?,
        vec![
            "SAMLRequest".to_string(),
            "RelayState".to_string(),
            "SigAlg".to_string(),
            "Signature".to_string(),
        ]
    );

    let sp = sp_with(signing_sp_validation())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let relay_state = RelayState::try_new("ordered-state")?;
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
