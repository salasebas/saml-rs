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

use saml_rs::binding::{base64_decode, deflate_raw_decode};
use saml_rs::{
    AcsEndpoint, AssertionSignaturePolicy, AudienceValidationPolicy, AuthnRequest,
    AuthnRequestSigningPolicy, AuthnRequestValidationPolicy, BrowserInput, Credentials, EntityId,
    FormField, IdpConfig, IdpDescriptor, IdpValidationPolicy, MetadataTrustPolicy, NameId,
    PrivateKeyPem, RelayState, RelayStateParam, ReplayPolicy, RespondSso, Saml, SamlError,
    SamlValidationContext, SpConfig, SpDescriptor, SpValidationPolicy, SsoEndpoint, SsoResponse,
    StartSso, Subject, TemplatePolicy, MAX_RECEIVED_RELAY_STATE_BYTES, MAX_RELAY_STATE_BYTES,
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
    Credentials {
        signing_key: Some(PrivateKeyPem::new(PRIVKEY)),
        signing_certificate: Some(saml_rs::CertificatePem::new(CERT)),
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

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility)
}

fn subject() -> Subject {
    Subject::new(NameId::new("alice@example.com", None), Vec::new())
}

fn sp_with(
    validation: SpValidationPolicy,
    templates: TemplatePolicy,
) -> Result<Saml<saml_rs::Sp>, SamlError> {
    Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS_POST)?.mark_default())
            .acs_endpoint(AcsEndpoint::simple_sign(SP_ACS_SIMPLESIGN)?)
            .credentials(credentials())
            .validation(validation)
            .templates(templates)
            .build()?,
    )
}

fn idp_with(validation: IdpValidationPolicy) -> Result<Saml<saml_rs::Idp>, SamlError> {
    Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
            .sso_endpoint(SsoEndpoint::redirect(IDP_SSO_REDIRECT)?)
            .sso_endpoint(SsoEndpoint::simple_sign(IDP_SSO_SIMPLESIGN)?)
            .credentials(credentials())
            .validation(validation)
            .build()?,
    )
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

fn redirect_xml(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let parsed = Url::parse(url)?;
    let encoded = parsed
        .query_pairs()
        .find(|(name, _)| name == "SAMLRequest")
        .map(|(_, value)| value.into_owned())
        .ok_or("missing SAMLRequest")?;
    Ok(String::from_utf8(deflate_raw_decode(&base64_decode(
        &encoded,
    )?)?)?)
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
    assert!(RelayStateParam::try_from_option(Some("a".repeat(MAX_RELAY_STATE_BYTES + 1))).is_err());
    let relay_state = RelayStateParam::try_from_option(Some("a".repeat(MAX_RELAY_STATE_BYTES)))?;

    let sp = sp_with(SpValidationPolicy::recommended(), TemplatePolicy::default())?;
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
    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::redirect(query),
        validation(),
    )?;
    let reused = received.relay_state().clone();
    match idp.initiate_sso(
        &sp_descriptor,
        subject(),
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

    let templates = TemplatePolicy {
        relay_state: "b".repeat(MAX_RELAY_STATE_BYTES + 1),
        ..TemplatePolicy::default()
    };
    let sp = sp_with(SpValidationPolicy::recommended(), templates)?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    match sp.start_sso(&idp_descriptor, StartSso::redirect()) {
        Err(SamlError::Invalid(message)) if message.contains("80") => Ok(()),
        other => Err(format!("expected the 80-byte RelayState prohibition, got {other:?}").into()),
    }
}

#[test]
fn typed_sso_accepts_and_echoes_received_relay_state_up_to_the_receive_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    let long = "c".repeat(200);
    let sp = sp_with(SpValidationPolicy::recommended(), TemplatePolicy::default())?;
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
        BrowserInput::<AuthnRequest>::redirect(request_query(&long)?),
        validation(),
    )?;
    assert_eq!(received.relay_state().as_deref(), Some(long.as_str()));

    let response = idp.respond_sso(&sp_descriptor, &received, subject(), RespondSso::post())?;
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
        BrowserInput::<SsoResponse>::post(response_fields),
        validation(),
    )?;
    assert_eq!(session.relay_state().as_deref(), Some(long.as_str()));

    let unsolicited = idp.initiate_sso(&sp_descriptor, subject(), RespondSso::post())?;
    let mut fields = unsolicited.post_form()?.fields().to_vec();
    fields.push(FormField::new("RelayState", long.as_str()));
    let session = sp.accept_unsolicited_sso(
        &idp_descriptor,
        BrowserInput::<SsoResponse>::post(fields),
        validation(),
    )?;
    assert_eq!(session.relay_state().as_deref(), Some(long.as_str()));
    Ok(())
}

#[test]
fn typed_sso_rejects_received_relay_state_above_the_receive_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    let too_long = "d".repeat(MAX_RECEIVED_RELAY_STATE_BYTES + 1);
    let sp = sp_with(SpValidationPolicy::recommended(), TemplatePolicy::default())?;
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
        BrowserInput::<AuthnRequest>::redirect(format!("{query}&RelayState={too_long}")),
        validation(),
    ) {
        Err(SamlError::Invalid(message)) if message.contains("receive limit") => {}
        other => {
            return Err(format!("expected the RelayState receive limit, got {other:?}").into())
        }
    }

    let response = idp.initiate_sso(&sp_descriptor, subject(), RespondSso::post())?;
    let mut fields = response.post_form()?.fields().to_vec();
    fields.push(FormField::new("RelayState", too_long));
    match sp.accept_unsolicited_sso(
        &idp_descriptor,
        BrowserInput::<SsoResponse>::post(fields),
        validation(),
    ) {
        Err(SamlError::Invalid(message)) if message.contains("receive limit") => Ok(()),
        other => Err(format!("expected the RelayState receive limit, got {other:?}").into()),
    }
}

fn expect_ambiguous_relay_state<T: std::fmt::Debug>(
    entry_point: &str,
    result: Result<T, SamlError>,
) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Err(SamlError::Invalid(message)) if message == "ambiguous form field" => Ok(()),
        other => Err(format!(
            "expected {entry_point} to refuse a repeated RelayState, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn typed_sso_rejects_a_repeated_relay_state() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(SpValidationPolicy::recommended(), TemplatePolicy::default())?;
    let idp = idp_with(IdpValidationPolicy::recommended())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let relay_state = RelayStateParam::try_from_option(Some("state".to_string()))?;

    let started = sp.start_sso(&idp_descriptor, StartSso::post().relay_state(relay_state))?;
    let mut request_fields = started.outbound.post_form()?.fields().to_vec();
    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(request_fields.clone()),
        validation(),
    )?;
    request_fields.push(FormField::new("RelayState", "https://evil.example/"));
    expect_ambiguous_relay_state(
        "receive_sso over HTTP-POST",
        idp.receive_sso(
            &sp_descriptor,
            BrowserInput::<AuthnRequest>::post(request_fields),
            validation(),
        ),
    )?;

    let response = idp.respond_sso(&sp_descriptor, &received, subject(), RespondSso::post())?;
    let mut response_fields = response.post_form()?.fields().to_vec();
    response_fields.push(FormField::new("RelayState", "https://evil.example/"));
    expect_ambiguous_relay_state(
        "finish_sso",
        sp.finish_sso(
            &idp_descriptor,
            &started.pending,
            BrowserInput::<SsoResponse>::post(response_fields),
            validation(),
        ),
    )?;

    let unsolicited = idp.initiate_sso(&sp_descriptor, subject(), RespondSso::post())?;
    let mut unsolicited_fields = unsolicited.post_form()?.fields().to_vec();
    unsolicited_fields.push(FormField::new("RelayState", "a"));
    unsolicited_fields.push(FormField::new("RelayState", "b"));
    expect_ambiguous_relay_state(
        "accept_unsolicited_sso",
        sp.accept_unsolicited_sso(
            &idp_descriptor,
            BrowserInput::<SsoResponse>::post(unsolicited_fields),
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
                BrowserInput::<AuthnRequest>::redirect(format!("{query}&{repeated}")),
                validation(),
            ),
        )?;
    }
    Ok(())
}

#[test]
fn typed_redirect_removes_protocol_signature_and_verifies_parameter_order(
) -> Result<(), Box<dyn std::error::Error>> {
    let templates = TemplatePolicy {
        login_request_template: Some(SIGNED_AUTHN_REQUEST_TEMPLATE.to_string()),
        ..TemplatePolicy::default()
    };
    let unsigned_sp = sp_with(SpValidationPolicy::recommended(), templates.clone())?;
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

    let sp = sp_with(signing_sp_validation(), templates)?;
    let idp = idp_with(signed_authn_request_idp_validation())?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    let relay_state = RelayStateParam::try_from_option(Some("ordered-state".to_string()))?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::redirect().relay_state(relay_state),
    )?;
    let url = started.outbound.redirect_url()?.to_string();
    let xml = redirect_xml(&url)?;
    saml_rs::xml::dom::parse(&xml)?;
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

    let sp = sp_with(signing_sp_validation(), TemplatePolicy::default())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let relay_state = RelayStateParam::try_from_option(Some("ordered-state".to_string()))?;
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
    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::redirect(reordered),
        validation(),
    )?;
    assert_eq!(received.message().id(), started.pending.request_id());
    assert_eq!(received.relay_state().as_deref(), Some("ordered-state"));
    Ok(())
}

#[test]
fn typed_simplesign_binds_relay_state_to_the_raw_xml_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(signing_sp_validation(), TemplatePolicy::default())?;
    let idp = idp_with(signed_authn_request_idp_validation())?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let relay_state = RelayStateParam::try_from_option(Some("signed-state".to_string()))?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::simple_sign().relay_state(relay_state),
    )?;
    let fields = started.outbound.post_form()?.fields().to_vec();
    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::simple_sign(fields.clone()),
        validation(),
    )?;
    assert_eq!(received.relay_state().as_deref(), Some("signed-state"));

    let mut tampered = fields;
    let relay = tampered
        .iter_mut()
        .find(|field| field.name() == "RelayState")
        .ok_or("missing RelayState")?;
    *relay = FormField::new("RelayState", "other-state");
    match idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::simple_sign(tampered),
        validation(),
    ) {
        Err(SamlError::SignatureVerification { .. }) => Ok(()),
        other => Err(format!(
            "expected SimpleSign to reject a RelayState the octet string did not cover, got {other:?}"
        )
        .into()),
    }
}
