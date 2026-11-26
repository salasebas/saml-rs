//! Identity-provider refusals of an `AuthnRequest` whose content it cannot
//! read after it authenticated the request.
//!
//! Profiles §4.1.4.1 requires an identity provider that cannot satisfy a
//! request to answer with an error `Response`, and Core §3.2.1 makes that
//! status `Requester`. Core §3.2.2.2 defines `UnsupportedBinding` for a
//! `ProtocolBinding` the responder cannot use.
#![cfg(crypto)]

mod common;

use common::signing_credentials;

use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::constants::status_code::UNSUPPORTED_BINDING;
use saml_rs::{
    AcsEndpoint, AuthnRequest, AuthnRequestRefusalReason, AuthnRequestValidationPolicy, EntityId,
    FormField, IdentityProvider, IdpConfig, IdpDescriptor, IdpValidationPolicy, Inbound,
    MetadataTrustPolicy, OutboundDelivery, RefusedAuthnRequest, ReplayPolicy, RespondSso,
    SamlError, SamlValidationContext, ServiceProvider, SpConfig, SpDescriptor, SsoEndpoint,
    StartSso, Started, Status, SubordinateStatusCode,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const SP_SECOND_ACS: &str = "https://sp.example.com/acs/second";
const UNLISTED_ACS: &str = "https://attacker.example/acs";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
const SOAP: &str = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";
const PAOS: &str = "urn:oasis:names:tc:SAML:2.0:bindings:PAOS";
const SECOND_SUBJECT: &str = concat!(
    "<saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>",
    "<saml:Subject><saml:NameID>bob@example.com</saml:NameID></saml:Subject>",
);
const SECOND_REQUESTED_AUTHN_CONTEXT: &str = concat!(
    "<samlp:RequestedAuthnContext><saml:AuthnContextClassRef>",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard",
    "</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>",
    "<samlp:RequestedAuthnContext><saml:AuthnContextClassRef>",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
    "</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>",
);

struct Peers {
    sp: ServiceProvider,
    idp: IdentityProvider,
    sp_descriptor: SpDescriptor,
    idp_descriptor: IdpDescriptor,
}

fn peers(validation: IdpValidationPolicy) -> Result<Peers, Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(SP_ACS)?.with_index(0).with_default(),
        )
        .acs_endpoint(AcsEndpoint::post(SP_SECOND_ACS)?.with_index(1))
        .credentials(signing_credentials())
        .build()?,
    );
    let idp = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO_POST)?,
        )
        .credentials(signing_credentials())
        .validation(validation)
        .build()?,
    );
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
    Ok(Peers {
        sp,
        idp,
        sp_descriptor,
        idp_descriptor,
    })
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache)
}

fn request_xml(started: &Started<AuthnRequest>) -> Result<String, Box<dyn std::error::Error>> {
    let OutboundDelivery::PostForm(form) = started.outbound.delivery() else {
        return Err("expected an HTTP-POST AuthnRequest".into());
    };
    Ok(String::from_utf8(STANDARD.decode(
        form.value("SAMLRequest").ok_or("missing SAMLRequest")?,
    )?)?)
}

/// `xml` with the root attribute `name` set to `value`, replacing the value
/// the service provider wrote or adding the attribute.
fn with_root_attribute(
    xml: &str,
    name: &str,
    value: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let root_end = xml.find('>').ok_or("missing AuthnRequest start tag")?;
    let needle = format!(" {name}=\"");
    if let Some(start) = xml[..root_end].find(&needle) {
        let value_start = start + needle.len();
        let value_end = value_start + xml[value_start..].find('"').ok_or("unclosed attribute")?;
        return Ok(format!(
            "{}{value}{}",
            &xml[..value_start],
            &xml[value_end..]
        ));
    }
    let insert_at = xml.find(' ').ok_or("missing AuthnRequest attributes")?;
    Ok(format!(
        "{} {name}=\"{value}\"{}",
        &xml[..insert_at],
        &xml[insert_at..]
    ))
}

fn before_name_id_policy(xml: &str, element: &str) -> Result<String, Box<dyn std::error::Error>> {
    let position = xml
        .find("<samlp:NameIDPolicy")
        .ok_or("missing NameIDPolicy")?;
    Ok(format!("{}{element}{}", &xml[..position], &xml[position..]))
}

fn after_name_id_policy(xml: &str, element: &str) -> Result<String, Box<dyn std::error::Error>> {
    let position = xml
        .find("<samlp:NameIDPolicy")
        .ok_or("missing NameIDPolicy")?;
    let end = position + xml[position..].find("/>").ok_or("unclosed NameIDPolicy")? + 2;
    Ok(format!("{}{element}{}", &xml[..end], &xml[end..]))
}

fn receive(peers: &Peers, xml: &str) -> Result<saml_rs::Received<AuthnRequest>, SamlError> {
    peers.idp.receive_sso(
        &peers.sp_descriptor,
        Inbound::post(vec![FormField::new(
            "SAMLRequest",
            STANDARD.encode(xml.as_bytes()),
        )]),
        validation(),
    )
}

fn refused(
    peers: &Peers,
    xml: &str,
) -> Result<Box<RefusedAuthnRequest>, Box<dyn std::error::Error>> {
    match receive(peers, xml) {
        Err(SamlError::AuthnRequestRefused { refusal, .. }) => Ok(refusal),
        other => Err(format!("expected refusal data, got {other:?}").into()),
    }
}

/// The status of the refusal's response, as the service provider that sent
/// `started` reads it, after checking that the response went to `acs`.
fn answered_status(
    peers: &Peers,
    started: &Started<AuthnRequest>,
    refusal: &RefusedAuthnRequest,
    acs: &str,
) -> Result<Status, Box<dyn std::error::Error>> {
    let response =
        peers
            .idp
            .respond_sso_refusal(&peers.sp_descriptor, refusal, RespondSso::post())?;
    let form = response.post_form()?;
    assert_eq!(form.action().as_str(), acs);
    match peers.sp.finish_sso(
        &peers.idp_descriptor,
        &started.pending,
        Inbound::post(form.fields().to_vec()),
        validation(),
    ) {
        Err(SamlError::StatusNotSuccess { status, .. }) => Ok(status),
        other => Err(format!("expected a correlated error status, got {other:?}").into()),
    }
}

#[test]
fn an_unusable_protocol_binding_is_answered_at_the_default_acs_with_unsupported_binding(
) -> TestResult {
    let peers = peers(IdpValidationPolicy::default())?;
    for binding in [REDIRECT, SOAP, PAOS, "urn:example:binding"] {
        let started = peers
            .sp
            .start_sso(&peers.idp_descriptor, StartSso::post())?;
        let xml = with_root_attribute(&request_xml(&started)?, "ProtocolBinding", binding)?;
        let xml = with_root_attribute(&xml, "AssertionConsumerServiceURL", UNLISTED_ACS)?;

        let refusal = refused(&peers, &xml)?;
        assert_eq!(
            refusal.reason(),
            AuthnRequestRefusalReason::UnsupportedProtocolBinding,
            "{binding}",
        );
        assert!(refusal.content_error().is_some(), "{binding}");

        let status = answered_status(&peers, &started, &refusal, SP_ACS)?;
        assert_eq!(
            status,
            Status::requester()
                .with_subordinate(SubordinateStatusCode::try_new(UNSUPPORTED_BINDING)?),
            "{binding}",
        );
    }
    Ok(())
}

#[test]
fn an_unreadable_acs_url_or_index_is_answered_at_the_default_acs_with_requester() -> TestResult {
    let peers = peers(IdpValidationPolicy::default())?;
    for (url, binding, index) in [
        (SP_SECOND_ACS, None, Some(" 1 0 ")),
        (
            "urn:example:acs",
            Some("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"),
            None,
        ),
    ] {
        let started = peers
            .sp
            .start_sso(&peers.idp_descriptor, StartSso::post())?;
        let mut xml =
            with_root_attribute(&request_xml(&started)?, "AssertionConsumerServiceURL", url)?;
        if let Some(binding) = binding {
            xml = with_root_attribute(&xml, "ProtocolBinding", binding)?;
        }
        if let Some(index) = index {
            xml = with_root_attribute(&xml, "AssertionConsumerServiceIndex", index)?;
        }

        let refusal = refused(&peers, &xml)?;
        assert_eq!(
            refusal.reason(),
            AuthnRequestRefusalReason::MalformedRequest,
            "{url}"
        );

        let status = answered_status(&peers, &started, &refusal, SP_ACS)?;
        assert_eq!(status, Status::requester(), "{url}");
    }
    Ok(())
}

#[test]
fn malformed_content_is_answered_at_the_requested_acs_with_requester() -> TestResult {
    let peers = peers(IdpValidationPolicy::default())?;
    let started = peers
        .sp
        .start_sso(&peers.idp_descriptor, StartSso::post().acs_index(1))?;
    let xml = request_xml(&started)?;
    for (element, insert) in [
        ("Subject", before_name_id_policy(&xml, SECOND_SUBJECT)),
        (
            "RequestedAuthnContext",
            after_name_id_policy(&xml, SECOND_REQUESTED_AUTHN_CONTEXT),
        ),
    ] {
        let refusal = refused(&peers, &insert?)?;
        assert_eq!(
            refusal.reason(),
            AuthnRequestRefusalReason::MalformedRequest,
            "{element}"
        );
        assert!(matches!(
            refusal.content_error(),
            Some(SamlError::Invalid(message)) if message.contains(&format!("{element} must occur once"))
        ));

        let status = answered_status(&peers, &started, &refusal, SP_SECOND_ACS)?;
        assert_eq!(status, Status::requester(), "{element}");
    }
    Ok(())
}

#[test]
fn signature_policy_destination_and_content_keep_their_order() -> TestResult {
    let peers = peers(IdpValidationPolicy::default())?;
    let started = peers
        .sp
        .start_sso(&peers.idp_descriptor, StartSso::post())?;
    let malformed = before_name_id_policy(&request_xml(&started)?, SECOND_SUBJECT)?;

    let mut require_signed = IdpValidationPolicy::default();
    require_signed.authn_request_signatures = AuthnRequestValidationPolicy::RequireSigned;
    assert_eq!(
        refused(&self::peers(require_signed)?, &malformed)?.reason(),
        AuthnRequestRefusalReason::Unsigned
    );

    let elsewhere =
        with_root_attribute(&malformed, "Destination", "https://idp.example.com/other")?;
    assert!(matches!(
        receive(&peers, &elsewhere),
        Err(SamlError::DestinationMismatch { .. })
    ));

    let repeated_policy = before_name_id_policy(&malformed, "<samlp:NameIDPolicy/>")?;
    assert_eq!(
        refused(&peers, &repeated_policy)?.reason(),
        AuthnRequestRefusalReason::MalformedRequest
    );
    Ok(())
}
