//! Artifact resolution over SOAP, through the typed identity provider and
//! service provider.
//!
//! The identity provider stores a protocol message and answers `ArtifactResolve`.
//! The service provider sends that request and reads the message from
//! `ArtifactResponse`. The deployment still performs HTTP and TLS.
//!
//! Config helpers relax the policy fields that need a crypto provider, so they
//! build without one for unsigned artifact resolution.

#[path = "artifact_resolution/schema_validation.rs"]
mod schema_validation;

#[path = "common/policies_without_crypto.rs"]
mod policies_without_crypto;

#[path = "common/tag_prefixes.rs"]
mod tag_prefixes;

use policies_without_crypto::sp_validation_without_crypto;

use std::time::{Duration, SystemTime};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::XmlLimits;
use saml_rs::{
    AcsEndpoint, Artifact, ArtifactRelease, ArtifactResolutionService, ArtifactWithheld,
    EndpointUrl, EntityId, HttpHeader, IdentityProvider, IdpConfig, IdpDescriptor,
    InMemoryReplayCache, IssuedArtifacts, MessageConfidentiality, MessageIntegrity,
    MetadataTrustPolicy, PartyAuthentication, ReplayKey, ReplayPolicy, SamlError,
    SamlValidationContext, ServiceProvider, SoapChannel, SpConfig, SpDescriptor, SsoEndpoint,
    TimeWindowField, XmlPolicy,
};

const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const OTHER_ENTITY_ID: &str = "https://other.example.com/metadata";
const RESOLUTION_URL: &str = "https://idp.example.com/artifact";
const ARTIFACT_LIFETIME: Duration = Duration::from_secs(60);
const BLOCKED_FOR: Duration = Duration::from_secs(10 * 60);
const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
const VERSION_MISMATCH: &str = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";
const SOAP_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";
const WEB_SSO_MARKER: &str = "web-sso-artifact-marker";
const LOGOUT_MARKER: &str = "logout-artifact-marker";

/// SHA-1 of `https://idp.example.com/metadata`, from Python `hashlib.sha1`.
const IDP_SOURCE_ID: &str = "d7070df08eacb863523f9c79f8215dc969a7813d";

struct Parties {
    idp: IdentityProvider,
    sp: ServiceProvider,
    other: ServiceProvider,
    idp_metadata: IdpDescriptor,
    sp_metadata: SpDescriptor,
    other_metadata: SpDescriptor,
}

fn parties() -> Result<Parties, Box<dyn std::error::Error>> {
    parties_with(XmlPolicy::default())
}

fn parties_with(xml: XmlPolicy) -> Result<Parties, Box<dyn std::error::Error>> {
    parties_with_templates(xml, Default::default(), Default::default())
}

fn parties_with_templates(
    xml: XmlPolicy,
    idp_templates: saml_rs::TemplatePolicy,
    sp_templates: saml_rs::TemplatePolicy,
) -> Result<Parties, Box<dyn std::error::Error>> {
    let idp = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::redirect("https://idp.example.com/sso")?,
        )
        .artifact_resolution_service(ArtifactResolutionService::new(
            0,
            EndpointUrl::try_new(RESOLUTION_URL)?,
        ))
        .templates(idp_templates)
        .xml(xml)
        .build()?,
    );
    let sp = service_provider(
        SP_ENTITY_ID,
        "https://sp.example.com/acs",
        xml,
        sp_templates,
    )?;
    let other = service_provider(
        OTHER_ENTITY_ID,
        "https://other.example.com/acs",
        xml,
        Default::default(),
    )?;
    let idp_metadata = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let sp_metadata = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let other_metadata = SpDescriptor::from_metadata_xml(
        EntityId::try_new(OTHER_ENTITY_ID)?,
        other.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    Ok(Parties {
        idp,
        sp,
        other,
        idp_metadata,
        sp_metadata,
        other_metadata,
    })
}

fn service_provider(
    entity_id: &str,
    acs: &str,
    xml: XmlPolicy,
    templates: saml_rs::TemplatePolicy,
) -> Result<ServiceProvider, Box<dyn std::error::Error>> {
    Ok(ServiceProvider::new(
        SpConfig::builder(EntityId::try_new(entity_id)?, AcsEndpoint::post(acs)?)
            .templates(templates)
            .xml(xml)
            .validation(sp_validation_without_crypto())
            .build()?,
    ))
}

fn web_sso_response() -> String {
    format!(
        r#"<samlp:Response xmlns:samlp="{PROTOCOL}" ID="_response" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">{WEB_SSO_MARKER}</samlp:Response>"#
    )
}

fn logout_request() -> String {
    format!(
        r#"<samlp:LogoutRequest xmlns:samlp="{PROTOCOL}" ID="_logout" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">{LOGOUT_MARKER}</samlp:LogoutRequest>"#
    )
}

fn single_use(cache: &mut InMemoryReplayCache) -> SamlValidationContext<'_> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(cache))
        .with_replay_retention(BLOCKED_FOR)
}

fn without_replay_cache() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache)
}

fn header_pairs(headers: &[HttpHeader]) -> Vec<(&str, &str)> {
    headers
        .iter()
        .map(|header| (header.name(), header.value()))
        .collect()
}

fn confidential() -> SoapChannel {
    SoapChannel::mutually_authenticated_confidential()
}

fn authenticated_without_confidentiality() -> SoapChannel {
    SoapChannel::new(
        PartyAuthentication::Mutual,
        MessageIntegrity::Protected,
        MessageConfidentiality::Unattested,
    )
}

fn issue(
    parties: &Parties,
    message: &str,
    issued: &mut IssuedArtifacts,
) -> Result<Artifact, SamlError> {
    parties
        .idp
        .issue_artifact(&parties.sp_metadata, message, 0, issued)
}

fn decode_artifact(artifact: &Artifact) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(STANDARD.decode(artifact.as_str())?)
}

fn recode(
    artifact: &Artifact,
    edit: impl FnOnce(&mut [u8]),
) -> Result<Artifact, Box<dyn std::error::Error>> {
    let mut bytes = decode_artifact(artifact)?;
    edit(&mut bytes);
    Ok(Artifact::try_new(STANDARD.encode(bytes))?)
}

fn remove_attribute(xml: &str, name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let key = format!("{name}=\"");
    let start = xml.find(&key).ok_or_else(|| format!("{name} is missing"))?;
    let value_end = xml[start + key.len()..]
        .find('"')
        .ok_or_else(|| format!("{name} is missing its closing quote"))?
        + start
        + key.len();
    let from = if start > 0 && xml.as_bytes()[start - 1] == b' ' {
        start - 1
    } else {
        start
    };
    let mut without = xml.to_string();
    without.replace_range(from..=value_end, "");
    Ok(without)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(not(crypto))]
#[test]
fn present_artifact_signatures_require_a_crypto_provider() -> Result<(), Box<dyn std::error::Error>>
{
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let with_signature = |envelope: &str| {
        envelope.replacen(
            "</saml:Issuer>",
            r#"</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>"#,
            1,
        )
    };
    let request = resolution.request().envelope();
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        &with_signature(request),
        &mut issued,
        channel,
    );
    assert!(
        matches!(answer, Err(SamlError::Unsupported(_))),
        "{answer:?}"
    );

    let answer =
        parties
            .idp
            .answer_artifact_resolve(&parties.sp_metadata, request, &mut issued, channel)?;
    let envelope = answer.response().envelope();
    let result = resolution.finish(&with_signature(envelope));
    assert!(
        matches!(result, Err(SamlError::Unsupported(_))),
        "{result:?}"
    );
    assert!(resolution.finish(envelope)?.xml().contains(WEB_SSO_MARKER));
    Ok(())
}

#[test]
fn web_browser_sso_round_trip_returns_the_stored_response() -> Result<(), Box<dyn std::error::Error>>
{
    let parties = parties_with_templates(
        XmlPolicy::default(),
        tag_prefixes::templates("i", "ia"),
        tag_prefixes::templates("p", "a"),
    )?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let request = resolution.request();
    assert_eq!(request.endpoint().as_str(), RESOLUTION_URL);
    assert_eq!(
        header_pairs(request.headers()),
        [
            ("Content-Type", "text/xml; charset=utf-8"),
            (
                "SOAPAction",
                "http://www.oasis-open.org/committees/security"
            ),
            ("Cache-Control", "no-cache, no-store"),
            ("Pragma", "no-cache"),
        ]
    );
    assert!(request.envelope().contains("<p:ArtifactResolve "));
    assert!(request.envelope().contains(artifact.as_str()));
    assert!(request
        .envelope()
        .contains(&format!("<a:Issuer>{SP_ENTITY_ID}</a:Issuer>")));
    assert!(request
        .envelope()
        .contains(&format!("Destination=\"{RESOLUTION_URL}\"")));
    assert!(!request.envelope().contains("Format="));

    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        request.envelope(),
        &mut issued,
        channel,
    )?;
    assert_eq!(answer.release(), ArtifactRelease::Returned);
    assert_eq!(
        header_pairs(answer.response().headers()),
        [
            ("Content-Type", "text/xml; charset=utf-8"),
            (
                "Cache-Control",
                "no-cache, no-store, must-revalidate, private"
            ),
            ("Pragma", "no-cache"),
        ]
    );
    assert!(answer
        .response()
        .envelope()
        .contains("<i:ArtifactResponse "));
    assert!(answer.response().envelope().contains(SUCCESS));
    assert!(answer.response().envelope().contains("<ia:Issuer>"));
    assert!(answer.response().envelope().contains(&web_sso_response()));

    let resolved = resolution.finish(answer.response().envelope())?;
    assert_eq!(resolved.local_name(), "Response");
    assert!(resolved.xml().contains(WEB_SSO_MARKER));
    assert!(!resolved.xml().contains("ArtifactResponse"));
    Ok(())
}

#[test]
fn a_different_presenter_does_not_receive_the_message() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let channel = confidential();
    let hostile = parties.other.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.other_metadata,
        hostile.request().envelope(),
        &mut issued,
        channel,
    )?;
    assert_eq!(
        answer.release(),
        ArtifactRelease::Withheld(ArtifactWithheld::DifferentPresenter)
    );
    assert!(answer.response().envelope().contains(SUCCESS));
    assert!(!answer.response().envelope().contains(WEB_SSO_MARKER));
    assert!(hostile.finish(answer.response().envelope()).is_err());

    let legitimate = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let second = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        legitimate.request().envelope(),
        &mut issued,
        channel,
    )?;
    assert_eq!(second.release(), ArtifactRelease::Returned);
    assert!(second.response().envelope().contains(WEB_SSO_MARKER));
    Ok(())
}

#[test]
fn web_sso_without_confidentiality_withholds_the_message() -> Result<(), Box<dyn std::error::Error>>
{
    let weak = authenticated_without_confidentiality();
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        weak,
    )?;
    assert_eq!(
        answer.release(),
        ArtifactRelease::Withheld(ArtifactWithheld::InsufficientChannelProtection)
    );
    assert!(answer.response().envelope().contains(SUCCESS));
    assert!(!answer.response().envelope().contains(WEB_SSO_MARKER));
    Ok(())
}

#[test]
fn the_issuer_returns_a_web_sso_message_only_once() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let channel = confidential();
    let first_resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let first = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        first_resolution.request().envelope(),
        &mut issued,
        channel,
    )?;
    assert_eq!(first.release(), ArtifactRelease::Returned);
    let second_resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let second = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        second_resolution.request().envelope(),
        &mut issued,
        channel,
    )?;
    assert_eq!(
        second.release(),
        ArtifactRelease::Withheld(ArtifactWithheld::NotOutstanding)
    );
    assert!(!second.response().envelope().contains(WEB_SSO_MARKER));
    Ok(())
}

#[test]
fn identity_provider_metadata_publishes_the_soap_resolution_service(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let xml = parties.idp.metadata_xml();
    assert!(xml.contains("ArtifactResolutionService"));
    assert!(xml.contains(SOAP_BINDING));
    assert!(xml.contains(RESOLUTION_URL));
    assert!(xml.contains("index=\"0\""));

    let without = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::redirect("https://idp.example.com/sso")?,
        )
        .build()?,
    );
    assert!(!without.metadata_xml().contains("ArtifactResolutionService"));
    let peer = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        parties.sp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let missing = without.issue_artifact(&peer, &web_sso_response(), 0, &mut issued);
    assert!(matches!(
        missing,
        Err(SamlError::MissingMetadata(detail)) if detail == "ArtifactResolutionService"
    ));
    Ok(())
}

#[test]
fn artifact_issue_rejects_xml_that_cannot_be_sent_over_soap(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let message = format!(
        r#"<samlp:LogoutRequest xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="_logout" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
            <?trace correlation="request-1"?>
            <saml:NameID>user@example.com</saml:NameID>
        </samlp:LogoutRequest>"#
    );
    let result = issue(&parties, &message, &mut issued);
    assert!(matches!(result, Err(SamlError::Xml { .. })), "{result:?}");
    Ok(())
}

#[test]
fn duplicate_resolution_indexes_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let location = EndpointUrl::try_new(RESOLUTION_URL)?;
    let other = EndpointUrl::try_new("https://idp.example.com/artifact-other")?;
    let built = IdpConfig::builder(
        EntityId::try_new(IDP_ENTITY_ID)?,
        SsoEndpoint::redirect("https://idp.example.com/sso")?,
    )
    .artifact_resolution_service(ArtifactResolutionService::new(0, location))
    .artifact_resolution_service(ArtifactResolutionService::new(0, other))
    .build();
    assert!(matches!(built, Err(SamlError::Invalid(detail)) if detail.contains("duplicate")));
    Ok(())
}

#[test]
fn artifact_source_id_is_the_sha1_of_the_issuer_entity_id() -> Result<(), Box<dyn std::error::Error>>
{
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let bytes = decode_artifact(&artifact)?;
    assert_eq!(bytes.len(), 44);
    assert_eq!(&bytes[0..2], &[0x00, 0x04]);
    assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 0);
    assert_eq!(hex(&bytes[4..24]), IDP_SOURCE_ID);
    assert_eq!(artifact.endpoint_index(), 0);

    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let unpadded = artifact.as_str().trim_end_matches('=').to_string();
    assert_ne!(unpadded, artifact.as_str());
    let request = resolution
        .request()
        .envelope()
        .replace(artifact.as_str(), &unpadded);
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        &request,
        &mut issued,
        channel,
    )?;
    assert_eq!(answer.release(), ArtifactRelease::Returned);
    assert!(answer.response().envelope().contains(WEB_SSO_MARKER));
    Ok(())
}

#[test]
fn a_version_mismatch_does_not_consume_the_artifact() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let envelope = resolution.request().envelope();
    let old_request = envelope.replacen("Version=\"2.0\"", "Version=\"1.1\"", 1);
    assert!(parties
        .idp
        .answer_artifact_resolve(&parties.sp_metadata, &old_request, &mut issued, channel)
        .is_err());
    let mismatched = envelope.replacen("Version=\"2.0\"", "Version=\"3.0\"", 1);
    let rejected = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        &mismatched,
        &mut issued,
        channel,
    )?;
    assert_eq!(rejected.release(), ArtifactRelease::VersionMismatch);
    assert!(rejected.response().envelope().contains(VERSION_MISMATCH));
    assert!(rejected
        .response()
        .envelope()
        .contains("urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh"));
    assert!(!rejected.response().envelope().contains(SUCCESS));
    assert!(!rejected.response().envelope().contains(WEB_SSO_MARKER));

    let accepted = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        channel,
    )?;
    assert_eq!(accepted.release(), ArtifactRelease::Returned);
    assert!(accepted.response().envelope().contains(WEB_SSO_MARKER));
    Ok(())
}

#[test]
fn an_unknown_or_unreadable_artifact_does_not_consume_another(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let unknown = recode(&artifact, |bytes| {
        bytes[43] ^= 0xff;
    })?;
    let unknown_request = resolution
        .request()
        .envelope()
        .replace(artifact.as_str(), unknown.as_str());
    let withheld = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        &unknown_request,
        &mut issued,
        channel,
    )?;
    assert_eq!(
        withheld.release(),
        ArtifactRelease::Withheld(ArtifactWithheld::NotOutstanding)
    );

    let mut broken = artifact.as_str().to_string();
    broken.insert(1, ' ');
    let spaced = resolution
        .request()
        .envelope()
        .replace(artifact.as_str(), &broken);
    let unreadable =
        parties
            .idp
            .answer_artifact_resolve(&parties.sp_metadata, &spaced, &mut issued, channel)?;
    assert_eq!(
        unreadable.release(),
        ArtifactRelease::Withheld(ArtifactWithheld::NotOutstanding)
    );

    let accepted = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        channel,
    )?;
    assert_eq!(accepted.release(), ArtifactRelease::Returned);
    Ok(())
}

#[test]
fn a_destination_mismatch_withholds_the_message_and_leaves_it_outstanding(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let redirected = resolution.request().envelope().replace(
        &format!("Destination=\"{RESOLUTION_URL}\""),
        "Destination=\"https://idp.example.com/elsewhere\"",
    );
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        &redirected,
        &mut issued,
        channel,
    )?;
    assert_eq!(
        answer.release(),
        ArtifactRelease::Withheld(ArtifactWithheld::DestinationMismatch)
    );
    assert!(!answer.response().envelope().contains(WEB_SSO_MARKER));
    let padded = resolution.request().envelope().replace(
        &format!("Destination=\"{RESOLUTION_URL}\""),
        &format!("Destination=\" {RESOLUTION_URL}&#10;\""),
    );
    assert_ne!(padded, resolution.request().envelope());
    let accepted =
        parties
            .idp
            .answer_artifact_resolve(&parties.sp_metadata, &padded, &mut issued, channel)?;
    assert_eq!(accepted.release(), ArtifactRelease::Returned);
    Ok(())
}

#[test]
fn the_service_provider_rejects_a_repeated_artifact() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let channel = confidential();
    let mut uses = InMemoryReplayCache::new();
    parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        single_use(&mut uses),
    )?;
    let repeated = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        single_use(&mut uses),
    );
    assert!(matches!(
        repeated,
        Err(SamlError::ReplayDetected { key: ReplayKey::Artifact(replayed) }) if replayed == artifact
    ));

    parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    Ok(())
}

#[test]
fn a_replay_cache_without_retention_records_nothing() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let mut uses = InMemoryReplayCache::new();
    let unbounded = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        confidential(),
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(&mut uses)),
    );
    assert!(matches!(
        unbounded,
        Err(SamlError::TimeWindowInvalid {
            field: TimeWindowField::ReplayExpiration,
            ..
        })
    ));
    parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        confidential(),
        single_use(&mut uses),
    )?;
    Ok(())
}

#[test]
fn an_artifact_from_another_issuer_is_rejected_before_it_is_recorded(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let foreign = recode(&artifact, |bytes| {
        bytes[4] ^= 0xff;
    })?;
    let channel = confidential();
    let mut uses = InMemoryReplayCache::new();
    let first = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &foreign,
        channel,
        single_use(&mut uses),
    );
    assert!(matches!(first, Err(SamlError::IssuerMismatch { .. })));
    let second = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &foreign,
        channel,
        single_use(&mut uses),
    );
    assert!(matches!(second, Err(SamlError::IssuerMismatch { .. })));
    Ok(())
}

#[test]
fn a_missing_or_non_soap_resolution_service_is_not_used() -> Result<(), Box<dyn std::error::Error>>
{
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let other_index = recode(&artifact, |bytes| {
        let index = 7u16.to_be_bytes();
        bytes[2] = index[0];
        bytes[3] = index[1];
    })?;
    let channel = confidential();
    let missing = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &other_index,
        channel,
        without_replay_cache(),
    );
    assert!(matches!(
        missing,
        Err(SamlError::MissingMetadata(detail)) if detail == "ArtifactResolutionService"
    ));

    let mut posted = parties.idp.metadata_xml().to_string();
    let replaced = posted.replacen(
        SOAP_BINDING,
        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        1,
    );
    assert_ne!(replaced, posted);
    posted = replaced;
    let peer = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        &posted,
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let unsupported =
        parties
            .sp
            .resolve_artifact(&peer, &artifact, channel, without_replay_cache());
    assert!(matches!(unsupported, Err(SamlError::Unsupported(_))));
    Ok(())
}

#[test]
fn the_issuer_releases_another_protocol_message_without_confidentiality(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &logout_request(), &mut issued)?;
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        confidential(),
        without_replay_cache(),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        authenticated_without_confidentiality(),
    )?;
    assert_eq!(answer.release(), ArtifactRelease::Returned);
    let resolved = resolution.finish(answer.response().envelope())?;
    assert_eq!(resolved.local_name(), "LogoutRequest");
    assert!(resolved.xml().contains(LOGOUT_MARKER));
    Ok(())
}

#[test]
fn a_header_the_responder_must_understand_is_refused_without_consuming_the_artifact(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let required = resolution.request().envelope().replacen(
        "<soap:Body>",
        "<soap:Header><ext:Trace xmlns:ext=\"urn:example:trace\" soap:mustUnderstand=\"1\">note</ext:Trace></soap:Header><soap:Body>",
        1,
    );
    let refused =
        parties
            .idp
            .answer_artifact_resolve(&parties.sp_metadata, &required, &mut issued, channel);
    assert!(matches!(refused, Err(SamlError::Xml { .. })));

    let for_router = resolution.request().envelope().replacen(
        "<soap:Body>",
        "<soap:Header><ext:Trace xmlns:ext=\"urn:example:trace\" soap:mustUnderstand=\"1\" soap:actor=\"urn:example:router\"/></soap:Header><soap:Body>",
        1,
    );
    let accepted = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        &for_router,
        &mut issued,
        channel,
    )?;
    assert_eq!(accepted.release(), ArtifactRelease::Returned);
    let resolved = resolution.finish(accepted.response().envelope())?;
    assert!(resolved.xml().contains(WEB_SSO_MARKER));
    Ok(())
}

#[test]
fn the_service_provider_rejects_an_artifact_response_it_cannot_attribute(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        channel,
    )?;
    let envelope = answer.response().envelope();
    let issuer = format!("<saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>");
    let missing_issuer = envelope.replace(&issuer, "");
    assert!(matches!(
        resolution.finish(&missing_issuer),
        Err(SamlError::IssuerMismatch { .. })
    ));
    let padded_issuer = envelope.replace(
        &issuer,
        &format!("<saml:Issuer>\n  {IDP_ENTITY_ID}\n</saml:Issuer>"),
    );
    assert_ne!(padded_issuer, envelope);
    assert!(matches!(
        resolution.finish(&padded_issuer),
        Err(SamlError::IssuerMismatch { .. })
    ));
    let email_issuer = envelope.replace(
        "<saml:Issuer>",
        "<saml:Issuer Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">",
    );
    assert!(matches!(
        resolution.finish(&email_issuer),
        Err(SamlError::ProtocolProfile(_))
    ));
    let without_correlation = remove_attribute(envelope, "InResponseTo")?;
    assert!(matches!(
        resolution.finish(&without_correlation),
        Err(SamlError::InResponseToMismatch { .. })
    ));
    Ok(())
}

#[test]
fn a_non_entity_resolve_issuer_does_not_receive_the_message(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let email_issuer = resolution.request().envelope().replace(
        "<saml:Issuer>",
        "<saml:Issuer Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">",
    );
    let withheld = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        &email_issuer,
        &mut issued,
        channel,
    )?;
    assert_eq!(
        withheld.release(),
        ArtifactRelease::Withheld(ArtifactWithheld::DifferentPresenter)
    );
    assert!(!withheld.response().envelope().contains(WEB_SSO_MARKER));
    let padded_issuer = resolution.request().envelope().replace(
        &format!("{SP_ENTITY_ID}</saml:Issuer>"),
        &format!(" {SP_ENTITY_ID} </saml:Issuer>"),
    );
    assert_ne!(padded_issuer, resolution.request().envelope());
    let withheld = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        &padded_issuer,
        &mut issued,
        channel,
    )?;
    assert_eq!(
        withheld.release(),
        ArtifactRelease::Withheld(ArtifactWithheld::DifferentPresenter)
    );
    let padded_entity_format = resolution.request().envelope().replace(
        "<saml:Issuer>",
        "<saml:Issuer Format=\"&#9;urn:oasis:names:tc:SAML:2.0:nameid-format:entity \">",
    );
    let accepted = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        &padded_entity_format,
        &mut issued,
        channel,
    )?;
    assert_eq!(accepted.release(), ArtifactRelease::Returned);
    Ok(())
}

#[test]
fn a_release_that_cannot_be_built_leaves_the_artifact_outstanding(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let prefix = format!(
        r#"<samlp:Response xmlns:samlp="{PROTOCOL}" ID="_response" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">"#
    );
    let suffix = "</samlp:Response>";
    let limit = XmlLimits::default().max_bytes;
    let text_len = limit
        .checked_sub(prefix.len() + suffix.len() + 256)
        .ok_or("XML byte limit is smaller than the response shell")?;
    let message = format!("{prefix}{}{suffix}", "m".repeat(text_len));
    assert!(message.len() < limit);
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &message, &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let first = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        channel,
    );
    assert!(matches!(&first, Err(SamlError::LimitExceeded { .. })));
    let second = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        channel,
    );
    assert!(matches!(second, Err(SamlError::LimitExceeded { .. })));
    Ok(())
}

#[test]
fn only_a_saml_protocol_element_is_stored() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let assertion = format!(
        r#"<saml:Assertion xmlns:saml="{ASSERTION}" ID="_assertion" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"/>"#
    );
    assert!(matches!(
        issue(&parties, &assertion, &mut issued),
        Err(SamlError::ProtocolProfile(_))
    ));
    Ok(())
}

#[test]
fn the_service_provider_rejects_an_artifact_response_without_id_or_instant(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        channel,
    )?;
    let envelope = answer.response().envelope();
    let without_id = remove_attribute(envelope, "ID")?;
    assert!(matches!(
        resolution.finish(&without_id),
        Err(SamlError::ProtocolProfile(_))
    ));
    let without_instant = remove_attribute(envelope, "IssueInstant")?;
    assert!(matches!(
        resolution.finish(&without_instant),
        Err(SamlError::ProtocolProfile(_))
    ));
    let bad_instant = envelope.replacen("IssueInstant=\"", "IssueInstant=\"not-a-time ", 1);
    assert_ne!(bad_instant, *envelope);
    assert!(matches!(
        resolution.finish(&bad_instant),
        Err(SamlError::ProtocolProfile(_))
    ));
    Ok(())
}

#[test]
fn a_foreign_artifact_sibling_does_not_release_the_message(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let foreign = resolution.request().envelope().replacen(
        "</samlp:Artifact>",
        "</samlp:Artifact><other:Artifact xmlns:other=\"urn:example:other\">extra</other:Artifact>",
        1,
    );
    let refused =
        parties
            .idp
            .answer_artifact_resolve(&parties.sp_metadata, &foreign, &mut issued, channel);
    assert!(matches!(refused, Err(SamlError::ProtocolProfile(_))));

    let accepted = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        channel,
    )?;
    assert_eq!(accepted.release(), ArtifactRelease::Returned);
    assert!(accepted.response().envelope().contains(WEB_SSO_MARKER));
    Ok(())
}

#[test]
fn a_non_http_resolution_location_does_not_consume_single_use(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let mut posted = parties.idp.metadata_xml().to_string();
    let replaced = posted.replacen(RESOLUTION_URL, "urn:example:artifact", 1);
    assert_ne!(replaced, posted);
    posted = replaced;
    let peer = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        &posted,
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let channel = confidential();
    let mut uses = InMemoryReplayCache::new();
    let first = parties
        .sp
        .resolve_artifact(&peer, &artifact, channel, single_use(&mut uses));
    assert!(matches!(first, Err(SamlError::Invalid(_))));

    let second = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        single_use(&mut uses),
    )?;
    assert!(second.request().envelope().contains("ArtifactResolve"));
    assert!(second.request().envelope().contains(artifact.as_str()));
    Ok(())
}

#[test]
fn a_duplicate_resolve_issuer_is_refused_as_malformed() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let duplicated = resolution.request().envelope().replacen(
        "</saml:Issuer>",
        &format!("</saml:Issuer><saml:Issuer>{SP_ENTITY_ID}</saml:Issuer>"),
        1,
    );
    let refused = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        &duplicated,
        &mut issued,
        channel,
    );
    assert!(matches!(refused, Err(SamlError::ProtocolProfile(_))));

    let accepted = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        channel,
    )?;
    assert_eq!(accepted.release(), ArtifactRelease::Returned);
    Ok(())
}

#[test]
fn the_service_provider_rejects_an_artifact_response_with_two_statuses(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        channel,
    )?;
    let envelope = answer.response().envelope();
    let status_end_tag = "</samlp:Status>";
    let start = envelope
        .find("<samlp:Status")
        .ok_or("ArtifactResponse is missing Status")?;
    let end = envelope
        .find(status_end_tag)
        .ok_or("ArtifactResponse is missing Status")?
        + status_end_tag.len();
    let mut duplicated = envelope.to_string();
    duplicated.insert_str(end, &envelope[start..end]);
    assert!(matches!(
        resolution.finish(&duplicated),
        Err(SamlError::ProtocolProfile(_))
    ));
    Ok(())
}

#[test]
fn the_service_provider_reports_an_artifact_response_without_a_status(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        channel,
    )?;
    let envelope = answer.response().envelope();
    let status_end_tag = "</samlp:Status>";
    let start = envelope
        .find("<samlp:Status")
        .ok_or("ArtifactResponse is missing Status")?;
    let end = envelope
        .find(status_end_tag)
        .ok_or("ArtifactResponse is missing Status")?
        + status_end_tag.len();
    let mut without_status = envelope.to_string();
    without_status.replace_range(start..end, "");
    let result = resolution.finish(&without_status);
    assert!(
        matches!(result, Err(SamlError::StatusMissing)),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn namespaces_declared_on_the_soap_envelope_reach_the_protocol_message(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let declarations = format!(r#" xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}""#);
    let hoisted_request = resolution
        .request()
        .envelope()
        .replace(&declarations, "")
        .replacen(
            "<soap:Envelope",
            &format!("<soap:Envelope{declarations}"),
            1,
        );
    assert!(hoisted_request.contains("<samlp:ArtifactResolve ID="));
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        &hoisted_request,
        &mut issued,
        channel,
    )?;
    assert_eq!(answer.release(), ArtifactRelease::Returned);

    let inherited_payload = answer.response().envelope().replace(
        &format!(r#"<samlp:Response xmlns:samlp="{PROTOCOL}""#),
        "<samlp:Response",
    );
    assert!(inherited_payload.contains("<samlp:Response ID="));
    let hoisted_response = inherited_payload.replace(&declarations, "").replacen(
        "<soap:Envelope",
        &format!("<soap:Envelope{declarations}"),
        1,
    );
    let soap = r#" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/""#;
    for (envelope, in_scope) in [
        (inherited_payload, format!("{soap}{declarations}")),
        (hoisted_response, format!("{declarations}{soap}")),
    ] {
        let resolved = resolution.finish(&envelope)?;
        assert_eq!(
            resolved.xml(),
            format!(
                r#"<samlp:Response{in_scope} ID="_response" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">{WEB_SSO_MARKER}</samlp:Response>"#
            )
        );
    }
    Ok(())
}

#[test]
fn the_service_provider_resolves_only_over_a_confidential_channel(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &logout_request(), &mut issued)?;
    let mut uses = InMemoryReplayCache::new();
    for weak in [
        authenticated_without_confidentiality(),
        SoapChannel::new(
            PartyAuthentication::Unattested,
            MessageIntegrity::Protected,
            MessageConfidentiality::Protected,
        ),
        SoapChannel::new(
            PartyAuthentication::Mutual,
            MessageIntegrity::Unattested,
            MessageConfidentiality::Protected,
        ),
    ] {
        let refused = parties.sp.resolve_artifact(
            &parties.idp_metadata,
            &artifact,
            weak,
            single_use(&mut uses),
        );
        assert!(
            matches!(refused, Err(SamlError::SoapChannelProtection)),
            "{weak:?}"
        );
    }
    parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        confidential(),
        single_use(&mut uses),
    )?;
    Ok(())
}

#[test]
fn a_removed_artifact_is_no_longer_outstanding() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    assert!(issued.remove(&artifact));
    assert!(!issued.remove(&artifact));
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        channel,
    )?;
    assert_eq!(
        answer.release(),
        ArtifactRelease::Withheld(ArtifactWithheld::NotOutstanding)
    );
    Ok(())
}

#[test]
fn an_artifact_past_its_lifetime_is_no_longer_outstanding() -> Result<(), Box<dyn std::error::Error>>
{
    let parties = parties()?;
    let mut issued = IssuedArtifacts::expire_after(Duration::ZERO);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        channel,
    )?;
    assert_eq!(
        answer.release(),
        ArtifactRelease::Withheld(ArtifactWithheld::NotOutstanding)
    );
    assert!(answer.response().envelope().contains(SUCCESS));
    assert!(!answer.response().envelope().contains(WEB_SSO_MARKER));
    assert!(matches!(
        resolution.finish(answer.response().envelope()),
        Err(SamlError::ArtifactNotReturned)
    ));

    let expired = issue(&parties, &web_sso_response(), &mut issued)?;
    assert!(!issued.remove(&expired));
    Ok(())
}

#[test]
fn soap_envelopes_are_read_under_the_configured_xml_limits(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut xml = XmlPolicy::default();
    xml.limits.max_depth = 6;
    xml.limits.max_attribute_value_bytes = 64 * 1024;
    let parties = parties_with(xml)?;
    let mut issued = IssuedArtifacts::expire_after(ARTIFACT_LIFETIME);
    let artifact = issue(&parties, &web_sso_response(), &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        channel,
        without_replay_cache(),
    )?;
    let deep_header =
        "<soap:Header><a><b><c><d><e>note</e></d></c></b></a></soap:Header><soap:Body>";
    let consent = format!(r#"Consent="{}" "#, "a".repeat(20 * 1024));
    let deep_request = resolution
        .request()
        .envelope()
        .replacen("<soap:Body>", deep_header, 1);
    let refused = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        &deep_request,
        &mut issued,
        channel,
    );
    assert!(
        matches!(
            &refused,
            Err(SamlError::LimitExceeded {
                limit: saml_rs::ResourceLimit::XmlDepth,
                ..
            })
        ),
        "{refused:?}"
    );

    let wide_request = resolution.request().envelope().replacen(
        "<samlp:ArtifactResolve ",
        &format!("<samlp:ArtifactResolve {consent}"),
        1,
    );
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        &wide_request,
        &mut issued,
        channel,
    )?;
    let deep_response = answer
        .response()
        .envelope()
        .replacen("<soap:Body>", deep_header, 1);
    let refused = resolution.finish(&deep_response);
    assert!(
        matches!(
            &refused,
            Err(SamlError::LimitExceeded {
                limit: saml_rs::ResourceLimit::XmlDepth,
                ..
            })
        ),
        "{refused:?}"
    );
    assert!(resolution
        .finish(answer.response().envelope())?
        .xml()
        .contains(WEB_SSO_MARKER));
    let wide_response = answer.response().envelope().replacen(
        "<samlp:ArtifactResponse ",
        &format!("<samlp:ArtifactResponse {consent}"),
        1,
    );
    assert!(resolution
        .finish(&wide_response)?
        .xml()
        .contains(WEB_SSO_MARKER));
    Ok(())
}
