//! Artifact resolution over SOAP, through the typed identity provider and
//! service provider.
//!
//! The identity provider stores a protocol message and answers `ArtifactResolve`.
//! The service provider sends that request and reads the message from
//! `ArtifactResponse`. The deployment still performs HTTP and TLS.
//!
//! Config helpers select `compatibility()` so they build without a crypto
//! provider. Artifact resolution does not read that preset.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::xml::XmlLimits;
use saml_rs::{
    AcsEndpoint, Artifact, ArtifactDereference, ArtifactRelease, ArtifactResolutionService,
    ArtifactUses, ArtifactWithheld, EndpointUrl, EntityId, Idp, IdpConfig, IdpDescriptor,
    IdpValidationPolicy, IssuedArtifacts, IssuedMessage, MessageConfidentiality, MessageIntegrity,
    MetadataTrustPolicy, PartyAuthentication, Saml, SamlError, SoapChannel, Sp, SpConfig,
    SpDescriptor, SpValidationPolicy, SsoEndpoint, XmlPolicy,
};

const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const OTHER_ENTITY_ID: &str = "https://other.example.com/metadata";
const RESOLUTION_URL: &str = "https://idp.example.com/artifact";
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
    idp: Saml<Idp>,
    sp: Saml<Sp>,
    other: Saml<Sp>,
    idp_metadata: IdpDescriptor,
    sp_metadata: SpDescriptor,
    other_metadata: SpDescriptor,
}

fn parties() -> Result<Parties, Box<dyn std::error::Error>> {
    parties_with(XmlPolicy::default())
}

fn parties_with(xml: XmlPolicy) -> Result<Parties, Box<dyn std::error::Error>> {
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso")?)
            .artifact_resolution_service(ArtifactResolutionService::new(
                0,
                EndpointUrl::try_new(RESOLUTION_URL)?,
            ))
            .xml(xml)
            .validation(IdpValidationPolicy::compatibility())
            .build()?,
    )?;
    let sp = service_provider(SP_ENTITY_ID, "https://sp.example.com/acs", xml)?;
    let other = service_provider(OTHER_ENTITY_ID, "https://other.example.com/acs", xml)?;
    let idp_metadata = IdpDescriptor::from_metadata_xml(
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let sp_metadata = SpDescriptor::from_metadata_xml(
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let other_metadata = SpDescriptor::from_metadata_xml(
        other.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
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
) -> Result<Saml<Sp>, Box<dyn std::error::Error>> {
    Ok(Saml::sp(
        SpConfig::builder(EntityId::try_new(entity_id)?)
            .acs_endpoint(AcsEndpoint::post(acs)?)
            .xml(xml)
            .validation(SpValidationPolicy::compatibility())
            .build()?,
    )?)
}

fn web_sso_response() -> Result<IssuedMessage, SamlError> {
    IssuedMessage::web_browser_sso_response(format!(
        r#"<samlp:Response xmlns:samlp="{PROTOCOL}" ID="_response" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">{WEB_SSO_MARKER}</samlp:Response>"#
    ))
}

fn logout_request() -> Result<IssuedMessage, SamlError> {
    IssuedMessage::protocol(format!(
        r#"<samlp:LogoutRequest xmlns:samlp="{PROTOCOL}" ID="_logout" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">{LOGOUT_MARKER}</samlp:LogoutRequest>"#
    ))
}

fn confidential() -> SoapChannel {
    SoapChannel::mutually_authenticated_confidential()
}

fn authenticated_without_confidentiality() -> SoapChannel {
    SoapChannel::new(
        PartyAuthentication::Mutual,
        MessageIntegrity::Protected,
        MessageConfidentiality::Absent,
    )
}

fn issue(
    parties: &Parties,
    message: IssuedMessage,
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
    Ok(Artifact::try_from_encoded(STANDARD.encode(bytes))?)
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

#[test]
fn web_browser_sso_round_trip_returns_the_stored_response() -> Result<(), Box<dyn std::error::Error>>
{
    let parties = parties()?;
    let mut issued = IssuedArtifacts::new();
    let artifact = issue(&parties, web_sso_response()?, &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut ArtifactUses::enforce_single_use(BLOCKED_FOR),
    )?;
    let request = resolution.request();
    assert_eq!(request.endpoint().as_str(), RESOLUTION_URL);
    assert_eq!(
        request.soap_action(),
        "http://www.oasis-open.org/committees/security"
    );
    assert_eq!(request.cache_control(), "no-cache, no-store");
    assert_eq!(request.pragma(), "no-cache");
    assert_eq!(request.content_type(), "text/xml; charset=utf-8");
    assert!(request.envelope().contains("ArtifactResolve"));
    assert!(request.envelope().contains(artifact.as_str()));
    assert!(request
        .envelope()
        .contains(&format!("<saml:Issuer>{SP_ENTITY_ID}</saml:Issuer>")));
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
        answer.cache_control(),
        "no-cache, no-store, must-revalidate, private"
    );
    assert_eq!(answer.pragma(), "no-cache");
    assert_eq!(answer.content_type(), "text/xml; charset=utf-8");
    assert!(answer.envelope().contains("ArtifactResponse"));
    assert!(answer.envelope().contains(SUCCESS));
    assert!(answer.envelope().contains(WEB_SSO_MARKER));

    let resolved = resolution.finish(answer.envelope())?;
    assert_eq!(resolved.local_name(), "Response");
    assert!(resolved.xml().contains(WEB_SSO_MARKER));
    assert!(!resolved.xml().contains("ArtifactResponse"));
    Ok(())
}

#[test]
fn a_different_presenter_does_not_receive_the_message() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::new();
    let artifact = issue(&parties, web_sso_response()?, &mut issued)?;
    let channel = confidential();
    let hostile = parties.other.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut ArtifactUses::enforce_single_use(BLOCKED_FOR),
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
    assert!(answer.envelope().contains(SUCCESS));
    assert!(!answer.envelope().contains(WEB_SSO_MARKER));
    assert!(hostile.finish(answer.envelope()).is_err());

    let legitimate = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut ArtifactUses::enforce_single_use(BLOCKED_FOR),
    )?;
    let second = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        legitimate.request().envelope(),
        &mut issued,
        channel,
    )?;
    assert_eq!(second.release(), ArtifactRelease::Returned);
    assert!(second.envelope().contains(WEB_SSO_MARKER));
    Ok(())
}

#[test]
fn web_sso_without_confidentiality_withholds_the_message() -> Result<(), Box<dyn std::error::Error>>
{
    let weak = authenticated_without_confidentiality();
    assert!(matches!(
        ArtifactDereference::web_browser_sso(weak),
        Err(SamlError::SoapChannelProtection)
    ));

    let parties = parties()?;
    let mut issued = IssuedArtifacts::new();
    let artifact = issue(&parties, web_sso_response()?, &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut ArtifactUses::enforce_single_use(BLOCKED_FOR),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        weak,
    )?;
    assert_eq!(
        answer.release(),
        ArtifactRelease::Withheld(ArtifactWithheld::Channel)
    );
    assert!(answer.envelope().contains(SUCCESS));
    assert!(!answer.envelope().contains(WEB_SSO_MARKER));
    Ok(())
}

#[test]
fn the_issuer_returns_a_web_sso_message_only_once() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::new();
    let artifact = issue(&parties, web_sso_response()?, &mut issued)?;
    let channel = confidential();
    let first_resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut ArtifactUses::allow_reuse(),
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
        ArtifactDereference::web_browser_sso(channel)?,
        &mut ArtifactUses::allow_reuse(),
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
    assert!(!second.envelope().contains(WEB_SSO_MARKER));
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

    let without = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso")?)
            .validation(IdpValidationPolicy::compatibility())
            .build()?,
    )?;
    assert!(!without.metadata_xml().contains("ArtifactResolutionService"));
    let peer = SpDescriptor::from_metadata_xml(
        parties.sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let mut issued = IssuedArtifacts::new();
    let missing = without.issue_artifact(&peer, web_sso_response()?, 0, &mut issued);
    assert!(matches!(
        missing,
        Err(SamlError::MissingMetadata(detail)) if detail == "ArtifactResolutionService"
    ));
    Ok(())
}

#[test]
fn duplicate_resolution_indexes_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let location = EndpointUrl::try_new(RESOLUTION_URL)?;
    let other = EndpointUrl::try_new("https://idp.example.com/artifact-other")?;
    let built = IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso")?)
        .artifact_resolution_service(ArtifactResolutionService::new(0, location))
        .artifact_resolution_service(ArtifactResolutionService::new(0, other))
        .validation(IdpValidationPolicy::compatibility())
        .build();
    assert!(matches!(built, Err(SamlError::Invalid(detail)) if detail.contains("duplicate")));
    Ok(())
}

#[test]
fn artifact_source_id_is_the_sha1_of_the_issuer_entity_id() -> Result<(), Box<dyn std::error::Error>>
{
    let parties = parties()?;
    let mut issued = IssuedArtifacts::new();
    let artifact = issue(&parties, web_sso_response()?, &mut issued)?;
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
        ArtifactDereference::web_browser_sso(channel)?,
        &mut ArtifactUses::enforce_single_use(BLOCKED_FOR),
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
    assert!(answer.envelope().contains(WEB_SSO_MARKER));
    Ok(())
}

#[test]
fn a_version_mismatch_does_not_consume_the_artifact() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::new();
    let artifact = issue(&parties, web_sso_response()?, &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut ArtifactUses::allow_reuse(),
    )?;
    let mismatched =
        resolution
            .request()
            .envelope()
            .replacen("Version=\"2.0\"", "Version=\"1.1\"", 1);
    let rejected = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        &mismatched,
        &mut issued,
        channel,
    )?;
    assert_eq!(rejected.release(), ArtifactRelease::VersionMismatch);
    assert!(rejected.envelope().contains(VERSION_MISMATCH));
    assert!(!rejected.envelope().contains(SUCCESS));
    assert!(!rejected.envelope().contains(WEB_SSO_MARKER));

    let accepted = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        channel,
    )?;
    assert_eq!(accepted.release(), ArtifactRelease::Returned);
    assert!(accepted.envelope().contains(WEB_SSO_MARKER));
    Ok(())
}

#[test]
fn an_unknown_or_unreadable_artifact_does_not_consume_another(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::new();
    let artifact = issue(&parties, web_sso_response()?, &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut ArtifactUses::allow_reuse(),
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
    let mut issued = IssuedArtifacts::new();
    let artifact = issue(&parties, web_sso_response()?, &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut ArtifactUses::enforce_single_use(BLOCKED_FOR),
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
        ArtifactRelease::Withheld(ArtifactWithheld::Destination)
    );
    assert!(!answer.envelope().contains(WEB_SSO_MARKER));
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
fn the_service_provider_rejects_a_repeated_artifact() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::new();
    let artifact = issue(&parties, web_sso_response()?, &mut issued)?;
    let channel = confidential();
    let mut uses = ArtifactUses::enforce_single_use(BLOCKED_FOR);
    parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut uses,
    )?;
    let repeated = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut uses,
    );
    assert!(matches!(repeated, Err(SamlError::ReplayDetected { .. })));

    let mut relaxed = ArtifactUses::allow_reuse();
    parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut relaxed,
    )?;
    parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut relaxed,
    )?;
    Ok(())
}

#[test]
fn an_artifact_from_another_issuer_is_rejected_before_it_is_recorded(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::new();
    let artifact = issue(&parties, web_sso_response()?, &mut issued)?;
    let foreign = recode(&artifact, |bytes| {
        bytes[4] ^= 0xff;
    })?;
    let channel = confidential();
    let mut uses = ArtifactUses::enforce_single_use(BLOCKED_FOR);
    let first = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &foreign,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut uses,
    );
    assert!(matches!(first, Err(SamlError::IssuerMismatch { .. })));
    let second = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &foreign,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut uses,
    );
    assert!(matches!(second, Err(SamlError::IssuerMismatch { .. })));
    Ok(())
}

#[test]
fn a_missing_or_non_soap_resolution_service_is_not_used() -> Result<(), Box<dyn std::error::Error>>
{
    let parties = parties()?;
    let mut issued = IssuedArtifacts::new();
    let artifact = issue(&parties, web_sso_response()?, &mut issued)?;
    let other_index = recode(&artifact, |bytes| {
        let index = 7u16.to_be_bytes();
        bytes[2] = index[0];
        bytes[3] = index[1];
    })?;
    let channel = confidential();
    let missing = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &other_index,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut ArtifactUses::enforce_single_use(BLOCKED_FOR),
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
    let peer =
        IdpDescriptor::from_metadata_xml(&posted, MetadataTrustPolicy::UnsignedForCompatibility)?;
    let unsupported = parties.sp.resolve_artifact(
        &peer,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut ArtifactUses::enforce_single_use(BLOCKED_FOR),
    );
    assert!(matches!(unsupported, Err(SamlError::Unsupported(_))));
    Ok(())
}

#[test]
fn another_protocol_message_uses_the_same_soap_channel() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::new();
    let artifact = issue(&parties, logout_request()?, &mut issued)?;
    let channel = authenticated_without_confidentiality();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::protocol(channel)?,
        &mut ArtifactUses::enforce_single_use(BLOCKED_FOR),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        channel,
    )?;
    assert_eq!(answer.release(), ArtifactRelease::Returned);
    let resolved = resolution.finish(answer.envelope())?;
    assert_eq!(resolved.local_name(), "LogoutRequest");
    assert!(resolved.xml().contains(LOGOUT_MARKER));
    Ok(())
}

#[test]
fn a_header_the_responder_must_understand_is_refused_without_consuming_the_artifact(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::new();
    let artifact = issue(&parties, web_sso_response()?, &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut ArtifactUses::allow_reuse(),
    )?;
    let required = resolution.request().envelope().replacen(
        "<soap:Body>",
        "<soap:Header><extra mustUnderstand=\"1\">note</extra></soap:Header><soap:Body>",
        1,
    );
    let refused =
        parties
            .idp
            .answer_artifact_resolve(&parties.sp_metadata, &required, &mut issued, channel);
    assert!(matches!(refused, Err(SamlError::Xml(_))));

    let optional = resolution.request().envelope().replacen(
        "<soap:Body>",
        "<soap:Header><extra>note</extra></soap:Header><soap:Body>",
        1,
    );
    let accepted = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        &optional,
        &mut issued,
        channel,
    )?;
    assert_eq!(accepted.release(), ArtifactRelease::Returned);
    let resolved = resolution.finish(accepted.envelope())?;
    assert!(resolved.xml().contains(WEB_SSO_MARKER));
    Ok(())
}

#[test]
fn the_service_provider_rejects_an_artifact_response_it_cannot_attribute(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::new();
    let artifact = issue(&parties, web_sso_response()?, &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut ArtifactUses::enforce_single_use(BLOCKED_FOR),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        channel,
    )?;
    let envelope = answer.envelope();
    let missing_issuer =
        envelope.replace(&format!("<saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>"), "");
    assert!(matches!(
        resolution.finish(&missing_issuer),
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
    let mut issued = IssuedArtifacts::new();
    let artifact = issue(&parties, web_sso_response()?, &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut ArtifactUses::allow_reuse(),
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
    assert!(!withheld.envelope().contains(WEB_SSO_MARKER));
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
fn a_release_that_cannot_be_built_leaves_the_artifact_outstanding(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let prefix = format!(
        r#"<samlp:Response xmlns:samlp="{PROTOCOL}" ID="_response" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">"#
    );
    let suffix = "</samlp:Response>";
    let limit = saml_rs::xml::dom::DEFAULT_XML_MAX_BYTES;
    let text_len = limit
        .checked_sub(prefix.len() + suffix.len() + 256)
        .ok_or("XML byte limit is smaller than the response shell")?;
    let message = IssuedMessage::web_browser_sso_response(format!(
        "{prefix}{}{suffix}",
        "m".repeat(text_len)
    ))?;
    assert!(message.xml().len() < limit);
    let mut issued = IssuedArtifacts::new();
    let artifact = issue(&parties, message, &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut ArtifactUses::enforce_single_use(BLOCKED_FOR),
    )?;
    let first = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        channel,
    );
    assert!(matches!(
        &first,
        Err(SamlError::Invalid(detail)) if detail.contains("ERR_XML_LIMIT_EXCEEDED")
    ));
    let second = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        channel,
    );
    assert!(matches!(
        second,
        Err(SamlError::Invalid(detail)) if detail.contains("ERR_XML_LIMIT_EXCEEDED")
    ));
    Ok(())
}

#[test]
fn a_response_must_be_stored_as_a_web_sso_response() -> Result<(), Box<dyn std::error::Error>> {
    let response = format!(
        r#"<samlp:Response xmlns:samlp="{PROTOCOL}" ID="_response" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">{WEB_SSO_MARKER}</samlp:Response>"#
    );
    assert!(matches!(
        IssuedMessage::protocol(response),
        Err(SamlError::ProtocolProfile(_))
    ));
    let logout = format!(
        r#"<samlp:LogoutRequest xmlns:samlp="{PROTOCOL}" ID="_logout" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">{LOGOUT_MARKER}</samlp:LogoutRequest>"#
    );
    assert!(matches!(
        IssuedMessage::web_browser_sso_response(logout),
        Err(SamlError::ProtocolProfile(_))
    ));
    Ok(())
}

#[test]
fn the_service_provider_rejects_an_artifact_response_without_id_or_instant(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::new();
    let artifact = issue(&parties, web_sso_response()?, &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut ArtifactUses::enforce_single_use(BLOCKED_FOR),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        channel,
    )?;
    let envelope = answer.envelope();
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
    let mut issued = IssuedArtifacts::new();
    let artifact = issue(&parties, web_sso_response()?, &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut ArtifactUses::allow_reuse(),
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
    assert!(accepted.envelope().contains(WEB_SSO_MARKER));
    Ok(())
}

#[test]
fn a_non_http_resolution_location_does_not_consume_single_use(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::new();
    let artifact = issue(&parties, web_sso_response()?, &mut issued)?;
    let mut posted = parties.idp.metadata_xml().to_string();
    let replaced = posted.replacen(RESOLUTION_URL, "urn:example:artifact", 1);
    assert_ne!(replaced, posted);
    posted = replaced;
    let peer =
        IdpDescriptor::from_metadata_xml(&posted, MetadataTrustPolicy::UnsignedForCompatibility)?;
    let channel = confidential();
    let mut uses = ArtifactUses::enforce_single_use(BLOCKED_FOR);
    let first = parties.sp.resolve_artifact(
        &peer,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut uses,
    );
    assert!(matches!(first, Err(SamlError::Invalid(_))));

    let second = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut uses,
    )?;
    assert!(second.request().envelope().contains("ArtifactResolve"));
    assert!(second.request().envelope().contains(artifact.as_str()));
    Ok(())
}

#[test]
fn a_duplicate_resolve_issuer_is_refused_as_malformed() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::new();
    let artifact = issue(&parties, web_sso_response()?, &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut ArtifactUses::allow_reuse(),
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
    let mut issued = IssuedArtifacts::new();
    let artifact = issue(&parties, web_sso_response()?, &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut ArtifactUses::enforce_single_use(BLOCKED_FOR),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        channel,
    )?;
    let envelope = answer.envelope();
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
fn namespaces_declared_on_the_soap_envelope_reach_the_protocol_message(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::new();
    let artifact = issue(&parties, web_sso_response()?, &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut ArtifactUses::enforce_single_use(BLOCKED_FOR),
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

    let inherited_payload = answer.envelope().replace(
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
fn a_protocol_dereference_does_not_return_a_response() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::new();
    let artifact = issue(&parties, logout_request()?, &mut issued)?;
    let channel = authenticated_without_confidentiality();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::protocol(channel)?,
        &mut ArtifactUses::enforce_single_use(BLOCKED_FOR),
    )?;
    let answer = parties.idp.answer_artifact_resolve(
        &parties.sp_metadata,
        resolution.request().envelope(),
        &mut issued,
        channel,
    )?;
    let as_response = answer
        .envelope()
        .replace("samlp:LogoutRequest", "samlp:Response");
    assert!(matches!(
        resolution.finish(&as_response),
        Err(SamlError::ProtocolProfile(_))
    ));
    Ok(())
}

#[test]
fn a_removed_artifact_is_no_longer_outstanding() -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties()?;
    let mut issued = IssuedArtifacts::new();
    let artifact = issue(&parties, web_sso_response()?, &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut ArtifactUses::enforce_single_use(BLOCKED_FOR),
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
fn soap_envelopes_are_read_under_the_configured_xml_limits(
) -> Result<(), Box<dyn std::error::Error>> {
    let parties = parties_with(XmlPolicy {
        limits: XmlLimits {
            max_depth: 6,
            max_attribute_value_bytes: 64 * 1024,
            ..XmlLimits::default()
        },
        ..XmlPolicy::default()
    })?;
    let mut issued = IssuedArtifacts::new();
    let artifact = issue(&parties, web_sso_response()?, &mut issued)?;
    let channel = confidential();
    let resolution = parties.sp.resolve_artifact(
        &parties.idp_metadata,
        &artifact,
        ArtifactDereference::web_browser_sso(channel)?,
        &mut ArtifactUses::allow_reuse(),
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
        matches!(&refused, Err(SamlError::Invalid(message)) if message.contains("max XML depth")),
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
    let deep_response = answer.envelope().replacen("<soap:Body>", deep_header, 1);
    let refused = resolution.finish(&deep_response);
    assert!(
        matches!(&refused, Err(SamlError::Invalid(message)) if message.contains("max XML depth")),
        "{refused:?}"
    );
    assert!(resolution
        .finish(answer.envelope())?
        .xml()
        .contains(WEB_SSO_MARKER));
    let wide_response = answer.envelope().replacen(
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
