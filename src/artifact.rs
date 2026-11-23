//! Artifact resolution over the SOAP binding.
//!
//! The identity provider stores a protocol message for one service provider and
//! answers `ArtifactResolve`. The service provider sends that request and
//! returns the protocol message from `ArtifactResponse`.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use sha1::{Digest, Sha1};

use crate::config::{IdpDescriptor, SpDescriptor};
use crate::constants::namespace;
use crate::entity::{generate_id, now_iso8601, EntitySetting};
use crate::error::SamlError;
use crate::metadata::IdpMetadata;
use crate::model::{EndpointUrl, ReplayKey, RequestVersionMismatch, SamlValidationContext, Status};
use crate::soap::{read_soap_body, MessageConfidentiality, SoapChannel, SoapRequest, SoapResponse};
use crate::xml::any_uri::collapse_whitespace;
use crate::xml::fragment::standalone_element;
use crate::xml::parse_saml_utc_date_time;
use crate::xml::protocol_element::{
    issuer, issuer_format_is_entity, parse_saml, parse_saml_with_limits, read_status, PartyName,
    SamlElement,
};
use crate::xml::write::{Prefixes, XmlWriter};
use crate::xml::XmlLimits;

const ARTIFACT_TYPE_CODE: u16 = 0x0004;
const ARTIFACT_LEN: usize = 44;
const SOURCE_ID_LEN: usize = 20;

/// SAML V2.0 type 0x0004 artifact.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Artifact {
    encoded: String,
    endpoint_index: u16,
    source_id: [u8; SOURCE_ID_LEN],
}

impl Artifact {
    /// Decode the base64 value of a type 0x0004 artifact.
    ///
    /// Padding may be omitted. [`Self::as_str`] returns the padded value.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when `value` is not a 44-byte type
    /// 0x0004 artifact.
    pub fn try_new(value: impl Into<String>) -> Result<Self, SamlError> {
        let encoded = value.into();
        if encoded.chars().any(char::is_whitespace) {
            return Err(SamlError::Invalid(
                "artifact must not contain whitespace".into(),
            ));
        }
        let bytes = STANDARD
            .decode(encoded.as_bytes())
            .or_else(|_| STANDARD_NO_PAD.decode(encoded.as_bytes()))
            .map_err(|_| SamlError::Invalid("artifact is not base64".into()))?;
        if bytes.len() != ARTIFACT_LEN {
            return Err(SamlError::Invalid(
                "artifact must be a 44-byte type 0x0004 value".into(),
            ));
        }
        let type_code = u16::from_be_bytes([bytes[0], bytes[1]]);
        if type_code != ARTIFACT_TYPE_CODE {
            return Err(SamlError::Invalid(
                "artifact type code must be 0x0004".into(),
            ));
        }
        let endpoint_index = u16::from_be_bytes([bytes[2], bytes[3]]);
        let mut source_id = [0u8; SOURCE_ID_LEN];
        source_id.copy_from_slice(&bytes[4..24]);
        Ok(Self {
            encoded: STANDARD.encode(bytes),
            endpoint_index,
            source_id,
        })
    }

    /// Base64 artifact value.
    pub fn as_str(&self) -> &str {
        &self.encoded
    }

    /// `EndpointIndex` of the issuer's `ArtifactResolutionService`.
    pub fn endpoint_index(&self) -> u16 {
        self.endpoint_index
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequiredChannel {
    Authenticated,
    Confidential,
}

/// Artifacts an identity provider has issued and not yet resolved.
///
/// An artifact resolves only within its lifetime. Each issue drops the
/// artifacts issued more than one lifetime ago, so memory holds only the
/// artifacts of the last lifetime.
#[derive(Debug)]
pub struct IssuedArtifacts {
    lifetime: Duration,
    entries: HashMap<String, IssuedEntry>,
    oldest_first: VecDeque<(Instant, String)>,
}

#[derive(Debug)]
struct IssuedEntry {
    issued_at: Instant,
    service_provider: String,
    message_xml: String,
    required_channel: RequiredChannel,
}

impl IssuedArtifacts {
    /// Outstanding artifacts that each resolve for `lifetime` after issue.
    ///
    /// Choose the shortest `lifetime` in which the service provider receives
    /// the artifact and sends `ArtifactResolve`. A later `ArtifactResolve`
    /// gets Success without the message. The replay retention the service
    /// provider passes to [`ServiceProvider::resolve_artifact`](crate::ServiceProvider::resolve_artifact)
    /// should be longer. A zero `lifetime` resolves nothing.
    pub fn expire_after(lifetime: Duration) -> Self {
        Self {
            lifetime,
            entries: HashMap::new(),
            oldest_first: VecDeque::new(),
        }
    }

    /// Discard `artifact` and its stored message without returning it.
    ///
    /// Returns whether the artifact was outstanding. A later `ArtifactResolve`
    /// for it gets Success without the message.
    pub fn remove(&mut self, artifact: &Artifact) -> bool {
        let now = Instant::now();
        self.entries
            .remove(artifact.as_str())
            .is_some_and(|entry| now.saturating_duration_since(entry.issued_at) < self.lifetime)
    }

    fn insert(&mut self, artifact: String, entry: IssuedEntry) {
        while self
            .oldest_first
            .front()
            .is_some_and(|(at, _)| entry.issued_at.saturating_duration_since(*at) >= self.lifetime)
        {
            if let Some((_, expired)) = self.oldest_first.pop_front() {
                self.entries.remove(&expired);
            }
        }
        self.oldest_first
            .push_back((entry.issued_at, artifact.clone()));
        self.entries.insert(artifact, entry);
    }

    fn outstanding(&self, artifact: &str, now: Instant) -> Option<&IssuedEntry> {
        self.entries
            .get(artifact)
            .filter(|entry| now.saturating_duration_since(entry.issued_at) < self.lifetime)
    }
}

/// Why an understood `ArtifactResolve` did not include the protocol message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactWithheld {
    /// No outstanding artifact matched, including one already resolved or
    /// past its lifetime.
    NotOutstanding,
    /// The presenter is not the service provider the artifact was issued to.
    DifferentPresenter,
    /// The channel does not authenticate the presenter and protect the exchange.
    Channel,
    /// `Destination`, when present, is not this artifact resolution endpoint.
    Destination,
}

/// What the identity provider put in `ArtifactResponse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactRelease {
    /// The protocol message is in the response.
    Returned,
    /// The response status is Success and the message is absent.
    Withheld(ArtifactWithheld),
    /// The request version is unsupported. The response status is `VersionMismatch`.
    VersionMismatch,
}

/// SOAP `ArtifactResponse` produced for one `ArtifactResolve`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnsweredArtifact {
    response: SoapResponse,
    release: ArtifactRelease,
}

impl AnsweredArtifact {
    /// SOAP response to return to the requester.
    pub fn response(&self) -> &SoapResponse {
        &self.response
    }

    /// Whether the protocol message was included.
    pub fn release(&self) -> ArtifactRelease {
        self.release
    }
}

/// In-progress artifact resolution. Send [`Self::request`], then [`Self::finish`].
///
/// Equality compares every data field and the stored schema callback address,
/// with the function-address limitations documented on [`crate::XmlPolicy`].
#[derive(Debug, Clone)]
pub struct ArtifactResolution {
    request: SoapRequest,
    request_id: String,
    identity_provider: String,
    artifact: String,
    xml_limits: XmlLimits,
    schema_validator: Option<crate::SchemaValidator>,
}

impl PartialEq for ArtifactResolution {
    fn eq(&self, other: &Self) -> bool {
        let Self {
            request,
            request_id,
            identity_provider,
            artifact,
            xml_limits,
            schema_validator,
        } = self;
        request == &other.request
            && request_id == &other.request_id
            && identity_provider == &other.identity_provider
            && artifact == &other.artifact
            && xml_limits == &other.xml_limits
            && crate::schema::validator_addresses_equal(*schema_validator, other.schema_validator)
    }
}

impl Eq for ArtifactResolution {}

impl ArtifactResolution {
    /// SOAP `ArtifactResolve` addressed to the peer `ArtifactResolutionService`.
    pub fn request(&self) -> &SoapRequest {
        &self.request
    }

    /// Read the protocol message from the SOAP `ArtifactResponse`.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the envelope is not an `ArtifactResponse`
    /// from the identity provider, the status is not success, or the response
    /// does not contain one SAML protocol element.
    pub fn finish(&self, response_envelope: &str) -> Result<ResolvedProtocolMessage, SamlError> {
        let body = read_soap_body(response_envelope, self.xml_limits)?;
        crate::schema::validate(response_envelope, self.schema_validator)?;
        if body.local_name != "ArtifactResponse" || body.namespace != namespace::PROTOCOL {
            return Err(SamlError::ProtocolProfile(
                "SOAP body must be an ArtifactResponse".into(),
            ));
        }
        let response = parse_saml_with_limits(&body.xml, self.xml_limits)?;
        let version = response.required_attr("Version")?;
        if version != "2.0" {
            return Err(SamlError::ProtocolProfile(
                "ArtifactResponse Version must be 2.0".into(),
            ));
        }
        let _response_id = response.required_attr("ID")?;
        let response_instant = response.required_attr("IssueInstant")?;
        if parse_saml_utc_date_time(&response_instant).is_none() {
            return Err(SamlError::ProtocolProfile(
                "ArtifactResponse IssueInstant must be a UTC xs:dateTime".into(),
            ));
        }
        let in_response_to = response.attr("InResponseTo");
        if in_response_to != Some(self.request_id.as_str()) {
            return Err(SamlError::in_response_to_mismatch(
                Some(&self.request_id),
                in_response_to,
            ));
        }
        let issuer = issuer(&response)
            .ok_or_else(|| SamlError::issuer_mismatch(&self.identity_provider, None))?;
        if issuer.value != self.identity_provider {
            return Err(SamlError::issuer_mismatch(
                &self.identity_provider,
                Some(&issuer.value),
            ));
        }
        if !issuer_format_is_entity(issuer.format.as_deref()) {
            return Err(SamlError::ProtocolProfile(
                "ArtifactResponse Issuer Format must be omitted or entity".into(),
            ));
        }
        read_status(&response)?.require_success()?;
        let Some(message) = protocol_payload(&response)? else {
            return Err(SamlError::ArtifactNotReturned);
        };
        if message.namespace != namespace::PROTOCOL {
            return Err(SamlError::ProtocolProfile(
                "ArtifactResponse payload must be a SAML protocol element".into(),
            ));
        }
        Ok(ResolvedProtocolMessage {
            local_name: message.local_name.clone(),
            xml: standalone_element(&body.xml, message.start, message.end)?,
            identity_provider: self.identity_provider.clone(),
            artifact: self.artifact.clone(),
        })
    }
}

/// Protocol element returned inside `ArtifactResponse`.
///
/// This is the dereferenced message. It is not a validated Web SSO session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedProtocolMessage {
    local_name: String,
    xml: String,
    identity_provider: String,
    artifact: String,
}

impl ResolvedProtocolMessage {
    /// Local name of the protocol element.
    pub fn local_name(&self) -> &str {
        &self.local_name
    }

    /// XML of the protocol element.
    pub fn xml(&self) -> &str {
        &self.xml
    }

    /// Entity ID of the identity provider that returned the message.
    pub(crate) fn identity_provider(&self) -> &str {
        &self.identity_provider
    }

    /// Artifact value the message was resolved from.
    pub(crate) fn artifact(&self) -> &str {
        &self.artifact
    }
}

pub(crate) fn issue(
    metadata: &IdpMetadata,
    service_provider: &SpDescriptor,
    protocol_xml: &str,
    endpoint_index: u16,
    issued: &mut IssuedArtifacts,
) -> Result<Artifact, SamlError> {
    let (message_xml, local_name) = stored_message(protocol_xml)?;
    let required_channel = if local_name == "Response" {
        RequiredChannel::Confidential
    } else {
        RequiredChannel::Authenticated
    };
    store(
        metadata,
        service_provider,
        message_xml,
        required_channel,
        endpoint_index,
        issued,
    )
}

pub(crate) fn issue_sso_response(
    metadata: &IdpMetadata,
    service_provider: &SpDescriptor,
    response_xml: &str,
    endpoint_index: u16,
    issued: &mut IssuedArtifacts,
) -> Result<Artifact, SamlError> {
    let (message_xml, local_name) = stored_message(response_xml)?;
    if local_name != "Response" {
        return Err(SamlError::ProtocolProfile(
            "Web Browser SSO artifact message must be a protocol Response".into(),
        ));
    }
    store(
        metadata,
        service_provider,
        message_xml,
        RequiredChannel::Confidential,
        endpoint_index,
        issued,
    )
}

fn store(
    metadata: &IdpMetadata,
    service_provider: &SpDescriptor,
    message_xml: String,
    required_channel: RequiredChannel,
    endpoint_index: u16,
    issued: &mut IssuedArtifacts,
) -> Result<Artifact, SamlError> {
    let entity_id = metadata
        .as_metadata()
        .entity_id()
        .ok_or_else(|| SamlError::MissingMetadata("entityID".into()))?;
    let _service = soap_service(metadata, endpoint_index)?;
    let source_id: [u8; SOURCE_ID_LEN] = Sha1::digest(entity_id.as_bytes()).into();
    let encoded = encode_artifact(endpoint_index, source_id, message_handle());
    if issued.entries.contains_key(&encoded) {
        return Err(SamlError::Invalid(
            "artifact value is already outstanding".into(),
        ));
    }
    let artifact = Artifact::try_new(encoded)?;
    issued.insert(
        artifact.as_str().to_string(),
        IssuedEntry {
            issued_at: Instant::now(),
            service_provider: service_provider.entity_id().as_str().to_string(),
            message_xml,
            required_channel,
        },
    );
    Ok(artifact)
}

fn stored_message(xml: &str) -> Result<(String, String), SamlError> {
    let element = parse_saml(xml)?;
    if element.namespace != namespace::PROTOCOL {
        return Err(SamlError::ProtocolProfile(
            "stored artifact message must be a SAML protocol element".into(),
        ));
    }
    Ok((
        xml[element.start..element.end].to_string(),
        element.local_name,
    ))
}

pub(crate) fn resolve(
    requester_entity_id: &str,
    identity_provider: &IdpDescriptor,
    artifact: &Artifact,
    channel: SoapChannel,
    validation: &mut SamlValidationContext<'_>,
    setting: &EntitySetting,
) -> Result<ArtifactResolution, SamlError> {
    if !channel_allows(channel, RequiredChannel::Confidential) {
        return Err(SamlError::SoapChannelProtection);
    }
    let idp_entity_id = identity_provider.entity_id().as_str();
    let source_id: [u8; SOURCE_ID_LEN] = Sha1::digest(idp_entity_id.as_bytes()).into();
    if artifact.source_id != source_id {
        return Err(SamlError::issuer_mismatch(idp_entity_id, None));
    }
    let prefixes = Prefixes::of(setting)?;
    let service = soap_service(identity_provider.metadata(), artifact.endpoint_index())?;
    let request_id = generate_id();
    let issue_instant = now_iso8601();
    let mut writer = XmlWriter::new();
    writer.start(
        &prefixes.protocol("ArtifactResolve"),
        &[
            (&prefixes.xmlns_protocol(), namespace::PROTOCOL),
            (&prefixes.xmlns_assertion(), namespace::ASSERTION),
            ("ID", request_id.as_str()),
            ("Version", "2.0"),
            ("IssueInstant", issue_instant.as_str()),
            ("Destination", service.location()),
        ],
    );
    writer.text_element(&prefixes.assertion("Issuer"), &[], requester_entity_id);
    writer.text_element(&prefixes.protocol("Artifact"), &[], artifact.as_str());
    writer.end(&prefixes.protocol("ArtifactResolve"));
    let request =
        SoapRequest::try_new(EndpointUrl::try_new(service.location())?, &writer.finish())?;
    validation.check_and_store_message_replay(ReplayKey::Artifact(artifact.clone()))?;
    Ok(ArtifactResolution {
        request,
        request_id,
        identity_provider: idp_entity_id.to_string(),
        artifact: artifact.as_str().to_string(),
        xml_limits: setting.xml_limits,
        schema_validator: setting.schema_validator,
    })
}

pub(crate) fn answer(
    metadata: &IdpMetadata,
    presenter: &SpDescriptor,
    request_envelope: &str,
    issued: &mut IssuedArtifacts,
    channel: SoapChannel,
    setting: &EntitySetting,
) -> Result<AnsweredArtifact, SamlError> {
    let entity_id = metadata
        .as_metadata()
        .entity_id()
        .ok_or_else(|| SamlError::MissingMetadata("entityID".into()))?
        .to_string();
    let body = read_soap_body(request_envelope, setting.xml_limits)?;
    crate::schema::validate(request_envelope, setting.schema_validator)?;
    if body.local_name != "ArtifactResolve" || body.namespace != namespace::PROTOCOL {
        return Err(SamlError::ProtocolProfile(
            "SOAP body must be an ArtifactResolve".into(),
        ));
    }
    let request = parse_resolve(&body.xml, setting.xml_limits)?;
    let prefixes = Prefixes::of(setting)?;
    if let Some(mismatch) = RequestVersionMismatch::for_request(&request.version)? {
        return answered(
            &prefixes,
            &entity_id,
            &request.id,
            &mismatch.status(),
            None,
            ArtifactRelease::VersionMismatch,
        );
    }
    let success_without = |reason| {
        answered(
            &prefixes,
            &entity_id,
            &request.id,
            &Status::success(),
            None,
            ArtifactRelease::Withheld(reason),
        )
    };
    let Ok(artifact) = Artifact::try_new(request.artifact.as_str()) else {
        return success_without(ArtifactWithheld::NotOutstanding);
    };
    let source_id: [u8; SOURCE_ID_LEN] = Sha1::digest(entity_id.as_bytes()).into();
    if artifact.source_id != source_id {
        return success_without(ArtifactWithheld::NotOutstanding);
    }
    let message_xml = {
        let Some(entry) = issued.outstanding(artifact.as_str(), Instant::now()) else {
            return success_without(ArtifactWithheld::NotOutstanding);
        };
        if let Ok(service) = soap_service(metadata, artifact.endpoint_index()) {
            if let Some(destination) = request.destination.as_deref() {
                if destination != service.location() {
                    return success_without(ArtifactWithheld::Destination);
                }
            }
        } else {
            return success_without(ArtifactWithheld::NotOutstanding);
        }
        if !channel_allows(channel, entry.required_channel) {
            return success_without(ArtifactWithheld::Channel);
        }
        let presenter_id = presenter.entity_id().as_str();
        let issuer_matches = request.issuer.as_ref().is_some_and(|issuer| {
            issuer.value == presenter_id && issuer_format_is_entity(issuer.format.as_deref())
        });
        if !issuer_matches || presenter_id != entry.service_provider {
            return success_without(ArtifactWithheld::DifferentPresenter);
        }
        entry.message_xml.clone()
    };
    let response = answered(
        &prefixes,
        &entity_id,
        &request.id,
        &Status::success(),
        Some(&message_xml),
        ArtifactRelease::Returned,
    )?;
    issued.entries.remove(artifact.as_str());
    Ok(response)
}

fn answered(
    prefixes: &Prefixes<'_>,
    issuer: &str,
    in_response_to: &str,
    status: &Status,
    message_xml: Option<&str>,
    release: ArtifactRelease,
) -> Result<AnsweredArtifact, SamlError> {
    let mut writer = XmlWriter::new();
    writer.start(
        &prefixes.protocol("ArtifactResponse"),
        &[
            (&prefixes.xmlns_protocol(), namespace::PROTOCOL),
            (&prefixes.xmlns_assertion(), namespace::ASSERTION),
            ("ID", generate_id().as_str()),
            ("Version", "2.0"),
            ("IssueInstant", now_iso8601().as_str()),
            ("InResponseTo", in_response_to),
        ],
    );
    writer.text_element(&prefixes.assertion("Issuer"), &[], issuer);
    writer.status(prefixes, status);
    if let Some(message_xml) = message_xml {
        writer.raw(message_xml);
    }
    writer.end(&prefixes.protocol("ArtifactResponse"));
    Ok(AnsweredArtifact {
        response: SoapResponse::try_new(&writer.finish())?,
        release,
    })
}

fn channel_allows(channel: SoapChannel, required: RequiredChannel) -> bool {
    let authenticated = channel.authenticates_peer();
    match required {
        RequiredChannel::Authenticated => authenticated,
        RequiredChannel::Confidential => {
            authenticated && channel.confidentiality() == MessageConfidentiality::Protected
        }
    }
}

fn soap_service(
    metadata: &IdpMetadata,
    index: u16,
) -> Result<crate::metadata::ArtifactResolutionServiceEndpoint, SamlError> {
    let services = metadata.artifact_resolution_services()?;
    let service = services
        .into_iter()
        .find(|service| service.index() == index)
        .ok_or_else(|| SamlError::MissingMetadata("ArtifactResolutionService".into()))?;
    if !service.is_soap() {
        return Err(SamlError::Unsupported(
            "ArtifactResolutionService binding is not SOAP".into(),
        ));
    }
    Ok(service)
}

fn message_handle() -> [u8; SOURCE_ID_LEN] {
    crate::entity::random_20_bytes()
}

fn encode_artifact(
    index: u16,
    source_id: [u8; SOURCE_ID_LEN],
    handle: [u8; SOURCE_ID_LEN],
) -> String {
    let mut bytes = [0u8; ARTIFACT_LEN];
    bytes[0] = 0x00;
    bytes[1] = 0x04;
    bytes[2..4].copy_from_slice(&index.to_be_bytes());
    bytes[4..24].copy_from_slice(&source_id);
    bytes[24..].copy_from_slice(&handle);
    STANDARD.encode(bytes)
}

struct ResolveRequest {
    id: String,
    version: String,
    destination: Option<String>,
    issuer: Option<PartyName>,
    artifact: String,
}

fn parse_resolve(xml: &str, limits: XmlLimits) -> Result<ResolveRequest, SamlError> {
    let element = parse_saml_with_limits(xml, limits)?;
    if element.local_name != "ArtifactResolve" || element.namespace != namespace::PROTOCOL {
        return Err(SamlError::ProtocolProfile(
            "SOAP body must be an ArtifactResolve".into(),
        ));
    }
    let id = element.required_attr("ID")?;
    let version = element.required_attr("Version")?;
    let issue_instant = element.required_attr("IssueInstant")?;
    if parse_saml_utc_date_time(&issue_instant).is_none() {
        return Err(SamlError::ProtocolProfile(
            "ArtifactResolve IssueInstant must be a UTC xs:dateTime".into(),
        ));
    }
    let artifact = element
        .children
        .iter()
        .find(|child| child.local_name == "Artifact" && child.namespace == namespace::PROTOCOL)
        .map(|child| child.text.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            SamlError::ProtocolProfile("ArtifactResolve requires one Artifact value".into())
        })?;
    if element
        .children
        .iter()
        .filter(|child| child.local_name == "Artifact")
        .count()
        != 1
    {
        return Err(SamlError::ProtocolProfile(
            "ArtifactResolve requires one Artifact value".into(),
        ));
    }
    if element
        .children
        .iter()
        .filter(|child| child.local_name == "Issuer" && child.namespace == namespace::ASSERTION)
        .count()
        > 1
    {
        return Err(SamlError::ProtocolProfile(
            "ArtifactResolve requires at most one Issuer".into(),
        ));
    }
    Ok(ResolveRequest {
        id,
        version,
        destination: element.attr("Destination").map(collapse_whitespace),
        issuer: issuer(&element),
        artifact,
    })
}

fn protocol_payload(response: &SamlElement) -> Result<Option<&SamlElement>, SamlError> {
    let mut payloads = response.children.iter().filter(|child| {
        !matches!(
            (child.namespace.as_str(), child.local_name.as_str()),
            (namespace::ASSERTION, "Issuer")
                | (namespace::PROTOCOL, "Status" | "Extensions")
                | ("http://www.w3.org/2000/09/xmldsig#", "Signature")
        )
    });
    let payload = payloads.next();
    if payloads.next().is_some() {
        return Err(SamlError::ProtocolProfile(
            "ArtifactResponse must contain at most one protocol message".into(),
        ));
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_callback_participates_in_artifact_resolution_equality(
    ) -> Result<(), Box<dyn std::error::Error>> {
        fn validate(_: &str) -> Result<(), String> {
            Ok(())
        }
        let unchecked = ArtifactResolution {
            request: SoapRequest::try_new(
                crate::EndpointUrl::try_new("https://idp.example.com/artifact")?,
                r#"<samlp:ArtifactResolve xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>"#,
            )?,
            request_id: "_request".into(),
            identity_provider: "https://idp.example.com/metadata".into(),
            artifact: "artifact".into(),
            xml_limits: XmlLimits::default(),
            schema_validator: None,
        };
        let checked = ArtifactResolution {
            schema_validator: Some(validate),
            ..unchecked.clone()
        };
        assert_ne!(unchecked, checked);
        assert_ne!(checked, unchecked);
        assert_eq!(checked.clone(), checked);
        let other_request = ArtifactResolution {
            request_id: "_other_request".into(),
            ..checked.clone()
        };
        assert_ne!(checked, other_request);
        Ok(())
    }

    #[test]
    fn issued_artifacts_resolve_and_are_kept_only_for_the_lifetime() {
        let lifetime = Duration::from_secs(60);
        let start = Instant::now();
        let entry = |issued_at| IssuedEntry {
            issued_at,
            service_provider: "sp".into(),
            message_xml: String::new(),
            required_channel: RequiredChannel::Authenticated,
        };
        let mut issued = IssuedArtifacts::expire_after(lifetime);
        for n in 0u32..1_000 {
            issued.insert(n.to_string(), entry(start));
        }
        let before = start + lifetime - Duration::from_secs(1);
        assert!(issued.outstanding("0", before).is_some());
        assert!(issued.outstanding("0", start + lifetime).is_none());

        issued.insert("new".into(), entry(start + lifetime));
        assert_eq!(issued.entries.keys().collect::<Vec<_>>(), ["new"]);
        assert_eq!(issued.oldest_first.len(), 1);
    }
}
