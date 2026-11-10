//! Artifact resolution over the SOAP binding.
//!
//! The identity provider stores a protocol message for one service provider and
//! answers `ArtifactResolve`. The service provider sends that request and
//! returns the protocol message from `ArtifactResponse`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;

use crate::config::{IdpDescriptor, SpDescriptor};
use crate::constants::{namespace, status_code};
use crate::entity::{generate_id, now_iso8601};
use crate::error::SamlError;
use crate::metadata::IdpMetadata;
use crate::model::EndpointUrl;
use crate::soap::{
    read_soap_body, MessageConfidentiality, SoapChannel, SoapProtocolMessage, SoapRequest,
};
use crate::xml::fragment::standalone_element;
use crate::xml::parse_saml_utc_date_time;
use crate::xml::protocol_element::{
    issuer, issuer_format_is_entity, parse_saml, parse_saml_with_limits, status_codes, PartyName,
    SamlElement,
};
use crate::xml::write::XmlWriter;
use crate::xml::XmlLimits;

const ARTIFACT_TYPE_CODE: u16 = 0x0004;
const ARTIFACT_LEN: usize = 44;
const SOURCE_ID_LEN: usize = 20;

/// SAML V2.0 type 0x0004 artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    encoded: String,
    endpoint_index: u16,
    source_id: [u8; SOURCE_ID_LEN],
}

impl Artifact {
    /// Decode a type 0x0004 artifact.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when `encoded` is not a 44-byte type
    /// 0x0004 artifact.
    pub fn try_from_encoded(encoded: impl Into<String>) -> Result<Self, SamlError> {
        let encoded = encoded.into();
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

/// Which artifact dereference the service provider is performing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactDereference {
    web_browser_sso: bool,
    channel: SoapChannel,
}

impl ArtifactDereference {
    /// Resolve a SAML protocol message other than a Web Browser SSO `<Response>`.
    ///
    /// The channel must authenticate both parties and protect integrity.
    /// Confidentiality is required only by [`Self::web_browser_sso`].
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::SoapChannelProtection`] when `channel` does not.
    pub fn protocol(channel: SoapChannel) -> Result<Self, SamlError> {
        require_channel(channel, false)?;
        Ok(Self {
            web_browser_sso: false,
            channel,
        })
    }

    /// Dereference of a Web Browser SSO `<Response>` artifact.
    ///
    /// The channel must authenticate both parties and protect integrity and
    /// confidentiality.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::SoapChannelProtection`] when `channel` does not.
    pub fn web_browser_sso(channel: SoapChannel) -> Result<Self, SamlError> {
        require_channel(channel, true)?;
        Ok(Self {
            web_browser_sso: true,
            channel,
        })
    }

    /// Channel protection supplied for this dereference.
    pub fn channel(self) -> SoapChannel {
        self.channel
    }
}

/// Protocol message an artifact issuer retains for one service provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedMessage {
    xml: String,
    web_browser_sso_response: bool,
}

impl IssuedMessage {
    /// Retain a SAML protocol element that is not a Web Browser SSO response.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when `xml` is not one element in the SAML protocol
    /// namespace.
    pub fn protocol(xml: impl Into<String>) -> Result<Self, SamlError> {
        Self::parse(xml.into(), false)
    }

    /// Retain a Web Browser SSO `<Response>`.
    ///
    /// Releasing it requires a mutually authenticated, integrity-protected,
    /// and confidential channel.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when `xml` is not one protocol `<Response>`.
    pub fn web_browser_sso_response(xml: impl Into<String>) -> Result<Self, SamlError> {
        Self::parse(xml.into(), true)
    }

    /// XML that will be placed in `ArtifactResponse`.
    pub fn xml(&self) -> &str {
        &self.xml
    }

    fn parse(xml: String, web_browser_sso_response: bool) -> Result<Self, SamlError> {
        let element = parse_saml(xml.as_str())?;
        if element.namespace != namespace::PROTOCOL {
            return Err(SamlError::ProtocolProfile(
                "stored artifact message must be a SAML protocol element".into(),
            ));
        }
        if web_browser_sso_response && element.local_name != "Response" {
            return Err(SamlError::ProtocolProfile(
                "Web Browser SSO artifact message must be a protocol Response".into(),
            ));
        }
        if !web_browser_sso_response && element.local_name == "Response" {
            return Err(SamlError::ProtocolProfile(
                "a protocol Response must be stored with IssuedMessage::web_browser_sso_response"
                    .into(),
            ));
        }
        Ok(Self {
            xml: xml[element.span].to_string(),
            web_browser_sso_response,
        })
    }
}

/// Artifacts an identity provider has issued and not yet resolved.
///
/// The caller owns eviction: [`Self::remove`] an artifact that will never
/// resolve, for example after a deployment-selected timeout, to bound memory.
#[derive(Debug, Default)]
pub struct IssuedArtifacts {
    entries: HashMap<String, IssuedEntry>,
}

#[derive(Debug)]
struct IssuedEntry {
    service_provider: String,
    message_xml: String,
    web_browser_sso_response: bool,
}

impl IssuedArtifacts {
    /// An empty set of outstanding artifacts.
    pub fn new() -> Self {
        Self::default()
    }

    /// Discard `artifact` and its stored message without returning it.
    ///
    /// Returns whether the artifact was outstanding. A later
    /// `ArtifactResolve` for it gets Success without the message.
    pub fn remove(&mut self, artifact: &Artifact) -> bool {
        self.entries.remove(artifact.as_str()).is_some()
    }
}

/// Artifacts a receiver has already accepted for resolution.
///
/// [`Self::enforce_single_use`] is the default. [`Self::allow_reuse`] relaxes
/// the receiver single-use recommendation.
#[derive(Debug)]
pub struct ArtifactUses {
    blocked: Option<BlockedArtifacts>,
}

#[derive(Debug)]
struct BlockedArtifacts {
    period: Duration,
    values: HashSet<String>,
    oldest_first: VecDeque<(Instant, String)>,
}

impl ArtifactUses {
    /// Reject a second resolution of the same artifact value for `period`.
    ///
    /// Choose a `period` longer than the identity provider would still resolve
    /// the artifact. Each resolution drops the values recorded more than
    /// `period` ago, so memory holds only the artifacts of the last `period`.
    pub fn enforce_single_use(period: Duration) -> Self {
        Self {
            blocked: Some(BlockedArtifacts {
                period,
                values: HashSet::new(),
                oldest_first: VecDeque::new(),
            }),
        }
    }

    /// Allow the same artifact value to be resolved again.
    ///
    /// This relaxes the receiver single-use recommendation. The artifact issuer
    /// still returns the message only once.
    pub fn allow_reuse() -> Self {
        Self { blocked: None }
    }

    fn record(&mut self, artifact: &str, now: Instant) -> Result<(), SamlError> {
        let Some(blocked) = &mut self.blocked else {
            return Ok(());
        };
        while blocked
            .oldest_first
            .front()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) >= blocked.period)
        {
            if let Some((_, expired)) = blocked.oldest_first.pop_front() {
                blocked.values.remove(&expired);
            }
        }
        if !blocked.values.insert(artifact.to_string()) {
            return Err(SamlError::ReplayDetected {
                key: artifact.to_string(),
            });
        }
        blocked.oldest_first.push_back((now, artifact.to_string()));
        Ok(())
    }
}

/// Why an understood `ArtifactResolve` did not include the protocol message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactWithheld {
    /// No outstanding artifact matched, including one already resolved.
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
    /// The request version is not 2.0. The response status is `VersionMismatch`.
    VersionMismatch,
}

/// SOAP `ArtifactResponse` produced for one `ArtifactResolve`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnsweredArtifact {
    envelope: String,
    release: ArtifactRelease,
}

impl AnsweredArtifact {
    /// SOAP envelope to return to the requester.
    pub fn envelope(&self) -> &str {
        &self.envelope
    }

    /// Whether the protocol message was included.
    pub fn release(&self) -> ArtifactRelease {
        self.release
    }

    /// `Cache-Control` value a responder should send.
    pub fn cache_control(&self) -> &'static str {
        crate::soap::response_cache_control()
    }

    /// `Pragma` value a responder should send.
    pub fn pragma(&self) -> &'static str {
        crate::soap::response_pragma()
    }

    /// `Content-Type` for SOAP 1.1.
    pub fn content_type(&self) -> &'static str {
        crate::soap::response_content_type()
    }
}

/// In-progress artifact resolution. Send [`Self::request`], then [`Self::finish`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactResolution {
    request: SoapRequest,
    request_id: String,
    identity_provider: String,
    artifact: String,
    web_browser_sso: bool,
    xml_limits: XmlLimits,
}

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
    /// from the identity provider, the status is not success, the response
    /// does not contain the protocol message, or the message is a `Response`
    /// and the dereference is not [`ArtifactDereference::web_browser_sso`].
    pub fn finish(&self, response_envelope: &str) -> Result<ResolvedProtocolMessage, SamlError> {
        let body = read_soap_body(response_envelope, self.xml_limits)?;
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
        let (top, second) = status_codes(&response)?;
        if top != status_code::SUCCESS {
            return Err(SamlError::StatusNotSuccess { top, second });
        }
        let Some(message) = protocol_payload(&response)? else {
            return Err(SamlError::ArtifactNotReturned);
        };
        if message.namespace != namespace::PROTOCOL {
            return Err(SamlError::ProtocolProfile(
                "ArtifactResponse payload must be a SAML protocol element".into(),
            ));
        }
        if self.web_browser_sso && message.local_name != "Response" {
            return Err(SamlError::ProtocolProfile(
                "Web Browser SSO artifact payload must be a Response".into(),
            ));
        }
        if !self.web_browser_sso && message.local_name == "Response" {
            return Err(SamlError::ProtocolProfile(
                "a protocol Response must be dereferenced with ArtifactDereference::web_browser_sso"
                    .into(),
            ));
        }
        Ok(ResolvedProtocolMessage {
            local_name: message.local_name.clone(),
            xml: standalone_element(&body.xml, message.span.start, message.span.end)?,
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
    message: IssuedMessage,
    endpoint_index: u16,
    issued: &mut IssuedArtifacts,
) -> Result<Artifact, SamlError> {
    let entity_id = metadata
        .get_entity_id()
        .ok_or_else(|| SamlError::MissingMetadata("entityID".into()))?;
    let _service = soap_service(metadata, endpoint_index)?;
    let source_id = sha1(entity_id.as_bytes());
    let encoded = encode_artifact(endpoint_index, source_id, message_handle());
    if issued.entries.contains_key(&encoded) {
        return Err(SamlError::Invalid(
            "artifact value is already outstanding".into(),
        ));
    }
    let artifact = Artifact::try_from_encoded(encoded)?;
    issued.entries.insert(
        artifact.as_str().to_string(),
        IssuedEntry {
            service_provider: service_provider.entity_id().as_str().to_string(),
            message_xml: message.xml,
            web_browser_sso_response: message.web_browser_sso_response,
        },
    );
    Ok(artifact)
}

pub(crate) fn resolve(
    requester_entity_id: &str,
    identity_provider: &IdpDescriptor,
    artifact: &Artifact,
    dereference: ArtifactDereference,
    uses: &mut ArtifactUses,
    xml_limits: XmlLimits,
) -> Result<ArtifactResolution, SamlError> {
    require_channel(dereference.channel, dereference.web_browser_sso)?;
    let idp_entity_id = identity_provider.entity_id().as_str();
    if artifact.source_id != sha1(idp_entity_id.as_bytes()) {
        return Err(SamlError::issuer_mismatch(idp_entity_id, None));
    }
    let service = soap_service(identity_provider.metadata(), artifact.endpoint_index())?;
    let request_id = generate_id();
    let issue_instant = now_iso8601();
    let mut writer = XmlWriter::new();
    writer.start(
        "samlp:ArtifactResolve",
        &[
            ("xmlns:samlp", namespace::PROTOCOL),
            ("xmlns:saml", namespace::ASSERTION),
            ("ID", request_id.as_str()),
            ("Version", "2.0"),
            ("IssueInstant", issue_instant.as_str()),
            ("Destination", service.location()),
        ],
    );
    writer.text_element("saml:Issuer", &[], requester_entity_id);
    writer.text_element("samlp:Artifact", &[], artifact.as_str());
    writer.end("samlp:ArtifactResolve");
    let request =
        SoapProtocolMessage::request(EndpointUrl::try_new(service.location())?, &writer.finish())?;
    uses.record(artifact.as_str(), Instant::now())?;
    Ok(ArtifactResolution {
        request,
        request_id,
        identity_provider: idp_entity_id.to_string(),
        artifact: artifact.as_str().to_string(),
        web_browser_sso: dereference.web_browser_sso,
        xml_limits,
    })
}

pub(crate) fn answer(
    metadata: &IdpMetadata,
    presenter: &SpDescriptor,
    request_envelope: &str,
    issued: &mut IssuedArtifacts,
    channel: SoapChannel,
    xml_limits: XmlLimits,
) -> Result<AnsweredArtifact, SamlError> {
    let entity_id = metadata
        .get_entity_id()
        .ok_or_else(|| SamlError::MissingMetadata("entityID".into()))?
        .to_string();
    let body = read_soap_body(request_envelope, xml_limits)?;
    if body.local_name != "ArtifactResolve" || body.namespace != namespace::PROTOCOL {
        return Err(SamlError::ProtocolProfile(
            "SOAP body must be an ArtifactResolve".into(),
        ));
    }
    let request = parse_resolve(&body.xml, xml_limits)?;
    if request.version != "2.0" {
        return answered(
            &entity_id,
            &request.id,
            status_code::VERSION_MISMATCH,
            None,
            ArtifactRelease::VersionMismatch,
        );
    }
    let Ok(artifact) = Artifact::try_from_encoded(&request.artifact) else {
        return success_without(&entity_id, &request.id, ArtifactWithheld::NotOutstanding);
    };
    if artifact.source_id != sha1(entity_id.as_bytes()) {
        return success_without(&entity_id, &request.id, ArtifactWithheld::NotOutstanding);
    }
    let message_xml = {
        let Some(entry) = issued.entries.get(artifact.as_str()) else {
            return success_without(&entity_id, &request.id, ArtifactWithheld::NotOutstanding);
        };
        if let Ok(service) = soap_service(metadata, artifact.endpoint_index()) {
            if let Some(destination) = request.destination.as_deref() {
                if destination != service.location() {
                    return success_without(&entity_id, &request.id, ArtifactWithheld::Destination);
                }
            }
        } else {
            return success_without(&entity_id, &request.id, ArtifactWithheld::NotOutstanding);
        }
        if !channel_allows(channel, entry.web_browser_sso_response) {
            return success_without(&entity_id, &request.id, ArtifactWithheld::Channel);
        }
        let presenter_id = presenter.entity_id().as_str();
        let issuer_matches = request.issuer.as_ref().is_some_and(|issuer| {
            issuer.value == presenter_id && issuer_format_is_entity(issuer.format.as_deref())
        });
        if !issuer_matches || presenter_id != entry.service_provider {
            return success_without(
                &entity_id,
                &request.id,
                ArtifactWithheld::DifferentPresenter,
            );
        }
        entry.message_xml.clone()
    };
    let response = answered(
        &entity_id,
        &request.id,
        status_code::SUCCESS,
        Some(&message_xml),
        ArtifactRelease::Returned,
    )?;
    issued.entries.remove(artifact.as_str());
    Ok(response)
}

fn success_without(
    issuer: &str,
    in_response_to: &str,
    reason: ArtifactWithheld,
) -> Result<AnsweredArtifact, SamlError> {
    answered(
        issuer,
        in_response_to,
        status_code::SUCCESS,
        None,
        ArtifactRelease::Withheld(reason),
    )
}

fn answered(
    issuer: &str,
    in_response_to: &str,
    status: &str,
    message_xml: Option<&str>,
    release: ArtifactRelease,
) -> Result<AnsweredArtifact, SamlError> {
    let mut writer = XmlWriter::new();
    writer.start(
        "samlp:ArtifactResponse",
        &[
            ("xmlns:samlp", namespace::PROTOCOL),
            ("xmlns:saml", namespace::ASSERTION),
            ("ID", generate_id().as_str()),
            ("Version", "2.0"),
            ("IssueInstant", now_iso8601().as_str()),
            ("InResponseTo", in_response_to),
        ],
    );
    writer.text_element("saml:Issuer", &[], issuer);
    writer.start("samlp:Status", &[]);
    writer.empty("samlp:StatusCode", &[("Value", status)]);
    writer.end("samlp:Status");
    if let Some(message_xml) = message_xml {
        writer.raw(message_xml);
    }
    writer.end("samlp:ArtifactResponse");
    Ok(AnsweredArtifact {
        envelope: SoapProtocolMessage::response_envelope(&writer.finish())?,
        release,
    })
}

fn require_channel(channel: SoapChannel, web_browser_sso: bool) -> Result<(), SamlError> {
    if channel_allows(channel, web_browser_sso) {
        Ok(())
    } else {
        Err(SamlError::SoapChannelProtection)
    }
}

fn channel_allows(channel: SoapChannel, web_browser_sso: bool) -> bool {
    let authenticated = channel.authenticates_peer();
    if web_browser_sso {
        authenticated && channel.confidentiality() == MessageConfidentiality::Protected
    } else {
        authenticated
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
        destination: element.attr("Destination").map(str::to_string),
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

fn sha1(input: &[u8]) -> [u8; 20] {
    let mut hash = [
        0x6745_2301_u32,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut data = Vec::with_capacity(input.len() + 72);
    data.extend_from_slice(input);
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in data.as_chunks::<64>().0 {
        let mut words = [0u32; 80];
        for (index, word) in words.iter_mut().enumerate().take(16) {
            let start = index * 4;
            *word = u32::from_be_bytes([
                chunk[start],
                chunk[start + 1],
                chunk[start + 2],
                chunk[start + 3],
            ]);
        }
        for index in 16..80 {
            words[index] =
                (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                    .rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (hash[0], hash[1], hash[2], hash[3], hash[4]);
        for (index, word) in words.iter().enumerate() {
            let (f, constant) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(constant)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        hash[0] = hash[0].wrapping_add(a);
        hash[1] = hash[1].wrapping_add(b);
        hash[2] = hash[2].wrapping_add(c);
        hash[3] = hash[3].wrapping_add(d);
        hash[4] = hash[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (index, value) in hash.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&value.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_matches_the_nist_abc_vector() {
        let digest = sha1(b"abc");
        assert_eq!(hex(&digest), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn sha1_matches_the_empty_vector() {
        let digest = sha1(b"");
        assert_eq!(hex(&digest), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn sha1_matches_the_two_block_nist_vector() {
        let digest = sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(hex(&digest), "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    }

    #[test]
    fn sha1_matches_the_quick_brown_fox_vector() {
        let digest = sha1(b"The quick brown fox jumps over the lazy dog");
        assert_eq!(hex(&digest), "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
    }

    #[test]
    fn single_use_blocks_an_artifact_only_for_the_period() -> Result<(), Box<dyn std::error::Error>>
    {
        let period = Duration::from_secs(60);
        let start = Instant::now();
        let mut uses = ArtifactUses::enforce_single_use(period);
        for n in 0u32..1_000 {
            uses.record(&n.to_string(), start)?;
        }
        let repeated = uses.record("0", start + period - Duration::from_secs(1));
        assert!(matches!(repeated, Err(SamlError::ReplayDetected { key }) if key == "0"));

        uses.record("0", start + period)?;
        let blocked = uses.blocked.as_ref().ok_or("single use is enforced")?;
        assert_eq!(blocked.values, HashSet::from(["0".to_string()]));
        assert_eq!(blocked.oldest_first.len(), 1);
        Ok(())
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
}
