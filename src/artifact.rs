use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha1::{Digest, Sha1};

mod store;
pub use store::{ArtifactChannelRequirement, ArtifactStore, IssuedArtifact, IssuedArtifacts};

use crate::binding::sign_soap_message;
use crate::config::{HmacSecret, IdpDescriptor, SpDescriptor, XmlSignatureProfile};
use crate::constants::{namespace, CertUse};
use crate::entity::{generate_id, now_iso8601, EntitySetting};
use crate::error::SamlError;
use crate::metadata::IdpMetadata;
use crate::model::{
    check_saml2_answer_allowed, EndpointUrl, ReplayKey, RequestVersionMismatch,
    SamlValidationContext, Status, SubordinateStatusCode,
};
use crate::soap::{
    read_soap_body, read_soap_status_response, reject_processing_instructions,
    MessageConfidentiality, RequestSignature, SoapChannel, SoapRequest, SoapResponse,
};
use crate::xml::fragment::standalone_element;
use crate::xml::name::{check_in_response_to, writable_in_response_to};
use crate::xml::protocol_element::{
    issuer, issuer_format_is_entity, parse_saml, parse_saml_with_limits, PartyName, SamlElement,
};
use crate::xml::status::read_status;
use crate::xml::write::{Prefixes, XmlWriter};
use crate::xml::XmlLimits;
use crate::xml::{any_uri::collapse_whitespace, dom};

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
    /// ASCII whitespace, such as a line break, is ignored, and padding may be
    /// omitted. [`Self::as_str`] returns the padded value without whitespace,
    /// so every spelling of one artifact compares equal.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when `value` is not a 44-byte type
    /// 0x0004 artifact, including a value with another character outside the
    /// base64 alphabet or a last character whose unused bits are not zero.
    pub fn try_new(value: impl Into<String>) -> Result<Self, SamlError> {
        let bytes = crate::binding::decode_base64_with_limit(&value.into(), ARTIFACT_LEN)
            .map_err(|_| SamlError::Invalid("artifact is not the base64 of 44 bytes".into()))?;
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

/// Why the identity provider withheld the protocol message in an `ArtifactResponse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactWithheld {
    /// No outstanding artifact matched, including one already resolved or
    /// past its lifetime.
    NotOutstanding,
    /// The presenter is not the service provider the artifact was issued to.
    DifferentPresenter,
    /// The SOAP channel is not confidential, and the stored message requires
    /// confidentiality.
    InsufficientChannelProtection,
    /// The request's `Destination` differs from the URL that received it.
    DestinationMismatch,
    /// The [`ArtifactStore`] failed, so the identity provider could not
    /// confirm or consume an outstanding artifact. [`AnsweredArtifact::error`]
    /// returns the store error.
    StoreUnavailable,
}

/// What the identity provider put in `ArtifactResponse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactRelease {
    /// The protocol message is in the response.
    Returned,
    /// The response status is Success and the message is absent.
    Withheld(ArtifactWithheld),
    /// The request version is unsupported. The response status is `VersionMismatch`.
    VersionMismatch,
    /// The request signature did not verify. The response status is
    /// `Requester` with `RequestDenied`, and the message is absent.
    /// [`AnsweredArtifact::error`] returns the verification error.
    RequestDenied,
    /// The request is signed, and this identity provider cannot verify the
    /// signature: the build has no crypto provider, or the provider failed to
    /// start. The response status is `Responder`, and the message is absent.
    /// [`AnsweredArtifact::error`] returns [`SamlError::Unsupported`] or
    /// [`SamlError::Crypto`].
    VerificationUnavailable,
    /// The request does not have exactly one `Artifact` and at most one
    /// `Issuer`, or lacks an `xs:NCName` `ID`, a `major.minor` `Version`, or
    /// a UTC `IssueInstant`. The response status is `Requester`, and the
    /// message is absent. [`AnsweredArtifact::error`] returns why.
    MalformedRequest,
}

/// SOAP `ArtifactResponse` produced for one `ArtifactResolve`.
#[derive(Debug)]
pub struct AnsweredArtifact {
    response: SoapResponse,
    release: ArtifactRelease,
    error: Option<SamlError>,
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

    /// Error that kept the identity provider from acting on the request.
    ///
    /// Present for [`ArtifactWithheld::StoreUnavailable`], with the error the
    /// [`ArtifactStore`] returned, for [`ArtifactRelease::RequestDenied`],
    /// with the signature verification error, for
    /// [`ArtifactRelease::VerificationUnavailable`], with the error that kept
    /// the signature from being verified, and for
    /// [`ArtifactRelease::MalformedRequest`], with what the request lacks.
    /// Send [`Self::response`] in every case. The response carries only its
    /// status, not this error.
    pub fn error(&self) -> Option<&SamlError> {
        self.error.as_ref()
    }

    fn caused_by(mut self, error: SamlError) -> Self {
        self.error = Some(error);
        self
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
    signing_certificates: Vec<String>,
    hmac_secret: Option<HmacSecret>,
    signature_profile: XmlSignatureProfile,
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
            signing_certificates,
            hmac_secret,
            signature_profile,
            xml_limits,
            schema_validator,
        } = self;
        request == &other.request
            && request_id == &other.request_id
            && identity_provider == &other.identity_provider
            && artifact == &other.artifact
            && signing_certificates == &other.signing_certificates
            && hmac_secret == &other.hmac_secret
            && signature_profile == &other.signature_profile
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
    /// A present XML signature must cover the `ArtifactResponse` and verify
    /// against the identity provider's signing keys and the signature profile
    /// captured when resolution started. The returned message is validated
    /// separately by the caller's SAML flow.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the envelope is not an `ArtifactResponse`
    /// from the identity provider, the status is not success, or the response
    /// does not contain one SAML protocol element. Returns
    /// [`SamlError::InResponseToMismatch`] when `InResponseTo` is not the
    /// `ArtifactResolve` ID, and [`SamlError::IssuerMismatch`] when the
    /// `Issuer` is absent or differs from the identity provider's entity ID.
    /// Returns [`SamlError::ArtifactNotReturned`] when a `Success` response
    /// carries no protocol message. An invalid signature returns a
    /// verification error. A present signature without a crypto provider
    /// returns [`SamlError::Unsupported`].
    pub fn finish(&self, response_envelope: &str) -> Result<ResolvedProtocolMessage, SamlError> {
        let (body, response) = read_soap_status_response(
            response_envelope,
            self.xml_limits,
            self.schema_validator,
            "ArtifactResponse",
            "SOAP body must be an ArtifactResponse",
            &self.request_id,
        )?;
        let issuer = issuer(&response)?
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
        body.verify_signature_if_present(
            response_envelope,
            &response,
            &self.signing_certificates,
            self.hmac_secret.as_ref(),
            self.signature_profile,
        )?;
        read_status(&body.xml, self.xml_limits)?.require_success()?;
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

    pub(crate) fn identity_provider(&self) -> &str {
        &self.identity_provider
    }

    pub(crate) fn artifact(&self) -> &str {
        &self.artifact
    }
}

pub(crate) fn issue<S: ArtifactStore + ?Sized>(
    metadata: &IdpMetadata,
    service_provider: &SpDescriptor,
    protocol_xml: &str,
    endpoint_index: u16,
    issued: &mut S,
    setting: &EntitySetting,
) -> Result<Artifact, SamlError> {
    let (message_xml, local_name) = stored_message(protocol_xml)?;
    let required_channel = if local_name == "Response" {
        ArtifactChannelRequirement::Confidential
    } else {
        ArtifactChannelRequirement::Authenticated
    };
    let (artifact, entry) = prepare_entry(
        metadata,
        service_provider,
        message_xml,
        required_channel,
        endpoint_index,
        issued,
        setting,
    )?;
    issued.store(&artifact, entry)?;
    Ok(artifact)
}

pub(crate) fn prepare_sso_response<S: ArtifactStore + ?Sized>(
    metadata: &IdpMetadata,
    service_provider: &SpDescriptor,
    response_xml: &str,
    endpoint_index: u16,
    issued: &S,
    setting: &EntitySetting,
) -> Result<(Artifact, IssuedArtifact), SamlError> {
    let (message_xml, local_name) = stored_message(response_xml)?;
    if local_name != "Response" {
        return Err(SamlError::ProtocolProfile(
            "Web Browser SSO artifact message must be a protocol Response".into(),
        ));
    }
    prepare_entry(
        metadata,
        service_provider,
        message_xml,
        ArtifactChannelRequirement::Confidential,
        endpoint_index,
        issued,
        setting,
    )
}

fn prepare_entry<S: ArtifactStore + ?Sized>(
    metadata: &IdpMetadata,
    service_provider: &SpDescriptor,
    message_xml: String,
    required_channel: ArtifactChannelRequirement,
    endpoint_index: u16,
    issued: &S,
    setting: &EntitySetting,
) -> Result<(Artifact, IssuedArtifact), SamlError> {
    let entity_id = metadata
        .as_metadata()
        .entity_id()
        .ok_or_else(|| SamlError::MissingMetadata("entityID".into()))?;
    let _service = soap_service(metadata, endpoint_index)?;
    let prefixes = Prefixes::of(setting)?;
    // A schema-valid xs:ID needs no XML escaping. Reserve the largest one the response can echo.
    let request_id = "_".repeat(XmlLimits::default().max_attribute_value_bytes);
    answered(
        &prefixes,
        entity_id,
        Some(&request_id),
        &Status::success(),
        Some(&message_xml),
        ArtifactRelease::Returned,
    )?;
    let now = issued.now()?;
    let lifetime = issued.lifetime()?;
    let expires_at = now.checked_add(lifetime).ok_or_else(|| {
        SamlError::Invalid("artifact expiration overflows supported time range".into())
    })?;
    let source_id: [u8; SOURCE_ID_LEN] = Sha1::digest(entity_id.as_bytes()).into();
    let encoded = encode_artifact(endpoint_index, source_id, message_handle());
    let artifact = Artifact::try_new(encoded)?;
    let entry = IssuedArtifact::new(
        service_provider.entity_id().clone(),
        message_xml,
        required_channel,
        expires_at,
    );
    Ok((artifact, entry))
}

fn stored_message(xml: &str) -> Result<(String, String), SamlError> {
    let element = parse_saml(xml)?;
    if element.namespace != namespace::PROTOCOL {
        return Err(SamlError::ProtocolProfile(
            "stored artifact message must be a SAML protocol element".into(),
        ));
    }
    let payload = &xml[element.start..element.end];
    reject_processing_instructions(payload)?;
    Ok((payload.to_owned(), element.local_name))
}

#[derive(Clone, Copy)]
pub(crate) enum ArtifactResolveSigning {
    Unsigned,
    Signed,
}

pub(crate) fn resolve(
    requester_entity_id: &str,
    identity_provider: &IdpDescriptor,
    artifact: &Artifact,
    channel: SoapChannel,
    validation: &mut SamlValidationContext<'_>,
    setting: &EntitySetting,
    signing: ArtifactResolveSigning,
) -> Result<ArtifactResolution, SamlError> {
    if !channel_allows(channel, ArtifactChannelRequirement::Confidential) {
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
    let xml = writer.finish();
    let xml = match signing {
        ArtifactResolveSigning::Unsigned => xml,
        ArtifactResolveSigning::Signed => sign_soap_message(setting, &xml)?,
    };
    let request = SoapRequest::try_new(EndpointUrl::try_new(service.location())?, &xml)?;
    validation.check_and_store_message_replay(ReplayKey::Artifact(artifact.clone()))?;
    Ok(ArtifactResolution {
        request,
        request_id,
        identity_provider: idp_entity_id.to_string(),
        artifact: artifact.as_str().to_string(),
        signing_certificates: identity_provider
            .metadata()
            .as_metadata()
            .x509_certificates(CertUse::Signing)
            .to_vec(),
        hmac_secret: identity_provider.provider().setting.hmac_secret.clone(),
        signature_profile: setting.xml_signatures,
        xml_limits: setting.xml_limits,
        schema_validator: setting.schema_validator,
    })
}

pub(crate) fn answer<S: ArtifactStore + ?Sized>(
    metadata: &IdpMetadata,
    presenter: &SpDescriptor,
    request_envelope: &str,
    received_at: &EndpointUrl,
    issued: &mut S,
    channel: SoapChannel,
    setting: &EntitySetting,
) -> Result<AnsweredArtifact, SamlError> {
    if !channel.authenticates_peer() {
        return Err(SamlError::SoapChannelProtection);
    }
    let entity_id = metadata
        .as_metadata()
        .entity_id()
        .ok_or_else(|| SamlError::MissingMetadata("entityID".into()))?
        .to_string();
    if !metadata
        .artifact_resolution_services()?
        .iter()
        .any(|service| service.is_soap() && service.location() == received_at.as_str())
    {
        return Err(SamlError::RecipientEndpointNotPublished);
    }
    let body = read_soap_body(request_envelope, setting.xml_limits)?;
    crate::schema::validate(request_envelope, setting.schema_validator)?;
    if body.local_name != "ArtifactResolve" || body.namespace != namespace::PROTOCOL {
        return Err(SamlError::ProtocolProfile(
            "SOAP body must be an ArtifactResolve".into(),
        ));
    }
    let element = parse_saml_with_limits(&body.xml, setting.xml_limits)?;
    check_saml2_answer_allowed(element.attr("Version"))?;
    let prefixes = Prefixes::of(setting)?;
    let refuse = |status: &Status, release, error| {
        Ok(answered(
            &prefixes,
            &entity_id,
            element.attr("ID").and_then(writable_in_response_to),
            status,
            None,
            release,
        )?
        .caused_by(error))
    };
    match body.check_request_signature(
        request_envelope,
        &element,
        presenter
            .metadata()
            .as_metadata()
            .x509_certificates(CertUse::Signing),
        presenter.provider().setting.hmac_secret.as_ref(),
        setting.xml_signatures,
    ) {
        RequestSignature::Accepted => {}
        RequestSignature::Unverifiable(error) => {
            return refuse(
                &Status::responder(),
                ArtifactRelease::VerificationUnavailable,
                error,
            )
        }
        RequestSignature::Rejected(error) => {
            return refuse(
                &Status::requester().with_subordinate(SubordinateStatusCode::request_denied()),
                ArtifactRelease::RequestDenied,
                error,
            )
        }
    }
    let request = match parse_resolve(&element) {
        Ok(request) => request,
        Err(error) => {
            return refuse(
                &Status::requester(),
                ArtifactRelease::MalformedRequest,
                error,
            )
        }
    };
    if let Some(mismatch) = request.version_mismatch {
        return answered(
            &prefixes,
            &entity_id,
            Some(&request.id),
            &mismatch.status(),
            None,
            ArtifactRelease::VersionMismatch,
        );
    }
    let success_without = |reason| {
        answered(
            &prefixes,
            &entity_id,
            Some(&request.id),
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
    let store_unavailable = |error: SamlError| {
        Ok(success_without(ArtifactWithheld::StoreUnavailable)?.caused_by(error))
    };
    let entry = match issued.lookup(&artifact) {
        Ok(Some(entry)) => entry,
        Ok(None) => return success_without(ArtifactWithheld::NotOutstanding),
        Err(error) => return store_unavailable(error),
    };
    let presenter_id = presenter.entity_id().as_str();
    let issuer_matches = request.issuer.as_ref().is_some_and(|issuer| {
        issuer.value == presenter_id && issuer_format_is_entity(issuer.format.as_deref())
    });
    if !issuer_matches || presenter_id != entry.service_provider().as_str() {
        return success_without(ArtifactWithheld::DifferentPresenter);
    }
    match issued.now() {
        Ok(now) if entry.expires_at() <= now => {
            return success_without(ArtifactWithheld::NotOutstanding)
        }
        Ok(_) => {}
        Err(error) => return store_unavailable(error),
    }
    if request
        .destination
        .as_deref()
        .is_some_and(|destination| destination != received_at.as_str())
    {
        return success_without(ArtifactWithheld::DestinationMismatch);
    }
    if !channel_allows(channel, entry.required_channel()) {
        return success_without(ArtifactWithheld::InsufficientChannelProtection);
    }
    let response = answered(
        &prefixes,
        &entity_id,
        Some(&request.id),
        &Status::success(),
        Some(entry.message_xml()),
        ArtifactRelease::Returned,
    )?;
    match issued.now() {
        Ok(now) if entry.expires_at() <= now => {
            return success_without(ArtifactWithheld::NotOutstanding)
        }
        Ok(_) => {}
        Err(error) => return store_unavailable(error),
    }
    match issued.consume(&artifact, &entry) {
        Ok(true) => Ok(response),
        Ok(false) => success_without(ArtifactWithheld::NotOutstanding),
        Err(error) => store_unavailable(error),
    }
}

fn answered(
    prefixes: &Prefixes<'_>,
    issuer: &str,
    in_response_to: Option<&str>,
    status: &Status,
    message_xml: Option<&str>,
    release: ArtifactRelease,
) -> Result<AnsweredArtifact, SamlError> {
    let xmlns_protocol = prefixes.xmlns_protocol();
    let xmlns_assertion = prefixes.xmlns_assertion();
    let id = generate_id();
    let issue_instant = now_iso8601();
    let mut attributes = vec![
        (xmlns_protocol.as_str(), namespace::PROTOCOL),
        (xmlns_assertion.as_str(), namespace::ASSERTION),
        ("ID", id.as_str()),
        ("Version", "2.0"),
        ("IssueInstant", issue_instant.as_str()),
    ];
    if let Some(in_response_to) = in_response_to {
        check_in_response_to(in_response_to)?;
        attributes.push(("InResponseTo", in_response_to));
    }
    let mut writer = XmlWriter::new();
    writer.start(&prefixes.protocol("ArtifactResponse"), &attributes);
    writer.text_element(&prefixes.assertion("Issuer"), &[], issuer);
    writer.status(prefixes, status, None);
    if let Some(message_xml) = message_xml {
        writer.raw(message_xml);
    }
    writer.end(&prefixes.protocol("ArtifactResponse"));
    let response = SoapResponse::try_new(&writer.finish())?;
    dom::parse_document(response.envelope(), XmlLimits::default())?;
    Ok(AnsweredArtifact {
        response,
        release,
        error: None,
    })
}

fn channel_allows(channel: SoapChannel, required: ArtifactChannelRequirement) -> bool {
    let authenticated = channel.authenticates_peer();
    match required {
        ArtifactChannelRequirement::Authenticated => authenticated,
        ArtifactChannelRequirement::Confidential => {
            authenticated && channel.confidentiality() == MessageConfidentiality::Protected
        }
    }
}

fn soap_service(
    metadata: &IdpMetadata,
    index: u16,
) -> Result<crate::metadata::ArtifactResolutionServiceEndpoint, SamlError> {
    let service = metadata
        .artifact_resolution_service(index)?
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
    version_mismatch: Option<RequestVersionMismatch>,
    destination: Option<String>,
    issuer: Option<PartyName>,
    artifact: String,
}

fn parse_resolve(element: &SamlElement) -> Result<ResolveRequest, SamlError> {
    if !element.is(namespace::PROTOCOL, "ArtifactResolve") {
        return Err(SamlError::ProtocolProfile(
            "SOAP body must be an ArtifactResolve".into(),
        ));
    }
    let id = element.required_attr("ID")?;
    check_in_response_to(&id)?;
    let version_mismatch = RequestVersionMismatch::for_request(&element.required_attr("Version")?)?;
    element.required_issue_instant()?;
    let artifact = element
        .children
        .iter()
        .find(|child| child.local_name == "Artifact" && child.namespace == namespace::PROTOCOL)
        .map(|child| child.text.trim().to_string())
        .ok_or_else(|| {
            SamlError::ProtocolProfile("ArtifactResolve requires one Artifact element".into())
        })?;
    if element
        .children
        .iter()
        .filter(|child| child.local_name == "Artifact")
        .count()
        != 1
    {
        return Err(SamlError::ProtocolProfile(
            "ArtifactResolve requires one Artifact element".into(),
        ));
    }
    Ok(ResolveRequest {
        id,
        version_mismatch,
        destination: element.attr("Destination").map(collapse_whitespace),
        issuer: issuer(element)?,
        artifact,
    })
}

fn protocol_payload(response: &SamlElement) -> Result<Option<&SamlElement>, SamlError> {
    let mut payloads = response.children.iter().filter(|child| {
        !matches!(
            (child.namespace.as_str(), child.local_name.as_str()),
            (namespace::ASSERTION, "Issuer")
                | (namespace::PROTOCOL, "Status" | "Extensions")
                | (namespace::DSIG, "Signature")
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
        let unchecked = ArtifactResolution {
            request: SoapRequest::try_new(
                crate::EndpointUrl::try_new("https://idp.example.com/artifact")?,
                r#"<samlp:ArtifactResolve xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>"#,
            )?,
            request_id: "_request".into(),
            identity_provider: "https://idp.example.com/metadata".into(),
            artifact: "artifact".into(),
            signing_certificates: Vec::new(),
            hmac_secret: None,
            signature_profile: XmlSignatureProfile::ExcludeWeakAlgorithms,
            xml_limits: XmlLimits::default(),
            schema_validator: None,
        };
        let checked = ArtifactResolution {
            schema_validator: Some(|_| Ok(())),
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
}
