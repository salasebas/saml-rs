//! Error types for `saml-rs`.
//!
//! [`SamlError`] is non-exhaustive. Callers should include a fallback match arm
//! so they can handle variants added in later releases.

use crate::config::{EntityId, NameIdFormat};
use crate::constants::Binding;
use crate::model::{
    AuthnContextReference, RefusedAuthnRequest, RefusedLogoutRequest, RelayState, ReplayKey,
    Status, StatusMessage, SubordinateStatusCode,
};
use std::fmt;

/// Why an unsolicited HTTP-POST response could not be matched to a trusted IdP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IdpResolutionReason {
    /// No eligible issuer was present.
    MissingIssuer,
    /// More than one issuer element was present where one was expected, or
    /// the plaintext assertions named different issuers.
    AmbiguousIssuer,
    /// An eligible issuer did not have the form of a SAML entity identifier.
    InvalidIssuer,
    /// The configured resolver returned no descriptor for the issuer.
    UnknownEntityId,
}

impl fmt::Display for IdpResolutionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingIssuer => f.write_str("missing issuer"),
            Self::AmbiguousIssuer => f.write_str("ambiguous issuer"),
            Self::InvalidIssuer => f.write_str("invalid issuer"),
            Self::UnknownEntityId => f.write_str("unknown issuer"),
        }
    }
}

/// Reason a required SAML signature verification failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureVerificationReason {
    /// Enveloped XML-DSig verification failed.
    XmlSignature,
    /// The `Signature` that HTTP-Redirect or HTTP-POST-SimpleSign carries
    /// beside the message failed verification.
    BindingSignature,
    /// Signed reference digest verification failed.
    ReferenceDigest,
}

impl fmt::Display for SignatureVerificationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::XmlSignature => f.write_str("xml signature"),
            Self::BindingSignature => f.write_str("binding signature"),
            Self::ReferenceDigest => f.write_str("reference digest"),
        }
    }
}

/// Reason a signed XML reference could not be resolved safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ReferenceResolutionReason {
    /// Reference URI points outside the same XML document.
    ExternalReference,
    /// Reference URI syntax is not supported by the SAML verifier.
    UnsupportedReferenceUri,
    /// Signature contained no references to validate.
    MissingSignatureReference,
    /// Same-document reference did not resolve to an XML node.
    UnresolvedReference,
}

impl fmt::Display for ReferenceResolutionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExternalReference => f.write_str("external reference"),
            Self::UnsupportedReferenceUri => f.write_str("unsupported reference URI"),
            Self::MissingSignatureReference => f.write_str("missing signature reference"),
            Self::UnresolvedReference => f.write_str("unresolved reference"),
        }
    }
}

/// Bearer subject confirmation validation failure reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SubjectConfirmationReason {
    /// SubjectConfirmation `Method` was missing or was not bearer.
    InvalidMethod,
    /// SubjectConfirmationData omitted `NotOnOrAfter`.
    MissingNotOnOrAfter,
    /// SubjectConfirmationData `NotBefore` or `NotOnOrAfter` time bounds were not satisfied.
    TimeWindowInvalid,
    /// SubjectConfirmationData `Recipient` did not match the ACS URL.
    RecipientMismatch,
    /// SubjectConfirmationData `InResponseTo` did not match the request ID.
    InResponseToMismatch,
    /// No bearer SubjectConfirmation satisfied the validation requirements.
    MissingBearerConfirmation,
}

impl fmt::Display for SubjectConfirmationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMethod => f.write_str("method"),
            Self::MissingNotOnOrAfter => f.write_str("missing NotOnOrAfter"),
            Self::TimeWindowInvalid => f.write_str("time window"),
            Self::RecipientMismatch => f.write_str("recipient"),
            Self::InResponseToMismatch => f.write_str("InResponseTo"),
            Self::MissingBearerConfirmation => f.write_str("missing bearer confirmation"),
        }
    }
}

/// SAML time-bound field whose validation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TimeWindowField {
    /// Expiration derived from the typed IdP issuance lifetime could not be
    /// represented for the current issue instant.
    IdpIssuanceExpiration,
    /// LogoutRequest `NotOnOrAfter`.
    LogoutRequestNotOnOrAfter,
    /// Assertion session `SessionNotOnOrAfter`.
    SessionNotOnOrAfter,
    /// Assertion `Conditions` NotBefore/NotOnOrAfter window.
    Conditions,
    /// Replay cache retention window could not be computed or has elapsed.
    ReplayExpiration,
    /// AuthnRequest `IssueInstant` age window.
    AuthnRequestIssueInstant,
    /// ManageNameIDRequest `IssueInstant` age window.
    ManageNameIdRequestIssueInstant,
    /// Metadata `validUntil` is malformed or has been reached.
    MetadataValidUntil,
}

impl fmt::Display for TimeWindowField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdpIssuanceExpiration => f.write_str("IdP issuance expiration"),
            Self::LogoutRequestNotOnOrAfter => f.write_str("LogoutRequest@NotOnOrAfter"),
            Self::SessionNotOnOrAfter => f.write_str("SessionNotOnOrAfter"),
            Self::Conditions => f.write_str("Conditions"),
            Self::ReplayExpiration => f.write_str("ReplayExpiration"),
            Self::AuthnRequestIssueInstant => f.write_str("AuthnRequest@IssueInstant"),
            Self::ManageNameIdRequestIssueInstant => {
                f.write_str("ManageNameIDRequest@IssueInstant")
            }
            Self::MetadataValidUntil => f.write_str("metadata validUntil"),
        }
    }
}

/// Resource limit that stopped reading an input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ResourceLimit {
    /// XML input bytes, [`crate::XmlLimits::max_bytes`].
    XmlBytes,
    /// Nested element depth, [`crate::XmlLimits::max_depth`].
    XmlDepth,
    /// Elements in one XML document, [`crate::XmlLimits::max_elements`].
    XmlElements,
    /// Attributes on one element,
    /// [`crate::XmlLimits::max_attributes_per_element`].
    XmlAttributesPerElement,
    /// Namespace bindings in scope at once. The maximum is
    /// [`crate::XmlLimits::max_attributes_per_element`].
    XmlNamespaceBindings,
    /// Decoded bytes of one attribute value,
    /// [`crate::XmlLimits::max_attribute_value_bytes`].
    XmlAttributeValueBytes,
    /// Decoded direct text bytes of one element,
    /// [`crate::XmlLimits::max_element_text_bytes`].
    XmlElementTextBytes,
    /// Bytes decoded from a base64 binding parameter. HTTP-POST and
    /// SimpleSign messages are bounded by [`crate::XmlLimits::max_bytes`], and
    /// HTTP-Redirect messages by
    /// [`crate::XmlPolicy::redirect_inflate_max_bytes`].
    Base64DecodedBytes,
    /// Bytes inflated from an HTTP-Redirect message,
    /// [`crate::XmlPolicy::redirect_inflate_max_bytes`].
    InflatedBytes,
    /// Estimated decryption work units per message,
    /// [`crate::XmlEncryptionPolicy::max_decryption_work`].
    DecryptionWork,
    /// Bytes of a received `RelayState`,
    /// [`crate::MAX_RECEIVED_RELAY_STATE_BYTES`].
    RelayStateBytes,
}

impl fmt::Display for ResourceLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::XmlBytes => f.write_str("XML bytes"),
            Self::XmlDepth => f.write_str("XML depth"),
            Self::XmlElements => f.write_str("XML elements"),
            Self::XmlAttributesPerElement => f.write_str("XML attributes per element"),
            Self::XmlNamespaceBindings => f.write_str("XML namespace bindings in scope"),
            Self::XmlAttributeValueBytes => f.write_str("XML attribute value bytes"),
            Self::XmlElementTextBytes => f.write_str("XML text bytes per element"),
            Self::Base64DecodedBytes => f.write_str("base64-decoded bytes"),
            Self::InflatedBytes => f.write_str("inflated bytes"),
            Self::DecryptionWork => f.write_str("decryption work units"),
            Self::RelayStateBytes => f.write_str("received RelayState bytes"),
        }
    }
}

/// Errors produced by the SAML-RS library.
///
/// Variants are grouped by validation category:
///
/// - wire and XML decoding failures;
/// - SAML protocol validation failures;
/// - signature, signed-reference, and delegated crypto failures;
/// - metadata and trust selection failures;
/// - configuration and unsupported binding failures.
///
/// A variant that wraps a lower-level failure returns it from
/// [`std::error::Error::source`]. Its type is not part of the API.
///
/// This enum is `#[non_exhaustive]`; downstream callers should include a
/// fallback arm when matching. Each variant with named fields is
/// `#[non_exhaustive]` too, so a pattern on it ends with `..` and a field can
/// be added later. [`Self::ReplayDetected`], [`Self::ReplayCacheUnavailable`],
/// and [`Self::ArtifactStoreUnavailable`] stay constructible, because a
/// [`crate::ReplayCache`] or [`crate::ArtifactStore`] implementation returns
/// them.
///
/// # Examples
///
/// ```
/// use saml_rs::{SamlError, TopLevelStatusCode};
///
/// fn http_status(error: &SamlError) -> u16 {
///     match error {
///         SamlError::LimitExceeded { .. } => 413,
///         SamlError::ReplayCacheUnavailable { .. } => 503,
///         SamlError::StatusNotSuccess { status, .. }
///             if status.top_level() == TopLevelStatusCode::Responder =>
///         {
///             502
///         }
///         _ => 400,
///     }
/// }
/// # let _ = http_status;
/// ```
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SamlError {
    /// Raw DEFLATE data could not be compressed or inflated.
    #[error("deflate error")]
    #[non_exhaustive]
    Deflate {
        /// Compression library error.
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// Base64 decoding failed.
    #[error("base64 decode error")]
    #[non_exhaustive]
    Base64 {
        /// Decoder error.
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// Input exceeded a resource limit.
    #[error("{limit} limit exceeded (maximum {maximum})")]
    #[non_exhaustive]
    LimitExceeded {
        /// Limit that stopped reading.
        limit: ResourceLimit,
        /// Configured maximum.
        maximum: usize,
    },
    /// Malformed or unexpected XML.
    #[error("xml error: {message}")]
    #[non_exhaustive]
    Xml {
        /// What could not be read.
        message: String,
        /// Parser error, when one caused this.
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    /// Input failed validation.
    #[error("invalid input: {0}")]
    Invalid(String),
    /// XML violates SAML protocol requirements such as QName, version, required
    /// attributes, or their lexical forms.
    #[error("SAML protocol profile violation: {0}")]
    ProtocolProfile(String),
    /// A binding parameter or form field occurs more than once.
    #[error("binding parameter occurs more than once: {name}")]
    #[non_exhaustive]
    DuplicateBindingParameter {
        /// Binding parameter name.
        name: &'static str,
    },
    /// Required binding parameter is absent.
    #[error("required binding parameter missing: {name}")]
    #[non_exhaustive]
    MissingBindingParameter {
        /// Binding parameter name.
        name: &'static str,
    },

    /// An operation or input is unsupported, including operations that
    /// require a Cargo feature disabled in this build.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// The called operation does not handle this binding.
    #[error("unsupported binding: {binding:?}")]
    #[non_exhaustive]
    UnsupportedBinding {
        /// Binding that reached the operation.
        binding: Binding,
    },
    /// The delivery action differs from the action this [`crate::Outbound`]
    /// accessor reads. Match on [`crate::Outbound::delivery`] to send the message.
    #[error("outbound delivery {actual:?} does not match this accessor")]
    #[non_exhaustive]
    OutboundDeliveryMismatch {
        /// Binding that represents the delivery action. An artifact delivered
        /// in a form reports [`Binding::Post`].
        actual: Binding,
    },

    /// Issuer in the message does not match the expected peer entity ID.
    #[error("issuer mismatch: expected {expected}, got {actual:?}")]
    #[non_exhaustive]
    IssuerMismatch {
        /// Expected peer entity ID.
        expected: String,
        /// Actual issuer value extracted from the message, when available.
        actual: Option<String>,
    },
    /// An unsolicited HTTP-POST response could not be matched to a trusted IdP.
    #[error("could not resolve the identity provider: {reason}")]
    #[non_exhaustive]
    IdpResolution {
        /// What prevented lookup of the identity provider.
        reason: IdpResolutionReason,
    },
    /// A message `Destination` does not match the expected recipient URL, an
    /// outbound response would go to an unpublished assertion consumer, or
    /// `finish_sso` received the response at another assertion consumer than
    /// the pending request asked for.
    #[error("destination mismatch: expected {expected}, got {actual:?}")]
    #[non_exhaustive]
    DestinationMismatch {
        /// Expected recipient URL.
        expected: String,
        /// The URL compared with `expected`, when one is available: the
        /// message's `Destination`, the published default assertion consumer
        /// for an outbound response, or the receiving URL supplied with
        /// [`crate::SamlValidationContext::with_recipient_endpoint`] that
        /// `finish_sso` rejects before parsing.
        actual: Option<String>,
    },
    /// The receiving URL given to
    /// [`crate::SamlValidationContext::with_recipient_endpoint`] or
    /// [`crate::IdentityProvider::answer_artifact_resolve`] is not published
    /// in local metadata for the message's binding and direction.
    #[error("receiving endpoint is not published for this binding and message direction")]
    RecipientEndpointNotPublished,
    /// Local metadata publishes several endpoints for the message's binding
    /// and direction, and none was selected with
    /// [`crate::SamlValidationContext::with_recipient_endpoint`].
    #[error("several receiving endpoints are published; select one with with_recipient_endpoint")]
    RecipientEndpointAmbiguous,
    /// `InResponseTo` does not match the expected request ID.
    #[error("inResponseTo mismatch: expected {expected:?}, got {actual:?}")]
    #[non_exhaustive]
    InResponseToMismatch {
        /// Expected request ID. `None` means no request correlation was expected.
        expected: Option<String>,
        /// Actual `InResponseTo` value extracted from the message, when available.
        actual: Option<String>,
    },
    /// RelayState does not match the pending message correlation state.
    #[error("relay state mismatch")]
    #[non_exhaustive]
    RelayStateMismatch {
        /// Expected RelayState. `None` means no `RelayState` parameter.
        expected: Option<RelayState>,
        /// Received RelayState. `None` means no `RelayState` parameter.
        actual: Option<RelayState>,
    },
    /// `<Audience>` does not include the expected Service Provider entity ID.
    #[error("audience restriction not satisfied: expected {expected}")]
    #[non_exhaustive]
    AudienceMismatch {
        /// Expected SP entity ID.
        expected: String,
    },
    /// A `<Conditions>` child is not one this service provider can evaluate.
    #[error("assertion condition is not understood: {element}")]
    #[non_exhaustive]
    UnrecognizedCondition {
        /// Local name of the unrecognized condition element.
        element: String,
    },
    /// Assertions in one response do not share one principal.
    ///
    /// The comparison is `NameID` value, `Format`, `NameQualifier`, and
    /// `SPNameQualifier`. An omitted `Format` is unspecified.
    #[error("assertions do not refer to one principal")]
    PrincipalMismatch,
    /// None of the consumed assertion's authentication statements matched the
    /// exact authentication context required by the pending request.
    #[error("authentication context mismatch")]
    #[non_exhaustive]
    AuthnContextMismatch {
        /// Exact authentication context references required by the pending
        /// request, in request order.
        expected: Vec<AuthnContextReference>,
        /// Authentication context class and declaration references reported by
        /// the consumed assertion's authentication statements, in statement
        /// order with each statement's class reference before its declaration
        /// reference.
        actual: Vec<AuthnContextReference>,
    },
    /// The assertion identifier differs from the standard format in the request's `NameIDPolicy`.
    #[error(
        "NameIDPolicy format mismatch: requested {}, issued {}",
        requested.as_uri(),
        issued.as_ref().map_or("no Format", NameIdFormat::as_uri)
    )]
    #[non_exhaustive]
    NameIdPolicyFormatMismatch {
        /// Standard identifier format the requester requires.
        requested: NameIdFormat,
        /// Format of the identifier that would be issued, or `None` if omitted.
        issued: Option<NameIdFormat>,
    },
    /// The request requires an `EncryptedID` and identifier encryption is disabled.
    #[error("NameIDPolicy requires EncryptedID but identifier encryption is disabled")]
    NameIdPolicyRequiresEncryptedId,
    /// A `<Response>` with status `Success` carries no assertion to read: none
    /// at all, or only `<EncryptedAssertion>` elements that were not
    /// decrypted.
    #[error("response carries no assertion")]
    AssertionMissing,
    /// An `ArtifactResponse` did not contain the dereferenced protocol message.
    #[error("artifact response did not contain the protocol message")]
    ArtifactNotReturned,
    /// The SOAP channel lacks the protection this exchange requires.
    #[error("SOAP channel protection is not sufficient for this exchange")]
    SoapChannelProtection,
    /// Response status has no top-level `StatusCode` value.
    #[error("response status code is missing")]
    StatusMissing,
    /// Response carried a top-level status other than `Success`.
    ///
    /// A top-level code outside the four SAML values is
    /// [`Self::ProtocolProfile`]. A subordinate code holds the peer's URI.
    #[error(
        "status not success: top={}, second={:?}",
        status.top_level().as_uri(),
        status.subordinate().map(SubordinateStatusCode::as_uri)
    )]
    #[non_exhaustive]
    StatusNotSuccess {
        /// Top-level and subordinate status codes.
        status: Status,
        /// Operator diagnostic from a verified login or logout response, when available.
        status_message: Option<StatusMessage>,
    },
    /// The authenticated LogoutRequest requires a version mismatch response.
    #[error("logout request has an unsupported newer SAML version")]
    #[non_exhaustive]
    LogoutRequestRefused {
        /// Data for the version mismatch response.
        refusal: Box<RefusedLogoutRequest>,
    },
    /// A SAML message, assertion, session, or replay time bound is not satisfied.
    #[error("SAML time window is invalid for {field}")]
    #[non_exhaustive]
    TimeWindowInvalid {
        /// SAML field or validation scope whose time window failed.
        field: TimeWindowField,
    },
    /// Bearer subject confirmation requirements are not satisfied.
    #[error("subject confirmation is not satisfied: {reason}")]
    #[non_exhaustive]
    SubjectConfirmationInvalid {
        /// Stable validation reason for callers and logs.
        reason: SubjectConfirmationReason,
    },
    /// A later assertion matches an outstanding logout that is still before
    /// `NotOnOrAfter`.
    #[error("assertion matches an outstanding logout")]
    AssertionMatchesOutstandingLogout,
    /// A message ID, assertion ID, or artifact was already accepted.
    #[error("replayed SAML message, assertion, or artifact: {}", key.cache_key())]
    ReplayDetected {
        /// Key that was already accepted.
        key: ReplayKey,
    },
    /// An HTTP-POST SSO response requires a caller-owned replay cache.
    #[error("HTTP-POST SSO requires a replay cache")]
    ReplayCacheRequired,
    /// The replay cache could not check or store a key, so the message was
    /// not accepted.
    #[error("replay cache could not check or store the key")]
    ReplayCacheUnavailable {
        /// Cache error.
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The artifact store could not store, look up, or consume an artifact.
    #[error("artifact store could not complete the operation")]
    ArtifactStoreUnavailable {
        /// Store error.
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Required signature is absent.
    #[error("signature missing where required")]
    SignatureMissing,
    /// The SP declared `AuthnRequestsSigned` and the request arrived unsigned.
    #[error(
        "unsigned authentication request from a service provider that declares AuthnRequestsSigned"
    )]
    #[non_exhaustive]
    AuthnRequestRefused {
        /// Data for a correlated SAML error response.
        refusal: Box<RefusedAuthnRequest>,
    },
    /// The identity provider's metadata sets `WantAuthnRequestsSigned`, and
    /// this service provider does not sign its `AuthnRequest`.
    #[error("identity provider requires signed AuthnRequests and this service provider does not sign them")]
    AuthnRequestSigningRequired,
    /// Signature verification failed for a semantic SAML validation reason.
    #[error("signature verification failed: {reason}")]
    #[non_exhaustive]
    SignatureVerification {
        /// Stable verification reason for callers and logs.
        reason: SignatureVerificationReason,
    },
    /// Signed reference could not be resolved safely.
    #[error("signed reference could not be resolved: {reason}")]
    #[non_exhaustive]
    ReferenceResolution {
        /// Stable reference-resolution reason for callers and logs.
        reason: ReferenceResolutionReason,
    },
    /// Verified signed reference does not cover the consumed payload.
    #[error("signed reference does not cover consumed payload")]
    SignedReferenceMismatch,
    /// Assertion-signature policy requires direct coverage of the consumed assertion.
    #[error("consumed assertion is not directly covered by a trusted XML signature")]
    AssertionSignatureRequired,
    /// The selected `XmlEncryptionPolicy` requires this assertion element in
    /// encrypted form, and the message carries it in plaintext.
    #[error("{element} must be encrypted")]
    #[non_exhaustive]
    EncryptionRequired {
        /// Local name of the plaintext element: `Assertion`, `NameID`, or
        /// `Attribute`.
        element: &'static str,
    },

    /// A signature that authenticates the message selected an algorithm
    /// outside the configured [`crate::XmlSignatureProfile`].
    #[error("signature algorithm is not allowed")]
    AlgorithmUnsupported,

    /// No trusted certificate could be selected for verification.
    #[error("no trusted certificate could be selected for verification")]
    NoTrustedCertificate,

    /// Caller supplied an empty request ID for response correlation.
    ///
    /// Prefer [`Self::InResponseToMismatch`] when a message value fails request
    /// correlation.
    #[error("request ID for response correlation is empty")]
    InvalidInResponseTo,
    /// A signature-wrapping (XSW) attempt was detected.
    #[error("signature wrapping attempt detected")]
    PotentialWrappingAttack,
    /// Required metadata (endpoint/certificate) was missing.
    #[error("missing metadata: {0}")]
    MissingMetadata(String),
    /// The aggregate has no member with the requested entity ID.
    #[error("metadata aggregate has no EntityDescriptor for `{}`", .entity_id.as_str())]
    #[non_exhaustive]
    MetadataEntityNotFound {
        /// The requested entity ID.
        entity_id: EntityId,
    },
    /// The aggregate has several members with the requested entity ID.
    #[error("metadata aggregate has more than one EntityDescriptor for `{}`", .entity_id.as_str())]
    #[non_exhaustive]
    DuplicateMetadataEntity {
        /// The requested entity ID.
        entity_id: EntityId,
    },
    /// A required cryptographic key was missing.
    #[error("missing key: {0}")]
    MissingKey(String),
    /// A delegated cryptographic operation failed, or a configured key or
    /// certificate cannot be used.
    #[error("crypto error: {message}")]
    #[non_exhaustive]
    Crypto {
        /// What failed.
        message: String,
        /// Backend error, when one caused this.
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

impl SamlError {
    pub(crate) fn with_status_message(mut self, message: Option<StatusMessage>) -> Self {
        if let Self::StatusNotSuccess { status_message, .. } = &mut self {
            *status_message = message;
        }
        self
    }

    pub(crate) fn xml(message: impl Into<String>) -> Self {
        Self::Xml {
            message: message.into(),
            source: None,
        }
    }

    #[cfg(crypto)]
    pub(crate) fn crypto(message: impl Into<String>) -> Self {
        Self::Crypto {
            message: message.into(),
            source: None,
        }
    }

    pub(crate) fn issuer_mismatch(expected: &str, actual: Option<&str>) -> Self {
        Self::IssuerMismatch {
            expected: expected.to_string(),
            actual: actual.map(str::to_string),
        }
    }

    pub(crate) fn destination_mismatch(expected: &str, actual: Option<&str>) -> Self {
        Self::DestinationMismatch {
            expected: expected.to_string(),
            actual: actual.map(str::to_string),
        }
    }

    pub(crate) fn in_response_to_mismatch(expected: Option<&str>, actual: Option<&str>) -> Self {
        Self::InResponseToMismatch {
            expected: expected.map(str::to_string),
            actual: actual.map(str::to_string),
        }
    }
}

pub(crate) fn xml_err(source: impl std::error::Error + Send + Sync + 'static) -> SamlError {
    SamlError::Xml {
        message: "document is not well-formed".into(),
        source: Some(Box::new(source)),
    }
}

#[cfg(crypto)]
pub(crate) fn crypto_err(source: impl std::error::Error + Send + Sync + 'static) -> SamlError {
    SamlError::Crypto {
        message: "backend operation failed".into(),
        source: Some(Box::new(source)),
    }
}
