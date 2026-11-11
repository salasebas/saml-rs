//! Error types for `saml-rs`.
//!
//! [`SamlError`] is non-exhaustive. Callers should include a fallback match arm
//! so new semantic SAML validation failures can be added without breaking
//! source compatibility.

use crate::constants::Binding;
use crate::model::RelayStateParam;
use std::fmt;

/// Reason a required SAML signature verification failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureVerificationReason {
    /// Enveloped XML-DSig verification failed.
    XmlSignature,
    /// HTTP-Redirect or SimpleSign detached message signature verification failed.
    DetachedMessageSignature,
    /// Detached signature input could not be correlated with consumed RelayState.
    RelayStateCorrelation,
    /// Signed reference digest verification failed.
    ReferenceDigest,
}

impl fmt::Display for SignatureVerificationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::XmlSignature => f.write_str("xml signature"),
            Self::DetachedMessageSignature => f.write_str("detached message signature"),
            Self::RelayStateCorrelation => f.write_str("relay state correlation"),
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

/// Errors produced by the SAML-RS library.
///
/// Variants are grouped by validation category:
///
/// - wire and XML decoding failures;
/// - SAML protocol validation failures;
/// - signature, signed-reference, and delegated crypto failures;
/// - metadata and trust selection failures;
/// - configuration, unsupported binding, and compatibility failures.
///
/// This enum is `#[non_exhaustive]`; downstream callers should include a
/// fallback arm when matching.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SamlError {
    // Wire / XML errors.
    /// Raw DEFLATE (de)compression failed.
    #[error("deflate error: {0}")]
    Deflate(#[from] std::io::Error),
    /// Base64 decoding failed.
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    /// Malformed or unexpected XML.
    #[error("xml error: {0}")]
    Xml(String),
    /// Input failed validation.
    #[error("invalid input: {0}")]
    Invalid(String),
    /// XML violates SAML protocol requirements such as QName, version, required
    /// attributes, or their lexical forms.
    #[error("SAML protocol profile violation: {0}")]
    ProtocolProfile(String),

    // Unsupported profiles and bindings.
    /// Functionality not yet implemented in the current milestone.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// Requested binding is not supported by this API path.
    #[error("unsupported binding: {binding:?}")]
    UnsupportedBinding {
        /// Binding that reached an unsupported profile path.
        binding: Binding,
    },

    // SAML protocol validation.
    /// Issuer in the message does not match the expected peer entity ID.
    #[error("issuer mismatch: expected {expected}, got {actual:?}")]
    IssuerMismatch {
        /// Expected peer entity ID.
        expected: String,
        /// Actual issuer value extracted from the message, when available.
        actual: Option<String>,
    },
    /// Response `Destination` does not match the expected recipient URL.
    #[error("destination mismatch: expected {expected}, got {actual:?}")]
    DestinationMismatch {
        /// Expected recipient URL.
        expected: String,
        /// Actual destination value extracted from the message, when available.
        actual: Option<String>,
    },
    /// `InResponseTo` does not match the expected request ID.
    #[error("inResponseTo mismatch: expected {expected:?}, got {actual:?}")]
    InResponseToMismatch {
        /// Expected request ID. `None` means no request correlation was expected.
        expected: Option<String>,
        /// Actual `InResponseTo` value extracted from the message, when available.
        actual: Option<String>,
    },
    /// RelayState does not match the pending message correlation state.
    #[error("relay state mismatch")]
    RelayStateMismatch {
        /// Expected RelayState presence and value.
        expected: RelayStateParam,
        /// Actual RelayState presence and value.
        actual: RelayStateParam,
    },
    /// `<Audience>` does not include the expected Service Provider entity ID.
    #[error("audience restriction not satisfied: expected {expected}")]
    AudienceMismatch {
        /// Expected SP entity ID.
        expected: String,
    },
    /// A `<Conditions>` child is not one this service provider can evaluate.
    #[error("assertion condition is not understood: {element}")]
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
    /// An `ArtifactResponse` did not contain the dereferenced protocol message.
    #[error("artifact response did not contain the protocol message")]
    ArtifactNotReturned,
    /// The SOAP channel lacks the protection this exchange requires.
    #[error("SOAP channel protection is not sufficient for this exchange")]
    SoapChannelProtection,
    /// Response carried a non-success SAML status code.
    #[error("status not success: top={top}, second={second:?}")]
    StatusNotSuccess {
        /// Top-tier status code.
        top: String,
        /// Optional second-tier status code.
        second: Option<String>,
    },
    /// A SAML message, assertion, session, or replay time bound is not satisfied.
    #[error("SAML time window is invalid for {field}")]
    TimeWindowInvalid {
        /// SAML field or validation scope whose time window failed.
        field: TimeWindowField,
    },
    /// Bearer subject confirmation requirements are not satisfied.
    #[error("subject confirmation is not satisfied: {reason}")]
    SubjectConfirmationInvalid {
        /// Stable validation reason for callers and logs.
        reason: SubjectConfirmationReason,
    },
    /// A later assertion matches an outstanding logout that is still before
    /// `NotOnOrAfter`.
    #[error("assertion matches an outstanding logout")]
    AssertionMatchesOutstandingLogout,
    /// A duplicate SAML message or assertion key was detected.
    #[error("replayed SAML message or assertion: {key}")]
    ReplayDetected {
        /// Replay cache key or duplicate identifier.
        key: String,
    },

    // Signature / crypto validation.
    /// Required signature is absent.
    #[error("signature missing where required")]
    SignatureMissing,
    /// Required binding parameter is absent.
    #[error("required binding parameter missing: {name}")]
    MissingBindingParameter {
        /// Binding parameter name.
        name: &'static str,
    },
    /// Signature verification failed for a semantic SAML validation reason.
    #[error("signature verification failed: {reason}")]
    SignatureVerification {
        /// Stable verification reason for callers and logs.
        reason: SignatureVerificationReason,
    },
    /// Signed reference could not be resolved safely.
    #[error("signed reference could not be resolved: {reason}")]
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
    EncryptionRequired {
        /// Local name of the plaintext element: `NameID` or `Attribute`.
        element: &'static str,
    },

    /// A signature that authenticates the message selected an algorithm
    /// outside the configured [`crate::XmlSignatureProfile`].
    #[error("signature algorithm is not allowed")]
    AlgorithmUnsupported,

    // Metadata / trust validation.
    /// No trusted certificate could be selected for verification.
    #[error("no trusted certificate could be selected for verification")]
    NoTrustedCertificate,
    /// Certificate embedded in the message does not match configured metadata.
    ///
    /// Signature verification does not return it: a signature verifies when a
    /// trusted key verifies it, whatever certificate its `KeyInfo` carries.
    #[error("certificate mismatch")]
    CertificateMismatch,

    // Legacy compatibility and lower-level operational variants.
    /// Compatibility variant for issuer validation; prefer [`Self::IssuerMismatch`].
    #[error("ERR_UNMATCH_ISSUER")]
    UnmatchIssuer,
    /// Compatibility variant for audience validation; prefer [`Self::AudienceMismatch`].
    #[error("ERR_UNMATCH_AUDIENCE")]
    UnmatchAudience,
    /// Compatibility variant for destination validation; prefer [`Self::DestinationMismatch`].
    #[error("ERR_UNMATCH_DESTINATION")]
    UnmatchDestination,
    /// Caller supplied a malformed request ID for response correlation.
    ///
    /// Prefer [`Self::InResponseToMismatch`] when a message value fails request
    /// correlation.
    #[error("ERR_INVALID_IN_RESPONSE_TO")]
    InvalidInResponseTo,
    /// Response status code is missing, empty, or could not be extracted.
    #[error("ERR_UNDEFINED_STATUS")]
    UndefinedStatus,
    /// Compatibility variant for non-success status; prefer [`Self::StatusNotSuccess`].
    #[error("ERR_FAILED_STATUS with top tier code: {top}, second tier code: {second}")]
    FailedStatus {
        /// Top-tier status code.
        top: String,
        /// Second-tier status code (empty when absent).
        second: String,
    },
    /// Compatibility variant for elapsed session bounds; prefer [`Self::TimeWindowInvalid`].
    #[error("ERR_EXPIRED_SESSION")]
    ExpiredSession,
    /// Compatibility variant for subject confirmation failures; prefer
    /// [`Self::SubjectConfirmationInvalid`].
    #[error("ERR_SUBJECT_UNCONFIRMED")]
    SubjectUnconfirmed,
    /// A signature-wrapping (XSW) attempt was detected.
    #[error("ERR_POTENTIAL_WRAPPING_ATTACK")]
    PotentialWrappingAttack,
    /// Compatibility variant for missing binding signature parameters; prefer
    /// [`Self::SignatureMissing`] or [`Self::MissingBindingParameter`].
    #[error("ERR_MISSING_SIG_ALG")]
    MissingSigAlg,
    /// Compatibility variant for detached signature failures; prefer
    /// [`Self::SignatureVerification`].
    #[error("ERR_FAILED_MESSAGE_SIGNATURE_VERIFICATION")]
    FailedMessageSignatureVerification,
    /// Compatibility variant for XML-DSig failures; prefer [`Self::SignatureVerification`].
    #[error("FAILED_TO_VERIFY_SIGNATURE")]
    FailedToVerifySignature,
    /// Compatibility variant for certificate mismatch; prefer [`Self::CertificateMismatch`].
    #[error("ERROR_UNMATCH_CERTIFICATE_DECLARATION_IN_METADATA")]
    UnmatchCertificate,
    /// Compatibility variant for unsupported bindings; prefer [`Self::UnsupportedBinding`].
    #[error("ERR_UNDEFINED_BINDING")]
    UndefinedBinding,
    /// Required metadata (endpoint/certificate) was missing.
    #[error("missing metadata: {0}")]
    MissingMetadata(String),
    /// A required cryptographic key was missing.
    #[error("missing key: {0}")]
    MissingKey(String),
    /// A delegated cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(String),
}

impl SamlError {
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
