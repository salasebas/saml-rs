use crate::binding::MAX_DEFLATE_RAW_DECODE_BYTES;
use crate::constants::MessageSignatureOrder;
use crate::entity::SignatureConfig;
use crate::error::SamlError;
use crate::template::LoginResponseTemplate;
use crate::xml::XmlLimits;

use super::algorithms::{
    DataEncryptionAlgorithm, KeyEncryptionAlgorithm, SignatureAlgorithm, TransformAlgorithm,
};

/// Whether an accepting service provider requires a signature on the Assertion
/// itself.
///
/// [`Self::RequireSigned`] is library hardening and stays off unless the caller
/// sets it. A response signed only on the `<Response>` remains acceptable
/// until then. The accept combination is classified in
/// `docs/conformance/web-browser-sso-acceptance.md`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AssertionSignaturePolicy {
    /// Reject an assertion that is not directly signed.
    ///
    /// Library hardening for the accepting service provider.
    RequireSigned,
    /// Do not require a signature directly on the Assertion.
    ///
    /// HTTP POST still requires the assertion to be protected by an Assertion
    /// signature or a Response signature.
    #[default]
    AllowUnsignedForCompatibility,
}

/// Whether an accepting service provider requires a signature on the
/// `<Response>`.
///
/// [`Self::RequireForEncryptedCbc`] follows the recommendation for a
/// CBC-encrypted assertion. [`Self::AllowUnsignedEncryptedCbc`] relaxes that
/// recommendation alone and is not the legacy permissive preset.
/// [`Self::RequireSigned`] requires a signature on every response and is
/// library hardening. The accept combination is classified in
/// `docs/conformance/web-browser-sso-acceptance.md`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ResponseSignaturePolicy {
    /// Accept a CBC `EncryptedAssertion` without a Response signature.
    #[default]
    AllowUnsignedEncryptedCbc,
    /// Require a signed Response when an `<EncryptedAssertion>` uses CBC.
    ///
    /// Plaintext responses are unchanged.
    RequireForEncryptedCbc,
    /// Require a Response signature on every response.
    ///
    /// Library hardening. Also rejects a response signed only on the Assertion.
    RequireSigned,
}

/// Inbound embedded XML-signature algorithm profile for accepted SSO and
/// Single Logout messages.
///
/// [`Self::StrictRsaSha2`] is library hardening. Selecting it does not require
/// a signature directly on the Assertion. The accept combination is classified
/// in `docs/conformance/web-browser-sso-acceptance.md`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum XmlSignatureProfile {
    /// Require one local `#id` reference, RSA-SHA256/384/512, a SHA-256/384/512
    /// digest, and exclusive canonicalization. Each transform element, when
    /// present, must belong to the XML-DSig namespace and use enveloped-signature
    /// or exclusive canonicalization.
    StrictRsaSha2,
    /// Accept every algorithm and same-document reference shape supported by
    /// the selected cryptographic provider.
    #[default]
    AllowProviderSupportedForCompatibility,
}

/// Whether an SP signs outgoing AuthnRequests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AuthnRequestSigningPolicy {
    /// Sign outgoing AuthnRequests.
    Sign,
    /// Send unsigned AuthnRequests, preserving the samlify port.
    #[default]
    DoNotSignForCompatibility,
}

/// Whether an identity provider requires a signed inbound `<AuthnRequest>`.
///
/// [`Self::RequireSigned`] is optional and stays off.
/// [`Self::AllowUnsignedVerifyIfPresent`] verifies a signature that is present
/// and still accepts an unsigned request.
/// [`Self::AllowUnsignedForCompatibility`] does not verify a present signature.
/// The accept combination is classified in
/// `docs/conformance/web-browser-sso-acceptance.md`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AuthnRequestValidationPolicy {
    /// Reject unsigned AuthnRequests.
    RequireSigned,
    /// Accept an unsigned AuthnRequest and verify a signature that is present.
    AllowUnsignedVerifyIfPresent,
    /// Accept unsigned AuthnRequests without verifying a signature that is present.
    #[default]
    AllowUnsignedForCompatibility,
}

/// Whether logout messages require signatures.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LogoutSignaturePolicy {
    /// Reject unsigned logout messages.
    #[default]
    RequireSigned,
    /// Accept unsigned logout messages, preserving the samlify port.
    AllowUnsignedForCompatibility,
}

/// Whether an accepting service provider evaluates `<AudienceRestriction>`.
///
/// [`Self::EvaluatePresentRestrictions`] checks restrictions that are present.
/// [`Self::Validate`] also rejects a bearer assertion that omits one.
/// [`Self::SkipForCompatibility`] skips the check. The accept combination is
/// classified in `docs/conformance/web-browser-sso-acceptance.md`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AudienceValidationPolicy {
    /// Evaluate audience restrictions and reject a bearer assertion that omits one.
    ///
    /// Rejecting a missing restriction is library hardening. Recommended uses
    /// [`Self::EvaluatePresentRestrictions`].
    #[default]
    Validate,
    /// Evaluate `<AudienceRestriction>` elements that are present.
    ///
    /// A bearer assertion that omits the element is not rejected.
    EvaluatePresentRestrictions,
    /// Skip audience evaluation, preserving the samlify port.
    SkipForCompatibility,
}

/// Whether SP AuthnRequests allow IdPs to create a new identifier.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NameIdCreationPolicy {
    /// Set `AllowCreate="true"` in AuthnRequests.
    AllowCreate,
    /// Set `AllowCreate="false"` in AuthnRequests.
    #[default]
    DoNotAllowCreate,
}

/// SP-side validation and outbound signing policy.
///
/// [`Self::recommended`] is the preset for claimed Web Browser SSO and Single
/// Logout features. [`Self::compatibility`] is the legacy permissive preset.
/// [`Default`](Default::default) is [`Self::recommended`]. Field classification
/// is in `docs/conformance/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpValidationPolicy {
    /// Assertion signature requirement.
    pub assertions: AssertionSignaturePolicy,
    /// Top-level SAML Response signature requirement.
    pub responses: ResponseSignaturePolicy,
    /// Embedded XML-signature algorithm and reference requirements.
    pub xml_signatures: XmlSignatureProfile,
    /// Outbound AuthnRequest signing behavior.
    pub authn_requests: AuthnRequestSigningPolicy,
    /// Audience validation behavior.
    pub audience: AudienceValidationPolicy,
    /// NameID creation behavior for AuthnRequests.
    pub name_id_creation: NameIdCreationPolicy,
    /// Logout signature validation behavior.
    pub logout: LogoutPolicy,
}

impl SpValidationPolicy {
    /// Validation preset for claimed Web Browser SSO and Single Logout features.
    ///
    /// Recommendations start enabled. Optional capabilities and library
    /// hardening stay off until a caller replaces one field.
    ///
    /// # Examples
    ///
    /// ```
    /// use saml_rs::{AssertionSignaturePolicy, SpValidationPolicy, XmlSignatureProfile};
    ///
    /// let with_assertion_signature = SpValidationPolicy {
    ///     assertions: AssertionSignaturePolicy::RequireSigned,
    ///     ..SpValidationPolicy::recommended()
    /// };
    /// assert_eq!(
    ///     with_assertion_signature.xml_signatures,
    ///     XmlSignatureProfile::AllowProviderSupportedForCompatibility
    /// );
    /// ```
    pub fn recommended() -> Self {
        Self {
            assertions: AssertionSignaturePolicy::AllowUnsignedForCompatibility,
            responses: ResponseSignaturePolicy::RequireForEncryptedCbc,
            xml_signatures: XmlSignatureProfile::AllowProviderSupportedForCompatibility,
            authn_requests: AuthnRequestSigningPolicy::DoNotSignForCompatibility,
            audience: AudienceValidationPolicy::EvaluatePresentRestrictions,
            name_id_creation: NameIdCreationPolicy::DoNotAllowCreate,
            logout: LogoutPolicy::recommended(),
        }
    }

    /// Legacy permissive preset: samlify-port behavior for a caller leaving
    /// the raw API.
    pub fn compatibility() -> Self {
        Self {
            assertions: AssertionSignaturePolicy::AllowUnsignedForCompatibility,
            responses: ResponseSignaturePolicy::AllowUnsignedEncryptedCbc,
            xml_signatures: XmlSignatureProfile::AllowProviderSupportedForCompatibility,
            authn_requests: AuthnRequestSigningPolicy::DoNotSignForCompatibility,
            audience: AudienceValidationPolicy::SkipForCompatibility,
            name_id_creation: NameIdCreationPolicy::DoNotAllowCreate,
            logout: LogoutPolicy::compatibility(),
        }
    }
}

impl Default for SpValidationPolicy {
    fn default() -> Self {
        Self::recommended()
    }
}

/// IdP-side validation policy.
///
/// [`Self::recommended`] is the preset for claimed Web Browser SSO and Single
/// Logout features. [`Self::compatibility`] is the legacy permissive preset.
/// [`Default`](Default::default) is [`Self::recommended`]. Field classification
/// is in `docs/conformance/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdpValidationPolicy {
    /// Inbound AuthnRequest signature requirement.
    pub authn_requests: AuthnRequestValidationPolicy,
    /// Logout signature validation behavior.
    pub logout: LogoutPolicy,
}

impl IdpValidationPolicy {
    /// Validation preset for claimed Web Browser SSO and Single Logout features.
    ///
    /// An inbound `AuthnRequest` may be unsigned. A signature that is present
    /// is verified. Logout requests and responses require a signature.
    pub fn recommended() -> Self {
        Self {
            authn_requests: AuthnRequestValidationPolicy::AllowUnsignedVerifyIfPresent,
            logout: LogoutPolicy::recommended(),
        }
    }

    /// Legacy permissive preset.
    ///
    /// Samlify-port behavior for a caller leaving the raw API. A signature
    /// present on an `AuthnRequest` is not verified.
    pub fn compatibility() -> Self {
        Self {
            authn_requests: AuthnRequestValidationPolicy::AllowUnsignedForCompatibility,
            logout: LogoutPolicy::compatibility(),
        }
    }
}

impl Default for IdpValidationPolicy {
    fn default() -> Self {
        Self::recommended()
    }
}

/// Logout request and response signature policy.
///
/// [`Self::recommended`] requires a signature on requests and responses.
/// [`Default`](Default::default) is that preset. [`Self::compatibility`] is
/// the legacy permissive preset.
///
/// `finish_slo` reads `responses`. `receive_slo` reads `requests`. With
/// [`crate::LogoutSigning::FollowLocalPolicy`], `requests` also decides
/// whether an outbound `LogoutRequest` is signed. See
/// `docs/conformance/single-logout.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogoutPolicy {
    /// LogoutRequest signature behavior.
    pub requests: LogoutSignaturePolicy,
    /// LogoutResponse signature behavior.
    pub responses: LogoutSignaturePolicy,
}

impl LogoutPolicy {
    /// Require a signature on logout requests and responses.
    pub fn recommended() -> Self {
        Self {
            requests: LogoutSignaturePolicy::RequireSigned,
            responses: LogoutSignaturePolicy::RequireSigned,
        }
    }

    /// Legacy permissive preset.
    ///
    /// Unsigned logout requests and responses are accepted. This is the
    /// samlify-port hatch.
    pub fn compatibility() -> Self {
        Self {
            requests: LogoutSignaturePolicy::AllowUnsignedForCompatibility,
            responses: LogoutSignaturePolicy::AllowUnsignedForCompatibility,
        }
    }
}

impl Default for LogoutPolicy {
    fn default() -> Self {
        Self::recommended()
    }
}

/// Whether assertions are encrypted in generated responses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AssertionEncryptionPolicy {
    /// Do not encrypt assertions.
    #[default]
    PlaintextAssertions,
    /// Encrypt assertions.
    EncryptAssertions,
}

/// XML encryption policy.
///
/// # Examples
///
/// Use typed configuration to request encrypted assertions in generated
/// responses. This only configures policy; actual encryption uses the crate's
/// XML-Enc backend and deployment credentials.
///
/// ```
/// use saml_rs::{EntityId, IdpConfig, SsoEndpoint, XmlEncryptionPolicy, XmlPolicy};
///
/// let xml = XmlPolicy {
///     encryption: XmlEncryptionPolicy::encrypt_assertions(),
///     ..XmlPolicy::default()
/// };
/// let idp_builder = IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
///     .sso_endpoint(SsoEndpoint::post("https://idp.example.com/sso")?)
///     .xml(xml);
/// # let _ = idp_builder;
/// # Ok::<(), saml_rs::SamlError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct XmlEncryptionPolicy {
    /// Assertion encryption behavior.
    pub assertions: AssertionEncryptionPolicy,
    allow_insecure_software_rsa_key_transport_decryption: bool,
}

impl XmlEncryptionPolicy {
    /// Enable assertion encryption.
    pub fn encrypt_assertions() -> Self {
        Self {
            assertions: AssertionEncryptionPolicy::EncryptAssertions,
            ..Self::default()
        }
    }

    /// Explicitly allow RustCrypto software RSA key-transport decryption despite
    /// `RUSTSEC-2023-0071` timing-risk concerns in that backend.
    pub fn allow_insecure_software_rsa_key_transport_decryption() -> Self {
        Self {
            allow_insecure_software_rsa_key_transport_decryption: true,
            ..Self::default()
        }
    }

    /// Return a copy with the software RSA key-transport risk explicitly allowed.
    pub fn with_insecure_software_rsa_key_transport_decryption_allowed(mut self) -> Self {
        self.allow_insecure_software_rsa_key_transport_decryption = true;
        self
    }

    pub(super) fn allows_insecure_software_rsa_key_transport_decryption(self) -> bool {
        self.allow_insecure_software_rsa_key_transport_decryption
    }
}

/// XML parser, redirect decompression, clock, and XML encryption policy.
///
/// # Examples
///
/// Software RSA key-transport decryption is disabled by default on the
/// RustCrypto provider because that backend, reached through `bergshamra` /
/// `kryptering`, is affected by `RUSTSEC-2023-0071`. Enable it only as an
/// explicit RustCrypto exception for a deployment that accepts
/// that risk. AWS-LC and FIPS ignore this opt-in.
///
/// ```
/// use saml_rs::{AcsEndpoint, EntityId, SpConfig, XmlEncryptionPolicy, XmlPolicy};
///
/// let xml = XmlPolicy {
///     encryption: XmlEncryptionPolicy::default()
///         .with_insecure_software_rsa_key_transport_decryption_allowed(),
///     ..XmlPolicy::default()
/// };
/// let sp_builder = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
///     .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
///     .xml(xml);
/// # let _ = sp_builder;
/// # Ok::<(), saml_rs::SamlError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XmlPolicy {
    /// Clock drift tolerance `(not_before_ms, not_on_or_after_ms)`.
    pub clock_drifts: (i64, i64),
    /// Maximum decoded compressed and inflated raw-DEFLATE bytes accepted for
    /// HTTP-Redirect input.
    pub redirect_inflate_max_bytes: usize,
    /// XML parser resource limits.
    pub limits: XmlLimits,
    /// XML encryption behavior.
    pub encryption: XmlEncryptionPolicy,
}

impl Default for XmlPolicy {
    fn default() -> Self {
        Self {
            clock_drifts: (0, 0),
            redirect_inflate_max_bytes: MAX_DEFLATE_RAW_DECODE_BYTES,
            limits: XmlLimits::default(),
            encryption: XmlEncryptionPolicy::default(),
        }
    }
}

/// Algorithm choices used by outgoing SAML messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmPolicy {
    /// Signature algorithm URI.
    pub signature: SignatureAlgorithm,
    /// Data encryption algorithm URI.
    pub data_encryption: DataEncryptionAlgorithm,
    /// Key encryption algorithm URI.
    pub key_encryption: KeyEncryptionAlgorithm,
    /// Sign/encrypt operation order for messages that do both.
    pub message_signing_order: MessageSignatureOrder,
    /// XML-DSig reference transforms.
    pub signed_reference_transforms: Vec<TransformAlgorithm>,
}

impl Default for AlgorithmPolicy {
    fn default() -> Self {
        Self {
            signature: SignatureAlgorithm::default(),
            data_encryption: DataEncryptionAlgorithm::default(),
            key_encryption: KeyEncryptionAlgorithm::default(),
            message_signing_order: MessageSignatureOrder::SignThenEncrypt,
            signed_reference_transforms: vec![
                TransformAlgorithm::EnvelopedSignature,
                TransformAlgorithm::ExclusiveCanonicalization,
            ],
        }
    }
}

/// Template and XML tag-prefix customization.
#[derive(Debug, Clone)]
pub struct TemplatePolicy {
    /// Default RelayState.
    pub relay_state: String,
    /// IdP protocol tag prefix for generated messages.
    pub tag_prefix_protocol: String,
    /// IdP assertion tag prefix for generated messages.
    pub tag_prefix_assertion: String,
    /// IdP tag prefix for generated `<EncryptedAssertion>` elements.
    pub tag_prefix_encrypted_assertion: String,
    /// IdP login response template and attributes.
    pub login_response_template: Option<LoginResponseTemplate>,
    /// SP login request template.
    pub login_request_template: Option<String>,
    /// Logout request template.
    ///
    /// Typed Session Authority generation requires a complete unqualified
    /// `NotOnOrAfter="{NotOnOrAfter}"` root attribute. Typed SP and raw
    /// samlify-port generation do not synthesize the attribute.
    ///
    /// `{NameQualifier}`, `{SPNameQualifier}`, and `{SPProvidedID}` are filled
    /// from the logout subject's `NameID`, and `{NameIDFormat}` with the
    /// `Format` sent for it. An attribute whose complete value is one of these
    /// placeholders is omitted when there is no value for it.
    ///
    /// Typed Session Authority generation, and typed SP generation with
    /// [`crate::StartSlo::apply_single_logout_generation_rules`], reject a
    /// template whose `NameID` attributes differ from the subject's. Other
    /// typed SP generation sends the template's `NameID` attributes as
    /// written.
    pub logout_request_template: Option<String>,
    /// Logout response template.
    ///
    /// After prefix and placeholder substitution, the final outbound XML must
    /// satisfy the enforced LogoutResponse structure, issuer, destination, and
    /// request-correlation requirements. A root `<ds:Signature>` is rejected
    /// before signing so the library owns signature construction. When
    /// `InResponseTo` is `None`, an attribute whose complete value is the
    /// `{InResponseTo}` placeholder is omitted.
    pub logout_response_template: Option<String>,
    /// Embedded-signature placement and prefix.
    pub signature_config: Option<SignatureConfig>,
}

impl Default for TemplatePolicy {
    fn default() -> Self {
        Self {
            relay_state: String::new(),
            tag_prefix_protocol: "samlp".to_string(),
            tag_prefix_assertion: "saml".to_string(),
            tag_prefix_encrypted_assertion: "saml".to_string(),
            login_response_template: None,
            login_request_template: None,
            logout_request_template: None,
            logout_response_template: None,
            signature_config: None,
        }
    }
}
pub(super) fn authn_request_signing_enabled(policy: AuthnRequestSigningPolicy) -> bool {
    matches!(policy, AuthnRequestSigningPolicy::Sign)
}

pub(super) fn authn_request_signature_required(policy: AuthnRequestValidationPolicy) -> bool {
    matches!(policy, AuthnRequestValidationPolicy::RequireSigned)
}

pub(super) fn verify_present_authn_request_signature(policy: AuthnRequestValidationPolicy) -> bool {
    matches!(
        policy,
        AuthnRequestValidationPolicy::AllowUnsignedVerifyIfPresent
    )
}

pub(super) fn assertion_signature_required(policy: AssertionSignaturePolicy) -> bool {
    matches!(policy, AssertionSignaturePolicy::RequireSigned)
}

pub(super) fn response_signature_required(policy: ResponseSignaturePolicy) -> bool {
    matches!(policy, ResponseSignaturePolicy::RequireSigned)
}

pub(super) fn encrypted_cbc_response_signature_required(policy: ResponseSignaturePolicy) -> bool {
    matches!(policy, ResponseSignaturePolicy::RequireForEncryptedCbc)
}

pub(super) fn logout_signature_required(policy: LogoutSignaturePolicy) -> Result<bool, SamlError> {
    match policy {
        LogoutSignaturePolicy::RequireSigned => Ok(true),
        LogoutSignaturePolicy::AllowUnsignedForCompatibility => Ok(false),
    }
}
pub(super) fn name_id_creation_allowed(policy: NameIdCreationPolicy) -> bool {
    matches!(policy, NameIdCreationPolicy::AllowCreate)
}

pub(super) fn audience_validation_enabled(policy: AudienceValidationPolicy) -> bool {
    matches!(
        policy,
        AudienceValidationPolicy::Validate | AudienceValidationPolicy::EvaluatePresentRestrictions
    )
}

pub(super) fn audience_restriction_required(policy: AudienceValidationPolicy) -> bool {
    matches!(policy, AudienceValidationPolicy::Validate)
}
