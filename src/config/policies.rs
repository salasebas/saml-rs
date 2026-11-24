use crate::binding::MAX_DEFLATE_RAW_DECODE_BYTES;
use crate::entity::SignatureConfig;
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
#[non_exhaustive]
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
    AllowUnsigned,
}

/// Whether an accepting service provider requires a signature on the
/// `<Response>`.
///
/// [`Self::RequireForEncryptedCbc`] follows the recommendation for a
/// CBC-encrypted assertion. [`Self::AllowUnsignedEncryptedCbc`] relaxes that
/// recommendation alone.
/// [`Self::RequireSigned`] requires a signature on every response and is
/// library hardening. The accept combination is classified in
/// `docs/conformance/web-browser-sso-acceptance.md`.
///
/// The policy has no `Default`. Take it from the role policy, for example
/// `SpValidationPolicy::default().response_signatures`:
///
/// ```compile_fail,E0599
/// let policy = saml_rs::ResponseSignaturePolicy::default();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResponseSignaturePolicy {
    /// Accept a CBC `EncryptedAssertion` without a Response signature.
    AllowUnsignedEncryptedCbc,
    /// Require a signed Response when an `<EncryptedAssertion>` uses CBC.
    ///
    /// Only an `<EncryptedAssertion>` that is a child of the `<Response>`
    /// counts. Covers AES-128-CBC, AES-192-CBC, AES-256-CBC, and Triple DES.
    /// The algorithm is read from the same XML representation as decryption.
    /// Missing methods return [`SamlError::Crypto`](crate::SamlError::Crypto);
    /// unknown data algorithms return [`SamlError::Unsupported`](crate::SamlError::Unsupported).
    /// Plaintext and AES-GCM responses do not require an outer signature.
    RequireForEncryptedCbc,
    /// Require a Response signature on every response.
    ///
    /// Library hardening. Also rejects a response signed only on the Assertion.
    RequireSigned,
}

/// Inbound signature algorithm profile for the messages a typed service
/// provider or identity provider accepts.
///
/// It applies to an embedded XML signature that authenticates the accepted
/// message and to the detached `SigAlg` of an HTTP-Redirect or
/// HTTP-POST-SimpleSign message. A signature outside the profile is rejected
/// with [`SamlError::AlgorithmUnsupported`](crate::SamlError::AlgorithmUnsupported).
///
/// On an inbound SSO response, the service provider verifies every signature on the
/// `Response` and its assertions, including decrypted assertions, under every
/// profile. HTTP-POST-SimpleSign also requires the detached signature to verify.
///
/// [`SpValidationPolicy::default`] and [`IdpValidationPolicy::default`]
/// select [`Self::ExcludeWeakAlgorithms`]. [`Self::StrictRsaSha2`] is
/// library hardening. Selecting it does not require a signature directly on the
/// Assertion. The accept combination is classified in
/// `docs/conformance/web-browser-sso-acceptance.md`.
///
/// The profile has no `Default`. Take it from the role policy, for example
/// `SpValidationPolicy::default().xml_signatures`:
///
/// ```compile_fail,E0599
/// let profile = saml_rs::XmlSignatureProfile::default();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum XmlSignatureProfile {
    /// Require RSA-SHA256/384/512.
    ///
    /// An embedded signature must also have one local `#id` reference, a
    /// SHA-256/384/512 digest, and exclusive canonicalization. Each transform
    /// element, when present, must belong to the XML-DSig namespace and use
    /// enveloped-signature or exclusive canonicalization.
    ///
    /// The verifier rejects RSA keys shorter than 2048 bits and a
    /// `ds:Object` in a signature that authenticates the message.
    StrictRsaSha2,
    /// Accept every algorithm the selected cryptographic provider supports,
    /// except MD5 and RIPEMD-160 signatures and digests and RSA keys shorter
    /// than 2048 bits.
    ///
    /// A signature method or digest outside the profile is rejected with
    /// [`SamlError::AlgorithmUnsupported`](crate::SamlError::AlgorithmUnsupported). A shorter RSA certificate is not
    /// used to verify, and a message only it could verify is rejected.
    ///
    /// A signature that authenticates the accepted message and contains a
    /// `ds:Object` is rejected with [`SamlError::SignedReferenceMismatch`](crate::SamlError::SignedReferenceMismatch).
    ExcludeWeakAlgorithms,
    /// Accept every algorithm, RSA key size, and same-document reference shape
    /// supported by the selected cryptographic provider, and a `ds:Object` in
    /// the signature. A `ds:Object` can carry unsigned data.
    AllowWeakAlgorithms,
}

/// Whether an SP signs outgoing AuthnRequests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthnRequestSigningPolicy {
    /// Sign outgoing AuthnRequests.
    Sign,
    /// Send unsigned AuthnRequests unless the IdP advertises `WantAuthnRequestsSigned`.
    /// In that case, request creation returns [`crate::SamlError::AuthnRequestSigningRequired`].
    #[default]
    DoNotSign,
}

/// Whether an identity provider requires a signed inbound `<AuthnRequest>`.
///
/// [`Self::RequireSigned`] is optional and stays off.
/// [`Self::AllowUnsigned`] verifies a signature that is present
/// and accepts an unsigned request unless the service provider's metadata sets
/// `AuthnRequestsSigned`.
/// The accept combination is classified in
/// `docs/conformance/web-browser-sso-acceptance.md`.
///
/// The policy has no `Default`. Take it from the role policy, for example
/// `IdpValidationPolicy::default().authn_request_signatures`:
///
/// ```compile_fail,E0599
/// let policy = saml_rs::AuthnRequestValidationPolicy::default();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthnRequestValidationPolicy {
    /// Reject unsigned AuthnRequests.
    RequireSigned,
    /// Verify a signature that is present, and accept an unsigned AuthnRequest
    /// from a service provider whose metadata does not set
    /// `AuthnRequestsSigned`.
    AllowUnsigned,
}

/// Whether a bearer assertion must contain an `<AudienceRestriction>`.
///
/// The service provider checks every present restriction under both policies.
/// At least one audience in each restriction must match its entity ID.
///
/// The policy has no `Default`. Take it from the role policy, for example
/// `SpValidationPolicy::default().audience`:
///
/// ```compile_fail,E0599
/// let policy = saml_rs::AudienceValidationPolicy::default();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AudienceValidationPolicy {
    /// Evaluate audience restrictions and reject a bearer assertion that omits one.
    ///
    /// Rejecting a missing restriction is library hardening. Recommended uses
    /// [`Self::EvaluatePresentRestrictions`].
    RequireRestriction,
    /// Evaluate `<AudienceRestriction>` elements that are present.
    ///
    /// A bearer assertion that omits the element is not rejected.
    EvaluatePresentRestrictions,
}

/// Whether SP AuthnRequests allow IdPs to create a new identifier.
///
/// `AllowCreate` lets the identity provider create an identifier for the
/// principal, or associate an existing one with the service provider, while it
/// answers the request. An AuthnRequest for the transient format omits
/// `AllowCreate` under either value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NameIdCreationPolicy {
    /// Set `AllowCreate="true"` in AuthnRequests.
    #[default]
    AllowCreate,
    /// Set `AllowCreate="false"` in AuthnRequests.
    ///
    /// An identity provider that keeps identifier state for each service
    /// provider can then refuse the first login of a principal it has no
    /// identifier for yet, with an `InvalidNameIDPolicy` status.
    DoNotAllowCreate,
}

/// SP-side validation and outbound signing policy.
///
/// The default policy selects the recommended settings for Web Browser SSO and Single Logout.
/// Field classification is in `docs/conformance/`.
///
/// Start from `default()` and assign the fields you change. A
/// struct literal does not compile outside the crate:
///
/// ```compile_fail,E0639
/// use saml_rs::{AudienceValidationPolicy, SpValidationPolicy};
///
/// let policy = SpValidationPolicy {
///     audience: AudienceValidationPolicy::RequireRestriction,
///     ..SpValidationPolicy::default()
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SpValidationPolicy {
    /// Assertion signature requirement.
    pub assertion_signatures: AssertionSignaturePolicy,
    /// Top-level SAML Response signature requirement.
    pub response_signatures: ResponseSignaturePolicy,
    /// Signature algorithm and reference requirements.
    pub xml_signatures: XmlSignatureProfile,
    /// Outbound AuthnRequest signing behavior.
    pub authn_request_signing: AuthnRequestSigningPolicy,
    /// Audience validation behavior.
    pub audience: AudienceValidationPolicy,
    /// NameID creation behavior for AuthnRequests.
    pub name_id_creation: NameIdCreationPolicy,
}

impl Default for SpValidationPolicy {
    /// Validation preset for claimed Web Browser SSO and Single Logout features.
    ///
    /// Recommendations start enabled, and
    /// [`XmlSignatureProfile::ExcludeWeakAlgorithms`] excludes weak signature
    /// algorithms. Optional capabilities and other library hardening stay off
    /// until a caller replaces one field.
    ///
    /// # Examples
    ///
    /// ```
    /// use saml_rs::{AssertionSignaturePolicy, SpValidationPolicy, XmlSignatureProfile};
    ///
    /// let mut with_assertion_signature = SpValidationPolicy::default();
    /// with_assertion_signature.assertion_signatures = AssertionSignaturePolicy::RequireSigned;
    /// assert_eq!(
    ///     with_assertion_signature.xml_signatures,
    ///     XmlSignatureProfile::ExcludeWeakAlgorithms
    /// );
    /// ```
    fn default() -> Self {
        Self {
            assertion_signatures: AssertionSignaturePolicy::AllowUnsigned,
            response_signatures: ResponseSignaturePolicy::RequireForEncryptedCbc,
            xml_signatures: XmlSignatureProfile::ExcludeWeakAlgorithms,
            authn_request_signing: AuthnRequestSigningPolicy::DoNotSign,
            audience: AudienceValidationPolicy::EvaluatePresentRestrictions,
            name_id_creation: NameIdCreationPolicy::AllowCreate,
        }
    }
}

/// IdP-side validation policy.
///
/// The default policy selects the recommended settings for Web Browser SSO and Single Logout.
/// Field classification is in `docs/conformance/`.
///
/// Start from `default()` and assign the fields you change. A
/// struct literal does not compile outside the crate:
///
/// ```compile_fail,E0639
/// use saml_rs::{AuthnRequestValidationPolicy, IdpValidationPolicy};
///
/// let policy = IdpValidationPolicy {
///     authn_request_signatures: AuthnRequestValidationPolicy::RequireSigned,
///     ..IdpValidationPolicy::default()
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IdpValidationPolicy {
    /// Inbound AuthnRequest signature requirement.
    pub authn_request_signatures: AuthnRequestValidationPolicy,
    /// Signature algorithm and reference requirements.
    pub xml_signatures: XmlSignatureProfile,
}

impl Default for IdpValidationPolicy {
    /// Validation preset for claimed Web Browser SSO and Single Logout features.
    ///
    /// An inbound `AuthnRequest` may be unsigned unless the service provider's
    /// metadata sets `AuthnRequestsSigned`. A signature that is present is
    /// verified under [`XmlSignatureProfile::ExcludeWeakAlgorithms`].
    fn default() -> Self {
        Self {
            authn_request_signatures: AuthnRequestValidationPolicy::AllowUnsigned,
            xml_signatures: XmlSignatureProfile::ExcludeWeakAlgorithms,
        }
    }
}

/// Assertion encryption for generated and received login responses.
///
/// A service provider with a decryption key decrypts an
/// `<EncryptedAssertion>` it receives under either value.
/// With [`Self::EncryptAssertions`], the service provider rejects a response
/// if any direct `<Assertion>` child is in plaintext, even when others are encrypted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssertionEncryptionPolicy {
    /// Generate plaintext assertions and allow both forms in received responses.
    #[default]
    PlaintextAssertions,
    /// Encrypt every generated assertion and require every received assertion to be encrypted.
    EncryptAssertions,
}

/// Whether a `<NameID>` is carried as an `<EncryptedID>`.
///
/// In [`XmlEncryptionPolicy::identifiers`], an identity provider encrypts the
/// `<NameID>` of each assertion `<Subject>` in a generated response. A service
/// provider with a decryption key decrypts each `<EncryptedID>` after the
/// signature that covers it verifies, under either value. Selected, it also
/// rejects a response whose assertion `<Subject>` carries a plaintext
/// `<NameID>`.
///
/// [`crate::StartSlo::identifier_encryption`] selects it for one
/// `LogoutRequest`, on either role.
/// [`crate::StartNameIdManagement::identifier_encryption`] selects it, for
/// the `<NameID>` and `<NewID>`, for one `ManageNameIDRequest` over SOAP or
/// HTTP-Redirect.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentifierEncryptionPolicy {
    /// Do not encrypt identifiers.
    #[default]
    PlaintextIdentifiers,
    /// Encrypt identifiers.
    EncryptIdentifiers,
}

/// Whether assertion attributes are carried as `<EncryptedAttribute>`.
///
/// An identity provider encrypts each `<Attribute>` of each assertion
/// `<AttributeStatement>` in a generated response. A service provider with a
/// decryption key decrypts each `<EncryptedAttribute>` after the signature
/// that covers it verifies, under either value. Selected, it also rejects a
/// response whose assertion `<AttributeStatement>` carries a plaintext
/// `<Attribute>`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttributeEncryptionPolicy {
    /// Do not encrypt attributes.
    #[default]
    PlaintextAttributes,
    /// Encrypt attributes.
    EncryptAttributes,
}

/// Whether an entity decrypts an `<EncryptedKey>` that uses RSA-v1.5 key
/// transport.
///
/// It applies to every encrypted element the entity receives, such as an
/// `<EncryptedAssertion>`, `<EncryptedID>`, or `<EncryptedAttribute>`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Rsa15KeyTransportPolicy {
    /// Reject an encrypted element whose `<EncryptedKey>` names RSA-v1.5 with
    /// [`SamlError::Unsupported`](crate::SamlError::Unsupported) before any
    /// key is decrypted.
    #[default]
    Reject,
    /// Decrypt an `<EncryptedKey>` that uses RSA-v1.5.
    ///
    /// RSA-v1.5 is open to Bleichenbacher's chosen-ciphertext attack. Select
    /// it only for a peer that cannot send RSA-OAEP. It needs
    /// `crypto-legacy-algorithms`.
    AllowDecryption,
}

/// XML encryption policy.
///
/// [`Default`](Default::default) encrypts nothing, rejects RSA-v1.5 key
/// transport, and allows [`DEFAULT_MAX_DECRYPTION_WORK`](crate::constants::DEFAULT_MAX_DECRYPTION_WORK)
/// units of decryption work. Start from it and assign the fields you change.
///
/// An identity provider encrypts a response for the first service provider
/// encryption key that the configured data encryption and key transport
/// algorithms can use. The first `X509Data` of a `KeyDescriptor` for
/// encryption gives the key of its first certificate, and each later
/// `X509Data` that holds exactly one certificate gives another key. A later
/// `X509Data` with a certificate chain is skipped. The identity provider skips a
/// key that does not load or that the crypto provider cannot encrypt for,
/// such as an EC key or an RSA key too small for the key transport. It needs
/// a key only when the response has an element to encrypt, so attribute
/// encryption alone needs none for an assertion without attributes. Without
/// a usable key it returns
/// [`SamlError::MissingMetadata`](crate::SamlError::MissingMetadata) when
/// none is published, or the [`SamlError::Crypto`](crate::SamlError::Crypto)
/// error of the first key.
///
/// # Examples
///
/// [`XmlPolicy`] shows how to encrypt assertions. Each element is selected on
/// its own. Selecting identifier encryption does not select attribute or
/// assertion encryption:
///
/// ```
/// use saml_rs::{AttributeEncryptionPolicy, IdentifierEncryptionPolicy, XmlEncryptionPolicy};
///
/// let mut encryption = XmlEncryptionPolicy::default();
/// encryption.identifiers = IdentifierEncryptionPolicy::EncryptIdentifiers;
/// encryption.attributes = AttributeEncryptionPolicy::EncryptAttributes;
/// # let _ = encryption;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct XmlEncryptionPolicy {
    /// Assertion encryption behavior.
    pub assertions: AssertionEncryptionPolicy,
    /// `<EncryptedID>` behavior for the assertion `<Subject>`.
    pub identifiers: IdentifierEncryptionPolicy,
    /// `<EncryptedAttribute>` behavior for assertion attribute statements.
    pub attributes: AttributeEncryptionPolicy,
    /// Whether a received `<EncryptedKey>` that uses RSA-v1.5 key transport
    /// is decrypted.
    pub rsa15_key_transport: Rsa15KeyTransportPolicy,
    /// Maximum estimated decryption work per inbound message.
    ///
    /// Each XML Encryption `EncryptedData`, `EncryptedKey`, and `DerivedKey`
    /// costs one unit per configured local decryption key, including rollover
    /// keys. Revealed encrypted content shares the allowance. Unused
    /// candidates count even when an earlier key succeeds. Zero refuses all
    /// encrypted input. Exceeding the allowance returns
    /// [`SamlError::LimitExceeded`](crate::SamlError::LimitExceeded) with
    /// [`ResourceLimit::DecryptionWork`](crate::ResourceLimit::DecryptionWork).
    /// The limit is an estimate of possible work, not a count of actual
    /// operations or a CPU-time guarantee.
    pub max_decryption_work: usize,
}

impl Default for XmlEncryptionPolicy {
    fn default() -> Self {
        Self {
            assertions: AssertionEncryptionPolicy::default(),
            identifiers: IdentifierEncryptionPolicy::default(),
            attributes: AttributeEncryptionPolicy::default(),
            rsa15_key_transport: Rsa15KeyTransportPolicy::default(),
            max_decryption_work: crate::constants::DEFAULT_MAX_DECRYPTION_WORK,
        }
    }
}

impl XmlEncryptionPolicy {
    pub(super) fn allows_rsa15_key_transport_decryption(self) -> bool {
        match self.rsa15_key_transport {
            Rsa15KeyTransportPolicy::Reject => false,
            Rsa15KeyTransportPolicy::AllowDecryption => true,
        }
    }

    pub(super) fn encrypts_assertions(self) -> bool {
        match self.assertions {
            AssertionEncryptionPolicy::EncryptAssertions => true,
            AssertionEncryptionPolicy::PlaintextAssertions => false,
        }
    }

    pub(super) fn selects_any_element(self) -> bool {
        self.encrypts_assertions() || self.assertion_elements().is_selected()
    }

    pub(super) fn assertion_elements(self) -> AssertionElementEncryption {
        AssertionElementEncryption {
            identifiers: self.identifiers,
            attributes: self.attributes,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct AssertionElementEncryption {
    pub(crate) identifiers: IdentifierEncryptionPolicy,
    pub(crate) attributes: AttributeEncryptionPolicy,
}

impl AssertionElementEncryption {
    pub(crate) fn is_selected(self) -> bool {
        let identifiers = match self.identifiers {
            IdentifierEncryptionPolicy::EncryptIdentifiers => true,
            IdentifierEncryptionPolicy::PlaintextIdentifiers => false,
        };
        let attributes = match self.attributes {
            AttributeEncryptionPolicy::EncryptAttributes => true,
            AttributeEncryptionPolicy::PlaintextAttributes => false,
        };
        identifiers || attributes
    }
}

/// XML parser, redirect decompression, and XML encryption policy.
///
/// Start from [`Default`](Default::default) and assign the fields you change,
/// including nested ones such as `encryption.assertions`.
///
/// Clock skew tolerance is not part of the config. Set it per call with
/// [`SamlValidationContext::with_clock_skew`](crate::SamlValidationContext::with_clock_skew).
///
/// Equality compares every data field and the stored schema callback address.
/// Address comparison uses [`std::ptr::fn_addr_eq`]. The same function can have
/// multiple addresses, and equivalent functions can share an address.
///
/// # Examples
///
/// Encrypt assertions and keep the other defaults:
///
/// ```
/// use saml_rs::{AcsEndpoint, AssertionEncryptionPolicy, EntityId, SpConfig, XmlPolicy};
///
/// let mut xml = XmlPolicy::default();
/// xml.encryption.assertions = AssertionEncryptionPolicy::EncryptAssertions;
/// let sp_builder = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?, AcsEndpoint::post("https://sp.example.com/acs")?)
///     .xml(xml);
/// # let _ = sp_builder;
/// # Ok::<(), saml_rs::SamlError>(())
/// ```
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct XmlPolicy {
    /// Optional schema validation for received XML, including decrypted messages.
    pub schema_validator: Option<crate::SchemaValidator>,
    /// Maximum decoded compressed and inflated raw-DEFLATE bytes accepted for
    /// HTTP-Redirect input.
    ///
    /// Defaults to 1 MiB (1,048,576 bytes).
    pub redirect_inflate_max_bytes: usize,
    /// XML parser resource limits.
    pub limits: XmlLimits,
    /// XML encryption behavior.
    pub encryption: XmlEncryptionPolicy,
}

impl PartialEq for XmlPolicy {
    fn eq(&self, other: &Self) -> bool {
        let Self {
            schema_validator,
            redirect_inflate_max_bytes,
            limits,
            encryption,
        } = self;
        redirect_inflate_max_bytes == &other.redirect_inflate_max_bytes
            && limits == &other.limits
            && encryption == &other.encryption
            && crate::schema::validator_addresses_equal(*schema_validator, other.schema_validator)
    }
}

impl Eq for XmlPolicy {}

impl Default for XmlPolicy {
    fn default() -> Self {
        Self {
            schema_validator: None,
            redirect_inflate_max_bytes: MAX_DEFLATE_RAW_DECODE_BYTES,
            limits: XmlLimits::default(),
            encryption: XmlEncryptionPolicy::default(),
        }
    }
}

/// Algorithm choices used by outgoing SAML messages.
///
/// Start from [`Default`](Default::default) and assign the fields you change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AlgorithmPolicy {
    /// Signature algorithm URI.
    pub signature: SignatureAlgorithm,
    /// Data encryption algorithm URI.
    pub data_encryption: DataEncryptionAlgorithm,
    /// Key encryption algorithm URI.
    pub key_encryption: KeyEncryptionAlgorithm,
    /// XML-DSig reference transforms.
    ///
    /// They apply to responses from `respond_sso` and `initiate_sso`, to an
    /// `AuthnRequest` with an XML signature, and to logout messages signed on
    /// HTTP-POST. Responses from `respond_sso_artifact` and
    /// `initiate_sso_artifact`, and logout messages over SOAP, keep the
    /// enveloped-signature and exclusive canonicalization
    /// transforms. The scope is in
    /// `docs/conformance/xml-security-algorithms.md`.
    pub signed_reference_transforms: Vec<TransformAlgorithm>,
}

impl Default for AlgorithmPolicy {
    fn default() -> Self {
        Self {
            signature: SignatureAlgorithm::default(),
            data_encryption: DataEncryptionAlgorithm::default(),
            key_encryption: KeyEncryptionAlgorithm::default(),
            signed_reference_transforms: vec![
                TransformAlgorithm::EnvelopedSignature,
                TransformAlgorithm::ExclusiveCanonicalization,
            ],
        }
    }
}

/// XML tag prefixes and embedded-signature placement for both roles.
///
/// Start from [`Default`](Default::default) and assign the fields you change.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TemplatePolicy {
    /// Prefix of the generated protocol-namespace elements, `samlp` by
    /// default.
    ///
    /// Applies to protocol elements the entity generates across bindings.
    /// Artifact resolution preserves the prefixes in the stored message.
    ///
    /// Must be an XML NCName that does not begin with `xml` in any case, and
    /// must differ from `tag_prefix_assertion`.
    pub tag_prefix_protocol: String,
    /// Prefix of the generated assertion-namespace elements, `saml` by
    /// default.
    ///
    /// Applies to assertion elements the entity generates across bindings,
    /// including the encrypted assertion wrapper.
    /// Artifact resolution preserves the prefixes in the stored message.
    ///
    /// Must be an XML NCName that does not begin with `xml` in any case, and
    /// must differ from `tag_prefix_protocol`.
    pub tag_prefix_assertion: String,
    /// Embedded-signature placement and prefix.
    ///
    /// The prefix must be an XML NCName that does not begin with `xml` in
    /// any case.
    pub signature_config: Option<SignatureConfig>,
}

impl Default for TemplatePolicy {
    fn default() -> Self {
        Self {
            tag_prefix_protocol: "samlp".to_string(),
            tag_prefix_assertion: "saml".to_string(),
            signature_config: None,
        }
    }
}
pub(super) fn authn_request_signing_enabled(policy: AuthnRequestSigningPolicy) -> bool {
    match policy {
        AuthnRequestSigningPolicy::Sign => true,
        AuthnRequestSigningPolicy::DoNotSign => false,
    }
}

pub(super) fn authn_request_signature_required(policy: AuthnRequestValidationPolicy) -> bool {
    match policy {
        AuthnRequestValidationPolicy::RequireSigned => true,
        AuthnRequestValidationPolicy::AllowUnsigned => false,
    }
}

pub(super) fn assertion_signature_required(policy: AssertionSignaturePolicy) -> bool {
    match policy {
        AssertionSignaturePolicy::RequireSigned => true,
        AssertionSignaturePolicy::AllowUnsigned => false,
    }
}

pub(super) fn response_signature_required(policy: ResponseSignaturePolicy) -> bool {
    match policy {
        ResponseSignaturePolicy::RequireSigned => true,
        ResponseSignaturePolicy::RequireForEncryptedCbc
        | ResponseSignaturePolicy::AllowUnsignedEncryptedCbc => false,
    }
}

pub(super) fn encrypted_cbc_response_signature_required(policy: ResponseSignaturePolicy) -> bool {
    match policy {
        ResponseSignaturePolicy::RequireForEncryptedCbc => true,
        ResponseSignaturePolicy::RequireSigned
        | ResponseSignaturePolicy::AllowUnsignedEncryptedCbc => false,
    }
}

pub(super) fn name_id_creation_allowed(policy: NameIdCreationPolicy) -> bool {
    match policy {
        NameIdCreationPolicy::AllowCreate => true,
        NameIdCreationPolicy::DoNotAllowCreate => false,
    }
}

pub(super) fn audience_restriction_required(policy: AudienceValidationPolicy) -> bool {
    match policy {
        AudienceValidationPolicy::RequireRestriction => true,
        AudienceValidationPolicy::EvaluatePresentRestrictions => false,
    }
}
