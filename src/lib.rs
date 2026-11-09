//! `saml-rs` - SAML 2.0 Service Provider and Identity Provider support.
//!
//! # Start here
//!
//! Guides are at <https://samlrs.vercel.app>.
//!
//! Start new browser SSO/SLO integrations with [`Saml`]. The typed facade keeps
//! local role state in [`Saml<Sp>`] or [`Saml<Idp>`], accepts peer metadata
//! through typed descriptors, and returns pending transaction values that
//! callers can store with browser session state.
//!
//! [`SpValidationPolicy::recommended`] is the preset for claimed features.
//! [`SpValidationPolicy::compatibility`] keeps the samlify-port behavior.
//! `Default`, `new`, `try_new`, and the config builders start on Recommended.
//!
//! Where the compact flow examples below use
//! [`ReplayPolicy::DisabledForCompatibility`] or unsigned metadata, treat those
//! as explicit interoperability choices. Production-shaped inbound flows should
//! use [`ReplayPolicy::RequireCache`] with a caller-owned [`ReplayCache`] and,
//! when protocol timestamps are not enough for expiry,
//! [`SamlValidationContext::with_replay_retention`].
//!
//! ```
//! use saml_rs::{AcsEndpoint, EntityId, SpConfig, SpValidationPolicy};
//!
//! # fn main() -> Result<(), saml_rs::SamlError> {
//! let config = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
//!     .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
//!     .validation(SpValidationPolicy::compatibility())
//!     .build()?;
//!
//! assert_eq!(config.entity_id.as_str(), "https://sp.example.com/metadata");
//! # Ok(()) }
//! ```
//!
//! # SP-initiated SSO
//!
//! [`Saml<Sp>::start_sso`] creates the browser action and [`PendingAuthnRequest`].
//! Store the pending value and pass it back to [`Saml<Sp>::finish_sso`] when the
//! ACS endpoint receives the SAML response.
//!
//! ```no_run
//! use saml_rs::{
//!     AcsEndpoint, BrowserInput, EntityId, FormField, IdpDescriptor,
//!     MetadataTrustPolicy, ReplayPolicy, Saml, SamlValidationContext, SpConfig,
//!     SpValidationPolicy, SsoResponse, StartSso,
//! };
//! use std::time::SystemTime;
//!
//! # fn run(
//! #     idp_metadata_xml: &str,
//! #     form_fields: Vec<FormField>,
//! # ) -> Result<(), saml_rs::SamlError> {
//! let sp = Saml::sp(
//!     SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
//!         .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
//!         .validation(SpValidationPolicy::compatibility())
//!         .build()?,
//! )?;
//! let idp = IdpDescriptor::from_metadata_xml_for(
//!     EntityId::try_new("https://idp.example.com/metadata")?,
//!     idp_metadata_xml,
//!     MetadataTrustPolicy::UnsignedForCompatibility,
//! )?;
//!
//! let started = sp.start_sso(&idp, StartSso::redirect())?;
//! let redirect_url = started.outbound.redirect_url()?;
//! # let _ = redirect_url;
//!
//! let validation = SamlValidationContext::new(
//!     SystemTime::now(),
//!     ReplayPolicy::DisabledForCompatibility,
//! );
//! let session = sp.finish_sso(
//!     &idp,
//!     &started.pending,
//!     BrowserInput::<SsoResponse>::post(form_fields),
//!     validation,
//! )?;
//! let name_id = session.name_id().value();
//! # let _ = name_id;
//! # Ok(()) }
//! ```
//!
//! [`SsoSession::verified_xml_signatures`] preserves structured evidence for
//! each successfully verified embedded XML signature that covers the Response
//! root or consumed Assertion. Its exact algorithm URI comes from the same
//! verifier-owned signature node as the successful verdict. This is separate
//! from [`SsoSession::sig_alg`], which retains its singular detached
//! HTTP-Redirect or HTTP-POST-SimpleSign meaning; neither accessor imposes an
//! application algorithm allowlist.
//!
//! # IdP-initiated SSO
//!
//! Use [`Saml<Sp>::accept_unsolicited_sso`] for IdP-initiated responses. This
//! method is separate from `finish_sso` so unsolicited responses are an explicit
//! caller choice rather than a missing pending request.
//!
//! ```no_run
//! use saml_rs::{
//!     BrowserInput, FormField, IdpDescriptor, ReplayPolicy, Saml,
//!     SamlValidationContext, SsoResponse,
//! };
//! use std::time::SystemTime;
//!
//! # fn accept(
//! #     sp: &Saml<saml_rs::Sp>,
//! #     idp: &IdpDescriptor,
//! #     form_fields: Vec<FormField>,
//! # ) -> Result<(), saml_rs::SamlError> {
//! let validation = SamlValidationContext::new(
//!     SystemTime::now(),
//!     ReplayPolicy::DisabledForCompatibility,
//! );
//! let session = sp.accept_unsolicited_sso(
//!     idp,
//!     BrowserInput::<SsoResponse>::post(form_fields),
//!     validation,
//! )?;
//! let issuer = session.issuer().as_str();
//! # let _ = issuer;
//! # Ok(()) }
//! ```
//!
//! # Identity Provider flows
//!
//! [`Saml<Idp>::receive_sso`] parses an SP `AuthnRequest`; [`Saml<Idp>::respond_sso`]
//! returns the typed browser response.
//!
//! ```no_run
//! use saml_rs::{
//!     AuthnRequest, BrowserInput, FormField, NameId, ReplayPolicy, RespondSso,
//!     Saml, SamlValidationContext, SpDescriptor, Subject,
//! };
//! use std::time::SystemTime;
//!
//! # fn respond(
//! #     idp: &Saml<saml_rs::Idp>,
//! #     sp: &SpDescriptor,
//! #     request_fields: Vec<FormField>,
//! # ) -> Result<(), saml_rs::SamlError> {
//! let validation = SamlValidationContext::new(
//!     SystemTime::now(),
//!     ReplayPolicy::DisabledForCompatibility,
//! );
//! let request = idp.receive_sso(
//!     sp,
//!     BrowserInput::<AuthnRequest>::post(request_fields),
//!     validation,
//! )?;
//! let response = idp.respond_sso(
//!     sp,
//!     &request,
//!     Subject::new(NameId::new("alice@example.com", None), Vec::new()),
//!     RespondSso::post(),
//! )?;
//! let form = response.post_form()?;
//! # let _ = form;
//! # Ok(()) }
//! ```
//!
//! [`Saml<Idp>::remember_identity_provider`] returns the `_saml_idp` cookie
//! for the caller to write after authentication.
//! [`Saml<Idp>::respond_sso`] does not write that cookie, and a service
//! provider has no method for it.
//!
//! # Single Logout
//!
//! Typed SLO uses the same pattern: start with a [`LogoutSubject`], store the
//! returned [`PendingLogoutRequest`], and finish only with the matching
//! [`LogoutResponse`]. Receiving and responding to peer-initiated logout uses
//! [`Received<LogoutRequest>`] instead of free-form request ID strings.
//! Inbound LogoutRequest messages require a UTC `IssueInstant`, but saml-rs
//! applies no library-selected maximum age to it. Optional UTC
//! `NotOnOrAfter` values are rejected at their skew-adjusted exclusive
//! deadline as a fail-closed saml-rs policy, not an OASIS receiver `MUST`.
//! A new [`SamlValidationContext`] allows five minutes of skew on that
//! deadline. [`ClockSkew::strict`] keeps the tolerance at zero, and replay
//! storage uses the same effective deadline when it is present.
//!
//! ```no_run
//! use saml_rs::{
//!     BrowserInput, FormField, IdpDescriptor, LogoutResponse, ReplayPolicy,
//!     Saml, SamlValidationContext, SsoSession, StartSlo,
//! };
//! use std::time::SystemTime;
//!
//! # fn logout(
//! #     sp: &Saml<saml_rs::Sp>,
//! #     idp: &IdpDescriptor,
//! #     session: &SsoSession,
//! #     response_fields: Vec<FormField>,
//! # ) -> Result<(), saml_rs::SamlError> {
//! if let Some(subject) = session.logout_subject() {
//!     let started = sp.start_slo(idp, subject, StartSlo::post())?;
//!     let validation = SamlValidationContext::new(
//!         SystemTime::now(),
//!         ReplayPolicy::DisabledForCompatibility,
//!     );
//!     let completed = sp.finish_slo(
//!         idp,
//!         &started.pending,
//!         BrowserInput::<LogoutResponse>::post(response_fields),
//!         validation,
//!     )?;
//!     let peer = completed.peer_entity_id().as_str();
//!     # let _ = peer;
//! }
//! # Ok(()) }
//! ```
//!
//! # Compile-time flow boundaries
//!
//! SSO and SLO pending values are different types. A logout pending value cannot
//! be used to finish Web SSO:
//!
//! ```compile_fail
//! use saml_rs::{
//!     BrowserInput, IdpDescriptor, PendingLogoutRequest, Saml,
//!     SamlValidationContext, SsoResponse,
//! };
//!
//! fn wrong(
//!     sp: &Saml<saml_rs::Sp>,
//!     idp: &IdpDescriptor,
//!     pending: &PendingLogoutRequest,
//!     input: BrowserInput<SsoResponse>,
//!     validation: SamlValidationContext<'_>,
//! ) -> Result<(), saml_rs::SamlError> {
//!     let _ = sp.finish_sso(idp, pending, input, validation)?;
//!     Ok(())
//! }
//! ```
//!
//! SLO responses are correlated through [`Received<LogoutRequest>`], not
//! arbitrary request ID strings:
//!
//! ```compile_fail
//! use saml_rs::{RespondSlo, Saml, SpDescriptor};
//!
//! fn wrong(
//!     idp: &Saml<saml_rs::Idp>,
//!     sp: &SpDescriptor,
//!     request_id: &str,
//! ) -> Result<(), saml_rs::SamlError> {
//!     let _ = idp.respond_slo(sp, request_id, RespondSlo::post())?;
//!     Ok(())
//! }
//! ```
//!
//! # Metadata trust
//!
//! Metadata trust is explicit and caller-pinned. [`MetadataTrustPolicy`] can
//! accept unsigned metadata with
//! [`MetadataTrustPolicy::UnsignedForCompatibility`] to preserve a samlify-port
//! or raw import, or require a signature from caller-provided certificates with
//! [`MetadataTrustPolicy::RequireSignature`].
//! [`MetadataTrustPolicy::RequireSignatureAllowingOtherCanonicalization`]
//! also accepts inclusive canonicalization. Prefer signed metadata with
//! pinned certificates for production trust decisions; the crate does not treat
//! the public web PKI CA store as SAML metadata trust.
//!
//! # Raw samlify-port API
//!
//! The [`raw`] module is the samlify-port surface. [`SpValidationPolicy::compatibility`]
//! keeps that behavior when leaving the raw API. The two surfaces keep their
//! own defaults. `Default`, `new`, `try_new`, and the config builders start
//! on Recommended. Advanced callers should import
//! [`raw::ServiceProvider`], [`raw::IdentityProvider`], [`raw::HttpRequest`],
//! and [`raw::BindingContext`] from there rather than using the root re-exports.
//!
//! Visible docs.rs modules and crate-root re-exports are the supported public
//! documentation surface. The [`raw`] module is the supported samlify-port
//! API. Hidden modules are lower-level implementation paths and should not be
//! the first choice for new integrations.
//!
//! # Artifact resolution
//!
//! [`Saml<Idp>::issue_artifact`] stores a protocol message for one service
//! provider. [`Saml<Idp>::answer_artifact_resolve`] returns that message in
//! `ArtifactResponse` only when the presenter is that provider.
//! [`Saml<Sp>::resolve_artifact`] sends `ArtifactResolve` to the identity
//! provider's `ArtifactResolutionService`, and [`ArtifactResolution::finish`]
//! reads the message back. The deployment POSTs the SOAP envelope. This does
//! not deliver the artifact through the browser and does not claim the IdP or
//! SP operational mode.
//!
//! # Unsupported profiles
//!
//! The high-level [`Saml`] API focuses on browser Web SSO, Enhanced Client/Proxy
//! SSO over PAOS at the service-provider and identity-provider ends,
//! metadata-driven SP/IdP setup, XML signature/encryption through `bergshamra`,
//! Single Logout, and artifact resolution over SOAP. The enhanced-client role
//! is not a facade. It does not implement HTTP-Artifact browser delivery, SOAP
//! profiles other than artifact resolution and the identity-provider leg of
//! Enhanced Client/Proxy SSO, SAML query protocols, NameID management, or
//! metadata federation. If you need one of those profiles for a real
//! interoperability target, please open an issue with the profile, binding,
//! IdP/SP product, and a minimal expected flow so we can consider the
//! implementation.
//!
//! XML cryptography (XML-DSig sign/verify with anti-wrapping, XML-Enc, detached
//! message signatures) is delegated to `bergshamra`. The default
//! `crypto-bergshamra` feature selects RustCrypto; applications
//! can instead select `crypto-aws-lc` or `crypto-fips` with default features
//! disabled. Configure assertion encryption and the RustCrypto XML-Enc exception
//! through [`XmlEncryptionPolicy`].
//! Disable default features to build the crypto-free protocol layer; crypto
//! operations then fail closed with [`SamlError::Unsupported`].

#![forbid(unsafe_code)]

#[cfg(any(
    all(feature = "crypto-rustcrypto", feature = "crypto-aws-lc"),
    all(feature = "crypto-rustcrypto", feature = "crypto-fips"),
    all(feature = "crypto-aws-lc", feature = "crypto-fips")
))]
compile_error!(
    "crypto-rustcrypto, crypto-aws-lc, and crypto-fips are mutually exclusive; select exactly one"
);

#[cfg(all(
    any(
        feature = "crypto-legacy-algorithms",
        feature = "crypto-post-quantum",
        feature = "crypto-pkcs11"
    ),
    not(any(
        feature = "crypto-rustcrypto",
        feature = "crypto-aws-lc",
        feature = "crypto-fips"
    ))
))]
compile_error!(
    "crypto capability features require one provider: crypto-rustcrypto, crypto-aws-lc, or crypto-fips"
);

#[doc(hidden)]
pub mod api;
mod artifact;
mod assertion_acceptance;
#[doc(hidden)]
pub mod binding;
pub mod browser;
pub mod config;
pub mod constants;
#[doc(hidden)]
pub mod context;
#[doc(hidden)]
pub mod crypto;
mod discovery;
#[doc(hidden)]
pub mod entity;
pub mod error;
#[doc(hidden)]
pub mod flow;
#[doc(hidden)]
pub mod idp;
#[doc(hidden)]
pub mod logout;
pub mod metadata;
pub mod model;
pub mod raw;
mod soap;
#[doc(hidden)]
pub mod sp;
#[doc(hidden)]
pub mod template;
#[doc(hidden)]
pub mod util;
#[doc(hidden)]
pub mod validator;
#[doc(hidden)]
pub mod xml;

pub use api::{
    ForceAuthn, HttpHeader, Idp, IsPassive, LogoutSigning, PaosAuthnRequest, PaosClientRequest,
    PaosHttpResponse, PaosSsoResponse, PendingPaosSso, PendingPaosSsoSnapshot, RespondSlo,
    RespondSso, Saml, SamlError, SoapFault, Sp, StartPaosSso, StartSlo, StartSso, StartedPaosSso,
    Unknown,
};
pub use artifact::{
    AnsweredArtifact, Artifact, ArtifactDereference, ArtifactRelease, ArtifactResolution,
    ArtifactUses, ArtifactWithheld, IssuedArtifacts, IssuedMessage, ResolvedProtocolMessage,
};
pub use browser::{
    AcsEndpoint, BrowserInput, EndpointUrl, FormField, LogoutBinding, Outbound, Pending,
    PendingAuthnRequest, PendingLogoutRequest, PendingSnapshot, PostForm, SloEndpoint, SsoEndpoint,
    SsoRequestBinding, SsoResponseBinding, Started,
};
pub use config::{
    AlgorithmPolicy, ArtifactResolutionService, AssertionEncryptionPolicy,
    AssertionSignaturePolicy, AudienceValidationPolicy, AuthnRequestSigningPolicy,
    AuthnRequestValidationPolicy, CertificatePem, Credentials, DataEncryptionAlgorithm,
    DigestAlgorithm, EntityId, IdpConfig, IdpConfigBuilder, IdpDescriptor, IdpMetadataConfig,
    IdpValidationPolicy, KeyEncryptionAlgorithm, LogoutPolicy, LogoutSignaturePolicy,
    MetadataTrustPolicy, NameIdCreationPolicy, NameIdFormat, Passphrase, PrivateKeyPem,
    ResponseSignaturePolicy, SignatureAlgorithm, SpConfig, SpConfigBuilder, SpDescriptor,
    SpMetadataConfig, SpValidationPolicy, TemplatePolicy, TransformAlgorithm, XmlEncryptionPolicy,
    XmlPolicy, XmlSignatureProfile,
};
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
pub use crypto::{
    crypto_provider_info, initialize_crypto_provider, CryptoFipsStatus, CryptoProvider,
    CryptoProviderInfo,
};
pub use discovery::{CommonDomainCookie, CommonDomainCookieLifetime, RememberIdentityProvider};
#[doc = "Re-export kept for older crate-root imports of the raw samlify-port API. Use `Saml` for new integrations; advanced raw callers should import `raw::EntitySetting`."]
pub use entity::EntitySetting;
#[doc = "Re-export kept for older crate-root imports of the raw samlify-port API. Use `Saml` for new integrations; advanced raw callers should import `raw::IdentityProvider`."]
pub use idp::IdentityProvider;
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
pub use metadata::MetadataSignatureVerification;
pub use model::{
    Assertion, AssertionId, Attribute, AttributeNameFormat, AttributeValue, Attributes,
    AuthnRequest, AuthnRequestAgePolicy, AuthnSession, ClockSkew, LogoutCompleted, LogoutRequest,
    LogoutResponse, LogoutSubject, MessageId, NameId, NameIdCreationRequest, NameIdPolicy,
    OutstandingLogout, Received, RelayState, RelayStateParam, ReplayCache, ReplayKey, ReplayPolicy,
    RequestedSubject, RequestedSubjectIdentifier, SamlInstant, SamlValidationContext, SessionIndex,
    SsoResponse, SsoSession, Status, Subject, SubjectConfirmation, SubordinateStatusCode,
    TopLevelStatusCode, VerifiedXmlSignature, VerifiedXmlSignatureCoverage, MAX_RELAY_STATE_BYTES,
};
pub use soap::{
    MessageConfidentiality, MessageIntegrity, PartyAuthentication, SoapChannel,
    SoapProtocolMessage, SoapRequest,
};
#[doc = "Re-export kept for older crate-root imports of the raw samlify-port API. Use `Saml` for new integrations; advanced raw callers should import `raw::ServiceProvider`."]
pub use sp::ServiceProvider;
