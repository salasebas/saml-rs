use std::time::Duration;

use crate::browser::{AcsEndpoint, SloEndpoint, SsoEndpoint};
use crate::entity::EntitySetting;
use crate::error::SamlError;
use crate::metadata::MetadataLifetime;

use super::algorithms::{
    name_id_format_uris, transform_algorithm_uris, NameIdFormat, SignatureAlgorithm,
};
use super::credentials::Credentials;
use super::descriptors::{
    validate_entity_id_syntax, ArtifactResolutionService, EntityId, IdpMetadataConfig,
    ManageNameIdService, SpMetadataConfig,
};
use super::policies::{
    assertion_signature_required, audience_restriction_required, audience_validation_enabled,
    authn_request_signature_required, authn_request_signing_enabled,
    encrypted_cbc_response_signature_required, logout_signature_required, name_id_creation_allowed,
    response_signature_required, verify_present_authn_request_signature, AlgorithmPolicy,
    AssertionEncryptionPolicy, AuthnRequestSigningPolicy, IdpValidationPolicy,
    ReceivedEncryptedElements, SpValidationPolicy, TemplatePolicy, XmlPolicy,
};
#[cfg(not(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
)))]
use super::policies::{
    AssertionSignaturePolicy, AuthnRequestValidationPolicy, LogoutPolicy, LogoutSignaturePolicy,
    ResponseSignaturePolicy,
};

/// Typed Service Provider configuration.
///
/// # Examples
///
/// ```
/// use saml_rs::{AcsEndpoint, EntityId, SpConfig, SpMetadataConfig, SpValidationPolicy};
///
/// let acs = AcsEndpoint::post("https://sp.example.com/acs")?;
/// let config = SpConfig::new(
///     EntityId::try_new("https://sp.example.com/metadata")?,
///     SpMetadataConfig::new(vec![acs]),
/// );
///
/// assert_eq!(config.entity_id.as_str(), "https://sp.example.com/metadata");
/// assert_eq!(config.validation, SpValidationPolicy::recommended());
/// # Ok::<(), saml_rs::SamlError>(())
/// ```
#[derive(Debug, Clone)]
pub struct SpConfig {
    /// Local SP entity ID.
    pub entity_id: EntityId,
    /// Local SP metadata inputs.
    pub metadata: SpMetadataConfig,
    /// Local credentials.
    pub credentials: Credentials,
    /// Validation and outbound signing policy.
    pub validation: SpValidationPolicy,
    /// Algorithm policy.
    pub algorithms: AlgorithmPolicy,
    /// XML parser, redirect, clock, and encryption policy.
    pub xml: XmlPolicy,
    /// Template and prefix policy.
    pub templates: TemplatePolicy,
}

impl SpConfig {
    /// Create SP configuration with required identity and metadata inputs.
    ///
    /// Validation starts on [`SpValidationPolicy::recommended`]. This
    /// convenience constructor accepts already-validated typed inputs but does
    /// not validate the final config. Use [`Self::try_new`] or [`Self::builder`]
    /// for caller-provided setup.
    pub fn new(entity_id: EntityId, metadata: SpMetadataConfig) -> Self {
        Self {
            entity_id,
            metadata,
            credentials: Credentials::default(),
            validation: SpValidationPolicy::default(),
            algorithms: AlgorithmPolicy::default(),
            xml: XmlPolicy::default(),
            templates: TemplatePolicy::default(),
        }
    }

    /// Validate and create SP configuration on [`SpValidationPolicy::recommended`].
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the entity ID is not an absolute URI reference
    /// of at most 1024 characters, required SP metadata endpoints are missing,
    /// or this build has no crypto provider and the Recommended preset needs
    /// one.
    pub fn try_new(entity_id: EntityId, metadata: SpMetadataConfig) -> Result<Self, SamlError> {
        let config = Self::new(entity_id, metadata);
        config.validate()?;
        Ok(config)
    }

    /// Start a dependency-free SP config builder on [`SpValidationPolicy::recommended`].
    ///
    /// [`Self::try_new`] uses the same preset. [`SpValidationPolicy::compatibility`]
    /// remains the legacy permissive preset.
    pub fn builder(entity_id: EntityId) -> SpConfigBuilder {
        SpConfigBuilder::new(entity_id)
    }

    /// Validate required SP config fields.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the entity ID is not an absolute URI reference
    /// of at most 1024 characters, required SP metadata endpoints are missing,
    /// or the selected policy requires crypto in a build without a crypto
    /// provider.
    pub fn validate(&self) -> Result<(), SamlError> {
        validate_entity_id_syntax(self.entity_id.as_str())?;
        self.metadata.validate()?;
        validate_sp_policy(self)
    }
}

/// Dependency-free builder for [`SpConfig`].
#[derive(Debug, Clone)]
pub struct SpConfigBuilder {
    entity_id: EntityId,
    metadata: SpMetadataConfig,
    credentials: Credentials,
    validation: SpValidationPolicy,
    algorithms: AlgorithmPolicy,
    xml: XmlPolicy,
    templates: TemplatePolicy,
}

impl SpConfigBuilder {
    fn new(entity_id: EntityId) -> Self {
        Self {
            entity_id,
            metadata: SpMetadataConfig::new(Vec::new()),
            credentials: Credentials::default(),
            validation: SpValidationPolicy::recommended(),
            algorithms: AlgorithmPolicy::default(),
            xml: XmlPolicy::default(),
            templates: TemplatePolicy::default(),
        }
    }

    /// Add an ACS endpoint.
    pub fn acs_endpoint(mut self, endpoint: AcsEndpoint) -> Self {
        self.metadata.assertion_consumer_service.push(endpoint);
        self
    }

    /// Add an SLO endpoint.
    pub fn slo_endpoint(mut self, endpoint: SloEndpoint) -> Self {
        self.metadata.single_logout_service.push(endpoint);
        self
    }

    /// Publish an HTTP-Redirect `ManageNameIDService` endpoint.
    ///
    /// This turns on name identifier management over HTTP-Redirect for this
    /// service provider. A SOAP endpoint makes [`Self::build`] fail.
    pub fn manage_name_id_service(mut self, service: ManageNameIdService) -> Self {
        self.metadata.manage_name_id_service.push(service);
        self
    }

    /// Add an advertised NameID format.
    pub fn name_id_format(mut self, format: NameIdFormat) -> Self {
        self.metadata.name_id_format.push(format);
        self
    }

    /// Set generated metadata element ordering.
    pub fn elements_order(mut self, elements_order: Vec<String>) -> Self {
        self.metadata.elements_order = Some(elements_order);
        self
    }

    /// Write `validUntil`, `cacheDuration`, or both on generated metadata.
    pub fn metadata_lifetime(mut self, lifetime: MetadataLifetime) -> Self {
        self.metadata.lifetime = Some(lifetime);
        self
    }

    /// Set local credentials.
    pub fn credentials(mut self, credentials: Credentials) -> Self {
        self.credentials = credentials;
        self
    }

    /// Set SP validation and outbound signing policy.
    pub fn validation(mut self, validation: SpValidationPolicy) -> Self {
        self.validation = validation;
        self
    }

    /// Set algorithm policy.
    pub fn algorithms(mut self, algorithms: AlgorithmPolicy) -> Self {
        self.algorithms = algorithms;
        self
    }

    /// Set XML policy.
    pub fn xml(mut self, xml: XmlPolicy) -> Self {
        self.xml = xml;
        self
    }

    /// Set template policy.
    pub fn templates(mut self, templates: TemplatePolicy) -> Self {
        self.templates = templates;
        self
    }

    /// Build and validate the SP config.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when required fields are missing, selected policy
    /// needs unavailable credentials, or selected policy requires crypto in a
    /// no-default-features build.
    pub fn build(self) -> Result<SpConfig, SamlError> {
        let config = SpConfig {
            entity_id: self.entity_id,
            metadata: self.metadata,
            credentials: self.credentials,
            validation: self.validation,
            algorithms: self.algorithms,
            xml: self.xml,
            templates: self.templates,
        };
        config.validate()?;
        Ok(config)
    }
}

/// Typed Identity Provider configuration.
///
/// # Examples
///
/// The builder starts on [`IdpValidationPolicy::recommended`].
/// Use [`IdpValidationPolicy::compatibility`] for the legacy permissive preset,
/// including when compiling or testing without the default crypto feature.
///
/// ```
/// use saml_rs::{EntityId, IdpConfig, IdpValidationPolicy, SsoEndpoint};
/// use std::time::Duration;
///
/// let config = IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
///     .sso_endpoint(SsoEndpoint::post("https://idp.example.com/sso")?)
///     .issuance_lifetime(Duration::from_secs(10 * 60))
///     .validation(IdpValidationPolicy::compatibility())
///     .build()?;
///
/// assert_eq!(config.entity_id.as_str(), "https://idp.example.com/metadata");
/// # Ok::<(), saml_rs::SamlError>(())
/// ```
#[derive(Debug, Clone)]
pub struct IdpConfig {
    /// Local IdP entity ID.
    pub entity_id: EntityId,
    /// Local IdP metadata inputs.
    pub metadata: IdpMetadataConfig,
    /// Local credentials.
    pub credentials: Credentials,
    /// Lifetime applied to assertions issued by this IdP and to
    /// Session Authority LogoutRequests.
    ///
    /// The default is exactly five minutes. That value is saml-rs policy, not
    /// an OASIS-mandated duration.
    pub issuance_lifetime: Duration,
    /// Validation policy.
    pub validation: IdpValidationPolicy,
    /// Algorithm policy.
    pub algorithms: AlgorithmPolicy,
    /// XML parser, redirect, clock, and encryption policy.
    pub xml: XmlPolicy,
    /// Template and prefix policy.
    pub templates: TemplatePolicy,
}

impl IdpConfig {
    /// Create IdP configuration with required identity and metadata inputs.
    ///
    /// This convenience constructor accepts already-validated typed inputs but
    /// does not validate the final config. Validation starts on
    /// [`IdpValidationPolicy::recommended`]. The issuance lifetime defaults to
    /// exactly five minutes. Use [`Self::try_new`] or [`Self::builder`] for
    /// caller-provided setup.
    pub fn new(entity_id: EntityId, metadata: IdpMetadataConfig) -> Self {
        Self {
            entity_id,
            metadata,
            credentials: Credentials::default(),
            issuance_lifetime: Duration::from_secs(300),
            validation: IdpValidationPolicy::default(),
            algorithms: AlgorithmPolicy::default(),
            xml: XmlPolicy::default(),
            templates: TemplatePolicy::default(),
        }
    }

    /// Validate and create IdP configuration on [`IdpValidationPolicy::recommended`].
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the entity ID is not an absolute URI reference
    /// of at most 1024 characters, required IdP metadata endpoints are missing,
    /// the issuance lifetime is zero or outside the range supported by the
    /// internal time representation, or this build has no crypto provider and
    /// the Recommended preset needs one.
    pub fn try_new(entity_id: EntityId, metadata: IdpMetadataConfig) -> Result<Self, SamlError> {
        let config = Self::new(entity_id, metadata);
        config.validate()?;
        Ok(config)
    }

    /// Start a dependency-free IdP config builder on [`IdpValidationPolicy::recommended`]
    /// and a five-minute issuance lifetime.
    pub fn builder(entity_id: EntityId) -> IdpConfigBuilder {
        IdpConfigBuilder::new(entity_id)
    }

    /// Validate required IdP config fields.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the entity ID is not an absolute URI reference
    /// of at most 1024 characters, required IdP metadata endpoints are missing,
    /// the issuance lifetime is zero or outside the range supported by the
    /// internal time representation, or the selected policy requires crypto in
    /// a build without a crypto provider.
    pub fn validate(&self) -> Result<(), SamlError> {
        validate_entity_id_syntax(self.entity_id.as_str())?;
        self.metadata.validate()?;
        validate_idp_policy(self)
    }
}

/// Dependency-free builder for [`IdpConfig`].
#[derive(Debug, Clone)]
pub struct IdpConfigBuilder {
    entity_id: EntityId,
    metadata: IdpMetadataConfig,
    credentials: Credentials,
    issuance_lifetime: Duration,
    validation: IdpValidationPolicy,
    algorithms: AlgorithmPolicy,
    xml: XmlPolicy,
    templates: TemplatePolicy,
}

impl IdpConfigBuilder {
    fn new(entity_id: EntityId) -> Self {
        Self {
            entity_id,
            metadata: IdpMetadataConfig::new(Vec::new()),
            credentials: Credentials::default(),
            issuance_lifetime: Duration::from_secs(300),
            validation: IdpValidationPolicy::recommended(),
            algorithms: AlgorithmPolicy::default(),
            xml: XmlPolicy::default(),
            templates: TemplatePolicy::default(),
        }
    }

    /// Add an SSO endpoint.
    pub fn sso_endpoint(mut self, endpoint: SsoEndpoint) -> Self {
        self.metadata.single_sign_on_service.push(endpoint);
        self
    }

    /// Add an SLO endpoint.
    pub fn slo_endpoint(mut self, endpoint: SloEndpoint) -> Self {
        self.metadata.single_logout_service.push(endpoint);
        self
    }

    /// Publish a SOAP `ArtifactResolutionService` endpoint.
    pub fn artifact_resolution_service(mut self, service: ArtifactResolutionService) -> Self {
        self.metadata.artifact_resolution_service.push(service);
        self
    }

    /// Publish a SOAP or HTTP-Redirect `ManageNameIDService` endpoint.
    ///
    /// This turns on name identifier management over that binding.
    /// [`Saml::start_name_id_management`](crate::Saml::start_name_id_management)
    /// and
    /// [`Saml::receive_name_id_management`](crate::Saml::receive_name_id_management)
    /// fail without a SOAP endpoint, and the `_redirect` operations without an
    /// HTTP-Redirect one.
    pub fn manage_name_id_service(mut self, service: ManageNameIdService) -> Self {
        self.metadata.manage_name_id_service.push(service);
        self
    }

    /// Add an advertised NameID format.
    pub fn name_id_format(mut self, format: NameIdFormat) -> Self {
        self.metadata.name_id_format.push(format);
        self
    }

    /// Set generated metadata element ordering.
    pub fn elements_order(mut self, elements_order: Vec<String>) -> Self {
        self.metadata.elements_order = Some(elements_order);
        self
    }

    /// Write `validUntil`, `cacheDuration`, or both on generated metadata.
    pub fn metadata_lifetime(mut self, lifetime: MetadataLifetime) -> Self {
        self.metadata.lifetime = Some(lifetime);
        self
    }

    /// Set local credentials.
    pub fn credentials(mut self, credentials: Credentials) -> Self {
        self.credentials = credentials;
        self
    }

    /// Set the lifetime for issued assertions and Session Authority
    /// LogoutRequests.
    ///
    /// The value is validated by [`Self::build`].
    pub fn issuance_lifetime(mut self, issuance_lifetime: Duration) -> Self {
        self.issuance_lifetime = issuance_lifetime;
        self
    }

    /// Set IdP validation policy.
    pub fn validation(mut self, validation: IdpValidationPolicy) -> Self {
        self.validation = validation;
        self
    }

    /// Set algorithm policy.
    pub fn algorithms(mut self, algorithms: AlgorithmPolicy) -> Self {
        self.algorithms = algorithms;
        self
    }

    /// Set XML policy.
    pub fn xml(mut self, xml: XmlPolicy) -> Self {
        self.xml = xml;
        self
    }

    /// Set template policy.
    pub fn templates(mut self, templates: TemplatePolicy) -> Self {
        self.templates = templates;
        self
    }

    /// Build and validate the IdP config.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when required fields are missing, the issuance
    /// lifetime is zero or outside the internal supported range, or selected
    /// policy requires crypto in a no-default-features build.
    pub fn build(self) -> Result<IdpConfig, SamlError> {
        let config = IdpConfig {
            entity_id: self.entity_id,
            metadata: self.metadata,
            credentials: self.credentials,
            issuance_lifetime: self.issuance_lifetime,
            validation: self.validation,
            algorithms: self.algorithms,
            xml: self.xml,
            templates: self.templates,
        };
        config.validate()?;
        Ok(config)
    }
}

fn validate_common_credentials(credentials: &Credentials) -> Result<(), SamlError> {
    if credentials.signing_key_passphrase.is_some() && credentials.signing_key.is_none() {
        return Err(SamlError::MissingKey("signing_key".into()));
    }
    if credentials.decryption_key_passphrase.is_some() && credentials.decryption_key.is_none() {
        return Err(SamlError::MissingKey("decryption_key".into()));
    }
    Ok(())
}

fn validate_sp_policy(config: &SpConfig) -> Result<(), SamlError> {
    validate_sp_crypto_support(config)?;
    validate_common_credentials(&config.credentials)?;
    if matches!(
        config.validation.authn_requests,
        AuthnRequestSigningPolicy::Sign
    ) {
        validate_signing_credentials(&config.credentials, &config.algorithms.signature)?;
    }
    if config.xml.encryption.selects_any_element() && config.credentials.decryption_key.is_none() {
        return Err(SamlError::MissingKey("decryption_key".into()));
    }
    Ok(())
}

fn validate_idp_policy(config: &IdpConfig) -> Result<(), SamlError> {
    validated_idp_issuance_lifetime(config.issuance_lifetime)?;
    validate_idp_crypto_support(config)?;
    validate_common_credentials(&config.credentials)
}

pub(crate) fn validated_idp_issuance_lifetime(
    issuance_lifetime: Duration,
) -> Result<time::Duration, SamlError> {
    if issuance_lifetime.is_zero() {
        return Err(SamlError::Invalid(
            "IdP issuance lifetime must be greater than zero".into(),
        ));
    }
    time::Duration::try_from(issuance_lifetime).map_err(|_| {
        SamlError::Invalid(
            "IdP issuance lifetime must fit in time::Duration (at most i64::MAX seconds plus 999,999,999 nanoseconds)".into(),
        )
    })
}

fn validate_signing_credentials(
    credentials: &Credentials,
    algorithm: &SignatureAlgorithm,
) -> Result<(), SamlError> {
    if matches!(algorithm, SignatureAlgorithm::HmacSha1) {
        if credentials.hmac_secret.is_none() {
            return Err(SamlError::MissingKey("hmac_secret".into()));
        }
        return Ok(());
    }
    if credentials.signing_key.is_none() {
        return Err(SamlError::MissingKey("signing_key".into()));
    }
    if credentials.signing_certificate.is_none() {
        return Err(SamlError::MissingKey("signing_certificate".into()));
    }
    Ok(())
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn validate_sp_crypto_support(_config: &SpConfig) -> Result<(), SamlError> {
    Ok(())
}

#[cfg(not(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
)))]
fn validate_sp_crypto_support(config: &SpConfig) -> Result<(), SamlError> {
    if sp_config_requires_crypto(config) {
        return Err(SamlError::Unsupported(
            "selected SP config policy requires a crypto provider feature".into(),
        ));
    }
    Ok(())
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn validate_idp_crypto_support(_config: &IdpConfig) -> Result<(), SamlError> {
    Ok(())
}

#[cfg(not(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
)))]
fn validate_idp_crypto_support(config: &IdpConfig) -> Result<(), SamlError> {
    if idp_config_requires_crypto(config) {
        return Err(SamlError::Unsupported(
            "selected IdP config policy requires a crypto provider feature".into(),
        ));
    }
    Ok(())
}

#[cfg(not(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
)))]
fn sp_config_requires_crypto(config: &SpConfig) -> bool {
    matches!(
        config.validation.assertions,
        AssertionSignaturePolicy::RequireSigned
    ) || matches!(
        config.validation.responses,
        ResponseSignaturePolicy::RequireSigned | ResponseSignaturePolicy::RequireForEncryptedCbc
    ) || matches!(
        config.validation.authn_requests,
        AuthnRequestSigningPolicy::Sign
    ) || logout_policy_requires_crypto(config.validation.logout)
        || config.xml.encryption.selects_any_element()
}

#[cfg(not(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
)))]
fn idp_config_requires_crypto(config: &IdpConfig) -> bool {
    matches!(
        config.validation.authn_requests,
        AuthnRequestValidationPolicy::RequireSigned
    ) || logout_policy_requires_crypto(config.validation.logout)
        || config.xml.encryption.selects_any_element()
}

#[cfg(not(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
)))]
fn logout_policy_requires_crypto(policy: LogoutPolicy) -> bool {
    logout_signature_policy_requires_crypto(policy.requests)
        || logout_signature_policy_requires_crypto(policy.responses)
}

#[cfg(not(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
)))]
fn logout_signature_policy_requires_crypto(policy: LogoutSignaturePolicy) -> bool {
    matches!(policy, LogoutSignaturePolicy::RequireSigned)
}

fn apply_common_settings(
    entity_id: &EntityId,
    name_id_format: &[NameIdFormat],
    credentials: &Credentials,
    algorithms: &AlgorithmPolicy,
    xml: &XmlPolicy,
    templates: &TemplatePolicy,
    setting: &mut EntitySetting,
) {
    setting.entity_id = Some(entity_id.as_str().to_string());
    setting.request_signature_algorithm = algorithms.signature.as_uri().to_string();
    setting.data_encryption_algorithm = algorithms.data_encryption.as_uri().to_string();
    setting.key_encryption_algorithm = algorithms.key_encryption.as_uri().to_string();
    setting.message_signing_order = algorithms.message_signing_order;
    setting.is_assertion_encrypted = matches!(
        xml.encryption.assertions,
        AssertionEncryptionPolicy::EncryptAssertions
    );
    setting.assertion_element_encryption = xml.encryption.assertion_elements();
    setting.received_encrypted_elements = ReceivedEncryptedElements::DecryptReceived;
    setting.allow_insecure_software_rsa_key_transport_decryption = xml
        .encryption
        .allows_insecure_software_rsa_key_transport_decryption();
    setting.allow_rsa15_key_transport_decryption =
        xml.encryption.allows_rsa15_key_transport_decryption();
    setting.relay_state = templates.relay_state.clone();
    setting.name_id_format = name_id_format_uris(name_id_format);
    setting.private_key = credentials
        .signing_key
        .as_ref()
        .map(|key| key.as_str().to_string());
    setting.private_key_pass = credentials
        .signing_key_passphrase
        .as_ref()
        .map(|passphrase| passphrase.as_str().to_string());
    setting.signing_cert = credentials
        .signing_certificate
        .as_ref()
        .map(|certificate| certificate.as_str().to_string());
    setting.hmac_secret = credentials.hmac_secret.clone();
    setting.encrypt_cert = credentials
        .encryption_certificate
        .as_ref()
        .map(|certificate| certificate.as_str().to_string());
    setting.enc_private_key = credentials
        .decryption_key
        .as_ref()
        .map(|key| key.as_str().to_string());
    setting.enc_private_key_pass = credentials
        .decryption_key_passphrase
        .as_ref()
        .map(|passphrase| passphrase.as_str().to_string());
    setting.clock_drifts = xml.clock_drifts;
    setting.redirect_inflate_max_bytes = xml.redirect_inflate_max_bytes;
    setting.xml_limits = xml.limits;
    setting.tag_prefix_protocol = templates.tag_prefix_protocol.clone();
    setting.tag_prefix_assertion = templates.tag_prefix_assertion.clone();
    setting.tag_prefix_encrypted_assertion = templates.tag_prefix_encrypted_assertion.clone();
    setting.login_response_template = templates.login_response_template.clone();
    setting.login_request_template = templates.login_request_template.clone();
    setting.logout_request_template = templates.logout_request_template.clone();
    setting.logout_response_template = templates.logout_response_template.clone();
    setting.signature_config = templates.signature_config.clone();
    setting.transformation_algorithms =
        transform_algorithm_uris(&algorithms.signed_reference_transforms);
}

impl TryFrom<&SpConfig> for EntitySetting {
    type Error = SamlError;

    fn try_from(config: &SpConfig) -> Result<Self, Self::Error> {
        config.validate()?;
        let mut setting = Self::default();
        apply_common_settings(
            &config.entity_id,
            &config.metadata.name_id_format,
            &config.credentials,
            &config.algorithms,
            &config.xml,
            &config.templates,
            &mut setting,
        );
        setting.allow_create = name_id_creation_allowed(config.validation.name_id_creation);
        setting.authn_requests_signed =
            authn_request_signing_enabled(config.validation.authn_requests);
        setting.want_assertions_signed = assertion_signature_required(config.validation.assertions);
        setting.validate_audience = audience_validation_enabled(config.validation.audience);
        setting.require_audience_restriction =
            audience_restriction_required(config.validation.audience);
        setting.want_message_signed = response_signature_required(config.validation.responses);
        setting.strict_xml_signature_profile = matches!(
            config.validation.xml_signatures,
            super::XmlSignatureProfile::StrictRsaSha2
        );
        setting.want_encrypted_cbc_response_signed =
            encrypted_cbc_response_signature_required(config.validation.responses);
        setting.want_logout_request_signed =
            logout_signature_required(config.validation.logout.requests)?;
        setting.want_logout_response_signed =
            logout_signature_required(config.validation.logout.responses)?;
        Ok(setting)
    }
}

impl TryFrom<&IdpConfig> for EntitySetting {
    type Error = SamlError;

    fn try_from(config: &IdpConfig) -> Result<Self, Self::Error> {
        config.validate()?;
        let mut setting = Self::default();
        apply_common_settings(
            &config.entity_id,
            &config.metadata.name_id_format,
            &config.credentials,
            &config.algorithms,
            &config.xml,
            &config.templates,
            &mut setting,
        );
        setting.want_authn_requests_signed =
            authn_request_signature_required(config.validation.authn_requests);
        setting.verify_authn_request_signature_if_present =
            verify_present_authn_request_signature(config.validation.authn_requests);
        setting.want_logout_request_signed =
            logout_signature_required(config.validation.logout.requests)?;
        setting.want_logout_response_signed =
            logout_signature_required(config.validation.logout.responses)?;
        Ok(setting)
    }
}

#[cfg(all(
    test,
    not(any(
        feature = "crypto-rustcrypto",
        feature = "crypto-aws-lc",
        feature = "crypto-fips"
    ))
))]
mod no_crypto_tests {
    use super::{
        IdpConfig, IdpMetadataConfig, IdpValidationPolicy, SpConfig, SpMetadataConfig,
        SpValidationPolicy,
    };
    use crate::browser::{AcsEndpoint, SsoEndpoint};
    use crate::config::descriptors::EntityId;
    use crate::error::SamlError;

    #[test]
    fn recommended_constructors_need_a_crypto_provider() -> Result<(), SamlError> {
        let sp = SpConfig::try_new(
            EntityId::try_new("https://sp.example.com/metadata")?,
            SpMetadataConfig::new(vec![AcsEndpoint::post("https://sp.example.com/acs")?]),
        );
        assert!(matches!(sp, Err(SamlError::Unsupported(_))));

        let idp = IdpConfig::try_new(
            EntityId::try_new("https://idp.example.com/metadata")?,
            IdpMetadataConfig::new(vec![SsoEndpoint::post("https://idp.example.com/sso")?]),
        );
        assert!(matches!(idp, Err(SamlError::Unsupported(_))));

        let sp_builder = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
            .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
            .build();
        assert!(matches!(sp_builder, Err(SamlError::Unsupported(_))));

        let idp_builder =
            IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
                .sso_endpoint(SsoEndpoint::post("https://idp.example.com/sso")?)
                .build();
        assert!(matches!(idp_builder, Err(SamlError::Unsupported(_))));

        SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
            .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
            .validation(SpValidationPolicy::compatibility())
            .build()?;
        IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
            .sso_endpoint(SsoEndpoint::post("https://idp.example.com/sso")?)
            .validation(IdpValidationPolicy::compatibility())
            .build()?;

        let mut sp = SpConfig::new(
            EntityId::try_new("https://sp.example.com/metadata")?,
            SpMetadataConfig::new(vec![AcsEndpoint::post("https://sp.example.com/acs")?]),
        );
        sp.validation = SpValidationPolicy::compatibility();
        sp.validate()?;

        let mut idp = IdpConfig::new(
            EntityId::try_new("https://idp.example.com/metadata")?,
            IdpMetadataConfig::new(vec![SsoEndpoint::post("https://idp.example.com/sso")?]),
        );
        idp.validation = IdpValidationPolicy::compatibility();
        idp.validate()?;
        Ok(())
    }
}
