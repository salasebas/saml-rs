use std::time::Duration;

use crate::browser::{AcsEndpoint, SloEndpoint, SsoEndpoint};
use crate::error::SamlError;
use crate::metadata::MetadataLifetime;

use super::algorithms::{NameIdFormat, SignatureAlgorithm};
use super::credentials::Credentials;
use super::descriptors::{
    validate_entity_id_syntax, ArtifactResolutionService, EntityId, IdpMetadataConfig,
    ManageNameIdService, SpMetadataConfig,
};
use super::policies::{
    AlgorithmPolicy, AuthnRequestSigningPolicy, IdpValidationPolicy, SpValidationPolicy,
    TemplatePolicy, XmlPolicy,
};
#[cfg(not(crypto))]
use super::policies::{
    AssertionSignaturePolicy, AuthnRequestValidationPolicy, LogoutPolicy, LogoutSignaturePolicy,
    ResponseSignaturePolicy,
};

/// Typed Service Provider configuration.
///
/// Build it with [`SpConfig::builder`]. A built config has passed every check
/// in [`SpConfigBuilder::build`] and cannot be changed afterwards.
///
/// # Examples
///
/// ```
/// use saml_rs::{AcsEndpoint, EntityId, SpConfig, SpValidationPolicy};
///
/// let config = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
///     .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
///     .validation(SpValidationPolicy::compatibility())
///     .build()?;
///
/// assert_eq!(config.entity_id().as_str(), "https://sp.example.com/metadata");
/// assert_eq!(config.validation(), &SpValidationPolicy::compatibility());
/// # Ok::<(), saml_rs::SamlError>(())
/// ```
#[derive(Debug, Clone)]
pub struct SpConfig {
    entity_id: EntityId,
    metadata: SpMetadataConfig,
    credentials: Credentials,
    validation: SpValidationPolicy,
    algorithms: AlgorithmPolicy,
    xml: XmlPolicy,
    templates: TemplatePolicy,
}

impl SpConfig {
    /// Start a dependency-free SP config builder on [`SpValidationPolicy::recommended`].
    ///
    /// [`SpValidationPolicy::compatibility`] remains the legacy permissive
    /// preset.
    pub fn builder(entity_id: EntityId) -> SpConfigBuilder {
        SpConfigBuilder::new(entity_id)
    }

    /// Local SP entity ID.
    pub fn entity_id(&self) -> &EntityId {
        &self.entity_id
    }

    /// Local SP metadata inputs.
    pub fn metadata(&self) -> &SpMetadataConfig {
        &self.metadata
    }

    /// Local credentials.
    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    /// Validation and outbound signing policy.
    pub fn validation(&self) -> &SpValidationPolicy {
        &self.validation
    }

    /// Algorithm policy.
    pub fn algorithms(&self) -> &AlgorithmPolicy {
        &self.algorithms
    }

    /// XML parser, redirect, clock, and encryption policy.
    pub fn xml(&self) -> &XmlPolicy {
        &self.xml
    }

    /// Template and prefix policy.
    pub fn templates(&self) -> &TemplatePolicy {
        &self.templates
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
            metadata: SpMetadataConfig::new(),
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

    /// Publish the entity-level organization.
    pub fn organization(mut self, organization: crate::metadata::Organization) -> Self {
        self.metadata.organization = Some(organization);
        self
    }

    /// Append an entity-level contact.
    pub fn contact(mut self, contact: crate::metadata::ContactPerson) -> Self {
        self.metadata.contacts.push(contact);
        self
    }

    /// Publish an error information URI on the SSO role descriptor.
    pub fn error_url(mut self, error_url: impl Into<String>) -> Self {
        self.metadata.error_url = Some(error_url.into());
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
    /// Returns [`SamlError`] when the entity ID is not an absolute URI
    /// reference of at most 1024 characters, no ACS endpoint is set, a SOAP
    /// `ManageNameIDService` is set, the organization, contacts, or error URI
    /// are invalid, an additional decryption key has no primary one, the
    /// selected policy needs credentials that are not set, the algorithm
    /// policy is not supported, or the selected policy requires crypto in a
    /// build without a crypto provider.
    pub fn build(self) -> Result<SpConfig, SamlError> {
        validate_entity_id_syntax(self.entity_id.as_str())?;
        self.metadata.validate()?;
        let config = SpConfig {
            entity_id: self.entity_id,
            metadata: self.metadata,
            credentials: self.credentials,
            validation: self.validation,
            algorithms: self.algorithms,
            xml: self.xml,
            templates: self.templates,
        };
        validate_sp_policy(&config)?;
        Ok(config)
    }
}

/// Typed Identity Provider configuration.
///
/// Build it with [`IdpConfig::builder`]. A built config has passed every check
/// in [`IdpConfigBuilder::build`] and cannot be changed afterwards.
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
/// assert_eq!(config.entity_id().as_str(), "https://idp.example.com/metadata");
/// assert_eq!(config.issuance_lifetime(), Duration::from_secs(10 * 60));
/// # Ok::<(), saml_rs::SamlError>(())
/// ```
#[derive(Debug, Clone)]
pub struct IdpConfig {
    entity_id: EntityId,
    metadata: IdpMetadataConfig,
    credentials: Credentials,
    issuance_lifetime: time::Duration,
    validation: IdpValidationPolicy,
    algorithms: AlgorithmPolicy,
    xml: XmlPolicy,
    templates: TemplatePolicy,
}

impl IdpConfig {
    /// Start a dependency-free IdP config builder on [`IdpValidationPolicy::recommended`]
    /// and a five-minute issuance lifetime.
    pub fn builder(entity_id: EntityId) -> IdpConfigBuilder {
        IdpConfigBuilder::new(entity_id)
    }

    /// Local IdP entity ID.
    pub fn entity_id(&self) -> &EntityId {
        &self.entity_id
    }

    /// Local IdP metadata inputs.
    pub fn metadata(&self) -> &IdpMetadataConfig {
        &self.metadata
    }

    /// Local credentials.
    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    /// Lifetime applied to assertions issued by this IdP and to
    /// Session Authority LogoutRequests.
    ///
    /// The default is exactly five minutes. That value is saml-rs policy, not
    /// an OASIS-mandated duration.
    pub fn issuance_lifetime(&self) -> Duration {
        Duration::new(
            self.issuance_lifetime.whole_seconds().unsigned_abs(),
            self.issuance_lifetime.subsec_nanoseconds().unsigned_abs(),
        )
    }

    /// Validation policy.
    pub fn validation(&self) -> &IdpValidationPolicy {
        &self.validation
    }

    /// Algorithm policy.
    pub fn algorithms(&self) -> &AlgorithmPolicy {
        &self.algorithms
    }

    /// XML parser, redirect, clock, and encryption policy.
    pub fn xml(&self) -> &XmlPolicy {
        &self.xml
    }

    /// Template and prefix policy.
    pub fn templates(&self) -> &TemplatePolicy {
        &self.templates
    }

    pub(crate) fn issuance_period(&self) -> time::Duration {
        self.issuance_lifetime
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
            metadata: IdpMetadataConfig::new(),
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

    /// Publish the entity-level organization.
    pub fn organization(mut self, organization: crate::metadata::Organization) -> Self {
        self.metadata.organization = Some(organization);
        self
    }

    /// Append an entity-level contact.
    pub fn contact(mut self, contact: crate::metadata::ContactPerson) -> Self {
        self.metadata.contacts.push(contact);
        self
    }

    /// Publish an error information URI on the SSO role descriptor.
    pub fn error_url(mut self, error_url: impl Into<String>) -> Self {
        self.metadata.error_url = Some(error_url.into());
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
    /// Returns [`SamlError`] when the entity ID is not an absolute URI
    /// reference of at most 1024 characters, no SSO endpoint is set, two
    /// `ArtifactResolutionService` endpoints share an index, the organization,
    /// contacts, or error URI are invalid, an additional decryption key has no
    /// primary one, the issuance lifetime is zero or outside the internal
    /// supported range, the algorithm policy is not supported, or the selected
    /// policy requires crypto in a build without a crypto provider.
    pub fn build(self) -> Result<IdpConfig, SamlError> {
        validate_entity_id_syntax(self.entity_id.as_str())?;
        self.metadata.validate()?;
        let config = IdpConfig {
            entity_id: self.entity_id,
            metadata: self.metadata,
            credentials: self.credentials,
            issuance_lifetime: validated_idp_issuance_lifetime(self.issuance_lifetime)?,
            validation: self.validation,
            algorithms: self.algorithms,
            xml: self.xml,
            templates: self.templates,
        };
        validate_idp_policy(&config)?;
        Ok(config)
    }
}

fn validate_common_credentials(credentials: &Credentials) -> Result<(), SamlError> {
    if !credentials.additional_decryption_keys().is_empty() && credentials.decryption().is_none() {
        return Err(SamlError::MissingKey("decryption_key".into()));
    }
    Ok(())
}

fn validate_sp_policy(config: &SpConfig) -> Result<(), SamlError> {
    validate_sp_crypto_support(config)?;
    super::encryption::validate_algorithms(&config.algorithms)?;
    validate_common_credentials(&config.credentials)?;
    if matches!(
        config.validation.authn_requests,
        AuthnRequestSigningPolicy::Sign
    ) {
        validate_signing_credentials(&config.credentials, &config.algorithms.signature)?;
    }
    if config.xml.encryption.selects_any_element() && config.credentials.decryption().is_none() {
        return Err(SamlError::MissingKey("decryption_key".into()));
    }
    Ok(())
}

fn validate_idp_policy(config: &IdpConfig) -> Result<(), SamlError> {
    validate_idp_crypto_support(config)?;
    super::encryption::validate_algorithms(&config.algorithms)?;
    validate_common_credentials(&config.credentials)
}

fn validated_idp_issuance_lifetime(
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
        if credentials.hmac_secret().is_none() {
            return Err(SamlError::MissingKey("hmac_secret".into()));
        }
        return Ok(());
    }
    if credentials.signing_key().is_none() {
        return Err(SamlError::MissingKey("signing_key".into()));
    }
    if credentials.signing_certificate().is_none() {
        return Err(SamlError::MissingKey("signing_certificate".into()));
    }
    Ok(())
}

#[cfg(crypto)]
fn validate_sp_crypto_support(_config: &SpConfig) -> Result<(), SamlError> {
    Ok(())
}

#[cfg(not(crypto))]
fn validate_sp_crypto_support(config: &SpConfig) -> Result<(), SamlError> {
    if sp_config_requires_crypto(config) {
        return Err(SamlError::Unsupported(
            "selected SP config policy requires a crypto provider feature".into(),
        ));
    }
    Ok(())
}

#[cfg(crypto)]
fn validate_idp_crypto_support(_config: &IdpConfig) -> Result<(), SamlError> {
    Ok(())
}

#[cfg(not(crypto))]
fn validate_idp_crypto_support(config: &IdpConfig) -> Result<(), SamlError> {
    if idp_config_requires_crypto(config) {
        return Err(SamlError::Unsupported(
            "selected IdP config policy requires a crypto provider feature".into(),
        ));
    }
    Ok(())
}

#[cfg(not(crypto))]
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

#[cfg(not(crypto))]
fn idp_config_requires_crypto(config: &IdpConfig) -> bool {
    matches!(
        config.validation.authn_requests,
        AuthnRequestValidationPolicy::RequireSigned
    ) || logout_policy_requires_crypto(config.validation.logout)
        || config.xml.encryption.selects_any_element()
}

#[cfg(not(crypto))]
fn logout_policy_requires_crypto(policy: LogoutPolicy) -> bool {
    logout_signature_policy_requires_crypto(policy.requests)
        || logout_signature_policy_requires_crypto(policy.responses)
}

#[cfg(not(crypto))]
fn logout_signature_policy_requires_crypto(policy: LogoutSignaturePolicy) -> bool {
    matches!(policy, LogoutSignaturePolicy::RequireSigned)
}

#[cfg(all(test, not(crypto)))]
mod no_crypto_tests {
    use super::{IdpConfig, IdpValidationPolicy, SpConfig, SpValidationPolicy};
    use crate::browser::{AcsEndpoint, SsoEndpoint};
    use crate::config::descriptors::EntityId;
    use crate::error::SamlError;

    #[test]
    fn recommended_builders_need_a_crypto_provider() -> Result<(), SamlError> {
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
        Ok(())
    }
}
