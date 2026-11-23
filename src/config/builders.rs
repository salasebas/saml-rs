//! Typed SP and IdP config builders.

use std::time::Duration;

use core::fmt;

use crate::browser::{AcsEndpoint, SloEndpoint, SsoEndpoint};
use crate::error::SamlError;
use crate::idp;
use crate::metadata::MetadataLifetime;
use crate::sp;
use crate::template::validate_tag_prefixes;
use crate::xml::name::validate_namespace_prefix;

use super::algorithms::{NameIdFormat, SignatureAlgorithm};
use super::credentials::Credentials;
use super::descriptors::{
    ArtifactResolutionService, EntityId, IdpMetadataConfig, ManageNameIdService, SpMetadataConfig,
};
#[cfg(not(crypto))]
use super::policies::{
    assertion_signature_required, authn_request_signature_required,
    encrypted_cbc_response_signature_required, response_signature_required,
};
use super::policies::{
    authn_request_signing_enabled, AlgorithmPolicy, IdpValidationPolicy, SpValidationPolicy,
    TemplatePolicy, XmlPolicy,
};
use crate::model::EndpointUrl;

/// Typed Service Provider configuration.
///
/// Build it with [`SpConfig::builder`]. A built config has passed every check
/// in [`SpConfigBuilder::build`], holds the metadata `build` generated, and
/// cannot be changed afterwards.
///
/// # Examples
///
/// ```
/// use saml_rs::{AcsEndpoint, EntityId, SpConfig, SpValidationPolicy};
///
/// # if cfg!(not(crypto)) { return Ok(()); }
/// let config = SpConfig::builder(
///     EntityId::try_new("https://sp.example.com/metadata")?,
///     AcsEndpoint::post("https://sp.example.com/acs")?,
/// )
/// .build()?;
///
/// assert_eq!(config.entity_id().as_str(), "https://sp.example.com/metadata");
/// assert_eq!(config.validation(), &SpValidationPolicy::default());
/// # Ok::<(), saml_rs::SamlError>(())
/// ```
#[derive(Clone)]
pub struct SpConfig {
    entity_id: EntityId,
    metadata: SpMetadataConfig,
    credentials: Credentials,
    validation: SpValidationPolicy,
    algorithms: AlgorithmPolicy,
    xml: XmlPolicy,
    templates: TemplatePolicy,
    pub(crate) engine: sp::Engine,
}

impl fmt::Debug for SpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpConfig")
            .field("entity_id", &self.entity_id)
            .field("metadata", &self.metadata)
            .field("credentials", &self.credentials)
            .field("validation", &self.validation)
            .field("algorithms", &self.algorithms)
            .field("xml", &self.xml)
            .field("templates", &self.templates)
            .finish_non_exhaustive()
    }
}

impl SpConfig {
    /// Start an SP config builder with its entity ID and first
    /// `AssertionConsumerService` endpoint, on [`SpValidationPolicy::default`].
    pub fn builder(entity_id: EntityId, acs: AcsEndpoint) -> SpConfigBuilder {
        SpConfigBuilder {
            entity_id,
            metadata: SpMetadataConfig::new(acs),
            credentials: Credentials::default(),
            validation: SpValidationPolicy::default(),
            algorithms: AlgorithmPolicy::default(),
            xml: XmlPolicy::default(),
            templates: TemplatePolicy::default(),
        }
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

/// Builder for [`SpConfig`].
#[derive(Debug, Clone)]
pub struct SpConfigBuilder {
    pub(super) entity_id: EntityId,
    pub(super) metadata: SpMetadataConfig,
    pub(super) credentials: Credentials,
    pub(super) validation: SpValidationPolicy,
    pub(super) algorithms: AlgorithmPolicy,
    pub(super) xml: XmlPolicy,
    pub(super) templates: TemplatePolicy,
}

impl SpConfigBuilder {
    /// Append an `AssertionConsumerService` endpoint after the ones added
    /// before.
    pub fn acs_endpoint(mut self, endpoint: AcsEndpoint) -> Self {
        self.metadata.acs_endpoints.push(endpoint);
        self
    }

    /// Append `AssertionConsumerService` endpoints after the ones added
    /// before, in iteration order.
    pub fn acs_endpoints(mut self, endpoints: impl IntoIterator<Item = AcsEndpoint>) -> Self {
        self.metadata.acs_endpoints.extend(endpoints);
        self
    }

    /// Append a `SingleLogoutService` endpoint.
    pub fn slo_endpoint(mut self, endpoint: SloEndpoint) -> Self {
        self.metadata.slo_endpoints.push(endpoint);
        self
    }

    /// Append `SingleLogoutService` endpoints, in iteration order.
    pub fn slo_endpoints(mut self, endpoints: impl IntoIterator<Item = SloEndpoint>) -> Self {
        self.metadata.slo_endpoints.extend(endpoints);
        self
    }

    /// Append an HTTP-Redirect `ManageNameIDService` endpoint at `location`.
    ///
    /// This turns on name identifier management over HTTP-Redirect for this
    /// service provider. saml-rs does not implement SOAP name identifier
    /// management for a service provider.
    pub fn manage_name_id_redirect_service(mut self, location: EndpointUrl) -> Self {
        self.metadata
            .manage_name_id_services
            .push(ManageNameIdService::redirect(location));
        self
    }

    /// Append an advertised NameID format.
    pub fn name_id_format(mut self, format: NameIdFormat) -> Self {
        self.metadata.name_id_formats.push(format);
        self
    }

    /// Append advertised NameID formats, in iteration order.
    pub fn name_id_formats(mut self, formats: impl IntoIterator<Item = NameIdFormat>) -> Self {
        self.metadata.name_id_formats.extend(formats);
        self
    }

    /// Set the entity-level organization.
    pub fn organization(mut self, organization: crate::metadata::Organization) -> Self {
        self.metadata.organization = Some(organization);
        self
    }

    /// Append an entity-level contact.
    pub fn contact(mut self, contact: crate::metadata::ContactPerson) -> Self {
        self.metadata.contacts.push(contact);
        self
    }

    /// Append entity-level contacts, in iteration order.
    pub fn contacts(
        mut self,
        contacts: impl IntoIterator<Item = crate::metadata::ContactPerson>,
    ) -> Self {
        self.metadata.contacts.extend(contacts);
        self
    }

    /// Set the error information URI of the SSO role descriptor.
    ///
    /// [`Self::build`] rejects one that is not an absolute URI reference.
    pub fn error_url(mut self, error_url: impl Into<String>) -> Self {
        self.metadata.error_url = Some(error_url.into());
        self
    }

    /// Append an entity attribute, published in the entity's
    /// `mdattr:EntityAttributes`.
    ///
    /// Build one from a name in [`crate::constants::entity_attribute`] with
    /// [`crate::AttributeNameFormat::Uri`], or convert a
    /// [`crate::SubjectIdRequirement`].
    pub fn entity_attribute(mut self, attribute: crate::Attribute) -> Self {
        self.metadata.entity_attributes.push(attribute);
        self
    }

    /// Append entity attributes, in iteration order.
    pub fn entity_attributes(
        mut self,
        attributes: impl IntoIterator<Item = crate::Attribute>,
    ) -> Self {
        self.metadata.entity_attributes.extend(attributes);
        self
    }

    /// Set `validUntil`, `cacheDuration`, or both on generated metadata.
    /// Without this setting, generation writes a one-day `cacheDuration`.
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
    /// Returns [`SamlError`] when:
    ///
    /// - the entity ID is not an absolute URI reference of at most 1024
    ///   characters, or the organization, contacts, error URI, or entity
    ///   attributes are invalid;
    /// - the selected policy needs a credential that is not set, or crypto
    ///   that a build without a crypto provider lacks;
    /// - the crypto provider does not support the selected combination of
    ///   RSA-OAEP digest and mask generation function;
    /// - a tag prefix or the `SignatureConfig` prefix is not an XML NCName or
    ///   begins with `xml` in any case, or the two tag prefixes are equal;
    /// - generating SP metadata fails: a NameID format that is not an absolute
    ///   URI reference, two ACS endpoints with the same index, more ACS
    ///   endpoints than `unsignedShort` indexes, or a `validUntil` outside the
    ///   years 0001 through 9999.
    pub fn build(self) -> Result<SpConfig, SamlError> {
        let engine = self.engine()?;
        validate_sp_policy(&self)?;
        Ok(SpConfig {
            entity_id: self.entity_id,
            metadata: self.metadata,
            credentials: self.credentials,
            validation: self.validation,
            algorithms: self.algorithms,
            xml: self.xml,
            templates: self.templates,
            engine,
        })
    }
}

/// Typed Identity Provider configuration.
///
/// Build it with [`IdpConfig::builder`]. A built config has passed every check
/// in [`IdpConfigBuilder::build`], holds the metadata `build` generated, and
/// cannot be changed afterwards.
///
/// # Examples
///
/// The builder starts on [`IdpValidationPolicy::default`].
///
/// ```
/// use saml_rs::{EntityId, IdpConfig, SsoEndpoint};
/// use std::time::Duration;
///
/// # if cfg!(not(crypto)) { return Ok(()); }
/// let config = IdpConfig::builder(
///     EntityId::try_new("https://idp.example.com/metadata")?,
///     SsoEndpoint::post("https://idp.example.com/sso")?,
/// )
/// .issuance_lifetime(Duration::from_secs(10 * 60))
/// .build()?;
///
/// assert_eq!(config.entity_id().as_str(), "https://idp.example.com/metadata");
/// assert_eq!(config.issuance_lifetime(), Duration::from_secs(10 * 60));
/// # Ok::<(), saml_rs::SamlError>(())
/// ```
#[derive(Clone)]
pub struct IdpConfig {
    entity_id: EntityId,
    metadata: IdpMetadataConfig,
    credentials: Credentials,
    pub(crate) issuance_lifetime: time::Duration,
    validation: IdpValidationPolicy,
    algorithms: AlgorithmPolicy,
    xml: XmlPolicy,
    templates: TemplatePolicy,
    pub(crate) engine: idp::Engine,
}

impl fmt::Debug for IdpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdpConfig")
            .field("entity_id", &self.entity_id)
            .field("metadata", &self.metadata)
            .field("credentials", &self.credentials)
            .field("issuance_lifetime", &self.issuance_lifetime)
            .field("validation", &self.validation)
            .field("algorithms", &self.algorithms)
            .field("xml", &self.xml)
            .field("templates", &self.templates)
            .finish_non_exhaustive()
    }
}

impl IdpConfig {
    /// Start an IdP config builder with its entity ID and first
    /// `SingleSignOnService` endpoint, on [`IdpValidationPolicy::default`]
    /// and a five-minute issuance lifetime.
    pub fn builder(entity_id: EntityId, sso: SsoEndpoint) -> IdpConfigBuilder {
        IdpConfigBuilder {
            entity_id,
            metadata: IdpMetadataConfig::new(sso),
            credentials: Credentials::default(),
            issuance_lifetime: Duration::from_secs(300),
            validation: IdpValidationPolicy::default(),
            algorithms: AlgorithmPolicy::default(),
            xml: XmlPolicy::default(),
            templates: TemplatePolicy::default(),
        }
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
}

/// Builder for [`IdpConfig`].
#[derive(Debug, Clone)]
pub struct IdpConfigBuilder {
    pub(super) entity_id: EntityId,
    pub(super) metadata: IdpMetadataConfig,
    pub(super) credentials: Credentials,
    pub(super) issuance_lifetime: Duration,
    pub(super) validation: IdpValidationPolicy,
    pub(super) algorithms: AlgorithmPolicy,
    pub(super) xml: XmlPolicy,
    pub(super) templates: TemplatePolicy,
}

impl IdpConfigBuilder {
    /// Append a `SingleSignOnService` endpoint after the ones added before.
    pub fn sso_endpoint(mut self, endpoint: SsoEndpoint) -> Self {
        self.metadata.sso_endpoints.push(endpoint);
        self
    }

    /// Append `SingleSignOnService` endpoints after the ones added before, in
    /// iteration order.
    pub fn sso_endpoints(mut self, endpoints: impl IntoIterator<Item = SsoEndpoint>) -> Self {
        self.metadata.sso_endpoints.extend(endpoints);
        self
    }

    /// Append a `SingleLogoutService` endpoint.
    pub fn slo_endpoint(mut self, endpoint: SloEndpoint) -> Self {
        self.metadata.slo_endpoints.push(endpoint);
        self
    }

    /// Append `SingleLogoutService` endpoints, in iteration order.
    pub fn slo_endpoints(mut self, endpoints: impl IntoIterator<Item = SloEndpoint>) -> Self {
        self.metadata.slo_endpoints.extend(endpoints);
        self
    }

    /// Append a SOAP `ArtifactResolutionService` endpoint.
    pub fn artifact_resolution_service(mut self, service: ArtifactResolutionService) -> Self {
        self.metadata.artifact_resolution_services.push(service);
        self
    }

    /// Append a SOAP or HTTP-Redirect `ManageNameIDService` endpoint.
    ///
    /// This turns on name identifier management over that binding.
    /// [`IdentityProvider::start_name_id_management`](crate::IdentityProvider::start_name_id_management)
    /// and
    /// [`IdentityProvider::receive_name_id_management`](crate::IdentityProvider::receive_name_id_management)
    /// fail without a SOAP endpoint, and the `_redirect` operations without an
    /// HTTP-Redirect one.
    pub fn manage_name_id_service(mut self, service: ManageNameIdService) -> Self {
        self.metadata.manage_name_id_services.push(service);
        self
    }

    /// Append an advertised NameID format.
    pub fn name_id_format(mut self, format: NameIdFormat) -> Self {
        self.metadata.name_id_formats.push(format);
        self
    }

    /// Append advertised NameID formats, in iteration order.
    pub fn name_id_formats(mut self, formats: impl IntoIterator<Item = NameIdFormat>) -> Self {
        self.metadata.name_id_formats.extend(formats);
        self
    }

    /// Set the entity-level organization.
    pub fn organization(mut self, organization: crate::metadata::Organization) -> Self {
        self.metadata.organization = Some(organization);
        self
    }

    /// Append an entity-level contact.
    pub fn contact(mut self, contact: crate::metadata::ContactPerson) -> Self {
        self.metadata.contacts.push(contact);
        self
    }

    /// Append entity-level contacts, in iteration order.
    pub fn contacts(
        mut self,
        contacts: impl IntoIterator<Item = crate::metadata::ContactPerson>,
    ) -> Self {
        self.metadata.contacts.extend(contacts);
        self
    }

    /// Set the error information URI of the SSO role descriptor.
    ///
    /// [`Self::build`] rejects one that is not an absolute URI reference.
    pub fn error_url(mut self, error_url: impl Into<String>) -> Self {
        self.metadata.error_url = Some(error_url.into());
        self
    }

    /// Append an entity attribute, published in the entity's
    /// `mdattr:EntityAttributes`.
    ///
    /// Build one from a name in [`crate::constants::entity_attribute`] with
    /// [`crate::AttributeNameFormat::Uri`], or convert a
    /// [`crate::SubjectIdRequirement`].
    pub fn entity_attribute(mut self, attribute: crate::Attribute) -> Self {
        self.metadata.entity_attributes.push(attribute);
        self
    }

    /// Append entity attributes, in iteration order.
    pub fn entity_attributes(
        mut self,
        attributes: impl IntoIterator<Item = crate::Attribute>,
    ) -> Self {
        self.metadata.entity_attributes.extend(attributes);
        self
    }

    /// Set `validUntil`, `cacheDuration`, or both on generated metadata.
    /// Without this setting, generation writes a one-day `cacheDuration`.
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
    /// Returns [`SamlError`] when:
    ///
    /// - the entity ID is not an absolute URI reference of at most 1024
    ///   characters, or the organization, contacts, error URI, or entity
    ///   attributes are invalid;
    /// - two `ArtifactResolutionService` endpoints share an index;
    /// - the issuance lifetime is zero or outside the internal supported
    ///   range;
    /// - the selected policy requires crypto that a build without a crypto
    ///   provider lacks;
    /// - the crypto provider does not support the selected combination of
    ///   RSA-OAEP digest and mask generation function;
    /// - a tag prefix or the `SignatureConfig` prefix is not an XML NCName or
    ///   begins with `xml` in any case, or the two tag prefixes are equal;
    /// - generating IdP metadata fails: a NameID format that is not an
    ///   absolute URI reference, or a `validUntil` outside the years 0001
    ///   through 9999.
    pub fn build(self) -> Result<IdpConfig, SamlError> {
        let issuance_lifetime = validated_idp_issuance_lifetime(self.issuance_lifetime)?;
        let engine = self.engine()?;
        validate_idp_policy(&self)?;
        Ok(IdpConfig {
            entity_id: self.entity_id,
            metadata: self.metadata,
            credentials: self.credentials,
            issuance_lifetime,
            validation: self.validation,
            algorithms: self.algorithms,
            xml: self.xml,
            templates: self.templates,
            engine,
        })
    }
}

fn validate_shared_policy(
    algorithms: &AlgorithmPolicy,
    templates: &TemplatePolicy,
) -> Result<(), SamlError> {
    super::encryption::validate_algorithms(algorithms)?;
    validate_tag_prefixes(
        &templates.tag_prefix_protocol,
        &templates.tag_prefix_assertion,
    )?;
    if let Some(signature) = &templates.signature_config {
        validate_namespace_prefix("SignatureConfig.prefix XML prefix", &signature.prefix)?;
    }
    Ok(())
}

fn validate_sp_policy(config: &SpConfigBuilder) -> Result<(), SamlError> {
    validate_sp_crypto_support(config)?;
    validate_shared_policy(&config.algorithms, &config.templates)?;
    if authn_request_signing_enabled(config.validation.authn_requests) {
        validate_signing_credentials(&config.credentials, &config.algorithms.signature)?;
    }
    if config.xml.encryption.selects_any_element()
        && config.credentials.decryption_credentials().is_empty()
    {
        return Err(SamlError::MissingKey("decryption_credential".into()));
    }
    Ok(())
}

fn validate_idp_policy(config: &IdpConfigBuilder) -> Result<(), SamlError> {
    validate_idp_crypto_support(config)?;
    validate_shared_policy(&config.algorithms, &config.templates)
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
    if credentials.signing_credential().is_none() {
        return Err(SamlError::MissingKey("signing_credential".into()));
    }
    Ok(())
}

#[cfg(crypto)]
fn validate_sp_crypto_support(_config: &SpConfigBuilder) -> Result<(), SamlError> {
    Ok(())
}

#[cfg(not(crypto))]
fn validate_sp_crypto_support(config: &SpConfigBuilder) -> Result<(), SamlError> {
    if sp_config_requires_crypto(config) {
        return Err(SamlError::Unsupported(
            "selected SP config policy requires a crypto provider feature".into(),
        ));
    }
    Ok(())
}

#[cfg(crypto)]
fn validate_idp_crypto_support(_config: &IdpConfigBuilder) -> Result<(), SamlError> {
    Ok(())
}

#[cfg(not(crypto))]
fn validate_idp_crypto_support(config: &IdpConfigBuilder) -> Result<(), SamlError> {
    if idp_config_requires_crypto(config) {
        return Err(SamlError::Unsupported(
            "selected IdP config policy requires a crypto provider feature".into(),
        ));
    }
    Ok(())
}

#[cfg(not(crypto))]
fn sp_config_requires_crypto(config: &SpConfigBuilder) -> bool {
    let validation = &config.validation;
    assertion_signature_required(validation.assertions)
        || response_signature_required(validation.responses)
        || encrypted_cbc_response_signature_required(validation.responses)
        || authn_request_signing_enabled(validation.authn_requests)
        || config.xml.encryption.selects_any_element()
}

#[cfg(not(crypto))]
fn idp_config_requires_crypto(config: &IdpConfigBuilder) -> bool {
    authn_request_signature_required(config.validation.authn_requests)
        || config.xml.encryption.selects_any_element()
}

#[cfg(all(test, not(crypto)))]
mod no_crypto_tests {
    use super::{IdpConfig, SpConfig};
    use crate::browser::{AcsEndpoint, SsoEndpoint};
    use crate::config::descriptors::EntityId;
    use crate::error::SamlError;
    use crate::tests::policies_without_crypto::sp_validation_without_crypto;

    #[test]
    fn protocol_only_builders_require_crypto_for_the_default_sp_response_policy(
    ) -> Result<(), SamlError> {
        let sp_builder = SpConfig::builder(
            EntityId::try_new("https://sp.example.com/metadata")?,
            AcsEndpoint::post("https://sp.example.com/acs")?,
        )
        .build();
        assert!(matches!(sp_builder, Err(SamlError::Unsupported(_))));

        SpConfig::builder(
            EntityId::try_new("https://sp.example.com/metadata")?,
            AcsEndpoint::post("https://sp.example.com/acs")?,
        )
        .validation(sp_validation_without_crypto())
        .build()?;
        IdpConfig::builder(
            EntityId::try_new("https://idp.example.com/metadata")?,
            SsoEndpoint::post("https://idp.example.com/sso")?,
        )
        .build()?;
        Ok(())
    }
}
