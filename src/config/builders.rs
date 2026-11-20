//! Typed SP and IdP config builders.
//!
//! Each SSO template is set on the builder of the role that renders it. A
//! service provider builder has no SSO response template:
//!
//! ```compile_fail,E0599
//! use saml_rs::{AcsEndpoint, EntityId, SpConfig};
//!
//! let builder = SpConfig::builder(
//!     EntityId::try_new("https://sp.example.com/metadata")?,
//!     AcsEndpoint::post("https://sp.example.com/acs")?,
//! )
//! .sso_response_template("<samlp:AuthnRequest/>");
//! # let _ = builder;
//! # Ok::<(), saml_rs::SamlError>(())
//! ```
//!
//! An identity provider builder has no AuthnRequest template:
//!
//! ```compile_fail,E0599
//! use saml_rs::{EntityId, IdpConfig, SsoEndpoint};
//!
//! let builder = IdpConfig::builder(
//!     EntityId::try_new("https://idp.example.com/metadata")?,
//!     SsoEndpoint::post("https://idp.example.com/sso")?,
//! )
//! .authn_request_template("<samlp:Response/>");
//! # let _ = builder;
//! # Ok::<(), saml_rs::SamlError>(())
//! ```

use std::time::Duration;

use core::fmt;

use crate::browser::{AcsEndpoint, SloEndpoint, SsoEndpoint};
use crate::error::SamlError;
use crate::idp::IdentityProvider;
use crate::metadata::MetadataLifetime;
use crate::sp::ServiceProvider;
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
    encrypted_cbc_response_signature_required, logout_signature_required,
    response_signature_required, LogoutPolicy,
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
/// let config = SpConfig::builder(
///     EntityId::try_new("https://sp.example.com/metadata")?,
///     AcsEndpoint::post("https://sp.example.com/acs")?,
/// )
/// .validation(SpValidationPolicy::compatibility())
/// .build()?;
///
/// assert_eq!(config.entity_id().as_str(), "https://sp.example.com/metadata");
/// assert_eq!(config.validation(), &SpValidationPolicy::compatibility());
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
    authn_request_template: Option<String>,
    pub(crate) service_provider: ServiceProvider,
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
            .field("authn_request_template", &self.authn_request_template)
            .finish_non_exhaustive()
    }
}

impl SpConfig {
    /// Start an SP config builder with its entity ID and first
    /// `AssertionConsumerService` endpoint, on [`SpValidationPolicy::recommended`].
    ///
    /// [`SpValidationPolicy::compatibility`] remains the legacy permissive
    /// preset.
    pub fn builder(entity_id: EntityId, acs: AcsEndpoint) -> SpConfigBuilder {
        SpConfigBuilder {
            entity_id,
            metadata: SpMetadataConfig::new(acs),
            credentials: Credentials::default(),
            validation: SpValidationPolicy::recommended(),
            algorithms: AlgorithmPolicy::default(),
            xml: XmlPolicy::default(),
            templates: TemplatePolicy::default(),
            authn_request_template: None,
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

    /// `<AuthnRequest>` template set with
    /// [`SpConfigBuilder::authn_request_template`], or `None` for the built-in
    /// renderer.
    pub fn authn_request_template(&self) -> Option<&str> {
        self.authn_request_template.as_deref()
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
    pub(super) authn_request_template: Option<String>,
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

    /// Set `validUntil`, `cacheDuration`, or both on generated metadata.
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

    /// Set the template [`Saml<Sp>::start_sso`](crate::Saml::start_sso)
    /// renders the `<AuthnRequest>` from, in place of the built-in renderer.
    /// [`Saml<Sp>::start_paos_sso`](crate::Saml::start_paos_sso) always uses
    /// the built-in renderer.
    ///
    /// [`AUTHN_REQUEST_TEMPLATE`](crate::config::AUTHN_REQUEST_TEMPLATE) is
    /// the default template to start from. `{NameIDFormat}` receives the first
    /// configured NameID format, checked to be an absolute URI reference. With
    /// no configured format, an attribute whose complete value is
    /// `{NameIDFormat}` is omitted.
    ///
    /// The request is sent with the prefixes the template writes:
    /// [`TemplatePolicy::tag_prefix_protocol`] and
    /// [`TemplatePolicy::tag_prefix_assertion`] do not rewrite it.
    ///
    /// `start_sso` returns [`SamlError::Invalid`] when a template is set and
    /// the [`StartSso`](crate::StartSso) options select
    /// [`apply_producer_rules`](crate::StartSso::apply_producer_rules),
    /// [`passive`](crate::StartSso::passive),
    /// [`provider_name`](crate::StartSso::provider_name), or
    /// [`requested_authn_context`](crate::StartSso::requested_authn_context).
    pub fn authn_request_template(mut self, template: impl Into<String>) -> Self {
        self.authn_request_template = Some(template.into());
        self
    }

    /// Build and validate the SP config.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when:
    ///
    /// - the entity ID is not an absolute URI reference of at most 1024
    ///   characters, or the organization, contacts, or error URI are invalid;
    /// - the selected policy needs a credential that is not set, or crypto
    ///   that a build without a crypto provider lacks;
    /// - the algorithm policy is not supported;
    /// - a tag prefix or the `SignatureConfig` prefix is not an XML NCName or
    ///   begins with `xml` in any case, or the two tag prefixes are equal;
    /// - generating SP metadata fails: a NameID format that is not an absolute
    ///   URI reference, two ACS endpoints with the same index, more ACS
    ///   endpoints than `unsignedShort` indexes, or a `validUntil` outside the
    ///   years 0001 through 9999.
    pub fn build(self) -> Result<SpConfig, SamlError> {
        let service_provider = self.service_provider()?;
        validate_sp_policy(&self)?;
        Ok(SpConfig {
            entity_id: self.entity_id,
            metadata: self.metadata,
            credentials: self.credentials,
            validation: self.validation,
            algorithms: self.algorithms,
            xml: self.xml,
            templates: self.templates,
            authn_request_template: self.authn_request_template,
            service_provider,
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
/// The builder starts on [`IdpValidationPolicy::recommended`].
/// Use [`IdpValidationPolicy::compatibility`] for the legacy permissive preset,
/// including when compiling or testing without the default crypto feature.
///
/// ```
/// use saml_rs::{EntityId, IdpConfig, IdpValidationPolicy, SsoEndpoint};
/// use std::time::Duration;
///
/// let config = IdpConfig::builder(
///     EntityId::try_new("https://idp.example.com/metadata")?,
///     SsoEndpoint::post("https://idp.example.com/sso")?,
/// )
/// .issuance_lifetime(Duration::from_secs(10 * 60))
/// .validation(IdpValidationPolicy::compatibility())
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
    sso_response_template: Option<String>,
    pub(crate) identity_provider: IdentityProvider,
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
            .field("sso_response_template", &self.sso_response_template)
            .finish_non_exhaustive()
    }
}

impl IdpConfig {
    /// Start an IdP config builder with its entity ID and first
    /// `SingleSignOnService` endpoint, on [`IdpValidationPolicy::recommended`]
    /// and a five-minute issuance lifetime.
    pub fn builder(entity_id: EntityId, sso: SsoEndpoint) -> IdpConfigBuilder {
        IdpConfigBuilder {
            entity_id,
            metadata: IdpMetadataConfig::new(sso),
            credentials: Credentials::default(),
            issuance_lifetime: Duration::from_secs(300),
            validation: IdpValidationPolicy::recommended(),
            algorithms: AlgorithmPolicy::default(),
            xml: XmlPolicy::default(),
            templates: TemplatePolicy::default(),
            sso_response_template: None,
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

    /// SSO `<Response>` template set with
    /// [`IdpConfigBuilder::sso_response_template`], or `None` for the built-in
    /// renderer.
    pub fn sso_response_template(&self) -> Option<&str> {
        self.sso_response_template.as_deref()
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
    pub(super) sso_response_template: Option<String>,
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
    /// [`Saml::start_name_id_management`](crate::Saml::start_name_id_management)
    /// and
    /// [`Saml::receive_name_id_management`](crate::Saml::receive_name_id_management)
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

    /// Set `validUntil`, `cacheDuration`, or both on generated metadata.
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

    /// Set the template the identity provider renders the SSO `<Response>`
    /// from, in place of the built-in renderer.
    ///
    /// [`SSO_RESPONSE_TEMPLATE`](crate::config::SSO_RESPONSE_TEMPLATE) is the
    /// default template to start from. `{NameIDFormat}` receives a format
    /// that has been checked to be an absolute URI reference. A `Format` the
    /// template writes itself is not checked.
    ///
    /// Tags written as `<samlp:` and `<saml:` and declarations written as
    /// `xmlns:samlp=` and `xmlns:saml=` are rewritten to
    /// [`TemplatePolicy::tag_prefix_protocol`] and
    /// [`TemplatePolicy::tag_prefix_assertion`]. A template that writes other
    /// prefixes, or whitespace before the `=`, is not rewritten.
    ///
    /// With a template set, the response methods return
    /// [`SamlError::Invalid`] for:
    ///
    /// - [`Saml::respond_paos_sso`](crate::Saml::respond_paos_sso), which
    ///   always applies the producer rules, and a response with
    ///   [`RespondSso::apply_producer_rules`](crate::RespondSso::apply_producer_rules);
    /// - a status other than `Success`, or a subordinate status code;
    /// - attributes from
    ///   [`RespondSso::attributes`](crate::RespondSso::attributes);
    /// - a [`NameId`](crate::NameId) with a `NameQualifier`,
    ///   `SPNameQualifier`, or `SPProvidedID`.
    pub fn sso_response_template(mut self, template: impl Into<String>) -> Self {
        self.sso_response_template = Some(template.into());
        self
    }

    /// Build and validate the IdP config.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when:
    ///
    /// - the entity ID is not an absolute URI reference of at most 1024
    ///   characters, or the organization, contacts, or error URI are invalid;
    /// - two `ArtifactResolutionService` endpoints share an index;
    /// - the issuance lifetime is zero or outside the internal supported
    ///   range;
    /// - the selected policy requires crypto that a build without a crypto
    ///   provider lacks;
    /// - the algorithm policy is not supported;
    /// - a tag prefix or the `SignatureConfig` prefix is not an XML NCName or
    ///   begins with `xml` in any case, or the two tag prefixes are equal;
    /// - generating IdP metadata fails: a NameID format that is not an
    ///   absolute URI reference, or a `validUntil` outside the years 0001
    ///   through 9999.
    pub fn build(self) -> Result<IdpConfig, SamlError> {
        self.metadata.ensure_unique_artifact_resolution_indexes()?;
        let issuance_lifetime = validated_idp_issuance_lifetime(self.issuance_lifetime)?;
        let identity_provider = self.identity_provider()?;
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
            sso_response_template: self.sso_response_template,
            identity_provider,
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
        || logout_policy_requires_crypto(validation.logout)
        || config.xml.encryption.selects_any_element()
}

#[cfg(not(crypto))]
fn idp_config_requires_crypto(config: &IdpConfigBuilder) -> bool {
    authn_request_signature_required(config.validation.authn_requests)
        || logout_policy_requires_crypto(config.validation.logout)
        || config.xml.encryption.selects_any_element()
}

#[cfg(not(crypto))]
fn logout_policy_requires_crypto(policy: LogoutPolicy) -> bool {
    logout_signature_required(policy.requests) || logout_signature_required(policy.responses)
}

#[cfg(all(test, not(crypto)))]
mod no_crypto_tests {
    use super::{IdpConfig, IdpValidationPolicy, SpConfig, SpValidationPolicy};
    use crate::browser::{AcsEndpoint, SsoEndpoint};
    use crate::config::descriptors::EntityId;
    use crate::error::SamlError;

    #[test]
    fn recommended_builders_need_a_crypto_provider() -> Result<(), SamlError> {
        let sp_builder = SpConfig::builder(
            EntityId::try_new("https://sp.example.com/metadata")?,
            AcsEndpoint::post("https://sp.example.com/acs")?,
        )
        .build();
        assert!(matches!(sp_builder, Err(SamlError::Unsupported(_))));

        let idp_builder = IdpConfig::builder(
            EntityId::try_new("https://idp.example.com/metadata")?,
            SsoEndpoint::post("https://idp.example.com/sso")?,
        )
        .build();
        assert!(matches!(idp_builder, Err(SamlError::Unsupported(_))));

        SpConfig::builder(
            EntityId::try_new("https://sp.example.com/metadata")?,
            AcsEndpoint::post("https://sp.example.com/acs")?,
        )
        .validation(SpValidationPolicy::compatibility())
        .build()?;
        IdpConfig::builder(
            EntityId::try_new("https://idp.example.com/metadata")?,
            SsoEndpoint::post("https://idp.example.com/sso")?,
        )
        .validation(IdpValidationPolicy::compatibility())
        .build()?;
        Ok(())
    }
}
