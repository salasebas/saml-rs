use core::str::FromStr;
use std::collections::HashSet;
use std::time::SystemTime;

use crate::browser::{AcsEndpoint, NameIdManagementBinding, SloEndpoint, SsoEndpoint};
use crate::entity::EntitySetting;
use crate::error::SamlError;
use crate::idp::IdentityProvider;
use crate::metadata::{IdpMetadata, MetadataLifetime, MetadataValidity, SpMetadata};
use crate::model::EndpointUrl;
use crate::sp::ServiceProvider;
use crate::xml::any_uri::{collapse_whitespace, is_absolute_uri_reference};

const MAX_ENTITY_ID_CHARACTERS: usize = 1024;

/// SOAP `ArtifactResolutionService` published by an artifact issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactResolutionService {
    index: u16,
    location: EndpointUrl,
}

impl ArtifactResolutionService {
    /// Publish a SOAP artifact resolution endpoint at `index`.
    pub fn new(index: u16, location: EndpointUrl) -> Self {
        Self { index, location }
    }

    /// Metadata index carried in the artifact's endpoint index.
    pub fn index(&self) -> u16 {
        self.index
    }

    /// Endpoint location.
    pub fn location(&self) -> &EndpointUrl {
        &self.location
    }
}

/// `ManageNameIDService` published by an identity or service provider.
///
/// Publishing one turns on name identifier management for that binding.
/// Without it, the provider neither sends nor accepts `ManageNameIDRequest`
/// on that binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManageNameIdService {
    binding: NameIdManagementBinding,
    location: EndpointUrl,
}

impl ManageNameIdService {
    /// Publish a SOAP name identifier management endpoint.
    ///
    /// Only an identity provider publishes it. A service provider
    /// configuration with it does not build.
    pub fn soap(location: EndpointUrl) -> Self {
        Self {
            binding: NameIdManagementBinding::Soap,
            location,
        }
    }

    /// Publish an HTTP-Redirect name identifier management endpoint.
    pub fn redirect(location: EndpointUrl) -> Self {
        Self {
            binding: NameIdManagementBinding::Redirect,
            location,
        }
    }

    /// Endpoint binding.
    pub fn binding(&self) -> NameIdManagementBinding {
        self.binding
    }

    /// Endpoint location.
    pub fn location(&self) -> &EndpointUrl {
        &self.location
    }

    pub(crate) fn to_raw(&self) -> crate::metadata::Endpoint {
        crate::metadata::Endpoint::new(self.binding.as_binding(), self.location.as_str())
    }
}

use super::algorithms::NameIdFormat;
use super::credentials::HmacSecret;
use super::metadata_trust::{
    ensure_expected_entity_id, ensure_metadata_trust, metadata_entity_id, AppliedMetadataTrust,
    MetadataTrustPolicy,
};

/// SAML entity ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityId(String);

impl EntityId {
    /// Wrap an entity ID URI or deployment-specific identifier without validation.
    ///
    /// Prefer [`Self::try_new`] for caller-provided input. Use this constructor
    /// for already-validated compatibility data, or to name a peer whose
    /// entity ID is not a URI. A configured provider's own entity ID is still
    /// checked when its config is validated.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Validate and wrap an entity ID.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the entity ID is not an absolute
    /// URI reference, is longer than 1024 characters, or has leading or
    /// trailing whitespace, a tab, a line break, or consecutive spaces.
    pub fn try_new(value: impl Into<String>) -> Result<Self, SamlError> {
        let value = value.into();
        validate_entity_id_syntax(&value)?;
        Ok(Self(value))
    }

    pub(crate) fn from_peer(value: impl Into<String>) -> Result<Self, SamlError> {
        let value = value.into();
        validate_peer_entity_id(&value)?;
        Ok(Self(value))
    }

    /// Borrow the entity ID string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for EntityId {
    type Err = SamlError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_new(value)
    }
}

impl TryFrom<&str> for EntityId {
    type Error = SamlError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl TryFrom<String> for EntityId {
    type Error = SamlError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

pub(crate) fn validate_entity_id_syntax(value: &str) -> Result<(), SamlError> {
    if value.chars().count() > MAX_ENTITY_ID_CHARACTERS
        || !is_absolute_uri_reference(value)
        || collapse_whitespace(value) != value
    {
        return Err(SamlError::Invalid(format!(
            "an entity ID must be an absolute URI reference of at most {MAX_ENTITY_ID_CHARACTERS} characters with collapsed whitespace"
        )));
    }
    Ok(())
}

fn validate_peer_entity_id(value: &str) -> Result<(), SamlError> {
    if value.trim().is_empty() {
        return Err(SamlError::Invalid("entity ID must not be empty".into()));
    }
    Ok(())
}

/// Local SP metadata inputs used by typed configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpMetadataConfig {
    /// `<NameIDFormat>` values advertised by the SP.
    pub name_id_format: Vec<NameIdFormat>,
    /// `SingleLogoutService` endpoints.
    pub single_logout_service: Vec<SloEndpoint>,
    /// `AssertionConsumerService` endpoints.
    pub assertion_consumer_service: Vec<AcsEndpoint>,
    /// HTTP-Redirect `ManageNameIDService` endpoints.
    pub manage_name_id_service: Vec<ManageNameIdService>,
    /// Element ordering profile for generated metadata.
    pub elements_order: Option<Vec<String>>,
    /// `validUntil` and `cacheDuration` on generated metadata. `None` writes
    /// neither.
    pub lifetime: Option<MetadataLifetime>,
}

impl SpMetadataConfig {
    /// Create SP metadata input with required ACS endpoints visible at the call site.
    ///
    /// This constructor does not validate the endpoint list. Use
    /// [`Self::try_new`] for caller-provided endpoint collections.
    pub fn new(assertion_consumer_service: Vec<AcsEndpoint>) -> Self {
        Self {
            name_id_format: Vec::new(),
            single_logout_service: Vec::new(),
            assertion_consumer_service,
            manage_name_id_service: Vec::new(),
            elements_order: None,
            lifetime: None,
        }
    }

    /// Validate and create SP metadata input.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::MissingMetadata`] when no ACS endpoint is supplied.
    pub fn try_new(assertion_consumer_service: Vec<AcsEndpoint>) -> Result<Self, SamlError> {
        let config = Self::new(assertion_consumer_service);
        config.validate()?;
        Ok(config)
    }

    /// Validate required SP metadata inputs.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::MissingMetadata`] when no ACS endpoint is supplied,
    /// and [`SamlError::Unsupported`] for a SOAP `ManageNameIDService`.
    pub fn validate(&self) -> Result<(), SamlError> {
        if self.assertion_consumer_service.is_empty() {
            return Err(SamlError::MissingMetadata(
                "AssertionConsumerService".into(),
            ));
        }
        if self
            .manage_name_id_service
            .iter()
            .any(|service| service.binding() == NameIdManagementBinding::Soap)
        {
            return Err(SamlError::Unsupported(
                "a service provider has no SOAP name identifier management".into(),
            ));
        }
        Ok(())
    }
}

/// Local IdP metadata inputs used by typed configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdpMetadataConfig {
    /// `<NameIDFormat>` values advertised by the IdP.
    pub name_id_format: Vec<NameIdFormat>,
    /// `SingleSignOnService` endpoints.
    pub single_sign_on_service: Vec<SsoEndpoint>,
    /// `SingleLogoutService` endpoints.
    pub single_logout_service: Vec<SloEndpoint>,
    /// SOAP `ArtifactResolutionService` endpoints.
    pub artifact_resolution_service: Vec<ArtifactResolutionService>,
    /// SOAP and HTTP-Redirect `ManageNameIDService` endpoints.
    pub manage_name_id_service: Vec<ManageNameIdService>,
    /// Element ordering profile for generated metadata.
    pub elements_order: Option<Vec<String>>,
    /// `validUntil` and `cacheDuration` on generated metadata. `None` writes
    /// neither.
    pub lifetime: Option<MetadataLifetime>,
}

impl IdpMetadataConfig {
    /// Create IdP metadata input with required SSO endpoints visible at the call site.
    ///
    /// This constructor does not validate the endpoint list. Use
    /// [`Self::try_new`] for caller-provided endpoint collections.
    pub fn new(single_sign_on_service: Vec<SsoEndpoint>) -> Self {
        Self {
            name_id_format: Vec::new(),
            single_sign_on_service,
            single_logout_service: Vec::new(),
            artifact_resolution_service: Vec::new(),
            manage_name_id_service: Vec::new(),
            elements_order: None,
            lifetime: None,
        }
    }

    /// Validate and create IdP metadata input.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::MissingMetadata`] when no SSO endpoint is supplied.
    pub fn try_new(single_sign_on_service: Vec<SsoEndpoint>) -> Result<Self, SamlError> {
        let config = Self::new(single_sign_on_service);
        config.validate()?;
        Ok(config)
    }

    /// Validate required IdP metadata inputs.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::MissingMetadata`] when no SSO endpoint is supplied.
    pub fn validate(&self) -> Result<(), SamlError> {
        if self.single_sign_on_service.is_empty() {
            return Err(SamlError::MissingMetadata("SingleSignOnService".into()));
        }
        let mut seen_indexes = HashSet::new();
        for service in &self.artifact_resolution_service {
            if !seen_indexes.insert(service.index()) {
                return Err(SamlError::Invalid(format!(
                    "duplicate ArtifactResolutionService index {}",
                    service.index()
                )));
            }
        }
        Ok(())
    }
}

/// Typed IdP peer descriptor imported from metadata.
///
/// Typed flows refuse it with [`SamlError::TimeWindowInvalid`] once the
/// earliest `validUntil` of its role descriptor, `EntityDescriptor`, and
/// enclosing `EntitiesDescriptor` elements has been reached.
#[derive(Debug, Clone)]
pub struct IdpDescriptor {
    entity_id: EntityId,
    provider: IdentityProvider,
    validity: MetadataValidity,
    trust: AppliedMetadataTrust,
}

impl IdpDescriptor {
    /// Parse IdP metadata for an expected entity ID and explicit trust policy.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the XML is malformed, the entity ID is absent
    /// or unexpected, the entity has no `IDPSSODescriptor` that lists the SAML 2.0
    /// protocol, the requested trust policy cannot be satisfied, or a
    /// `validUntil` is not an `xs:dateTime` with a timezone.
    pub fn from_metadata_xml_for(
        expected_entity_id: EntityId,
        xml: &str,
        trust: MetadataTrustPolicy<'_>,
    ) -> Result<Self, SamlError> {
        validate_peer_entity_id(expected_entity_id.as_str())?;
        let metadata = IdpMetadata::from_xml(xml)?;
        let actual_entity_id = metadata_entity_id(&metadata)?;
        ensure_expected_entity_id(&expected_entity_id, actual_entity_id)?;
        let trust = ensure_metadata_trust(&metadata, trust)?;
        let validity = metadata.validity()?;
        Ok(Self {
            entity_id: expected_entity_id,
            provider: IdentityProvider::from_parsed_metadata(metadata, EntitySetting::default()),
            validity,
            trust,
        })
    }

    /// Parse IdP metadata when the caller accepts the metadata-declared entity ID.
    ///
    /// Prefer [`Self::from_metadata_xml_for`] when the expected entity ID is known.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the XML is malformed, the entity ID is absent,
    /// the entity has no `IDPSSODescriptor` that lists the SAML 2.0 protocol, the
    /// requested trust policy cannot be satisfied, or a `validUntil` is not an
    /// `xs:dateTime` with a timezone.
    pub fn from_metadata_xml(xml: &str, trust: MetadataTrustPolicy<'_>) -> Result<Self, SamlError> {
        let metadata = IdpMetadata::from_xml(xml)?;
        let entity_id = EntityId::from_peer(metadata_entity_id(&metadata)?)?;
        let trust = ensure_metadata_trust(&metadata, trust)?;
        let validity = metadata.validity()?;
        Ok(Self {
            entity_id,
            provider: IdentityProvider::from_parsed_metadata(metadata, EntitySetting::default()),
            validity,
            trust,
        })
    }

    /// Metadata entity ID.
    pub fn entity_id(&self) -> &EntityId {
        &self.entity_id
    }

    /// Original metadata XML.
    pub fn metadata_xml(&self) -> &str {
        self.provider.metadata.get_metadata()
    }

    /// Parsed IdP metadata.
    pub fn metadata(&self) -> &IdpMetadata {
        &self.provider.metadata
    }

    pub(crate) fn ensure_valid_at(&self, now: SystemTime) -> Result<(), SamlError> {
        self.validity.ensure_valid_at(now)
    }

    pub(crate) fn provider(&self) -> &IdentityProvider {
        &self.provider
    }

    /// Verify this identity provider's HMAC signatures with `secret`.
    ///
    /// Use it when the peer signs with [`crate::SignatureAlgorithm::HmacSha1`].
    /// Its metadata certificates still verify its other signatures.
    pub fn with_hmac_secret(mut self, secret: HmacSecret) -> Self {
        self.provider.setting.hmac_secret = Some(secret);
        self
    }

    /// Whether this descriptor was verified with pinned signing certificates.
    pub fn was_verified_with_pinned_certificates(&self) -> bool {
        matches!(
            self.trust,
            AppliedMetadataTrust::SignedByPinnedCertificates { .. }
        )
    }

    /// Signed metadata root when pinned verification passed, including a
    /// covering `<EntitiesDescriptor>`.
    pub fn signed_entity_descriptor_xml(&self) -> Option<&str> {
        match &self.trust {
            AppliedMetadataTrust::SignedByPinnedCertificates {
                signed_entity_descriptor_xml,
            } => Some(signed_entity_descriptor_xml.as_str()),
            AppliedMetadataTrust::UnsignedForCompatibility => None,
        }
    }
}

/// Typed SP peer descriptor imported from metadata.
///
/// Typed flows refuse it with [`SamlError::TimeWindowInvalid`] once the
/// earliest `validUntil` of its role descriptor, `EntityDescriptor`, and
/// enclosing `EntitiesDescriptor` elements has been reached.
#[derive(Debug, Clone)]
pub struct SpDescriptor {
    entity_id: EntityId,
    provider: ServiceProvider,
    validity: MetadataValidity,
    trust: AppliedMetadataTrust,
}

impl SpDescriptor {
    /// Parse SP metadata for an expected entity ID and explicit trust policy.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the XML is malformed, the entity ID is absent
    /// or unexpected, the entity has no `SPSSODescriptor` that lists the SAML 2.0
    /// protocol, the requested trust policy cannot be satisfied, or a
    /// `validUntil` is not an `xs:dateTime` with a timezone.
    pub fn from_metadata_xml_for(
        expected_entity_id: EntityId,
        xml: &str,
        trust: MetadataTrustPolicy<'_>,
    ) -> Result<Self, SamlError> {
        validate_peer_entity_id(expected_entity_id.as_str())?;
        let metadata = SpMetadata::from_xml(xml)?;
        let actual_entity_id = metadata_entity_id(&metadata)?;
        ensure_expected_entity_id(&expected_entity_id, actual_entity_id)?;
        let trust = ensure_metadata_trust(&metadata, trust)?;
        let validity = metadata.validity()?;
        Ok(Self {
            entity_id: expected_entity_id,
            provider: ServiceProvider::from_parsed_metadata(metadata, EntitySetting::default()),
            validity,
            trust,
        })
    }

    /// Parse SP metadata when the caller accepts the metadata-declared entity ID.
    ///
    /// Prefer [`Self::from_metadata_xml_for`] when the expected entity ID is known.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the XML is malformed, the entity ID is absent,
    /// the entity has no `SPSSODescriptor` that lists the SAML 2.0 protocol, the
    /// requested trust policy cannot be satisfied, or a `validUntil` is not an
    /// `xs:dateTime` with a timezone.
    pub fn from_metadata_xml(xml: &str, trust: MetadataTrustPolicy<'_>) -> Result<Self, SamlError> {
        let metadata = SpMetadata::from_xml(xml)?;
        let entity_id = EntityId::from_peer(metadata_entity_id(&metadata)?)?;
        let trust = ensure_metadata_trust(&metadata, trust)?;
        let validity = metadata.validity()?;
        Ok(Self {
            entity_id,
            provider: ServiceProvider::from_parsed_metadata(metadata, EntitySetting::default()),
            validity,
            trust,
        })
    }

    /// Metadata entity ID.
    pub fn entity_id(&self) -> &EntityId {
        &self.entity_id
    }

    /// Original metadata XML.
    pub fn metadata_xml(&self) -> &str {
        self.provider.metadata.get_metadata()
    }

    /// Parsed SP metadata.
    pub fn metadata(&self) -> &SpMetadata {
        &self.provider.metadata
    }

    pub(crate) fn ensure_valid_at(&self, now: SystemTime) -> Result<(), SamlError> {
        self.validity.ensure_valid_at(now)
    }

    pub(crate) fn provider(&self) -> &ServiceProvider {
        &self.provider
    }

    /// Verify this service provider's HMAC signatures with `secret`.
    ///
    /// Use it when the peer signs with [`crate::SignatureAlgorithm::HmacSha1`].
    /// Its metadata certificates still verify its other signatures.
    pub fn with_hmac_secret(mut self, secret: HmacSecret) -> Self {
        self.provider.setting.hmac_secret = Some(secret);
        self
    }

    /// Whether this descriptor was verified with pinned signing certificates.
    pub fn was_verified_with_pinned_certificates(&self) -> bool {
        matches!(
            self.trust,
            AppliedMetadataTrust::SignedByPinnedCertificates { .. }
        )
    }

    /// Signed metadata root when pinned verification passed, including a
    /// covering `<EntitiesDescriptor>`.
    pub fn signed_entity_descriptor_xml(&self) -> Option<&str> {
        match &self.trust {
            AppliedMetadataTrust::SignedByPinnedCertificates {
                signed_entity_descriptor_xml,
            } => Some(signed_entity_descriptor_xml.as_str()),
            AppliedMetadataTrust::UnsignedForCompatibility => None,
        }
    }
}
