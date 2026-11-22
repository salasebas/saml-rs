use core::str::FromStr;
use std::collections::HashSet;
use std::time::SystemTime;

use crate::browser::{
    AcsEndpoint, LogoutBinding, NameIdManagementBinding, SloEndpoint, SsoEndpoint,
    SsoRequestBinding, SsoResponseBinding,
};
use crate::constants::Binding;
use crate::entity::EntitySetting;
use crate::error::SamlError;
use crate::idp;
use crate::metadata::{IdpMetadata, Metadata, MetadataLifetime, MetadataValidity, SpMetadata};
use crate::model::EndpointUrl;
use crate::sp;
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
    /// Only an identity provider publishes it:
    /// [`SpConfigBuilder::manage_name_id_redirect_service`](crate::SpConfigBuilder::manage_name_id_redirect_service)
    /// publishes an HTTP-Redirect endpoint.
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
        crate::metadata::Endpoint::new(Binding::from(self.binding), self.location.as_str())
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
    /// Wrap an entity ID.
    ///
    /// Any value with a non-whitespace character is accepted, so this also
    /// names a peer whose entity ID is not a URI, such as `idp.example.com`.
    /// A provider's own entity ID must be an absolute URI reference of at most
    /// 1024 characters with collapsed whitespace; building an `SpConfig` or
    /// `IdpConfig` checks that.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the entity ID has no
    /// non-whitespace character.
    pub fn try_new(value: impl Into<String>) -> Result<Self, SamlError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(SamlError::Invalid("entity ID must not be empty".into()));
        }
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

/// Local SP metadata inputs used by typed configuration.
///
/// [`SpConfigBuilder`](crate::SpConfigBuilder) fills it, and
/// [`SpConfig::metadata`](crate::SpConfig::metadata) reads it back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpMetadataConfig {
    pub(super) name_id_formats: Vec<NameIdFormat>,
    pub(super) slo_endpoints: Vec<SloEndpoint>,
    pub(super) acs_endpoints: Vec<AcsEndpoint>,
    pub(super) manage_name_id_services: Vec<ManageNameIdService>,
    pub(super) lifetime: Option<MetadataLifetime>,
    pub(super) organization: Option<crate::metadata::Organization>,
    pub(super) contacts: Vec<crate::metadata::ContactPerson>,
    pub(super) error_url: Option<String>,
}

impl SpMetadataConfig {
    pub(super) fn new(acs: AcsEndpoint) -> Self {
        Self {
            name_id_formats: Vec::new(),
            slo_endpoints: Vec::new(),
            acs_endpoints: vec![acs],
            manage_name_id_services: Vec::new(),
            lifetime: None,
            organization: None,
            contacts: Vec::new(),
            error_url: None,
        }
    }

    /// `<NameIDFormat>` values advertised by the SP.
    pub fn name_id_formats(&self) -> &[NameIdFormat] {
        &self.name_id_formats
    }

    /// `SingleLogoutService` endpoints.
    pub fn slo_endpoints(&self) -> &[SloEndpoint] {
        &self.slo_endpoints
    }

    /// `AssertionConsumerService` endpoints, never empty.
    pub fn acs_endpoints(&self) -> &[AcsEndpoint] {
        &self.acs_endpoints
    }

    /// HTTP-Redirect `ManageNameIDService` endpoints.
    pub fn manage_name_id_services(&self) -> &[ManageNameIdService] {
        &self.manage_name_id_services
    }

    /// Configured metadata lifetime. `None` uses a one-day `cacheDuration` in the generated XML.
    pub fn lifetime(&self) -> Option<MetadataLifetime> {
        self.lifetime
    }

    /// Entity-level organization. `None` writes no `Organization`.
    pub fn organization(&self) -> Option<&crate::metadata::Organization> {
        self.organization.as_ref()
    }

    /// Entity-level contacts, in publication order.
    pub fn contacts(&self) -> &[crate::metadata::ContactPerson] {
        &self.contacts
    }

    /// Error information URI on the SSO role descriptor. `None` omits it.
    pub fn error_url(&self) -> Option<&str> {
        self.error_url.as_deref()
    }
}

/// Local IdP metadata inputs used by typed configuration.
///
/// [`IdpConfigBuilder`](crate::IdpConfigBuilder) fills it, and
/// [`IdpConfig::metadata`](crate::IdpConfig::metadata) reads it back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdpMetadataConfig {
    pub(super) name_id_formats: Vec<NameIdFormat>,
    pub(super) sso_endpoints: Vec<SsoEndpoint>,
    pub(super) slo_endpoints: Vec<SloEndpoint>,
    pub(super) artifact_resolution_services: Vec<ArtifactResolutionService>,
    pub(super) manage_name_id_services: Vec<ManageNameIdService>,
    pub(super) lifetime: Option<MetadataLifetime>,
    pub(super) organization: Option<crate::metadata::Organization>,
    pub(super) contacts: Vec<crate::metadata::ContactPerson>,
    pub(super) error_url: Option<String>,
}

impl IdpMetadataConfig {
    pub(super) fn new(sso: SsoEndpoint) -> Self {
        Self {
            name_id_formats: Vec::new(),
            sso_endpoints: vec![sso],
            slo_endpoints: Vec::new(),
            artifact_resolution_services: Vec::new(),
            manage_name_id_services: Vec::new(),
            lifetime: None,
            organization: None,
            contacts: Vec::new(),
            error_url: None,
        }
    }

    pub(super) fn ensure_unique_artifact_resolution_indexes(&self) -> Result<(), SamlError> {
        let mut seen_indexes = HashSet::new();
        for service in &self.artifact_resolution_services {
            if !seen_indexes.insert(service.index()) {
                return Err(SamlError::Invalid(format!(
                    "duplicate ArtifactResolutionService index {}",
                    service.index()
                )));
            }
        }
        Ok(())
    }

    /// `<NameIDFormat>` values advertised by the IdP.
    pub fn name_id_formats(&self) -> &[NameIdFormat] {
        &self.name_id_formats
    }

    /// `SingleSignOnService` endpoints, never empty.
    pub fn sso_endpoints(&self) -> &[SsoEndpoint] {
        &self.sso_endpoints
    }

    /// `SingleLogoutService` endpoints.
    pub fn slo_endpoints(&self) -> &[SloEndpoint] {
        &self.slo_endpoints
    }

    /// SOAP `ArtifactResolutionService` endpoints.
    pub fn artifact_resolution_services(&self) -> &[ArtifactResolutionService] {
        &self.artifact_resolution_services
    }

    /// SOAP and HTTP-Redirect `ManageNameIDService` endpoints.
    pub fn manage_name_id_services(&self) -> &[ManageNameIdService] {
        &self.manage_name_id_services
    }

    /// Configured metadata lifetime. `None` uses a one-day `cacheDuration` in the generated XML.
    pub fn lifetime(&self) -> Option<MetadataLifetime> {
        self.lifetime
    }

    /// Entity-level organization. `None` writes no `Organization`.
    pub fn organization(&self) -> Option<&crate::metadata::Organization> {
        self.organization.as_ref()
    }

    /// Entity-level contacts, in publication order.
    pub fn contacts(&self) -> &[crate::metadata::ContactPerson] {
        &self.contacts
    }

    /// Error information URI on the SSO role descriptor. `None` omits it.
    pub fn error_url(&self) -> Option<&str> {
        self.error_url.as_deref()
    }
}

/// What both peer descriptors keep from importing metadata.
#[derive(Debug, Clone)]
struct ImportedMetadata {
    entity_id: EntityId,
    validity: MetadataValidity,
    trust: AppliedMetadataTrust,
}

impl ImportedMetadata {
    fn check(
        expected_entity_id: EntityId,
        metadata: &Metadata,
        trust: MetadataTrustPolicy<'_>,
    ) -> Result<Self, SamlError> {
        ensure_expected_entity_id(&expected_entity_id, metadata_entity_id(metadata)?)?;
        let trust = ensure_metadata_trust(metadata, trust)?;
        let validity = metadata.validity()?;
        Ok(Self {
            entity_id: expected_entity_id,
            validity,
            trust,
        })
    }

    fn signed_metadata_xml(&self) -> Option<&str> {
        match &self.trust {
            AppliedMetadataTrust::SignedByPinnedCertificates {
                signed_metadata_xml,
            } => Some(signed_metadata_xml.as_str()),
            AppliedMetadataTrust::Unverified => None,
        }
    }
}

/// Typed IdP peer descriptor imported from metadata.
///
/// Typed flows refuse it with [`SamlError::TimeWindowInvalid`] once the
/// earliest `validUntil` of its role descriptor, `EntityDescriptor`, and
/// enclosing `EntitiesDescriptor` elements has been reached.
#[derive(Debug, Clone)]
pub struct IdpDescriptor {
    imported: ImportedMetadata,
    provider: idp::Engine,
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
    pub fn from_metadata_xml(
        expected_entity_id: EntityId,
        xml: &str,
        trust: MetadataTrustPolicy<'_>,
    ) -> Result<Self, SamlError> {
        Self::from_metadata_xml_with_policy(
            expected_entity_id,
            xml,
            trust,
            &crate::XmlPolicy::default(),
        )
    }

    /// Parse peer metadata with explicit XML limits and an optional schema validator.
    ///
    /// Encryption and Redirect limits in the policy do not affect metadata.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] for malformed or rejected XML, an unexpected entity
    /// ID, invalid metadata, or an unsatisfied trust policy.
    pub fn from_metadata_xml_with_policy(
        expected_entity_id: EntityId,
        xml: &str,
        trust: MetadataTrustPolicy<'_>,
        xml_policy: &crate::XmlPolicy,
    ) -> Result<Self, SamlError> {
        let metadata = IdpMetadata::from_xml_with_policy(xml, xml_policy)?;
        let imported = ImportedMetadata::check(expected_entity_id, metadata.as_metadata(), trust)?;
        Ok(Self {
            imported,
            provider: idp::Engine::from_parsed_metadata(metadata, EntitySetting::default()),
        })
    }

    /// Metadata entity ID.
    pub fn entity_id(&self) -> &EntityId {
        &self.imported.entity_id
    }

    /// Original metadata XML.
    pub fn metadata_xml(&self) -> &str {
        self.raw_metadata().metadata_xml()
    }

    /// Name identifier formats advertised by this peer's SAML 2.0 role, in document order.
    pub fn name_id_formats(&self) -> Vec<NameIdFormat> {
        self.raw_metadata().name_id_formats()
    }

    /// Entity-level organization in the imported metadata.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] for multiple organizations or a localized
    /// value without `xml:lang`.
    pub fn organization(&self) -> Result<Option<crate::metadata::Organization>, SamlError> {
        self.raw_metadata().organization()
    }

    /// Entity-level contacts in document order.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] for a missing or unknown `contactType`.
    pub fn contacts(&self) -> Result<Vec<crate::metadata::ContactPerson>, SamlError> {
        self.raw_metadata().contacts()
    }

    /// First non-empty logout request location for this peer's SAML 2.0 role and binding.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the selected location is not an absolute HTTP(S) URL.
    pub fn single_logout_location(
        &self,
        binding: LogoutBinding,
    ) -> Result<Option<EndpointUrl>, SamlError> {
        single_logout_location(self.raw_metadata(), binding)
    }

    /// First logout response location, falling back to the endpoint's request location.
    ///
    /// For SOAP this reports the published location; a SOAP response returns on
    /// the request's HTTP exchange and is not sent to that URL.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the selected location is not an absolute HTTP(S) URL.
    pub fn single_logout_response_location(
        &self,
        binding: LogoutBinding,
    ) -> Result<Option<EndpointUrl>, SamlError> {
        single_logout_response_location(self.raw_metadata(), binding)
    }

    /// First non-empty SSO location for this peer's SAML 2.0 IdP role and binding.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the selected location is not an absolute HTTP(S) URL.
    pub fn single_sign_on_location(
        &self,
        binding: SsoRequestBinding,
    ) -> Result<Option<EndpointUrl>, SamlError> {
        endpoint_location(
            self.provider
                .metadata
                .single_sign_on_location(binding.into()),
            "SingleSignOnService",
            binding.into(),
        )
    }

    /// Verify this identity provider's HMAC signatures with `secret`.
    ///
    /// Use it when the peer signs with [`crate::SignatureAlgorithm::HmacSha1`].
    /// Its metadata certificates still verify its other signatures.
    pub fn with_hmac_secret(mut self, secret: HmacSecret) -> Self {
        self.provider.setting.hmac_secret = Some(secret);
        self
    }

    /// Signed metadata root when the metadata signature verified with a
    /// caller-pinned certificate, including a covering `<EntitiesDescriptor>`.
    ///
    /// `None` under [`MetadataTrustPolicy::AllowUnsigned`], even when the
    /// document carries a signature. It reports verification at import and
    /// does not check metadata expiration.
    pub fn signed_metadata_xml(&self) -> Option<&str> {
        self.imported.signed_metadata_xml()
    }

    /// Parsed IdP metadata.
    pub(crate) fn metadata(&self) -> &IdpMetadata {
        &self.provider.metadata
    }

    pub(crate) fn ensure_valid_at(&self, now: SystemTime) -> Result<(), SamlError> {
        self.imported.validity.ensure_valid_at(now)
    }

    pub(crate) fn provider(&self) -> &idp::Engine {
        &self.provider
    }

    fn raw_metadata(&self) -> &Metadata {
        self.provider.metadata.as_metadata()
    }
}

/// Typed SP peer descriptor imported from metadata.
///
/// Typed flows refuse it with [`SamlError::TimeWindowInvalid`] once the
/// earliest `validUntil` of its role descriptor, `EntityDescriptor`, and
/// enclosing `EntitiesDescriptor` elements has been reached.
#[derive(Debug, Clone)]
pub struct SpDescriptor {
    imported: ImportedMetadata,
    provider: sp::Engine,
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
    pub fn from_metadata_xml(
        expected_entity_id: EntityId,
        xml: &str,
        trust: MetadataTrustPolicy<'_>,
    ) -> Result<Self, SamlError> {
        Self::from_metadata_xml_with_policy(
            expected_entity_id,
            xml,
            trust,
            &crate::XmlPolicy::default(),
        )
    }

    /// Parse peer metadata with explicit XML limits and an optional schema validator.
    ///
    /// Encryption and Redirect limits in the policy do not affect metadata.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] for malformed or rejected XML, an unexpected entity
    /// ID, invalid metadata, or an unsatisfied trust policy.
    pub fn from_metadata_xml_with_policy(
        expected_entity_id: EntityId,
        xml: &str,
        trust: MetadataTrustPolicy<'_>,
        xml_policy: &crate::XmlPolicy,
    ) -> Result<Self, SamlError> {
        let metadata = SpMetadata::from_xml_with_policy(xml, xml_policy)?;
        let imported = ImportedMetadata::check(expected_entity_id, metadata.as_metadata(), trust)?;
        Ok(Self {
            imported,
            provider: sp::Engine::from_parsed_metadata(metadata, EntitySetting::default()),
        })
    }

    /// Metadata entity ID.
    pub fn entity_id(&self) -> &EntityId {
        &self.imported.entity_id
    }

    /// Original metadata XML.
    pub fn metadata_xml(&self) -> &str {
        self.raw_metadata().metadata_xml()
    }

    /// Name identifier formats advertised by this peer's SAML 2.0 role, in document order.
    pub fn name_id_formats(&self) -> Vec<NameIdFormat> {
        self.raw_metadata().name_id_formats()
    }

    /// Entity-level organization in the imported metadata.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] for multiple organizations or a localized
    /// value without `xml:lang`.
    pub fn organization(&self) -> Result<Option<crate::metadata::Organization>, SamlError> {
        self.raw_metadata().organization()
    }

    /// Entity-level contacts in document order.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] for a missing or unknown `contactType`.
    pub fn contacts(&self) -> Result<Vec<crate::metadata::ContactPerson>, SamlError> {
        self.raw_metadata().contacts()
    }

    /// First non-empty logout request location for this peer's SAML 2.0 role and binding.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the selected location is not an absolute HTTP(S) URL.
    pub fn single_logout_location(
        &self,
        binding: LogoutBinding,
    ) -> Result<Option<EndpointUrl>, SamlError> {
        single_logout_location(self.raw_metadata(), binding)
    }

    /// First logout response location, falling back to the endpoint's request location.
    ///
    /// For SOAP this reports the published location; a SOAP response returns on
    /// the request's HTTP exchange and is not sent to that URL.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the selected location is not an absolute HTTP(S) URL.
    pub fn single_logout_response_location(
        &self,
        binding: LogoutBinding,
    ) -> Result<Option<EndpointUrl>, SamlError> {
        single_logout_response_location(self.raw_metadata(), binding)
    }

    /// Default assertion consumer location for this peer's SAML 2.0 SP role and binding.
    ///
    /// Uses the metadata's indexed endpoint default selection.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the selected location is not an absolute HTTP(S) URL.
    pub fn assertion_consumer_location(
        &self,
        binding: SsoResponseBinding,
    ) -> Result<Option<EndpointUrl>, SamlError> {
        endpoint_location(
            self.provider
                .metadata
                .assertion_consumer_location(binding.into()),
            "AssertionConsumerService",
            binding.into(),
        )
    }

    /// Verify this service provider's HMAC signatures with `secret`.
    ///
    /// Use it when the peer signs with [`crate::SignatureAlgorithm::HmacSha1`].
    /// Its metadata certificates still verify its other signatures.
    pub fn with_hmac_secret(mut self, secret: HmacSecret) -> Self {
        self.provider.setting.hmac_secret = Some(secret);
        self
    }

    /// Signed metadata root when the metadata signature verified with a
    /// caller-pinned certificate, including a covering `<EntitiesDescriptor>`.
    ///
    /// `None` under [`MetadataTrustPolicy::AllowUnsigned`], even when the
    /// document carries a signature. It reports verification at import and
    /// does not check metadata expiration.
    pub fn signed_metadata_xml(&self) -> Option<&str> {
        self.imported.signed_metadata_xml()
    }

    /// Parsed SP metadata.
    pub(crate) fn metadata(&self) -> &SpMetadata {
        &self.provider.metadata
    }

    pub(crate) fn ensure_valid_at(&self, now: SystemTime) -> Result<(), SamlError> {
        self.imported.validity.ensure_valid_at(now)
    }

    pub(crate) fn provider(&self) -> &sp::Engine {
        &self.provider
    }

    fn raw_metadata(&self) -> &Metadata {
        self.provider.metadata.as_metadata()
    }
}

fn single_logout_location(
    metadata: &Metadata,
    binding: LogoutBinding,
) -> Result<Option<EndpointUrl>, SamlError> {
    endpoint_location(
        metadata.single_logout_location(binding.into()),
        "SingleLogoutService",
        binding.into(),
    )
}

fn single_logout_response_location(
    metadata: &Metadata,
    binding: LogoutBinding,
) -> Result<Option<EndpointUrl>, SamlError> {
    endpoint_location(
        metadata.single_logout_response_location(binding.into()),
        "SingleLogoutService",
        binding.into(),
    )
}

fn endpoint_location(
    location: Option<String>,
    element: &str,
    binding: crate::constants::Binding,
) -> Result<Option<EndpointUrl>, SamlError> {
    location
        .map(EndpointUrl::try_new)
        .transpose()
        .map_err(|error| {
            if let SamlError::Invalid(detail) = error {
                SamlError::Invalid(format!(
                    "{element} location for binding {}: {detail}",
                    binding.urn()
                ))
            } else {
                error
            }
        })
}
