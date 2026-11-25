use std::sync::Arc;

use super::{as_object_list, Metadata};
use crate::constants::Binding;
use crate::error::SamlError;
use crate::util::Value;
use crate::xml::protocol_element::SamlElement;
use crate::xml::XmlLimits;

/// One `ArtifactResolutionService` endpoint read from IdP metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactResolutionServiceEndpoint {
    index: u16,
    binding: String,
    location: String,
}

impl ArtifactResolutionServiceEndpoint {
    /// Metadata `index`.
    pub fn index(&self) -> u16 {
        self.index
    }

    /// Binding URI. Artifact resolution uses the SOAP binding.
    pub fn binding(&self) -> &str {
        &self.binding
    }

    /// Endpoint location.
    pub fn location(&self) -> &str {
        &self.location
    }

    /// Whether this endpoint's binding is the SAML SOAP binding.
    pub fn is_soap(&self) -> bool {
        self.binding == Binding::Soap.urn()
    }
}

/// Parsed IdP metadata. Use [`Self::as_metadata`] for role-scoped shared fields.
#[derive(Debug, Clone)]
pub struct IdpMetadata {
    inner: Metadata,
    artifact_resolution_roles: Vec<Value>,
}

impl IdpMetadata {
    /// Scope declarations on the entity and its selected SAML 2.0 IdP roles,
    /// entity first, then role declarations in document order.
    ///
    /// These declarations carry no scope authorization by themselves.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] for nested elements or an invalid or
    /// qualified `regexp` attribute.
    pub fn scopes(&self) -> Result<Vec<super::MetadataScope>, SamlError> {
        super::scope::read_scopes(&self.inner.scope_elements)
    }

    /// Borrow shared metadata fields selected from this SAML 2.0 role.
    pub fn as_metadata(&self) -> &Metadata {
        &self.inner
    }

    /// Parse IdP metadata XML with the default XML limits and no schema
    /// validator.
    ///
    /// Keys, flags, and endpoints are read from the entity's `IDPSSODescriptor`
    /// elements in the SAML metadata namespace whose
    /// `protocolSupportEnumeration` lists `urn:oasis:names:tc:SAML:2.0:protocol`.
    /// Endpoints are the children of those descriptors in the SAML metadata
    /// namespace. A child with the same local name in another namespace is
    /// not an endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::MissingMetadata`] when the entity has no such
    /// `IDPSSODescriptor`. Returns [`SamlError::Invalid`] when a signing flag
    /// on a selected descriptor has an invalid `xs:boolean` value or uses the
    /// SAML metadata namespace. XML parsing, resource limits, and IdP-specific
    /// metadata extraction can also fail.
    pub fn from_xml(xml: &str) -> Result<Self, SamlError> {
        Self::from_xml_with_policy(xml, &crate::XmlPolicy::default())
    }

    /// Parse IdP metadata XML as [`Self::from_xml`] does, with the XML limits
    /// and optional schema validator of `policy`.
    ///
    /// # Errors
    ///
    /// Returns the errors from [`Self::from_xml`] and any schema validation
    /// error from `policy`.
    pub fn from_xml_with_policy(xml: &str, policy: &crate::XmlPolicy) -> Result<Self, SamlError> {
        let (inner, roles) = Metadata::parse_role_with_policy(
            xml,
            super::SsoDescriptorRole::IdentityProvider,
            policy,
        )?;
        Ok(Self::from_roles(inner, &roles))
    }

    pub(crate) fn from_aggregate_entity(
        xml: &Arc<str>,
        path: &[&SamlElement],
        limits: XmlLimits,
    ) -> Result<Self, SamlError> {
        let (inner, roles) = Metadata::from_aggregate_entity(
            xml,
            path,
            super::SsoDescriptorRole::IdentityProvider,
            limits,
        )?;
        Ok(Self::from_roles(inner, &roles))
    }

    fn from_roles(mut inner: Metadata, roles: &[SamlElement]) -> Self {
        let artifact_resolution_roles = roles
            .iter()
            .map(|role| {
                super::endpoints::role_endpoints(
                    role,
                    "ArtifactResolutionService",
                    &["Binding", "Location", "index"],
                )
            })
            .collect();
        inner.meta.insert(
            "singleSignOnService",
            super::endpoints::roles_endpoints(
                roles,
                "SingleSignOnService",
                &["Binding", "Location"],
            ),
        );
        inner.meta.insert(
            "manageNameIDService",
            super::endpoints::roles_endpoints(
                roles,
                "ManageNameIDService",
                &["Binding", "Location", "ResponseLocation"],
            ),
        );
        Self {
            inner,
            artifact_resolution_roles,
        }
    }

    /// `WantAuthnRequestsSigned` flag.
    ///
    /// True when the first SAML 2.0 `IDPSSODescriptor` that specifies the
    /// attribute sets it to `true` or `1`. An absent attribute is false.
    pub fn want_authn_requests_signed(&self) -> bool {
        self.inner
            .signing_flags
            .want_authn_requests_signed
            .unwrap_or_default()
    }

    /// First non-empty `SingleSignOnService` `Location` for `binding`.
    ///
    /// AuthnRequests are sent to this URL.
    pub fn single_sign_on_location(&self, binding: Binding) -> Option<String> {
        super::first_published_location(
            self.inner.meta.get("singleSignOnService"),
            binding,
            super::EndpointDirection::Request,
        )
    }

    pub(crate) fn single_sign_on_service_locations(&self, binding: Binding) -> Vec<String> {
        super::published_locations_for_binding(
            self.inner.meta.get("singleSignOnService"),
            binding,
            super::EndpointDirection::Request,
        )
    }

    /// `ArtifactResolutionService` endpoints of every selected
    /// `IDPSSODescriptor`, in document order.
    ///
    /// Each `index` is unique within its `IDPSSODescriptor`. An entity with
    /// several SAML 2.0 IdP roles can publish the same `index` in more than
    /// one of them.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when an endpoint is missing `Binding`,
    /// `Location`, or `index`, when `index` is not a 16-bit integer, or when
    /// two endpoints of one `IDPSSODescriptor` share an `index`.
    pub fn artifact_resolution_services(
        &self,
    ) -> Result<Vec<ArtifactResolutionServiceEndpoint>, SamlError> {
        Ok(self
            .artifact_resolution_roles()?
            .into_iter()
            .flatten()
            .collect())
    }

    /// The `ArtifactResolutionService` at `index`, looked up in each selected
    /// `IDPSSODescriptor`.
    ///
    /// Returns `None` when no selected role publishes `index`.
    ///
    /// # Errors
    ///
    /// Returns the errors from [`Self::artifact_resolution_services`]. Also
    /// returns [`SamlError::Invalid`] when more than one selected
    /// `IDPSSODescriptor` publishes `index`.
    pub fn artifact_resolution_service(
        &self,
        index: u16,
    ) -> Result<Option<ArtifactResolutionServiceEndpoint>, SamlError> {
        let mut published = self
            .artifact_resolution_roles()?
            .into_iter()
            .filter_map(|role| role.into_iter().find(|service| service.index == index));
        let service = published.next();
        if published.next().is_some() {
            return Err(SamlError::Invalid(format!(
                "ArtifactResolutionService index {index} is published by more than one IDPSSODescriptor"
            )));
        }
        Ok(service)
    }

    fn artifact_resolution_roles(
        &self,
    ) -> Result<Vec<Vec<ArtifactResolutionServiceEndpoint>>, SamlError> {
        self.artifact_resolution_roles
            .iter()
            .map(role_artifact_resolution_endpoints)
            .collect()
    }
}

fn role_artifact_resolution_endpoints(
    services: &Value,
) -> Result<Vec<ArtifactResolutionServiceEndpoint>, SamlError> {
    let mut endpoints = Vec::new();
    for value in as_object_list(services) {
        let endpoint = artifact_resolution_service_from_value(value)?;
        if endpoints
            .iter()
            .any(|existing: &ArtifactResolutionServiceEndpoint| existing.index == endpoint.index)
        {
            return Err(SamlError::Invalid(format!(
                "duplicate ArtifactResolutionService index {}",
                endpoint.index
            )));
        }
        endpoints.push(endpoint);
    }
    Ok(endpoints)
}

fn artifact_resolution_service_from_value(
    value: &Value,
) -> Result<ArtifactResolutionServiceEndpoint, SamlError> {
    let binding = required_artifact_attribute(value, "Binding")?;
    let location = required_artifact_attribute(value, "Location")?;
    let index_text = required_artifact_attribute(value, "index")?;
    let index = index_text.parse::<u16>().map_err(|_| {
        SamlError::Invalid(format!(
            "ArtifactResolutionService index is not a 16-bit integer: {index_text}"
        ))
    })?;
    Ok(ArtifactResolutionServiceEndpoint {
        index,
        binding,
        location,
    })
}

fn required_artifact_attribute(value: &Value, name: &str) -> Result<String, SamlError> {
    value
        .get_str(&name.to_ascii_lowercase())
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .ok_or_else(|| SamlError::Invalid(format!("ArtifactResolutionService is missing {name}")))
}
