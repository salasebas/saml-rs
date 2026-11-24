//! Identity Provider metadata.

use super::{as_object_list, Metadata};
use crate::constants::Binding;
use crate::error::SamlError;
use crate::util::Value;
use crate::xml::ExtractorField;

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
        let extra = vec![
            ExtractorField::new(
                "singleSignOnService",
                &[
                    "EntityDescriptor",
                    "IDPSSODescriptor",
                    "SingleSignOnService",
                ],
            )
            .capture_source(),
            ExtractorField::new(
                "artifactResolutionService",
                &[
                    "EntityDescriptor",
                    "IDPSSODescriptor",
                    "ArtifactResolutionService",
                ],
            )
            .capture_source(),
            ExtractorField::new(
                "manageNameIDService",
                &[
                    "EntityDescriptor",
                    "IDPSSODescriptor",
                    "ManageNameIDService",
                ],
            )
            .capture_source(),
        ];
        let mut inner = Metadata::parse_role_with_policy(
            xml,
            super::SsoDescriptorRole::IdentityProvider,
            extra,
            policy,
        )?;
        super::endpoints::read_endpoints(
            &mut inner.meta,
            "singleSignOnService",
            &["Binding", "Location"],
        )?;
        super::endpoints::read_endpoints(
            &mut inner.meta,
            "artifactResolutionService",
            &["Binding", "Location", "index"],
        )?;
        super::endpoints::read_endpoints(
            &mut inner.meta,
            "manageNameIDService",
            &["Binding", "Location", "ResponseLocation"],
        )?;
        Ok(Self { inner })
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

    /// Every `Location` published on `SingleSignOnService` for `binding`.
    pub(crate) fn single_sign_on_service_locations(&self, binding: Binding) -> Vec<String> {
        super::published_locations_for_binding(
            self.inner.meta.get("singleSignOnService"),
            binding,
            super::EndpointDirection::Request,
        )
    }

    /// `ArtifactResolutionService` endpoints.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when an endpoint is missing `Binding`,
    /// `Location`, or `index`, when `index` is not a 16-bit integer, or when
    /// two endpoints share one `index`.
    pub fn artifact_resolution_services(
        &self,
    ) -> Result<Vec<ArtifactResolutionServiceEndpoint>, SamlError> {
        let Some(services) = self.inner.meta.get("artifactResolutionService") else {
            return Ok(Vec::new());
        };
        let mut endpoints = Vec::new();
        for value in as_object_list(services) {
            let endpoint = artifact_resolution_service_from_value(value)?;
            if endpoints
                .iter()
                .any(|existing: &ArtifactResolutionServiceEndpoint| {
                    existing.index == endpoint.index
                })
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
