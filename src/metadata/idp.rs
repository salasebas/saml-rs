//! Identity Provider metadata.

use super::{as_object_list, Metadata};
use crate::constants::{Binding, SOAP_BINDING_URN};
use crate::error::SamlError;
use crate::util::Value;
use crate::xml::{ExtractorField, XmlLimits};
use std::ops::Deref;

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
        self.binding == SOAP_BINDING_URN
    }
}

/// Parsed IdP metadata. Derefs to [`Metadata`] for the shared accessors.
#[derive(Debug, Clone)]
pub struct IdpMetadata {
    inner: Metadata,
}

impl IdpMetadata {
    /// Parse IdP metadata XML.
    ///
    /// Keys, flags, and endpoints are read from the entity's `IDPSSODescriptor`
    /// elements in the SAML metadata namespace whose
    /// `protocolSupportEnumeration` lists `urn:oasis:names:tc:SAML:2.0:protocol`.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::MissingMetadata`] when the entity has no such
    /// `IDPSSODescriptor`, and [`SamlError`] when XML parsing, parser resource
    /// limits, or IdP-specific metadata extraction fails.
    pub fn from_xml(xml: &str) -> Result<Self, SamlError> {
        Self::from_xml_with_limits(xml, XmlLimits::default())
    }

    /// Parse IdP metadata XML with explicit XML parser resource limits.
    ///
    /// Keys, flags, and endpoints are read from the entity's `IDPSSODescriptor`
    /// elements in the SAML metadata namespace whose
    /// `protocolSupportEnumeration` lists `urn:oasis:names:tc:SAML:2.0:protocol`.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::MissingMetadata`] when the entity has no such
    /// `IDPSSODescriptor`, and [`SamlError`] when XML parsing, parser resource
    /// limits, or IdP-specific metadata extraction fails.
    pub fn from_xml_with_limits(xml: &str, limits: XmlLimits) -> Result<Self, SamlError> {
        let extra = vec![
            ExtractorField::new(
                "wantAuthnRequestsSigned",
                &["EntityDescriptor", "IDPSSODescriptor"],
            )
            .attrs(&["WantAuthnRequestsSigned"]),
            ExtractorField::new(
                "singleSignOnService",
                &[
                    "EntityDescriptor",
                    "IDPSSODescriptor",
                    "SingleSignOnService",
                ],
            )
            .attrs(&["Binding", "Location"]),
            ExtractorField::new(
                "artifactResolutionService",
                &[
                    "EntityDescriptor",
                    "IDPSSODescriptor",
                    "ArtifactResolutionService",
                ],
            )
            .attrs(&["Binding", "Location", "index"]),
            ExtractorField::new(
                "manageNameIDService",
                &[
                    "EntityDescriptor",
                    "IDPSSODescriptor",
                    "ManageNameIDService",
                ],
            )
            .attrs(&["Binding", "Location", "ResponseLocation"]),
        ];
        Ok(Self {
            inner: Metadata::parse_role_with_limits(
                xml,
                super::SsoDescriptorRole::IdentityProvider,
                extra,
                limits,
            )?,
        })
    }

    /// `WantAuthnRequestsSigned` flag.
    ///
    /// `true` and `1` are true. An absent attribute or another value is false.
    pub fn is_want_authn_requests_signed(&self) -> bool {
        crate::xml::xs_boolean(self.inner.meta.get_str("wantAuthnRequestsSigned")) == Some(true)
    }

    /// First non-empty `SingleSignOnService` `Location` for `binding`.
    ///
    /// AuthnRequests are sent to this URL.
    pub fn get_single_sign_on_service(&self, binding: Binding) -> Option<String> {
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

impl Deref for IdpMetadata {
    type Target = Metadata;
    fn deref(&self) -> &Metadata {
        &self.inner
    }
}
