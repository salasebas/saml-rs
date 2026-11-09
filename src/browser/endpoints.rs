//! Browser endpoint wrappers for SAML metadata locations.
//!
//! References: SAML Metadata 2.0 <https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf>.

use super::bindings::{LogoutBinding, SsoRequestBinding, SsoResponseBinding};
use crate::error::SamlError;
use crate::metadata::Endpoint;
use crate::model::EndpointUrl;

/// Single Sign-On service endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsoEndpoint {
    binding: SsoRequestBinding,
    url: EndpointUrl,
}

impl SsoEndpoint {
    /// Create an SSO endpoint from an already validated URL.
    pub fn new(binding: SsoRequestBinding, url: EndpointUrl) -> Self {
        Self { binding, url }
    }

    /// Create an HTTP-Redirect SSO endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] if `url` fails [`EndpointUrl::try_new`]
    /// validation.
    pub fn redirect(url: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self::new(
            SsoRequestBinding::Redirect,
            EndpointUrl::try_new(url)?,
        ))
    }

    /// Create an HTTP-POST SSO endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] if `url` fails [`EndpointUrl::try_new`]
    /// validation.
    pub fn post(url: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self::new(
            SsoRequestBinding::Post,
            EndpointUrl::try_new(url)?,
        ))
    }

    /// Create an HTTP-POST-SimpleSign SSO endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] if `url` fails [`EndpointUrl::try_new`]
    /// validation.
    pub fn simple_sign(url: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self::new(
            SsoRequestBinding::SimpleSign,
            EndpointUrl::try_new(url)?,
        ))
    }

    /// Narrow a raw metadata endpoint into an SSO endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] if the raw binding is not valid for SSO requests
    /// or if the endpoint location fails [`EndpointUrl::try_new`] validation.
    pub fn try_from_raw(endpoint: Endpoint) -> Result<Self, SamlError> {
        Ok(Self::new(
            SsoRequestBinding::try_from(endpoint.binding)?,
            EndpointUrl::try_new(endpoint.location)?,
        ))
    }

    /// Convert to the raw metadata endpoint shape.
    pub fn to_raw(&self) -> Endpoint {
        Endpoint {
            binding: self.binding.as_binding(),
            location: self.url.as_str().to_string(),
            index: None,
            is_default: false,
        }
    }

    /// Endpoint binding.
    pub fn binding(&self) -> SsoRequestBinding {
        self.binding
    }

    /// Metadata endpoint location.
    pub fn location(&self) -> &EndpointUrl {
        &self.url
    }
}

/// Assertion Consumer Service endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcsEndpoint {
    binding: SsoResponseBinding,
    url: EndpointUrl,
    index: Option<u16>,
    is_default: bool,
}

impl AcsEndpoint {
    /// Create an ACS endpoint from an already validated URL.
    pub fn new(binding: SsoResponseBinding, url: EndpointUrl) -> Self {
        Self {
            binding,
            url,
            index: None,
            is_default: false,
        }
    }

    /// Create an HTTP-POST ACS endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] if `url` fails [`EndpointUrl::try_new`]
    /// validation.
    pub fn post(url: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self::new(
            SsoResponseBinding::Post,
            EndpointUrl::try_new(url)?,
        ))
    }

    /// Create an HTTP-POST-SimpleSign ACS endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] if `url` fails [`EndpointUrl::try_new`]
    /// validation.
    pub fn simple_sign(url: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self::new(
            SsoResponseBinding::SimpleSign,
            EndpointUrl::try_new(url)?,
        ))
    }

    /// Create an HTTP-Artifact ACS endpoint.
    ///
    /// The endpoint receives the artifact in a `SAMLart` query parameter on
    /// GET and in a `SAMLart` form field on POST.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] if `url` fails [`EndpointUrl::try_new`]
    /// validation.
    pub fn artifact(url: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self::new(
            SsoResponseBinding::Artifact,
            EndpointUrl::try_new(url)?,
        ))
    }

    /// Set the ACS index advertised in metadata.
    pub fn with_index(mut self, index: u16) -> Self {
        self.index = Some(index);
        self
    }

    /// Mark this ACS endpoint as the default endpoint in metadata.
    pub fn mark_default(mut self) -> Self {
        self.is_default = true;
        self
    }

    pub(crate) fn with_default_flag(mut self, is_default: bool) -> Self {
        self.is_default = is_default;
        self
    }

    /// Narrow a raw metadata endpoint into an ACS endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] if the raw binding is not valid for SSO responses
    /// or if the endpoint location fails [`EndpointUrl::try_new`] validation.
    pub fn try_from_raw(endpoint: Endpoint) -> Result<Self, SamlError> {
        Ok(Self {
            binding: SsoResponseBinding::try_from(endpoint.binding)?,
            url: EndpointUrl::try_new(endpoint.location)?,
            index: endpoint.index,
            is_default: endpoint.is_default,
        })
    }

    /// Convert to the raw metadata endpoint shape.
    pub fn to_raw(&self) -> Endpoint {
        Endpoint {
            binding: self.binding.as_binding(),
            location: self.url.as_str().to_string(),
            index: self.index,
            is_default: self.is_default,
        }
    }

    /// Endpoint binding.
    pub fn binding(&self) -> SsoResponseBinding {
        self.binding
    }

    /// Metadata endpoint location.
    pub fn location(&self) -> &EndpointUrl {
        &self.url
    }

    /// ACS index advertised in metadata.
    pub fn index(&self) -> Option<u16> {
        self.index
    }

    /// Whether this ACS endpoint is the default metadata endpoint.
    pub fn is_default(&self) -> bool {
        self.is_default
    }
}

/// Single Logout service endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SloEndpoint {
    binding: LogoutBinding,
    url: EndpointUrl,
}

impl SloEndpoint {
    /// Create an SLO endpoint from an already validated URL.
    pub fn new(binding: LogoutBinding, url: EndpointUrl) -> Self {
        Self { binding, url }
    }

    /// Create an HTTP-Redirect SLO endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] if `url` fails [`EndpointUrl::try_new`]
    /// validation.
    pub fn redirect(url: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self::new(
            LogoutBinding::Redirect,
            EndpointUrl::try_new(url)?,
        ))
    }

    /// Create an HTTP-POST SLO endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] if `url` fails [`EndpointUrl::try_new`]
    /// validation.
    pub fn post(url: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self::new(LogoutBinding::Post, EndpointUrl::try_new(url)?))
    }

    /// Create an HTTP-POST-SimpleSign SLO endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] if `url` fails [`EndpointUrl::try_new`]
    /// validation.
    pub fn simple_sign(url: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self::new(
            LogoutBinding::SimpleSign,
            EndpointUrl::try_new(url)?,
        ))
    }

    /// Narrow a raw metadata endpoint into an SLO endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] if the raw binding is not valid for logout or if
    /// the endpoint location fails [`EndpointUrl::try_new`] validation.
    pub fn try_from_raw(endpoint: Endpoint) -> Result<Self, SamlError> {
        Ok(Self::new(
            LogoutBinding::try_from(endpoint.binding)?,
            EndpointUrl::try_new(endpoint.location)?,
        ))
    }

    /// Convert to the raw metadata endpoint shape.
    pub fn to_raw(&self) -> Endpoint {
        Endpoint {
            binding: self.binding.as_binding(),
            location: self.url.as_str().to_string(),
            index: None,
            is_default: false,
        }
    }

    /// Endpoint binding.
    pub fn binding(&self) -> LogoutBinding {
        self.binding
    }

    /// Metadata endpoint location.
    pub fn location(&self) -> &EndpointUrl {
        &self.url
    }
}
