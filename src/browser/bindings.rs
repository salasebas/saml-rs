//! Browser binding enum wrappers.
//!
//! References: SAML Bindings 2.0 <https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf>.

use crate::constants::Binding;
use crate::error::SamlError;

/// Browser SSO request bindings supported by the typed API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SsoRequestBinding {
    /// HTTP-Redirect binding.
    Redirect,
    /// HTTP-POST binding.
    Post,
    /// HTTP-POST-SimpleSign binding.
    SimpleSign,
}

impl From<SsoRequestBinding> for Binding {
    fn from(value: SsoRequestBinding) -> Self {
        match value {
            SsoRequestBinding::Redirect => Binding::Redirect,
            SsoRequestBinding::Post => Binding::Post,
            SsoRequestBinding::SimpleSign => Binding::SimpleSign,
        }
    }
}

impl TryFrom<Binding> for SsoRequestBinding {
    type Error = SamlError;

    fn try_from(value: Binding) -> Result<Self, Self::Error> {
        match value {
            Binding::Redirect => Ok(Self::Redirect),
            Binding::Post => Ok(Self::Post),
            Binding::SimpleSign => Ok(Self::SimpleSign),
            binding @ (Binding::Artifact | Binding::Soap) => {
                Err(SamlError::UnsupportedBinding { binding })
            }
        }
    }
}

/// Browser SSO response bindings supported by the typed API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SsoResponseBinding {
    /// HTTP-POST binding.
    Post,
    /// HTTP-POST-SimpleSign binding.
    SimpleSign,
    /// HTTP-Artifact binding. The response is resolved over SOAP.
    Artifact,
}

impl From<SsoResponseBinding> for Binding {
    fn from(value: SsoResponseBinding) -> Self {
        match value {
            SsoResponseBinding::Post => Binding::Post,
            SsoResponseBinding::SimpleSign => Binding::SimpleSign,
            SsoResponseBinding::Artifact => Binding::Artifact,
        }
    }
}

impl TryFrom<Binding> for SsoResponseBinding {
    type Error = SamlError;

    fn try_from(value: Binding) -> Result<Self, Self::Error> {
        match value {
            Binding::Post => Ok(Self::Post),
            Binding::SimpleSign => Ok(Self::SimpleSign),
            Binding::Artifact => Ok(Self::Artifact),
            binding @ (Binding::Redirect | Binding::Soap) => {
                Err(SamlError::UnsupportedBinding { binding })
            }
        }
    }
}

/// Single Logout bindings supported by the typed API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LogoutBinding {
    /// HTTP-Redirect binding.
    Redirect,
    /// HTTP-POST binding.
    Post,
    /// HTTP-POST-SimpleSign binding.
    SimpleSign,
    /// SOAP binding. The request and its response are one synchronous SOAP
    /// exchange that the deployment sends. Generated messages carry an XML
    /// signature and no RelayState.
    Soap,
}

impl From<LogoutBinding> for Binding {
    fn from(value: LogoutBinding) -> Self {
        match value {
            LogoutBinding::Redirect => Binding::Redirect,
            LogoutBinding::Post => Binding::Post,
            LogoutBinding::SimpleSign => Binding::SimpleSign,
            LogoutBinding::Soap => Binding::Soap,
        }
    }
}

impl TryFrom<Binding> for LogoutBinding {
    type Error = SamlError;

    fn try_from(value: Binding) -> Result<Self, Self::Error> {
        match value {
            Binding::Redirect => Ok(Self::Redirect),
            Binding::Post => Ok(Self::Post),
            Binding::SimpleSign => Ok(Self::SimpleSign),
            Binding::Soap => Ok(Self::Soap),
            Binding::Artifact => Err(SamlError::UnsupportedBinding {
                binding: Binding::Artifact,
            }),
        }
    }
}

/// Name identifier management bindings supported by the typed API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NameIdManagementBinding {
    /// HTTP-Redirect binding, for the identity provider and the service
    /// provider.
    Redirect,
    /// SOAP binding, for the identity provider only.
    Soap,
}

impl From<NameIdManagementBinding> for Binding {
    fn from(value: NameIdManagementBinding) -> Self {
        match value {
            NameIdManagementBinding::Redirect => Binding::Redirect,
            NameIdManagementBinding::Soap => Binding::Soap,
        }
    }
}

impl TryFrom<Binding> for NameIdManagementBinding {
    type Error = SamlError;

    fn try_from(value: Binding) -> Result<Self, Self::Error> {
        match value {
            Binding::Redirect => Ok(Self::Redirect),
            Binding::Soap => Ok(Self::Soap),
            binding @ (Binding::Post | Binding::SimpleSign | Binding::Artifact) => {
                Err(SamlError::UnsupportedBinding { binding })
            }
        }
    }
}
