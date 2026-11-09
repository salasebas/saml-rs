//! Browser binding enum wrappers.
//!
//! References: SAML Bindings 2.0 <https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf>.

use crate::constants::Binding;
use crate::error::SamlError;

/// Browser SSO request bindings supported by the typed API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SsoRequestBinding {
    /// HTTP-Redirect binding.
    Redirect,
    /// HTTP-POST binding.
    Post,
    /// HTTP-POST-SimpleSign binding.
    SimpleSign,
}

impl SsoRequestBinding {
    /// Convert to the raw compatibility binding.
    pub fn as_binding(self) -> Binding {
        match self {
            Self::Redirect => Binding::Redirect,
            Self::Post => Binding::Post,
            Self::SimpleSign => Binding::SimpleSign,
        }
    }
}

impl From<SsoRequestBinding> for Binding {
    fn from(value: SsoRequestBinding) -> Self {
        value.as_binding()
    }
}

impl TryFrom<Binding> for SsoRequestBinding {
    type Error = SamlError;

    fn try_from(value: Binding) -> Result<Self, Self::Error> {
        match value {
            Binding::Redirect => Ok(Self::Redirect),
            Binding::Post => Ok(Self::Post),
            Binding::SimpleSign => Ok(Self::SimpleSign),
            Binding::Artifact | Binding::Soap => Err(SamlError::UndefinedBinding),
        }
    }
}

/// Browser SSO response bindings supported by the typed API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SsoResponseBinding {
    /// HTTP-POST binding.
    Post,
    /// HTTP-POST-SimpleSign binding.
    SimpleSign,
    /// HTTP-Artifact binding. The response is resolved over SOAP.
    Artifact,
}

impl SsoResponseBinding {
    /// Convert to the raw compatibility binding.
    pub fn as_binding(self) -> Binding {
        match self {
            Self::Post => Binding::Post,
            Self::SimpleSign => Binding::SimpleSign,
            Self::Artifact => Binding::Artifact,
        }
    }
}

impl From<SsoResponseBinding> for Binding {
    fn from(value: SsoResponseBinding) -> Self {
        value.as_binding()
    }
}

impl TryFrom<Binding> for SsoResponseBinding {
    type Error = SamlError;

    fn try_from(value: Binding) -> Result<Self, Self::Error> {
        match value {
            Binding::Post => Ok(Self::Post),
            Binding::SimpleSign => Ok(Self::SimpleSign),
            Binding::Artifact => Ok(Self::Artifact),
            Binding::Redirect | Binding::Soap => Err(SamlError::UndefinedBinding),
        }
    }
}

/// Single Logout bindings supported by the typed API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogoutBinding {
    /// HTTP-Redirect binding.
    Redirect,
    /// HTTP-POST binding.
    Post,
    /// HTTP-POST-SimpleSign binding.
    SimpleSign,
    /// SOAP binding. The request and its response are one synchronous SOAP
    /// exchange that the deployment sends. Each message carries an XML
    /// signature and no RelayState.
    Soap,
}

impl LogoutBinding {
    /// Convert to the raw compatibility binding.
    pub fn as_binding(self) -> Binding {
        match self {
            Self::Redirect => Binding::Redirect,
            Self::Post => Binding::Post,
            Self::SimpleSign => Binding::SimpleSign,
            Self::Soap => Binding::Soap,
        }
    }
}

impl From<LogoutBinding> for Binding {
    fn from(value: LogoutBinding) -> Self {
        value.as_binding()
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
            Binding::Artifact => Err(SamlError::UndefinedBinding),
        }
    }
}
