use crate::constants::status_code;
use crate::error::SamlError;
use crate::xml::any_uri::{collapse_whitespace, is_absolute_uri_reference};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestVersionMismatch {
    SameMajor,
    NewerMajor,
}

impl RequestVersionMismatch {
    pub(crate) fn for_request(version: &str) -> Result<Option<Self>, SamlError> {
        if version == "2.0" {
            return Ok(None);
        }
        let malformed = || SamlError::ProtocolProfile("invalid request Version".into());
        let (major, minor) = version.split_once('.').ok_or_else(malformed)?;
        for part in [major, minor] {
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(malformed());
            }
        }
        match major.trim_start_matches('0') {
            "" | "1" => Err(SamlError::ProtocolProfile(
                "request Version is too low for a SAML 2.0 response".into(),
            )),
            "2" => Ok(Some(Self::SameMajor)),
            _ => Ok(Some(Self::NewerMajor)),
        }
    }

    pub(crate) fn status(self) -> Status {
        let status = Status::version_mismatch();
        match self {
            Self::SameMajor => status,
            Self::NewerMajor => status.with_subordinate(SubordinateStatusCode {
                uri: status_code::REQUEST_VERSION_TOO_HIGH.to_string(),
            }),
        }
    }
}

/// Top-level `StatusCode` value.
///
/// Core §3.2.2.2 allows only these four URIs. For logout, Core §3.7.3.2 says
/// it reports only the session authority's own session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TopLevelStatusCode {
    /// `urn:oasis:names:tc:SAML:2.0:status:Success`.
    Success,
    /// `urn:oasis:names:tc:SAML:2.0:status:Requester`.
    Requester,
    /// `urn:oasis:names:tc:SAML:2.0:status:Responder`.
    Responder,
    /// `urn:oasis:names:tc:SAML:2.0:status:VersionMismatch`.
    VersionMismatch,
}

impl TopLevelStatusCode {
    /// Absolute URI carried in `StatusCode/@Value`.
    pub fn as_uri(self) -> &'static str {
        match self {
            Self::Success => status_code::SUCCESS,
            Self::Requester => status_code::REQUESTER,
            Self::Responder => status_code::RESPONDER,
            Self::VersionMismatch => status_code::VERSION_MISMATCH,
        }
    }

    pub(crate) fn from_uri(uri: &str) -> Option<Self> {
        [
            Self::Success,
            Self::Requester,
            Self::Responder,
            Self::VersionMismatch,
        ]
        .into_iter()
        .find(|code| code.as_uri() == uri)
    }
}

/// Optional second-level `StatusCode`.
///
/// [`Self::partial_logout`] is Core §3.7.3.2 `PartialLogout`. Other absolute
/// URIs go through [`Self::try_new`]. A code read from a received response
/// holds the peer's `Value` with XML Schema `anyURI` whitespace collapsed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubordinateStatusCode {
    uri: String,
}

impl SubordinateStatusCode {
    /// `urn:oasis:names:tc:SAML:2.0:status:PartialLogout`.
    pub fn partial_logout() -> Self {
        Self {
            uri: status_code::PARTIAL_LOGOUT.to_string(),
        }
    }

    /// `urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal`.
    ///
    /// A name identifier management responder may answer with it when it does
    /// not recognize the identifier.
    pub fn unknown_principal() -> Self {
        Self {
            uri: status_code::UNKNOWN_PRINCIPAL.to_string(),
        }
    }

    /// `urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext`.
    ///
    /// An identity provider may answer with it under top-level `Responder`
    /// when it cannot meet a [`crate::RequestedAuthnContext`].
    pub fn no_authn_context() -> Self {
        Self {
            uri: status_code::NO_AUTHN_CONTEXT.to_string(),
        }
    }

    /// Wrap an absolute status-code URI.
    ///
    /// Pass the URI as written, including any literal `&` or `'`. The XML
    /// writer escapes the attribute value when it generates the response.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when `uri` has whitespace, contains
    /// `"`, `<`, or `>`, or is not an absolute URI reference.
    pub fn try_new(uri: impl Into<String>) -> Result<Self, SamlError> {
        let uri = uri.into();
        if uri.chars().any(char::is_whitespace)
            || uri.contains(['"', '<', '>'])
            || !is_absolute_uri_reference(&uri)
        {
            return Err(SamlError::Invalid(
                "subordinate status code must be an absolute URI without whitespace, double quotes, or angle brackets"
                    .into(),
            ));
        }
        Ok(Self { uri })
    }

    /// URI carried in the nested `StatusCode/@Value`.
    pub fn as_uri(&self) -> &str {
        &self.uri
    }
}

/// Top-level `StatusCode` and an optional subordinate code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    top_level: TopLevelStatusCode,
    subordinate: Option<SubordinateStatusCode>,
}

impl Status {
    /// Top-level `Success` and no subordinate code.
    pub fn success() -> Self {
        Self::from_top_level(TopLevelStatusCode::Success)
    }

    /// Top-level `Requester` and no subordinate code.
    pub fn requester() -> Self {
        Self::from_top_level(TopLevelStatusCode::Requester)
    }

    /// Top-level `Responder` and no subordinate code.
    pub fn responder() -> Self {
        Self::from_top_level(TopLevelStatusCode::Responder)
    }

    /// Top-level `VersionMismatch` and no subordinate code.
    pub fn version_mismatch() -> Self {
        Self::from_top_level(TopLevelStatusCode::VersionMismatch)
    }

    pub(crate) fn from_top_level(top_level: TopLevelStatusCode) -> Self {
        Self {
            top_level,
            subordinate: None,
        }
    }

    /// Status read from a received message.
    ///
    /// A subordinate value that collapses to an empty string is read as absent.
    pub(crate) fn received(top_level: &str, subordinate: Option<&str>) -> Result<Self, SamlError> {
        let uri = collapse_whitespace(top_level);
        if uri.is_empty() {
            return Err(SamlError::StatusMissing);
        }
        let top_level = TopLevelStatusCode::from_uri(&uri).ok_or_else(|| {
            SamlError::ProtocolProfile(format!(
                "top-level StatusCode {top_level} is not a SAML top-level status code"
            ))
        })?;
        Ok(Self {
            top_level,
            subordinate: subordinate
                .map(collapse_whitespace)
                .filter(|uri| !uri.is_empty())
                .map(|uri| SubordinateStatusCode { uri }),
        })
    }

    pub(crate) fn require_success(self) -> Result<(), SamlError> {
        match self.top_level {
            TopLevelStatusCode::Success => Ok(()),
            TopLevelStatusCode::Requester
            | TopLevelStatusCode::Responder
            | TopLevelStatusCode::VersionMismatch => {
                Err(SamlError::StatusNotSuccess { status: self })
            }
        }
    }

    /// Nest a subordinate `StatusCode` under the top-level code.
    ///
    /// A later call replaces the previous subordinate code.
    #[must_use]
    pub fn with_subordinate(mut self, subordinate: SubordinateStatusCode) -> Self {
        self.subordinate = Some(subordinate);
        self
    }

    /// Top-level status code.
    pub fn top_level(&self) -> TopLevelStatusCode {
        self.top_level
    }

    /// Subordinate status code, when one was supplied.
    pub fn subordinate(&self) -> Option<&SubordinateStatusCode> {
        self.subordinate.as_ref()
    }
}
