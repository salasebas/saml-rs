use crate::constants::status_code;
use crate::error::SamlError;

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
}

/// Optional second-level `StatusCode`.
///
/// [`Self::partial_logout`] is Core §3.7.3.2 `PartialLogout`. Other absolute
/// URIs go through [`Self::try_new`].
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

    /// Wrap an absolute status-code URI.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when `uri` is empty, has whitespace, is
    /// not absolute, or contains `&`, `"`, `'`, `<`, or `>`.
    pub fn try_new(uri: impl Into<String>) -> Result<Self, SamlError> {
        let uri = uri.into();
        if uri.is_empty()
            || uri.chars().any(char::is_whitespace)
            || uri
                .chars()
                .any(|character| matches!(character, '&' | '"' | '\'' | '<' | '>'))
            || url::Url::parse(&uri).is_err()
        {
            return Err(SamlError::Invalid(
                "subordinate status code must be a non-empty absolute URI without whitespace or XML attribute markup"
                    .into(),
            ));
        }
        Ok(Self { uri })
    }

    /// Absolute URI carried in the nested `StatusCode/@Value`.
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

    fn from_top_level(top_level: TopLevelStatusCode) -> Self {
        Self {
            top_level,
            subordinate: None,
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
