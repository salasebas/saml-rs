use crate::error::SamlError;

/// SAML Bindings 2.0 prohibits a RelayState value longer than 80 bytes.
///
/// Bindings §3.4.3, §3.5.3, and HTTP-POST-SimpleSign CD-04 §2.3.
/// Reference: <https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf>.
pub const MAX_RELAY_STATE_BYTES: usize = 80;

/// Longest RelayState a typed receive path accepts from a peer.
///
/// A received value up to this length is kept and returned unchanged in the
/// response to it. A longer received value returns [`SamlError::Invalid`].
pub const MAX_RECEIVED_RELAY_STATE_BYTES: usize = 4096;

/// RelayState value when a browser message carries the parameter.
///
/// A value built with [`Self::try_new`] is at most [`MAX_RELAY_STATE_BYTES`].
/// A value received from a peer is at most [`MAX_RECEIVED_RELAY_STATE_BYTES`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayState(String);

impl RelayState {
    /// Wrap a RelayState value after enforcing the SAML Bindings byte limit.
    ///
    /// Explicit empty RelayState is allowed so callers can preserve browser
    /// parameter presence separately from absence.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the UTF-8 byte length exceeds
    /// [`MAX_RELAY_STATE_BYTES`].
    pub fn try_new(value: impl Into<String>) -> Result<Self, SamlError> {
        let value = value.into();
        validate_relay_state_bytes(&value)?;
        Ok(Self(value))
    }

    pub(crate) fn received(value: String) -> Result<Self, SamlError> {
        if value.len() > MAX_RECEIVED_RELAY_STATE_BYTES {
            return Err(SamlError::Invalid(format!(
                "received RelayState exceeds the {MAX_RECEIVED_RELAY_STATE_BYTES}-byte receive limit"
            )));
        }
        Ok(Self(value))
    }

    /// Borrow the RelayState string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// RelayState represented as absent, present empty, or present with a value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RelayStateParam {
    /// No RelayState parameter was sent.
    Absent,
    /// RelayState was sent with an empty value.
    PresentEmpty,
    /// RelayState was sent with a non-empty value.
    PresentValue(RelayState),
}

impl RelayStateParam {
    /// Construct an absent RelayState parameter.
    pub fn absent() -> Self {
        Self::Absent
    }

    /// Construct a present RelayState parameter with an empty value.
    pub fn present_empty() -> Self {
        Self::PresentEmpty
    }

    /// Preserve the exact RelayState presence state from optional caller input.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when a present non-empty value exceeds
    /// the SAML Bindings 80-byte RelayState limit.
    pub fn try_from_option(value: Option<impl Into<String>>) -> Result<Self, SamlError> {
        Self::from_option(value.map(Into::into), RelayState::try_new)
    }

    pub(crate) fn received(value: Option<String>) -> Result<Self, SamlError> {
        Self::from_option(value, RelayState::received)
    }

    fn from_option(
        value: Option<String>,
        wrap: fn(String) -> Result<RelayState, SamlError>,
    ) -> Result<Self, SamlError> {
        match value {
            None => Ok(Self::Absent),
            Some(value) if value.is_empty() => Ok(Self::PresentEmpty),
            Some(value) => Ok(Self::PresentValue(wrap(value)?)),
        }
    }

    /// Borrow RelayState as an optional value.
    pub fn as_deref(&self) -> Option<&str> {
        match self {
            Self::Absent => None,
            Self::PresentEmpty => Some(""),
            Self::PresentValue(value) => Some(value.as_str()),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), SamlError> {
        self.validate_echoed()?;
        if let Some(value) = self.as_deref() {
            validate_relay_state_bytes(value)?;
        }
        Ok(())
    }

    pub(crate) fn validate_echoed(&self) -> Result<(), SamlError> {
        if matches!(self, Self::PresentValue(value) if value.as_str().is_empty()) {
            return Err(SamlError::Invalid(
                "RelayState PresentValue must not be empty".into(),
            ));
        }
        Ok(())
    }
}

impl TryFrom<Option<String>> for RelayStateParam {
    type Error = SamlError;

    fn try_from(value: Option<String>) -> Result<Self, Self::Error> {
        Self::try_from_option(value)
    }
}

fn validate_relay_state_bytes(value: &str) -> Result<(), SamlError> {
    if value.len() > MAX_RELAY_STATE_BYTES {
        return Err(SamlError::Invalid(
            "RelayState exceeds SAML Bindings 80-byte limit".into(),
        ));
    }
    Ok(())
}
