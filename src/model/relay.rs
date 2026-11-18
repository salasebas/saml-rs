use crate::error::{ResourceLimit, SamlError};

/// SAML Bindings 2.0 prohibits a RelayState value longer than 80 bytes.
///
/// Bindings §3.4.3, §3.5.3, and HTTP-POST-SimpleSign CD-04 §2.3.
/// Reference: <https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf>.
pub const MAX_RELAY_STATE_BYTES: usize = 80;

/// Longest RelayState a typed receive path accepts from a peer.
///
/// A received value up to this length is kept and returned unchanged in the
/// response to it. A longer received value returns
/// [`SamlError::LimitExceeded`] with [`ResourceLimit::RelayStateBytes`].
pub const MAX_RECEIVED_RELAY_STATE_BYTES: usize = 4096;

/// RelayState value of a browser message.
///
/// The typed API takes and returns `Option<RelayState>`: `None` is a message
/// without a `RelayState` parameter, and an empty value is a `RelayState`
/// parameter sent with no value. The two stay distinct when a value is
/// compared or returned to its sender.
///
/// A value built with [`Self::try_new`] is at most [`MAX_RELAY_STATE_BYTES`].
/// A value received from a peer is at most [`MAX_RECEIVED_RELAY_STATE_BYTES`].
/// An operation that sends a value set by the caller rejects one longer than
/// [`MAX_RELAY_STATE_BYTES`], including a received value passed back in.
///
/// # Examples
///
/// ```
/// use saml_rs::RelayState;
///
/// let relay_state = RelayState::try_new("return-to-cart")?;
/// assert_eq!(relay_state.as_str(), "return-to-cart");
///
/// assert!(RelayState::try_new("x".repeat(81)).is_err());
/// # Ok::<(), saml_rs::SamlError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayState(String);

impl RelayState {
    /// Wrap a RelayState value this side sends.
    ///
    /// An empty value sends the `RelayState` parameter with no value.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the UTF-8 byte length exceeds
    /// [`MAX_RELAY_STATE_BYTES`].
    pub fn try_new(value: impl Into<String>) -> Result<Self, SamlError> {
        let relay_state = Self(value.into());
        relay_state.ensure_sendable()?;
        Ok(relay_state)
    }

    pub(crate) fn received(value: String) -> Result<Self, SamlError> {
        if value.len() > MAX_RECEIVED_RELAY_STATE_BYTES {
            return Err(SamlError::LimitExceeded {
                limit: ResourceLimit::RelayStateBytes,
                maximum: MAX_RECEIVED_RELAY_STATE_BYTES,
            });
        }
        Ok(Self(value))
    }

    pub(crate) fn ensure_sendable(&self) -> Result<(), SamlError> {
        if self.0.len() > MAX_RELAY_STATE_BYTES {
            return Err(SamlError::Invalid(
                "RelayState exceeds SAML Bindings 80-byte limit".into(),
            ));
        }
        Ok(())
    }

    /// Borrow the RelayState string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
