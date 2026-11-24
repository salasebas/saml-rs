use super::RelayState;
use crate::constants::Binding;
use crate::flow::MessageAuthentication;

/// Typed received message wrapper.
#[derive(Debug, Clone)]
pub struct Received<Message> {
    message: Message,
    binding: Binding,
    relay_state: Option<RelayState>,
    authentication: MessageAuthentication,
}

impl<Message> Received<Message> {
    pub(crate) fn new(
        message: Message,
        binding: Binding,
        relay_state: Option<RelayState>,
        authentication: MessageAuthentication,
    ) -> Self {
        Self {
            message,
            binding,
            relay_state,
            authentication,
        }
    }

    pub(crate) fn binding(&self) -> Binding {
        self.binding
    }

    /// Borrow the typed message.
    pub fn message(&self) -> &Message {
        &self.message
    }

    /// RelayState received with the browser message.
    pub fn relay_state(&self) -> Option<&RelayState> {
        self.relay_state.as_ref()
    }

    /// Whether a verified signature or an attested SOAP channel authenticated
    /// the message.
    ///
    /// An `AuthnRequest` can be [`MessageAuthentication::Unauthenticated`]
    /// unless the identity provider requires signed requests. A received
    /// `LogoutRequest` or `ManageNameIDRequest` is always
    /// [`MessageAuthentication::Authenticated`], because receiving one
    /// requires it.
    pub fn authentication(&self) -> MessageAuthentication {
        self.authentication
    }

    /// Consume the wrapper and return the typed message.
    pub fn into_message(self) -> Message {
        self.message
    }
}
