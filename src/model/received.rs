use super::RelayState;

/// Typed received message wrapper.
#[derive(Debug, Clone)]
pub struct Received<Message> {
    message: Message,
    relay_state: Option<RelayState>,
}

impl<Message> Received<Message> {
    pub(crate) fn new(message: Message, relay_state: Option<RelayState>) -> Self {
        Self {
            message,
            relay_state,
        }
    }

    /// Borrow the typed message.
    pub fn message(&self) -> &Message {
        &self.message
    }

    /// RelayState received with the browser message.
    pub fn relay_state(&self) -> Option<&RelayState> {
        self.relay_state.as_ref()
    }

    /// Consume the wrapper and return the typed message.
    pub fn into_message(self) -> Message {
        self.message
    }
}
