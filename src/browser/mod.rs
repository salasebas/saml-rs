//! Typed browser binding, endpoint, outbound, inbound, and pending-state APIs.
//!
//! References: SAML Bindings 2.0 <https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf> and SAML Profiles 2.0 <https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf>.

mod artifact;
mod bindings;
mod endpoints;
mod forms;
mod input;
mod outbound;
mod pending;

pub use crate::model::EndpointUrl;
pub use artifact::{ArtifactDelivery, DeliveredArtifact};
pub use bindings::{LogoutBinding, SsoRequestBinding, SsoResponseBinding};
pub use endpoints::{AcsEndpoint, SloEndpoint, SsoEndpoint};
pub use forms::{FormField, PostForm};
pub use input::BrowserInput;
pub use outbound::Outbound;
pub use pending::{Pending, PendingAuthnRequest, PendingLogoutRequest, PendingSnapshot, Started};
