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
pub use bindings::{LogoutBinding, NameIdManagementBinding, SsoRequestBinding, SsoResponseBinding};
pub use endpoints::{AcsEndpoint, SloEndpoint, SsoEndpoint};
pub use forms::{FormField, PostForm};
pub(crate) use input::{field_value, parse_form_fields, Transport};
pub use input::{Inbound, PostMessage, RedirectMessage, SoapMessage};
pub use outbound::{Outbound, OutboundDelivery};
pub use pending::{
    Pending, PendingAuthnRequest, PendingAuthnRequestSnapshot, PendingLogoutRequest,
    PendingLogoutRequestSnapshot, PendingManageNameIdRequest, PendingManageNameIdRequestSnapshot,
    Started,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageField {
    Request,
    Response,
}

impl MessageField {
    fn param_name(self) -> &'static str {
        match self {
            Self::Request => crate::constants::url_params::SAML_REQUEST,
            Self::Response => crate::constants::url_params::SAML_RESPONSE,
        }
    }

    fn opposite_param_name(self) -> &'static str {
        match self {
            Self::Request => crate::constants::url_params::SAML_RESPONSE,
            Self::Response => crate::constants::url_params::SAML_REQUEST,
        }
    }
}
