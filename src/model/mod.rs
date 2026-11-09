//! Typed SAML domain models built from validated raw flow results.
//!
//! References: SAML Core 2.0 <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf> and SAML Profiles 2.0 <https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf>.

mod attributes;
mod authn;
mod endpoint;
mod extract;
mod identifiers;
mod logout;
mod outstanding_logout;
mod received;
mod relay;
mod session;
mod sso;
mod status;
mod subject;
mod validation;

pub(crate) use extract::{authn_statement_not_on_or_after_values, name_id_format_from_uri};
pub(crate) use session::earliest_authn_session_expiration;
pub(crate) use subject::{validate_issued_name_id_length, validate_name_id_format};

pub use attributes::{Attribute, AttributeNameFormat, AttributeValue, Attributes};
pub use authn::{AuthnRequest, ForceAuthn, IsPassive};
pub use endpoint::EndpointUrl;
pub use identifiers::{AssertionId, MessageId, SamlInstant, SessionIndex};
pub use logout::{LogoutCompleted, LogoutRequest, LogoutResponse, LogoutSubject};
pub use outstanding_logout::OutstandingLogout;
pub use received::Received;
pub use relay::{RelayState, RelayStateParam, MAX_RELAY_STATE_BYTES};
pub use session::AuthnSession;
pub use sso::{
    Assertion, SsoResponse, SsoSession, VerifiedXmlSignature, VerifiedXmlSignatureCoverage,
};
pub use status::{Status, SubordinateStatusCode, TopLevelStatusCode};
pub use subject::{
    NameId, NameIdCreationRequest, NameIdPolicy, RequestedSubject, RequestedSubjectIdentifier,
    Subject, SubjectConfirmation,
};
pub use validation::{
    AuthnRequestAgePolicy, ClockSkew, ReplayCache, ReplayKey, ReplayPolicy, SamlValidationContext,
};
