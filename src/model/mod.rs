//! Typed SAML domain models built from validated messages.
//!
//! References: SAML Core 2.0 <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf> and SAML Profiles 2.0 <https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf>.

mod attributes;
mod audience_restriction;
mod authn;
mod authn_context;
mod authn_details;
mod authn_statement;
mod endpoint;
mod extension;
mod extract;
mod identifiers;
mod logout;
mod outstanding_logout;
mod received;
mod relay;
mod replay_cache;
mod sso;
mod status;
mod subject;
mod subject_identifier;
mod validation;

pub(crate) use authn_statement::earliest_authn_session_expiration;
pub(crate) use extract::authn_statement_not_on_or_after_values;
pub(crate) use subject::{
    is_name_id_format, validate_issued_name_id_length, validate_name_id_format,
};
pub(crate) use subject_identifier::{check_issued_subject_identifiers, is_subject_identifier};

pub use attributes::{Attribute, AttributeNameFormat, AttributeValue, Attributes};
pub use audience_restriction::AudienceRestriction;
pub use authn::{AuthnRequest, ForceAuthn, IsPassive};
pub use authn_context::{
    AuthnContextComparison, AuthnContextReference, AuthnContextReferenceKind, RequestedAuthnContext,
};
pub use authn_details::{AuthnContext, SubjectLocality};
pub use authn_statement::AuthnStatement;
pub use endpoint::EndpointUrl;
pub use extension::ExtensionElement;
pub use identifiers::{AssertionId, MessageId, SamlInstant, SessionIndex};
pub use logout::{
    LogoutCompleted, LogoutRequest, LogoutResponse, LogoutSubject, RefusedLogoutRequest,
};
pub use outstanding_logout::OutstandingLogout;
pub use received::Received;
pub use relay::{RelayState, MAX_RECEIVED_RELAY_STATE_BYTES, MAX_RELAY_STATE_BYTES};
pub use replay_cache::InMemoryReplayCache;
pub use sso::{SsoResponse, SsoSession, VerifiedXmlSignature, VerifiedXmlSignatureCoverage};
pub(crate) use status::RequestVersionMismatch;
pub use status::{Status, SubordinateStatusCode, TopLevelStatusCode};
pub use subject::{
    NameId, NameIdCreationRequest, NameIdPolicy, RequestedSubject, RequestedSubjectIdentifier,
    SubjectConfirmation,
};
pub use subject_identifier::{PairwiseId, SubjectId};
pub use validation::{
    ClockSkew, ReplayCache, ReplayKey, ReplayPolicy, RequestAgePolicy, SamlValidationContext,
};
