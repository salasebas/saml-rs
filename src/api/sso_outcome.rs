use std::time::SystemTime;

use crate::config::NameIdFormat;
use crate::entity::User;
use crate::model::{
    Attribute, Attributes, AuthnContextReference, NameId, Status, TopLevelStatusCode,
};
use crate::xml::OutboundNameIdQualifiers;

use super::SamlError;

/// The assertion a successful login response carries.
///
/// The caller chooses the subject `NameId` and, optionally, the attributes,
/// the authentication context, and the authentication instant. The library
/// writes the rest of the assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsoAssertion {
    name_id: NameId,
    attributes: Attributes,
    authn_context: Option<AuthnContextReference>,
    authn_instant: Option<SystemTime>,
}

impl SsoAssertion {
    /// An assertion whose `Subject` is `name_id`.
    ///
    /// The assertion has no `AttributeStatement` until [`Self::with_attributes`]
    /// sets one.
    pub fn new(name_id: NameId) -> Self {
        Self {
            name_id,
            attributes: Attributes::default(),
            authn_context: None,
            authn_instant: None,
        }
    }

    /// Replace the attributes of the assertion's `AttributeStatement`.
    ///
    /// Each attribute is written with its `Name`, its `NameFormat` and
    /// `FriendlyName` when it has them, and one `xs:string` `AttributeValue`
    /// for each value. An attribute without values is written without
    /// `AttributeValue`. An empty collection writes no `AttributeStatement`.
    ///
    /// The response is rejected when a `NameFormat` is not an absolute URI
    /// reference, or when an [`crate::AttributeNameFormat::Basic`] name is not an
    /// XML name.
    pub fn with_attributes(mut self, attributes: Attributes) -> Self {
        self.attributes = attributes;
        self
    }

    /// Set the authentication context of the assertion's `AuthnStatement`.
    ///
    /// Pass the context in which the subject was actually authenticated.
    /// Omitting the context writes the unspecified class.
    ///
    /// Where the statement is written and the request's
    /// [`crate::RequestedAuthnContext`] uses
    /// [`crate::AuthnContextComparison::Exact`], the response is rejected
    /// unless this context, or the unspecified class when it is omitted, is
    /// one of the requested references. The other comparisons are judged by
    /// the caller. When no requested context can be met, answer with
    /// [`SsoOutcome::Failure`] and [`Status::responder`], optionally with
    /// [`crate::SubordinateStatusCode::no_authn_context`].
    pub fn with_authn_context(mut self, authn_context: AuthnContextReference) -> Self {
        self.authn_context = Some(authn_context);
        self
    }

    /// Set the `AuthnInstant` of the assertion's `AuthnStatement`.
    ///
    /// Pass the time at which the subject actually authenticated, such as the
    /// start of a reused identity provider session. It is written in UTC,
    /// rounded down to the second. Omitting the instant writes the assertion
    /// `IssueInstant`.
    ///
    /// The response is rejected when the written instant is later than the
    /// response `IssueInstant` or before year 1.
    pub fn with_authn_instant(mut self, authn_instant: SystemTime) -> Self {
        self.authn_instant = Some(authn_instant);
        self
    }
}

/// What a login `<Response>` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsoOutcome {
    /// A `Success` response that carries this assertion.
    Success(SsoAssertion),
    /// A response with this error status and no assertion.
    ///
    /// A top-level `Success` status returns [`SamlError::Invalid`] from every
    /// operation that takes an outcome.
    Failure(Status),
}

impl From<SsoAssertion> for SsoOutcome {
    fn from(assertion: SsoAssertion) -> Self {
        Self::Success(assertion)
    }
}

pub(super) struct OutcomeParts<'a> {
    pub(super) user: User,
    pub(super) name_id_format: Option<&'a str>,
    pub(super) name_id_qualifiers: OutboundNameIdQualifiers<'a>,
    pub(super) status: Option<&'a Status>,
    pub(super) typed_attributes: &'a [Attribute],
    pub(super) authn_context: Option<&'a AuthnContextReference>,
    pub(super) authn_instant: Option<SystemTime>,
}

impl SsoOutcome {
    pub(super) fn parts(&self) -> Result<OutcomeParts<'_>, SamlError> {
        match self {
            Self::Success(assertion) => Ok(OutcomeParts {
                user: User::new(assertion.name_id.value()),
                name_id_format: assertion.name_id.format().map(NameIdFormat::as_uri),
                name_id_qualifiers: OutboundNameIdQualifiers::from(&assertion.name_id),
                status: None,
                typed_attributes: assertion.attributes.as_slice(),
                authn_context: assertion.authn_context.as_ref(),
                authn_instant: assertion.authn_instant,
            }),
            Self::Failure(status) if status.top_level() == TopLevelStatusCode::Success => Err(
                SamlError::Invalid("a failure response requires an error status".into()),
            ),
            Self::Failure(status) => Ok(OutcomeParts {
                user: User::default(),
                name_id_format: None,
                name_id_qualifiers: OutboundNameIdQualifiers::default(),
                status: Some(status),
                typed_attributes: &[],
                authn_context: None,
                authn_instant: None,
            }),
        }
    }
}
