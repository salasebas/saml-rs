use super::authn_details::{AuthnContext, SubjectLocality};
use super::identifiers::{SamlInstant, SessionIndex};
use crate::error::{SamlError, TimeWindowField};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

/// One `<AuthnStatement>` of an accepted assertion.
///
/// Each value keeps that statement's `SessionIndex`, `AuthnInstant`,
/// `SessionNotOnOrAfter`, `AuthnContext`, and `SubjectLocality` together.
/// [`crate::SsoSession::authn_statements`] lists one value for each statement,
/// in document order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthnStatement {
    session_index: Option<SessionIndex>,
    authn_instant: Option<SamlInstant>,
    session_not_on_or_after: Option<SamlInstant>,
    authn_context: Option<AuthnContext>,
    subject_locality: Option<SubjectLocality>,
}

pub(crate) fn earliest_authn_session_expiration<'a>(
    values: impl IntoIterator<Item = &'a str>,
    error_field: TimeWindowField,
) -> Result<Option<OffsetDateTime>, SamlError> {
    let mut earliest = None;
    for value in values {
        let candidate = OffsetDateTime::parse(value, &Rfc3339)
            .map_err(|_| SamlError::TimeWindowInvalid { field: error_field })?;
        if earliest.is_none_or(|current| candidate < current) {
            earliest = Some(candidate);
        }
    }
    Ok(earliest)
}

impl AuthnStatement {
    pub(super) fn new(
        session_index: Option<SessionIndex>,
        authn_instant: Option<SamlInstant>,
        session_not_on_or_after: Option<SamlInstant>,
    ) -> Self {
        Self {
            session_index,
            authn_instant,
            session_not_on_or_after,
            authn_context: None,
            subject_locality: None,
        }
    }

    pub(super) fn with_authn_context(mut self, context: AuthnContext) -> Self {
        self.authn_context = Some(context);
        self
    }

    pub(super) fn with_subject_locality(mut self, locality: SubjectLocality) -> Self {
        self.subject_locality = Some(locality);
        self
    }

    /// The reported authentication context, when present.
    pub fn authn_context(&self) -> Option<&AuthnContext> {
        self.authn_context.as_ref()
    }

    /// The reported network location, when present.
    pub fn subject_locality(&self) -> Option<&SubjectLocality> {
        self.subject_locality.as_ref()
    }

    /// SessionIndex, when present.
    pub fn session_index(&self) -> Option<&SessionIndex> {
        self.session_index.as_ref()
    }

    /// AuthnInstant, when present.
    pub fn authn_instant(&self) -> Option<&SamlInstant> {
        self.authn_instant.as_ref()
    }

    /// `SessionNotOnOrAfter`, when present: the instant after which the
    /// identity provider asks the service provider to end this session.
    ///
    /// The assertion's `Conditions@NotOnOrAfter` is
    /// [`crate::SsoSession::not_on_or_after`].
    pub fn session_not_on_or_after(&self) -> Option<&SamlInstant> {
        self.session_not_on_or_after.as_ref()
    }
}
