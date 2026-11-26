use super::identifiers::{SamlInstant, SessionIndex};
use super::sso::SsoSession;
use super::subject::NameId;
use super::validation::SamlValidationContext;
use crate::config::EntityId;
use crate::error::SamlError;
use crate::validator::effective_not_on_or_after;
use crate::xml::parse_saml_utc_date_time;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

/// A caller-stored record of an authenticated IdP `LogoutRequest`.
///
/// Pass it to [`ServiceProvider::finish_sso_with_outstanding_logout`] or
/// [`ServiceProvider::accept_unsolicited_sso_with_outstanding_logout`]. While
/// the record is unexpired, it applies to assertions from the same issuer
/// whose full `NameID` matches, including its qualifiers. An omitted `Format`
/// is equivalent to `unspecified`. An empty session list applies to every
/// session with that issuer and `NameID`. An assertion without a `NameID` does
/// not match.
///
/// [`ServiceProvider::finish_sso_with_outstanding_logout`]: crate::ServiceProvider::finish_sso_with_outstanding_logout
/// [`ServiceProvider::accept_unsolicited_sso_with_outstanding_logout`]: crate::ServiceProvider::accept_unsolicited_sso_with_outstanding_logout
///
/// # Examples
///
/// ```
/// use saml_rs::{LogoutRequest, OutstandingLogout, Received, SamlError};
///
/// fn remember_logout(
///     received: &Received<LogoutRequest>,
/// ) -> Result<Option<OutstandingLogout>, SamlError> {
///     let request = received.message();
///     let (Some(name_id), Some(deadline)) = (request.name_id(), request.not_on_or_after()) else {
///         return Ok(None);
///     };
///     let logout = OutstandingLogout::try_new(
///         request.issuer().clone(),
///         name_id.clone(),
///         request.session_indexes().to_vec(),
///         deadline.clone(),
///     )?;
///     Ok(Some(logout))
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutstandingLogout {
    issuer: EntityId,
    name_id: NameId,
    session_indexes: Vec<SessionIndex>,
    not_on_or_after: SamlInstant,
    deadline: OffsetDateTime,
}

impl OutstandingLogout {
    /// Create a record from the issuer, `NameID`, session indexes, and
    /// `NotOnOrAfter` of the same authenticated logout request.
    ///
    /// Take these values from the result of [`crate::ServiceProvider::receive_slo`]
    /// or restore them together from a trusted store. Every `NameID` value is
    /// recorded as given, an empty one included.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when `not_on_or_after` is not a
    /// representable SAML UTC `xs:dateTime`.
    pub fn try_new(
        issuer: EntityId,
        name_id: NameId,
        session_indexes: Vec<SessionIndex>,
        not_on_or_after: SamlInstant,
    ) -> Result<Self, SamlError> {
        let normalized = parse_saml_utc_date_time(not_on_or_after.as_str()).ok_or_else(|| {
            SamlError::Invalid(
                "outstanding logout NotOnOrAfter must be a SAML UTC xs:dateTime ending in Z".into(),
            )
        })?;
        let deadline = OffsetDateTime::parse(normalized, &Rfc3339).map_err(|_| {
            SamlError::Invalid(
                "outstanding logout NotOnOrAfter cannot be represented as a UTC instant".into(),
            )
        })?;
        let not_on_or_after = if normalized == not_on_or_after.as_str() {
            not_on_or_after
        } else {
            SamlInstant::try_new(normalized)?
        };
        Ok(Self {
            issuer,
            name_id,
            session_indexes,
            not_on_or_after,
            deadline,
        })
    }

    /// Issuer of the authenticated logout request.
    pub fn issuer(&self) -> &EntityId {
        &self.issuer
    }

    /// Principal named by the accepted logout.
    pub fn name_id(&self) -> &NameId {
        &self.name_id
    }

    /// Sessions named by the accepted logout.
    ///
    /// Empty means the logout carried no `SessionIndex`.
    pub fn session_indexes(&self) -> &[SessionIndex] {
        &self.session_indexes
    }

    /// `NotOnOrAfter` from the accepted logout, normalized as a SAML UTC instant.
    pub fn not_on_or_after(&self) -> &SamlInstant {
        &self.not_on_or_after
    }

    pub(crate) fn matches_unexpired(
        &self,
        session: &SsoSession,
        validation: &SamlValidationContext<'_>,
    ) -> Result<bool, SamlError> {
        if self.issuer() != session.issuer()
            || !session
                .name_id()
                .is_some_and(|name_id| self.name_id().strongly_matches(name_id))
            || !self.same_session(session)
        {
            return Ok(false);
        }
        let now = validation.now_offset()?;
        let effective = effective_not_on_or_after(
            self.deadline,
            validation.clock_skew().not_on_or_after_millis(),
        )?;
        Ok(now < effective)
    }

    fn same_session(&self, session: &SsoSession) -> bool {
        if self.session_indexes.is_empty() {
            return true;
        }
        session.authn_statements().iter().any(|authn| {
            authn
                .session_index()
                .is_some_and(|index| self.session_indexes.contains(index))
        })
    }
}
