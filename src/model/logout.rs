use super::extract::{
    name_id_from_extract, optional_endpoint, optional_request_id, required_saml_utc_instant,
    required_str, saml_utc_instant, session_indexes_from_value,
};
use super::identifiers::{MessageId, SamlInstant, SessionIndex};
use super::status::{RequestVersionMismatch, Status, StatusMessage};
use super::subject::NameId;
use super::{EndpointUrl, Received, RelayState};
use crate::browser::LogoutBinding;
use crate::config::EntityId;
use crate::error::SamlError;
use crate::flow::FlowResult;
use crate::xml::fields::{logout_request, logout_response, name_id, request, response, ISSUER};

/// How the IdP completes an authenticated SP logout request.
#[derive(Debug, Clone)]
pub enum IdpLogoutAction {
    /// End the relevant sessions and send a LogoutResponse with the outcome.
    Respond(Received<LogoutRequest>),
    /// End the relevant sessions and present the outcome at the IdP without
    /// sending a LogoutResponse to the initiating SP.
    CompleteLocally(LogoutRequest),
}

/// An authenticated LogoutRequest that requires a version mismatch response.
#[derive(Debug, Clone)]
pub struct RefusedLogoutRequest {
    pub(crate) id: MessageId,
    pub(crate) issuer: EntityId,
    pub(crate) relay_state: Option<RelayState>,
    pub(crate) binding: LogoutBinding,
    pub(crate) status: Status,
}

impl RefusedLogoutRequest {
    pub(crate) fn for_version(
        flow: &FlowResult,
        issuer: &EntityId,
        relay_state: Option<&RelayState>,
        binding: LogoutBinding,
    ) -> Result<Option<Self>, SamlError> {
        let version = required_str(&flow.extract, request::VERSION)?;
        let Some(mismatch) = RequestVersionMismatch::for_request(version)? else {
            return Ok(None);
        };
        Ok(Some(Self {
            id: MessageId::try_new(required_str(&flow.extract, request::ID)?)?,
            issuer: issuer.clone(),
            relay_state: relay_state.cloned(),
            binding,
            status: mismatch.status(),
        }))
    }

    /// Status the LogoutResponse will report.
    pub fn status(&self) -> &Status {
        &self.status
    }
}

/// Subject data used to issue a Single Logout request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutSubject {
    name_id: NameId,
    session_indexes: Vec<SessionIndex>,
}

impl LogoutSubject {
    /// Create logout subject data with no SessionIndex values.
    ///
    /// A session authority can omit all indexes to target every applicable
    /// session for the NameID. A service provider must add at least one
    /// index with [`Self::with_session_index`] or [`Self::with_session_indexes`].
    pub fn new(name_id: NameId) -> Self {
        Self {
            name_id,
            session_indexes: Vec::new(),
        }
    }

    /// Append a SessionIndex to include in the logout request.
    pub fn with_session_index(mut self, session_index: SessionIndex) -> Self {
        self.session_indexes.push(session_index);
        self
    }

    /// Append session indexes in iteration order, preserving existing selections and duplicates.
    ///
    /// An empty iterator leaves the selection unchanged.
    pub fn with_session_indexes(
        mut self,
        session_indexes: impl IntoIterator<Item = SessionIndex>,
    ) -> Self {
        self.session_indexes.extend(session_indexes);
        self
    }

    /// Subject NameID.
    pub fn name_id(&self) -> &NameId {
        &self.name_id
    }

    /// SessionIndex values to include in the logout request.
    pub fn session_indexes(&self) -> &[SessionIndex] {
        &self.session_indexes
    }
}

/// Parsed LogoutRequest result.
#[derive(Debug, Clone)]
pub struct LogoutRequest {
    id: MessageId,
    issue_instant: SamlInstant,
    not_on_or_after: Option<SamlInstant>,
    issuer: EntityId,
    name_id: Option<NameId>,
    session_indexes: Vec<SessionIndex>,
    destination: Option<EndpointUrl>,
    reason: Option<String>,
    raw_flow: FlowResult,
}

impl LogoutRequest {
    /// LogoutRequest ID.
    pub fn id(&self) -> &MessageId {
        &self.id
    }

    /// LogoutRequest `IssueInstant`, normalized according to XML Schema whitespace rules.
    pub fn issue_instant(&self) -> &SamlInstant {
        &self.issue_instant
    }

    /// LogoutRequest `NotOnOrAfter`, normalized according to XML Schema whitespace rules.
    pub fn not_on_or_after(&self) -> Option<&SamlInstant> {
        self.not_on_or_after.as_ref()
    }

    /// LogoutRequest issuer.
    pub fn issuer(&self) -> &EntityId {
        &self.issuer
    }

    /// The plaintext or decrypted `NameID`.
    ///
    /// Returns `None` for a `BaseID`, including a decrypted `BaseID`, or when
    /// the request's `EncryptedID` could not be decrypted. See
    /// [`crate::ServiceProvider::receive_slo`] for the receive contract.
    pub fn name_id(&self) -> Option<&NameId> {
        self.name_id.as_ref()
    }

    /// Session indexes.
    pub fn session_indexes(&self) -> &[SessionIndex] {
        &self.session_indexes
    }

    /// `Destination`, when present, with its XML Schema `anyURI` whitespace
    /// collapsed.
    pub fn destination(&self) -> Option<&EndpointUrl> {
        self.destination.as_ref()
    }

    /// Peer-supplied `Reason` attribute, when present.
    ///
    /// Returns the XML-parsed attribute value without whitespace collapse or
    /// URI validation, or `None` when the attribute was absent.
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    pub(crate) fn raw_flow(&self) -> &FlowResult {
        &self.raw_flow
    }
}

impl LogoutRequest {
    pub(crate) fn from_flow(
        raw_flow: FlowResult,
        reason: Option<String>,
    ) -> Result<Self, SamlError> {
        let id = MessageId::try_new(required_str(&raw_flow.extract, request::ID)?)?;
        let issue_instant = required_saml_utc_instant(
            raw_flow.extract.get_str(request::ISSUE_INSTANT),
            "LogoutRequest",
            "IssueInstant",
        )?;
        let not_on_or_after = raw_flow
            .extract
            .get_str(request::NOT_ON_OR_AFTER)
            .map(|value| saml_utc_instant(value, "LogoutRequest", "NotOnOrAfter"))
            .transpose()?;
        let issuer = EntityId::try_new(required_str(&raw_flow.extract, ISSUER)?)?;
        let name_id = raw_flow
            .extract
            .get_str(name_id::VALUE)
            .map(|value| name_id_from_extract(&raw_flow.extract, value));
        let session_indexes =
            session_indexes_from_value(raw_flow.extract.get(logout_request::SESSION_INDEXES))?;
        let destination = optional_endpoint(&raw_flow.extract, request::DESTINATION)?;
        Ok(Self {
            id,
            issue_instant,
            not_on_or_after,
            issuer,
            name_id,
            session_indexes,
            destination,
            reason,
            raw_flow,
        })
    }
}

impl Received<LogoutRequest> {
    /// Return whether an authenticated IdP logout names one local SP session.
    ///
    /// Call this on the result of [`crate::ServiceProvider::receive_slo`].
    /// Store the session's assertion issuer and logout subject using
    /// [`crate::SsoSession::issuer`] and [`crate::SsoSession::logout_subject`]
    /// when the SP accepts the sign-in.
    ///
    /// The issuer and the full `NameID` must match, including its qualifiers.
    /// An omitted format is equivalent to `unspecified`. If the request
    /// carries indexes, at least one must match an index in the stored subject.
    /// A request with no indexes can match each session with the same issuer
    /// and `NameID`. A `BaseID` or an undecryptable `EncryptedID` returns `false`.
    /// The application owns session lookup and invalidation.
    ///
    /// # Examples
    ///
    /// ```
    /// use saml_rs::{EntityId, LogoutRequest, LogoutSubject, Received};
    ///
    /// fn end_matching_session(
    ///     request: &Received<LogoutRequest>,
    ///     assertion_issuer: &EntityId,
    ///     logout_subject: &LogoutSubject,
    ///     invalidate: impl FnOnce(),
    /// ) {
    ///     if request.matches_sp_session(assertion_issuer, logout_subject) {
    ///         invalidate();
    ///     }
    /// }
    /// ```
    #[must_use]
    pub fn matches_sp_session(
        &self,
        assertion_issuer: &EntityId,
        logout_subject: &LogoutSubject,
    ) -> bool {
        let request = self.message();
        request.issuer() == assertion_issuer
            && request
                .name_id()
                .is_some_and(|name_id| name_id.strongly_matches(logout_subject.name_id()))
            && (request.session_indexes().is_empty()
                || request
                    .session_indexes()
                    .iter()
                    .any(|index| logout_subject.session_indexes().contains(index)))
    }
}

/// Parsed LogoutResponse result.
#[derive(Debug, Clone)]
pub struct LogoutResponse {
    id: MessageId,
    issuer: EntityId,
    issue_instant: SamlInstant,
    in_response_to: Option<MessageId>,
    destination: Option<EndpointUrl>,
    status: Status,
    status_message: Option<StatusMessage>,
}

impl LogoutResponse {
    /// LogoutResponse ID.
    pub fn id(&self) -> &MessageId {
        &self.id
    }

    /// LogoutResponse issuer.
    pub fn issuer(&self) -> &EntityId {
        &self.issuer
    }

    /// LogoutResponse `IssueInstant`, normalized according to XML Schema whitespace rules.
    pub fn issue_instant(&self) -> &SamlInstant {
        &self.issue_instant
    }

    /// InResponseTo, when present.
    pub fn in_response_to(&self) -> Option<&MessageId> {
        self.in_response_to.as_ref()
    }

    /// `Destination`, when present, with its XML Schema `anyURI` whitespace
    /// collapsed.
    pub fn destination(&self) -> Option<&EndpointUrl> {
        self.destination.as_ref()
    }

    /// Top-level `StatusCode` and the subordinate `StatusCode`, when present.
    ///
    /// A session authority reports `PartialLogout` as the subordinate code
    /// under `Success` when it could not log out every other session
    /// participant.
    pub fn status(&self) -> &Status {
        &self.status
    }

    /// Return the authenticated peer's operator diagnostic, when present.
    ///
    /// Debug output omits this text.
    pub fn status_message(&self) -> Option<&str> {
        self.status_message.as_ref().map(StatusMessage::as_str)
    }
}

impl LogoutResponse {
    pub(crate) fn from_flow(
        raw_flow: &FlowResult,
        status_message: Option<StatusMessage>,
    ) -> Result<Self, SamlError> {
        let id = MessageId::try_new(required_str(&raw_flow.extract, response::ID)?)?;
        let issue_instant = required_saml_utc_instant(
            raw_flow.extract.get_str(response::ISSUE_INSTANT),
            "LogoutResponse",
            "IssueInstant",
        )?;
        let issuer = EntityId::try_new(required_str(&raw_flow.extract, ISSUER)?)?;
        let in_response_to = optional_request_id(&raw_flow.extract, response::IN_RESPONSE_TO)?;
        let destination = optional_endpoint(&raw_flow.extract, response::DESTINATION)?;
        let status = status_from_extract(&raw_flow.extract)?;
        Ok(Self {
            id,
            issuer,
            issue_instant,
            in_response_to,
            destination,
            status,
            status_message,
        })
    }
}

fn status_from_extract(extract: &crate::util::Value) -> Result<Status, SamlError> {
    let top_level = extract
        .get_str(logout_response::STATUS_CODE)
        .ok_or_else(|| {
            SamlError::ProtocolProfile(
                "LogoutResponse is missing required Status/StatusCode".into(),
            )
        })?;
    Status::received(
        top_level,
        extract.get_str(logout_response::SUBORDINATE_STATUS_CODE),
    )
}

/// Result of a completed logout exchange, including the responder's status.
#[derive(Debug, Clone)]
pub struct LogoutCompleted {
    response: LogoutResponse,
    relay_state: Option<RelayState>,
}

impl LogoutCompleted {
    pub(crate) fn new(response: LogoutResponse, relay_state: Option<RelayState>) -> Self {
        Self {
            response,
            relay_state,
        }
    }

    /// Peer entity ID from the completed logout response's issuer.
    pub fn peer_entity_id(&self) -> &EntityId {
        self.response.issuer()
    }

    /// LogoutResponse received by the completed exchange.
    pub fn response(&self) -> &LogoutResponse {
        &self.response
    }

    /// RelayState received with the LogoutResponse.
    ///
    /// When the request carried RelayState, this is the same value. When it
    /// carried none, this is whatever the responder supplied, which the caller
    /// interprets by prior agreement.
    pub fn relay_state(&self) -> Option<&RelayState> {
        self.relay_state.as_ref()
    }
}
