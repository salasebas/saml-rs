use super::extract::{
    optional_endpoint, optional_request_id, required_str, session_indexes_from_value,
};
use super::identifiers::{MessageId, SamlInstant, SessionIndex};
use super::status::Status;
use super::subject::NameId;
use super::{EndpointUrl, RelayState};
use crate::config::{EntityId, NameIdFormat};
use crate::error::SamlError;
use crate::flow::FlowResult;
use crate::xml::fields::{logout_request, logout_response, name_id, request, response, ISSUER};
use crate::xml::parse_saml_utc_date_time;

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

    /// NameID, when present.
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

    pub(crate) fn raw_flow(&self) -> &FlowResult {
        &self.raw_flow
    }
}

impl LogoutRequest {
    pub(crate) fn from_flow(raw_flow: FlowResult) -> Result<Self, SamlError> {
        let id = MessageId::try_new(required_str(&raw_flow.extract, request::ID)?)?;
        let issue_instant = raw_flow
            .extract
            .get_str(request::ISSUE_INSTANT)
            .ok_or_else(|| {
                SamlError::ProtocolProfile(
                    "LogoutRequest is missing required unqualified attribute IssueInstant".into(),
                )
            })?;
        let issue_instant = logout_request_instant(issue_instant, "IssueInstant")?;
        let not_on_or_after = raw_flow
            .extract
            .get_str(request::NOT_ON_OR_AFTER)
            .map(|value| logout_request_instant(value, "NotOnOrAfter"))
            .transpose()?;
        let issuer = EntityId::try_new(required_str(&raw_flow.extract, ISSUER)?)?;
        let name_id_attribute = |field: &str| raw_flow.extract.get_str(field).map(str::to_string);
        let name_id = raw_flow.extract.get_str(name_id::VALUE).map(|value| {
            NameId::received(
                value,
                raw_flow
                    .extract
                    .get_str(name_id::FORMAT)
                    .map(NameIdFormat::from_uri),
                name_id_attribute(name_id::NAME_QUALIFIER),
                name_id_attribute(name_id::SP_NAME_QUALIFIER),
                name_id_attribute(name_id::SP_PROVIDED_ID),
            )
        });
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
            raw_flow,
        })
    }
}

fn logout_request_instant(value: &str, attribute: &str) -> Result<SamlInstant, SamlError> {
    let normalized = parse_saml_utc_date_time(value).ok_or_else(|| {
        SamlError::ProtocolProfile(format!(
            "LogoutRequest {attribute} must use the SAML-conformant UTC xs:dateTime form ending in Z"
        ))
    })?;
    SamlInstant::try_new(normalized)
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
}

impl LogoutResponse {
    pub(crate) fn from_flow(raw_flow: FlowResult) -> Result<Self, SamlError> {
        let id = MessageId::try_new(required_str(&raw_flow.extract, response::ID)?)?;
        let issue_instant = issue_instant_from_extract(&raw_flow.extract)?;
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

fn issue_instant_from_extract(extract: &crate::util::Value) -> Result<SamlInstant, SamlError> {
    let issue_instant = extract.get_str(response::ISSUE_INSTANT).ok_or_else(|| {
        SamlError::ProtocolProfile(
            "LogoutResponse is missing required unqualified attribute IssueInstant".into(),
        )
    })?;
    let issue_instant = parse_saml_utc_date_time(issue_instant).ok_or_else(|| {
        SamlError::ProtocolProfile(
            "LogoutResponse IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z"
                .into(),
        )
    })?;
    SamlInstant::try_new(issue_instant)
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
