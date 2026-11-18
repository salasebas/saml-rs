use core::marker::PhantomData;

use super::bindings::{LogoutBinding, SsoResponseBinding};
use super::endpoints::AcsEndpoint;
use super::outbound::Outbound;
use crate::config::EntityId;
use crate::constants::Binding;
use crate::error::SamlError;
use crate::model::{AuthnRequest, EndpointUrl, LogoutRequest, MessageId, RelayState, SamlInstant};
use crate::name_id_management::ManageNameIdRequest;

mod sealed {
    pub trait Sealed {}
}

/// Message marker support for typed pending state.
#[doc(hidden)]
pub trait PendingMessage: sealed::Sealed {
    /// Private storage for protocol-specific pending fields.
    type Details: Clone + core::fmt::Debug + PartialEq + Eq;
}

/// Protocol-specific pending AuthnRequest details.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthnPendingDetails {
    acs: AcsEndpoint,
}

/// Protocol-specific pending LogoutRequest details.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutPendingDetails {
    binding: LogoutBinding,
    validity: Option<LogoutRequestValidity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LogoutRequestValidity {
    issued_at: SamlInstant,
    expires_at: SamlInstant,
}

impl sealed::Sealed for AuthnRequest {}

impl PendingMessage for AuthnRequest {
    type Details = AuthnPendingDetails;
}

impl sealed::Sealed for LogoutRequest {}

impl PendingMessage for LogoutRequest {
    type Details = LogoutPendingDetails;
}

impl sealed::Sealed for ManageNameIdRequest {}

impl PendingMessage for ManageNameIdRequest {
    type Details = ();
}

/// State a requester keeps until the response to its request arrives.
///
/// The start operation returns it in [`Started`]. Store its snapshot with the
/// user's session and rebuild it with `from_snapshot` for the finish
/// operation, which checks that the response answers this request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending<Message: PendingMessage> {
    id: MessageId,
    relay_state: Option<RelayState>,
    peer_entity_id: EntityId,
    details: Message::Details,
    _message: PhantomData<Message>,
}

/// Pending AuthnRequest correlation state.
pub type PendingAuthnRequest = Pending<AuthnRequest>;

/// Pending LogoutRequest correlation state.
pub type PendingLogoutRequest = Pending<LogoutRequest>;

/// Pending ManageNameIDRequest correlation state.
pub type PendingManageNameIdRequest = Pending<ManageNameIdRequest>;

impl<Message: PendingMessage> Pending<Message> {
    fn with_details(
        id: MessageId,
        relay_state: Option<RelayState>,
        peer_entity_id: EntityId,
        details: Message::Details,
    ) -> Self {
        Self {
            id,
            relay_state,
            peer_entity_id,
            details,
            _message: PhantomData,
        }
    }

    /// `ID` of the request. The response's `InResponseTo` must equal it.
    pub fn id(&self) -> &MessageId {
        &self.id
    }

    /// RelayState the request carried. The response must return it unchanged.
    pub fn relay_state(&self) -> Option<&RelayState> {
        self.relay_state.as_ref()
    }

    /// Entity ID of the peer the request went to. The response must come
    /// from it.
    pub fn peer_entity_id(&self) -> &EntityId {
        &self.peer_entity_id
    }
}

impl Pending<AuthnRequest> {
    pub(crate) fn new(
        id: MessageId,
        relay_state: Option<RelayState>,
        peer_entity_id: EntityId,
        acs: AcsEndpoint,
    ) -> Self {
        Self::with_details(id, relay_state, peer_entity_id, AuthnPendingDetails { acs })
    }

    /// Assertion consumer service the AuthnRequest asked for. The response
    /// must arrive on its binding and name its location.
    pub fn acs(&self) -> &AcsEndpoint {
        &self.details.acs
    }

    /// Fields to store until the response arrives.
    pub fn snapshot(&self) -> PendingAuthnRequestSnapshot {
        let acs = &self.details.acs;
        PendingAuthnRequestSnapshot {
            id: self.id.as_str().to_string(),
            relay_state: self
                .relay_state
                .as_ref()
                .map(|relay_state| relay_state.as_str().to_string()),
            peer_entity_id: self.peer_entity_id.as_str().to_string(),
            acs_binding: Binding::from(acs.binding()).short_name().to_string(),
            acs_url: acs.location().as_str().to_string(),
            acs_index: acs.index(),
            acs_is_default: acs.is_default(),
        }
    }

    /// Rebuild pending AuthnRequest state from stored fields.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when a field fails the check of its type:
    /// [`MessageId::try_new`], [`RelayState::try_new`], [`EntityId::try_new`],
    /// or [`EndpointUrl::try_new`]. Returns [`SamlError::Invalid`] when
    /// `acs_binding` is not a binding name, and
    /// [`SamlError::UnsupportedBinding`] when it names a binding an SSO
    /// response cannot use.
    ///
    /// # Examples
    ///
    /// ```
    /// use saml_rs::{PendingAuthnRequest, PendingAuthnRequestSnapshot};
    ///
    /// let snapshot = PendingAuthnRequestSnapshot {
    ///     id: "_request123".to_string(),
    ///     relay_state: Some("return-to-cart".to_string()),
    ///     peer_entity_id: "https://idp.example.com/metadata".to_string(),
    ///     acs_binding: "post".to_string(),
    ///     acs_url: "https://sp.example.com/acs".to_string(),
    ///     acs_index: None,
    ///     acs_is_default: false,
    /// };
    /// let pending = PendingAuthnRequest::from_snapshot(snapshot.clone())?;
    ///
    /// assert_eq!(pending.peer_entity_id().as_str(), "https://idp.example.com/metadata");
    /// assert_eq!(pending.snapshot(), snapshot);
    /// # Ok::<(), saml_rs::SamlError>(())
    /// ```
    pub fn from_snapshot(snapshot: PendingAuthnRequestSnapshot) -> Result<Self, SamlError> {
        let binding: SsoResponseBinding = snapshot_binding(&snapshot.acs_binding)?;
        let mut acs = AcsEndpoint::new(binding, EndpointUrl::try_new(snapshot.acs_url)?);
        if let Some(index) = snapshot.acs_index {
            acs = acs.with_index(index);
        }
        if snapshot.acs_is_default {
            acs = acs.with_default();
        }
        Ok(Self::new(
            MessageId::try_new(snapshot.id)?,
            snapshot.relay_state.map(RelayState::try_new).transpose()?,
            EntityId::try_new(snapshot.peer_entity_id)?,
            acs,
        ))
    }
}

impl Pending<LogoutRequest> {
    pub(crate) fn new(
        id: MessageId,
        relay_state: Option<RelayState>,
        peer_entity_id: EntityId,
        binding: LogoutBinding,
    ) -> Self {
        Self::with_details(
            id,
            relay_state,
            peer_entity_id,
            LogoutPendingDetails {
                binding,
                validity: None,
            },
        )
    }

    pub(crate) fn with_validity(mut self, issued_at: SamlInstant, expires_at: SamlInstant) -> Self {
        self.details.validity = Some(LogoutRequestValidity {
            issued_at,
            expires_at,
        });
        self
    }

    /// Binding the LogoutRequest was sent with.
    ///
    /// `finish_slo` accepts the response over SOAP when this is
    /// [`LogoutBinding::Soap`], and otherwise over any front-channel binding.
    pub fn binding(&self) -> LogoutBinding {
        self.details.binding
    }

    /// `IssueInstant` of a LogoutRequest a session authority sent. `None` for
    /// a session participant.
    pub fn issued_at(&self) -> Option<&SamlInstant> {
        self.details
            .validity
            .as_ref()
            .map(|validity| &validity.issued_at)
    }

    /// `NotOnOrAfter` of a LogoutRequest a session authority sent. `None` for
    /// a session participant.
    pub fn expires_at(&self) -> Option<&SamlInstant> {
        self.details
            .validity
            .as_ref()
            .map(|validity| &validity.expires_at)
    }

    /// Fields to store until the response arrives.
    pub fn snapshot(&self) -> PendingLogoutRequestSnapshot {
        PendingLogoutRequestSnapshot {
            id: self.id.as_str().to_string(),
            relay_state: self
                .relay_state
                .as_ref()
                .map(|relay_state| relay_state.as_str().to_string()),
            peer_entity_id: self.peer_entity_id.as_str().to_string(),
            binding: Binding::from(self.details.binding).short_name().to_string(),
            issued_at: self.issued_at().map(|instant| instant.as_str().to_string()),
            expires_at: self
                .expires_at()
                .map(|instant| instant.as_str().to_string()),
        }
    }

    /// Rebuild pending LogoutRequest state from stored fields.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when a field fails the check of its type:
    /// [`MessageId::try_new`], [`RelayState::try_new`], [`EntityId::try_new`],
    /// or [`SamlInstant::try_new`]. Returns [`SamlError::Invalid`] when
    /// `binding` is not a binding name or only one of `issued_at` and
    /// `expires_at` is set, [`SamlError::UnsupportedBinding`] when `binding`
    /// names a binding logout cannot use, and [`SamlError::ProtocolProfile`]
    /// when a SOAP request has RelayState.
    ///
    /// # Examples
    ///
    /// ```
    /// use saml_rs::{LogoutBinding, PendingLogoutRequest, PendingLogoutRequestSnapshot};
    ///
    /// let pending = PendingLogoutRequest::from_snapshot(PendingLogoutRequestSnapshot {
    ///     id: "_logout123".to_string(),
    ///     relay_state: None,
    ///     peer_entity_id: "https://idp.example.com/metadata".to_string(),
    ///     binding: "post".to_string(),
    ///     issued_at: None,
    ///     expires_at: None,
    /// })?;
    ///
    /// assert_eq!(pending.binding(), LogoutBinding::Post);
    /// # Ok::<(), saml_rs::SamlError>(())
    /// ```
    pub fn from_snapshot(snapshot: PendingLogoutRequestSnapshot) -> Result<Self, SamlError> {
        let binding: LogoutBinding = snapshot_binding(&snapshot.binding)?;
        let relay_state = snapshot.relay_state.map(RelayState::try_new).transpose()?;
        crate::logout::reject_soap_relay_state(
            Binding::from(binding),
            relay_state.as_ref().map(RelayState::as_str),
        )?;
        let pending = Self::new(
            MessageId::try_new(snapshot.id)?,
            relay_state,
            EntityId::try_new(snapshot.peer_entity_id)?,
            binding,
        );
        match (snapshot.issued_at, snapshot.expires_at) {
            (None, None) => Ok(pending),
            (Some(issued_at), Some(expires_at)) => Ok(pending.with_validity(
                SamlInstant::try_new(issued_at)?,
                SamlInstant::try_new(expires_at)?,
            )),
            (Some(_), None) | (None, Some(_)) => Err(SamlError::Invalid(
                "a pending logout snapshot stores issued_at and expires_at together".into(),
            )),
        }
    }
}

impl Pending<ManageNameIdRequest> {
    pub(crate) fn new(
        id: MessageId,
        relay_state: Option<RelayState>,
        peer_entity_id: EntityId,
    ) -> Self {
        Self::with_details(id, relay_state, peer_entity_id, ())
    }

    /// Fields to store until the response arrives.
    pub fn snapshot(&self) -> PendingManageNameIdRequestSnapshot {
        PendingManageNameIdRequestSnapshot {
            id: self.id.as_str().to_string(),
            relay_state: self
                .relay_state
                .as_ref()
                .map(|relay_state| relay_state.as_str().to_string()),
            peer_entity_id: self.peer_entity_id.as_str().to_string(),
        }
    }

    /// Rebuild pending HTTP-Redirect ManageNameIDRequest state from stored
    /// fields.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when a field fails the check of its type:
    /// [`MessageId::try_new`], [`RelayState::try_new`], or
    /// [`EntityId::try_new`].
    pub fn from_snapshot(snapshot: PendingManageNameIdRequestSnapshot) -> Result<Self, SamlError> {
        Ok(Self::new(
            MessageId::try_new(snapshot.id)?,
            snapshot.relay_state.map(RelayState::try_new).transpose()?,
            EntityId::try_new(snapshot.peer_entity_id)?,
        ))
    }
}

/// Stored fields of a [`PendingAuthnRequest`].
///
/// [`PendingAuthnRequest::snapshot`] writes the binding as its short name.
/// [`PendingAuthnRequest::from_snapshot`] reads a short name or a binding URN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAuthnRequestSnapshot {
    /// `ID` of the AuthnRequest.
    pub id: String,
    /// RelayState the request carried. `None` when it carried none, and an
    /// empty string when it carried an empty one.
    pub relay_state: Option<String>,
    /// Entity ID of the identity provider.
    pub peer_entity_id: String,
    /// Binding of the requested assertion consumer service.
    pub acs_binding: String,
    /// Location of the requested assertion consumer service.
    pub acs_url: String,
    /// Index of the requested assertion consumer service, if it has one.
    pub acs_index: Option<u16>,
    /// Whether the requested assertion consumer service is the default one.
    pub acs_is_default: bool,
}

/// Stored fields of a [`PendingLogoutRequest`].
///
/// [`PendingLogoutRequest::snapshot`] writes the binding as its short name.
/// [`PendingLogoutRequest::from_snapshot`] reads a short name or a binding
/// URN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingLogoutRequestSnapshot {
    /// `ID` of the LogoutRequest.
    pub id: String,
    /// RelayState the request carried. `None` when it carried none, and an
    /// empty string when it carried an empty one.
    pub relay_state: Option<String>,
    /// Entity ID of the peer the request went to.
    pub peer_entity_id: String,
    /// Binding the request was sent with.
    pub binding: String,
    /// `IssueInstant` of a session authority's request. Set together with
    /// `expires_at`.
    pub issued_at: Option<String>,
    /// `NotOnOrAfter` of a session authority's request. Set together with
    /// `issued_at`.
    pub expires_at: Option<String>,
}

/// Stored fields of a [`PendingManageNameIdRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingManageNameIdRequestSnapshot {
    /// `ID` of the ManageNameIDRequest.
    pub id: String,
    /// RelayState the request carried. `None` when it carried none, and an
    /// empty string when it carried an empty one.
    pub relay_state: Option<String>,
    /// Entity ID of the peer the request went to.
    pub peer_entity_id: String,
}

fn snapshot_binding<TypedBinding>(value: &str) -> Result<TypedBinding, SamlError>
where
    TypedBinding: TryFrom<Binding, Error = SamlError>,
{
    let binding = Binding::from_short_name(value)
        .or_else(|| Binding::from_urn(value))
        .ok_or_else(|| {
            SamlError::Invalid(format!("snapshot binding `{value}` is not a SAML binding"))
        })?;
    TypedBinding::try_from(binding)
}

/// Started browser flow with pending state and outbound browser action.
#[derive(Debug, Clone)]
pub struct Started<Message: PendingMessage> {
    /// Pending correlation state.
    pub pending: Pending<Message>,
    /// Outbound browser action.
    pub outbound: Outbound<Message>,
}
