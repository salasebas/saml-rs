use core::marker::PhantomData;

use super::bindings::{
    LogoutBinding, NameIdManagementBinding, SsoRequestBinding, SsoResponseBinding,
};
use super::endpoints::AcsEndpoint;
use super::outbound::Outbound;
use crate::config::EntityId;
use crate::constants::Binding;
use crate::error::SamlError;
use crate::model::{
    AuthnRequest, EndpointUrl, LogoutRequest, MessageId, RelayStateParam, SamlInstant,
};
use crate::name_id_management::ManageNameIdRequest;

mod sealed {
    pub trait Sealed {}
}

/// Message marker support for typed pending state.
#[doc(hidden)]
pub trait PendingMessage: sealed::Sealed {
    /// Private storage for protocol-specific pending fields.
    type Details: Clone + core::fmt::Debug + PartialEq + Eq;
    /// Binding type used for outbound request dispatch.
    type RequestBinding: Copy + core::fmt::Debug + PartialEq + Eq;
    /// Binding type expected for the correlated response.
    type ResponseBinding: Copy + core::fmt::Debug + PartialEq + Eq;
}

/// Protocol-specific pending AuthnRequest details.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthnPendingDetails {
    request_binding: Option<SsoRequestBinding>,
    response_binding: SsoResponseBinding,
    acs: AcsEndpoint,
}

/// Protocol-specific pending LogoutRequest details.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutPendingDetails {
    binding: LogoutBinding,
}

/// Protocol-specific pending ManageNameIDRequest details.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManageNameIdPendingDetails {
    binding: NameIdManagementBinding,
}

impl sealed::Sealed for AuthnRequest {}

impl PendingMessage for AuthnRequest {
    type Details = AuthnPendingDetails;
    type RequestBinding = SsoRequestBinding;
    type ResponseBinding = SsoResponseBinding;
}

impl sealed::Sealed for LogoutRequest {}

impl PendingMessage for LogoutRequest {
    type Details = LogoutPendingDetails;
    type RequestBinding = LogoutBinding;
    type ResponseBinding = LogoutBinding;
}

impl sealed::Sealed for ManageNameIdRequest {}

impl PendingMessage for ManageNameIdRequest {
    type Details = ManageNameIdPendingDetails;
    type RequestBinding = NameIdManagementBinding;
    type ResponseBinding = NameIdManagementBinding;
}

/// Persistable correlation snapshot for a pending SAML message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSnapshot<Message: PendingMessage> {
    /// Correlation ID.
    pub id: String,
    /// Exact RelayState state.
    pub relay_state: RelayStateParam,
    /// Peer entity ID.
    pub peer_entity_id: String,
    /// Expected response binding keyword.
    pub expected_binding: String,
    /// Selected request binding keyword, if tracked.
    pub request_binding: Option<String>,
    /// Selected ACS URL for AuthnRequest snapshots.
    ///
    /// LogoutRequest snapshots leave this empty and [`PendingLogoutRequest::from_snapshot`]
    /// ignores it.
    pub acs_url: String,
    /// Selected ACS binding keyword for AuthnRequest snapshots.
    ///
    /// LogoutRequest snapshots leave this empty and [`PendingLogoutRequest::from_snapshot`]
    /// ignores it.
    pub acs_binding: String,
    /// Selected ACS index for AuthnRequest snapshots, if any.
    ///
    /// LogoutRequest snapshots leave this unset and [`PendingLogoutRequest::from_snapshot`]
    /// ignores it.
    pub acs_index: Option<u16>,
    /// Whether the selected AuthnRequest ACS was default.
    ///
    /// LogoutRequest snapshots leave this false and [`PendingLogoutRequest::from_snapshot`]
    /// ignores it.
    pub acs_is_default: bool,
    /// Issue instant, if recorded.
    pub issued_at: Option<SamlInstant>,
    /// Expiration instant, if recorded.
    pub expires_at: Option<SamlInstant>,
    _message: PhantomData<Message>,
}

impl PendingSnapshot<AuthnRequest> {
    /// Build an AuthnRequest snapshot from persistence fields.
    ///
    /// Snapshots store correlation data without copying keys or peer metadata.
    ///
    /// # Examples
    ///
    /// ```
    /// use saml_rs::{AuthnRequest, PendingSnapshot, RelayStateParam};
    ///
    /// let snapshot = PendingSnapshot::<AuthnRequest>::authn_request(
    ///     "_request123",
    ///     RelayStateParam::absent(),
    ///     "https://idp.example.com/metadata",
    ///     "post",
    ///     "https://sp.example.com/acs",
    ///     "post",
    /// );
    ///
    /// assert_eq!(snapshot.peer_entity_id, "https://idp.example.com/metadata");
    /// assert_eq!(snapshot.acs_url, "https://sp.example.com/acs");
    /// ```
    pub fn authn_request(
        id: impl Into<String>,
        relay_state: RelayStateParam,
        peer_entity_id: impl Into<String>,
        expected_binding: impl Into<String>,
        acs_url: impl Into<String>,
        acs_binding: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            relay_state,
            peer_entity_id: peer_entity_id.into(),
            expected_binding: expected_binding.into(),
            request_binding: None,
            acs_url: acs_url.into(),
            acs_binding: acs_binding.into(),
            acs_index: None,
            acs_is_default: false,
            issued_at: None,
            expires_at: None,
            _message: PhantomData,
        }
    }
}

impl PendingSnapshot<LogoutRequest> {
    /// Build a LogoutRequest snapshot from persistence fields.
    ///
    /// ACS fields are AuthnRequest-only and are intentionally left empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use saml_rs::{LogoutBinding, LogoutRequest, PendingSnapshot, RelayStateParam};
    ///
    /// let snapshot = PendingSnapshot::<LogoutRequest>::logout_request(
    ///     "_logout123",
    ///     RelayStateParam::absent(),
    ///     "https://idp.example.com/metadata",
    ///     LogoutBinding::Post,
    /// );
    ///
    /// assert_eq!(snapshot.expected_binding, "post");
    /// assert!(snapshot.acs_url.is_empty());
    /// ```
    pub fn logout_request(
        id: impl Into<String>,
        relay_state: RelayStateParam,
        peer_entity_id: impl Into<String>,
        binding: LogoutBinding,
    ) -> Self {
        Self {
            id: id.into(),
            relay_state,
            peer_entity_id: peer_entity_id.into(),
            expected_binding: binding.as_binding().short_name().to_string(),
            request_binding: Some(binding.as_binding().short_name().to_string()),
            acs_url: String::new(),
            acs_binding: String::new(),
            acs_index: None,
            acs_is_default: false,
            issued_at: None,
            expires_at: None,
            _message: PhantomData,
        }
    }
}

impl PendingSnapshot<ManageNameIdRequest> {
    /// Build a ManageNameIDRequest snapshot from persistence fields.
    ///
    /// ACS fields are AuthnRequest-only and are left empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use saml_rs::{
    ///     ManageNameIdRequest, NameIdManagementBinding, PendingSnapshot, RelayStateParam,
    /// };
    ///
    /// let snapshot = PendingSnapshot::<ManageNameIdRequest>::manage_name_id_request(
    ///     "_manage123",
    ///     RelayStateParam::absent(),
    ///     "https://idp.example.com/metadata",
    ///     NameIdManagementBinding::Redirect,
    /// );
    ///
    /// assert_eq!(snapshot.expected_binding, "redirect");
    /// ```
    pub fn manage_name_id_request(
        id: impl Into<String>,
        relay_state: RelayStateParam,
        peer_entity_id: impl Into<String>,
        binding: NameIdManagementBinding,
    ) -> Self {
        Self {
            id: id.into(),
            relay_state,
            peer_entity_id: peer_entity_id.into(),
            expected_binding: binding.as_binding().short_name().to_string(),
            request_binding: Some(binding.as_binding().short_name().to_string()),
            acs_url: String::new(),
            acs_binding: String::new(),
            acs_index: None,
            acs_is_default: false,
            issued_at: None,
            expires_at: None,
            _message: PhantomData,
        }
    }
}

/// Pending SAML message correlation state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending<Message: PendingMessage> {
    id: MessageId,
    relay_state: RelayStateParam,
    details: Message::Details,
    peer_entity_id: EntityId,
    issued_at: Option<SamlInstant>,
    expires_at: Option<SamlInstant>,
    _message: PhantomData<Message>,
}

/// Pending AuthnRequest correlation state.
pub type PendingAuthnRequest = Pending<AuthnRequest>;

/// Pending LogoutRequest correlation state.
pub type PendingLogoutRequest = Pending<LogoutRequest>;

/// Pending ManageNameIDRequest correlation state.
pub type PendingManageNameIdRequest = Pending<ManageNameIdRequest>;

impl<Message: PendingMessage> Pending<Message> {
    fn validate_common(
        relay_state: &RelayStateParam,
        peer_entity_id: &EntityId,
    ) -> Result<(), SamlError> {
        relay_state.validate()?;
        EntityId::try_new(peer_entity_id.as_str().to_string())?;
        Ok(())
    }

    fn validate_snapshot_timing(
        issued_at: &Option<SamlInstant>,
        expires_at: &Option<SamlInstant>,
    ) -> Result<(), SamlError> {
        if expires_at.is_some() && issued_at.is_none() {
            return Err(SamlError::Invalid(
                "pending snapshot expiration requires an issue instant".into(),
            ));
        }
        Ok(())
    }

    /// Record an issue instant.
    pub fn with_issue_instant(mut self, issued_at: SamlInstant) -> Self {
        self.issued_at = Some(issued_at);
        self
    }

    /// Record an expiration instant.
    pub fn with_expiration(mut self, expires_at: SamlInstant) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// SAML protocol message ID.
    pub fn id(&self) -> &MessageId {
        &self.id
    }

    /// RelayState state.
    pub fn relay_state(&self) -> &RelayStateParam {
        &self.relay_state
    }

    /// Peer entity ID.
    pub fn peer_entity_id(&self) -> &EntityId {
        &self.peer_entity_id
    }

    /// Issue instant, if recorded.
    pub fn issued_at(&self) -> Option<&SamlInstant> {
        self.issued_at.as_ref()
    }

    /// Expiration instant, if recorded.
    pub fn expires_at(&self) -> Option<&SamlInstant> {
        self.expires_at.as_ref()
    }
}

impl Pending<AuthnRequest> {
    /// Create pending AuthnRequest state without storing keys or metadata.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the RelayState state is malformed,
    /// the IdP entity ID is empty, or the selected ACS binding does not match
    /// the expected response binding.
    pub fn try_new(
        request_id: MessageId,
        relay_state: RelayStateParam,
        acs: AcsEndpoint,
        response_binding: SsoResponseBinding,
        idp_entity_id: EntityId,
    ) -> Result<Self, SamlError> {
        Self::validate_common(&relay_state, &idp_entity_id)?;
        if acs.binding() != response_binding {
            return Err(SamlError::Invalid(
                "ACS binding must match expected response binding".into(),
            ));
        }
        Ok(Self {
            id: request_id,
            relay_state,
            details: AuthnPendingDetails {
                request_binding: None,
                response_binding,
                acs,
            },
            peer_entity_id: idp_entity_id,
            issued_at: None,
            expires_at: None,
            _message: PhantomData,
        })
    }

    /// Record the outbound AuthnRequest binding selected for dispatch.
    pub fn with_request_binding(mut self, request_binding: SsoRequestBinding) -> Self {
        self.details.request_binding = Some(request_binding);
        self
    }

    /// Reconstruct pending AuthnRequest state from a snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when any snapshot field is malformed or
    /// inconsistent.
    ///
    /// # Examples
    ///
    /// ```
    /// use saml_rs::{AuthnRequest, Pending, PendingSnapshot, RelayStateParam};
    ///
    /// let snapshot = PendingSnapshot::<AuthnRequest>::authn_request(
    ///     "_request123",
    ///     RelayStateParam::absent(),
    ///     "https://idp.example.com/metadata",
    ///     "post",
    ///     "https://sp.example.com/acs",
    ///     "post",
    /// );
    /// let pending = Pending::<AuthnRequest>::from_snapshot(snapshot)?;
    ///
    /// assert_eq!(pending.idp_entity_id().as_str(), "https://idp.example.com/metadata");
    /// # Ok::<(), saml_rs::SamlError>(())
    /// ```
    pub fn from_snapshot(snapshot: PendingSnapshot<AuthnRequest>) -> Result<Self, SamlError> {
        snapshot.relay_state.validate()?;
        Self::validate_snapshot_timing(&snapshot.issued_at, &snapshot.expires_at)?;
        let request_id = MessageId::try_new(snapshot.id)?;
        let idp_entity_id = EntityId::try_new(snapshot.peer_entity_id)?;
        let response_binding =
            sso_response_binding_from_snapshot_value(&snapshot.expected_binding)?;
        let acs_binding = sso_response_binding_from_snapshot_value(&snapshot.acs_binding)?;
        let mut acs = AcsEndpoint::new(acs_binding, EndpointUrl::try_new(snapshot.acs_url)?)
            .with_default_flag(snapshot.acs_is_default);
        if let Some(index) = snapshot.acs_index {
            acs = acs.with_index(index);
        }
        let request_binding = snapshot
            .request_binding
            .as_deref()
            .map(sso_request_binding_from_snapshot_value)
            .transpose()?;
        let mut pending = Self::try_new(
            request_id,
            snapshot.relay_state,
            acs,
            response_binding,
            idp_entity_id,
        )?;
        pending.details.request_binding = request_binding;
        pending.issued_at = snapshot.issued_at;
        pending.expires_at = snapshot.expires_at;
        Ok(pending)
    }

    /// Build a persistable snapshot.
    pub fn snapshot(&self) -> PendingSnapshot<AuthnRequest> {
        let mut snapshot = PendingSnapshot::authn_request(
            self.id.as_str(),
            self.relay_state.clone(),
            self.peer_entity_id.as_str(),
            self.details.response_binding.as_binding().short_name(),
            self.details.acs.location().as_str(),
            self.details.acs.binding().as_binding().short_name(),
        );
        snapshot.request_binding = self
            .details
            .request_binding
            .map(|binding| binding.as_binding().short_name().to_string());
        snapshot.acs_index = self.details.acs.index();
        snapshot.acs_is_default = self.details.acs.is_default();
        snapshot.issued_at = self.issued_at.clone();
        snapshot.expires_at = self.expires_at.clone();
        snapshot
    }

    /// Request ID.
    pub fn request_id(&self) -> &MessageId {
        &self.id
    }

    /// Request binding, when tracked.
    pub fn request_binding(&self) -> Option<SsoRequestBinding> {
        self.details.request_binding
    }

    /// Expected response binding.
    pub fn response_binding(&self) -> SsoResponseBinding {
        self.details.response_binding
    }

    /// Selected ACS endpoint.
    pub fn acs(&self) -> &AcsEndpoint {
        &self.details.acs
    }

    /// Selected IdP entity ID.
    pub fn idp_entity_id(&self) -> &EntityId {
        &self.peer_entity_id
    }
}

impl Pending<LogoutRequest> {
    /// Create pending LogoutRequest state without storing keys or metadata.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when RelayState or peer entity ID are malformed.
    pub fn try_new(
        request_id: MessageId,
        relay_state: RelayStateParam,
        binding: LogoutBinding,
        peer_entity_id: EntityId,
    ) -> Result<Self, SamlError> {
        Self::validate_common(&relay_state, &peer_entity_id)?;
        Ok(Self {
            id: request_id,
            relay_state,
            details: LogoutPendingDetails { binding },
            peer_entity_id,
            issued_at: None,
            expires_at: None,
            _message: PhantomData,
        })
    }

    /// Reconstruct pending LogoutRequest state from a snapshot.
    ///
    /// AuthnRequest-only ACS snapshot fields are ignored.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when any snapshot field is malformed or
    /// inconsistent.
    ///
    /// # Examples
    ///
    /// ```
    /// use saml_rs::{LogoutBinding, LogoutRequest, Pending, PendingSnapshot, RelayStateParam};
    ///
    /// let snapshot = PendingSnapshot::<LogoutRequest>::logout_request(
    ///     "_logout123",
    ///     RelayStateParam::absent(),
    ///     "https://idp.example.com/metadata",
    ///     LogoutBinding::Post,
    /// );
    /// let pending = Pending::<LogoutRequest>::from_snapshot(snapshot)?;
    ///
    /// assert_eq!(pending.peer_entity_id().as_str(), "https://idp.example.com/metadata");
    /// # Ok::<(), saml_rs::SamlError>(())
    /// ```
    pub fn from_snapshot(snapshot: PendingSnapshot<LogoutRequest>) -> Result<Self, SamlError> {
        snapshot.relay_state.validate()?;
        Self::validate_snapshot_timing(&snapshot.issued_at, &snapshot.expires_at)?;
        let request_id = MessageId::try_new(snapshot.id)?;
        let peer_entity_id = EntityId::try_new(snapshot.peer_entity_id)?;
        let response_binding = logout_binding_from_snapshot_value(&snapshot.expected_binding)?;
        let request_binding = snapshot
            .request_binding
            .as_deref()
            .map(logout_binding_from_snapshot_value)
            .transpose()?
            .unwrap_or(response_binding);
        if request_binding != response_binding {
            return Err(SamlError::Invalid(
                "logout request and response bindings must match".into(),
            ));
        }
        let mut pending = Self::try_new(
            request_id,
            snapshot.relay_state,
            response_binding,
            peer_entity_id,
        )?;
        pending.issued_at = snapshot.issued_at;
        pending.expires_at = snapshot.expires_at;
        Ok(pending)
    }

    /// Build a persistable snapshot.
    pub fn snapshot(&self) -> PendingSnapshot<LogoutRequest> {
        let mut snapshot = PendingSnapshot::logout_request(
            self.id.as_str(),
            self.relay_state.clone(),
            self.peer_entity_id.as_str(),
            self.details.binding,
        );
        snapshot.issued_at = self.issued_at.clone();
        snapshot.expires_at = self.expires_at.clone();
        snapshot
    }

    /// Logout request binding selected for dispatch.
    pub fn request_binding(&self) -> LogoutBinding {
        self.details.binding
    }

    /// Expected logout response binding.
    pub fn response_binding(&self) -> LogoutBinding {
        self.details.binding
    }
}

impl Pending<ManageNameIdRequest> {
    /// Create pending HTTP-Redirect ManageNameIDRequest state without storing
    /// keys or metadata.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when RelayState or peer entity ID are
    /// malformed, and [`SamlError::UnsupportedBinding`] for
    /// [`NameIdManagementBinding::Soap`], which has no pending browser state.
    pub fn try_new(
        request_id: MessageId,
        relay_state: RelayStateParam,
        binding: NameIdManagementBinding,
        peer_entity_id: EntityId,
    ) -> Result<Self, SamlError> {
        Self::validate_common(&relay_state, &peer_entity_id)?;
        if binding == NameIdManagementBinding::Soap {
            return Err(SamlError::UnsupportedBinding {
                binding: Binding::Soap,
            });
        }
        Ok(Self {
            id: request_id,
            relay_state,
            details: ManageNameIdPendingDetails { binding },
            peer_entity_id,
            issued_at: None,
            expires_at: None,
            _message: PhantomData,
        })
    }

    /// Reconstruct pending ManageNameIDRequest state from a snapshot.
    ///
    /// AuthnRequest-only ACS snapshot fields are ignored.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when any snapshot field is malformed or
    /// inconsistent, or names a binding other than HTTP-Redirect.
    pub fn from_snapshot(
        snapshot: PendingSnapshot<ManageNameIdRequest>,
    ) -> Result<Self, SamlError> {
        snapshot.relay_state.validate()?;
        Self::validate_snapshot_timing(&snapshot.issued_at, &snapshot.expires_at)?;
        let request_id = MessageId::try_new(snapshot.id)?;
        let peer_entity_id = EntityId::try_new(snapshot.peer_entity_id)?;
        let response_binding =
            name_id_management_binding_from_snapshot_value(&snapshot.expected_binding)?;
        let request_binding = snapshot
            .request_binding
            .as_deref()
            .map(name_id_management_binding_from_snapshot_value)
            .transpose()?
            .unwrap_or(response_binding);
        if request_binding != response_binding {
            return Err(SamlError::Invalid(
                "name identifier management request and response bindings must match".into(),
            ));
        }
        let mut pending = Self::try_new(
            request_id,
            snapshot.relay_state,
            response_binding,
            peer_entity_id,
        )?;
        pending.issued_at = snapshot.issued_at;
        pending.expires_at = snapshot.expires_at;
        Ok(pending)
    }

    /// Build a persistable snapshot.
    pub fn snapshot(&self) -> PendingSnapshot<ManageNameIdRequest> {
        let mut snapshot = PendingSnapshot::manage_name_id_request(
            self.id.as_str(),
            self.relay_state.clone(),
            self.peer_entity_id.as_str(),
            self.details.binding,
        );
        snapshot.issued_at = self.issued_at.clone();
        snapshot.expires_at = self.expires_at.clone();
        snapshot
    }

    /// ManageNameIDRequest binding selected for dispatch.
    pub fn request_binding(&self) -> NameIdManagementBinding {
        self.details.binding
    }

    /// Expected ManageNameIDResponse binding.
    pub fn response_binding(&self) -> NameIdManagementBinding {
        self.details.binding
    }
}

fn sso_response_binding_from_snapshot_value(value: &str) -> Result<SsoResponseBinding, SamlError> {
    let binding = Binding::from_short_name(value)
        .or_else(|| Binding::from_urn(value))
        .ok_or(SamlError::UndefinedBinding)?;
    SsoResponseBinding::try_from(binding)
}

fn sso_request_binding_from_snapshot_value(value: &str) -> Result<SsoRequestBinding, SamlError> {
    let binding = Binding::from_short_name(value)
        .or_else(|| Binding::from_urn(value))
        .ok_or(SamlError::UndefinedBinding)?;
    SsoRequestBinding::try_from(binding)
}

fn logout_binding_from_snapshot_value(value: &str) -> Result<LogoutBinding, SamlError> {
    let binding = Binding::from_short_name(value)
        .or_else(|| Binding::from_urn(value))
        .ok_or(SamlError::UndefinedBinding)?;
    LogoutBinding::try_from(binding)
}

fn name_id_management_binding_from_snapshot_value(
    value: &str,
) -> Result<NameIdManagementBinding, SamlError> {
    let binding = Binding::from_short_name(value)
        .or_else(|| Binding::from_urn(value))
        .ok_or(SamlError::UndefinedBinding)?;
    match binding {
        Binding::Redirect => Ok(NameIdManagementBinding::Redirect),
        Binding::Post | Binding::SimpleSign | Binding::Artifact | Binding::Soap => {
            Err(SamlError::UnsupportedBinding { binding })
        }
    }
}

/// Started browser flow with pending state and outbound browser action.
#[derive(Debug, Clone)]
pub struct Started<Message: PendingMessage> {
    /// Pending correlation state.
    pub pending: Pending<Message>,
    /// Outbound browser action.
    pub outbound: Outbound<Message>,
}
