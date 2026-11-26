use crate::browser::{
    Inbound, NameIdManagementBinding, Outbound, PendingManageNameIdRequest, Started,
};
use crate::config::{IdpDescriptor, SpDescriptor};
use crate::constants::Binding;
use crate::entity::{generate_id, EntitySetting};
use crate::flow::MessageAuthentication;
use crate::metadata::{EndpointDirection, Metadata, RoleLocation};
use crate::model::{
    MessageId, NameId, Received, RelayState, ReplayKey, SamlValidationContext, Status,
};
use crate::name_id_management::redirect::{
    create_request, create_response, parse_request, parse_response, request_from_flow,
    response_id_from_flow, InboundValidation, ParsedRequest,
};
use crate::name_id_management::xml::{RequestXml, Requester, ResponseXml};
use crate::name_id_management::{
    ManageNameIdRequest, ManageNameIdResponse, NameIdChange, NameIdManagementReceipt, Refusal,
    RefusedNameIdManagement,
};
use std::time::SystemTime;

use super::super::options::PeerEndpointTransport;
use super::super::peer::{
    ensure_entity_id, ensure_relay_state, peer_endpoint_for_transport, relay_state_from_input, Peer,
};
use super::super::{
    IdentityProvider, ReceiveNameIdManagement, RespondNameIdManagement, SamlError, ServiceProvider,
    StartNameIdManagement,
};

/// Answer to a `ManageNameIDRequest` received over HTTP-Redirect.
pub type NameIdManagementRedirectReceipt = NameIdManagementReceipt<Outbound<ManageNameIdResponse>>;

impl ServiceProvider {
    /// Send `ManageNameIDRequest` to the identity provider over HTTP-Redirect.
    ///
    /// `name_id` is the identifier as both providers know it, with the
    /// `SPProvidedID` most recently set, if any. A persistent identifier
    /// without `NameQualifier` is sent with the identity provider's entity ID,
    /// and one without `SPNameQualifier` with this service provider's.
    /// [`NameIdChange::NewId`] asks the identity provider to send the new
    /// value as `SPProvidedID` from now on. [`NameIdChange::Terminate`] says
    /// this service provider no longer accepts assertions with the
    /// identifier. To end the principal's sessions too, send `LogoutRequest`
    /// first: a `LogoutRequest` must not follow the termination.
    /// The caller's duties after the exchange, such as which identifier to
    /// use next, are listed in `docs/conformance/name-id-management.md#after-the-exchange`.
    ///
    /// `name_id` is sent as the identity provider issued it, without the length
    /// and `entity` checks the identity provider applies.
    ///
    /// The request goes to the identity provider's first HTTP-Redirect
    /// `ManageNameIDService` with an `https` `Location`. With
    /// [`StartNameIdManagement::allow_http`], it goes to the first one.
    ///
    /// Store [`Started::pending`] and redirect the browser to
    /// [`Started::outbound`]. [`Self::finish_name_id_management_redirect`]
    /// reads the answer.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::MissingMetadata`] when this service provider or
    /// the identity provider publishes no HTTP-Redirect `ManageNameIDService`.
    /// Returns [`SamlError::ProtocolProfile`] for a transient identifier.
    /// When no identity-provider endpoint is `https` and
    /// [`StartNameIdManagement::allow_http`] is not selected, the first
    /// endpoint decides the error: [`SamlError::ProtocolProfile`] for a
    /// URL that is not `https`, [`SamlError::Invalid`] for a value that is not
    /// a URL.
    /// Returns [`SamlError::Invalid`] when the NameID format is not an
    /// absolute URI reference, when the `name_id` value, `NameQualifier`,
    /// `SPNameQualifier`, or `SPProvidedID`, or a [`NameIdChange::NewId`]
    /// value, is empty or made only of XML whitespace, or when `allow_http` is
    /// selected and the first endpoint is not an `http` or `https` URL. With
    /// [`IdentifierEncryptionPolicy::EncryptIdentifiers`](crate::IdentifierEncryptionPolicy::EncryptIdentifiers),
    /// returns [`SamlError::MissingMetadata`] when the identity provider role
    /// that publishes the receiving `ManageNameIDService` has no encryption
    /// certificate. Returns another [`SamlError`] when
    /// relay state is invalid, the signing key is missing, or no crypto
    /// provider is enabled.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{IdpDescriptor, NameId, NameIdChange, ServiceProvider, StartNameIdManagement};
    ///
    /// # fn manage(
    /// #     sp: &ServiceProvider,
    /// #     idp: &IdpDescriptor,
    /// #     name_id: &NameId,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let started = sp.start_name_id_management_redirect(
    ///     idp,
    ///     name_id,
    ///     &NameIdChange::NewId("alias-42".into()),
    ///     StartNameIdManagement::new(),
    /// )?;
    /// let location = started.outbound.redirect_url()?;
    /// let snapshot = started.pending.snapshot();
    /// # let _ = (location, snapshot);
    /// # Ok(()) }
    /// ```
    pub fn start_name_id_management_redirect(
        &self,
        idp: &IdpDescriptor,
        name_id: &NameId,
        change: &NameIdChange,
        options: StartNameIdManagement,
    ) -> Result<Started<ManageNameIdRequest>, SamlError> {
        let peer = Peer::from_idp(idp, SystemTime::now())?;
        start(self.local(), peer, name_id, change, options)
    }

    /// Read an identity provider's `ManageNameIDRequest` sent over
    /// HTTP-Redirect.
    ///
    /// A [`NameIdManagementReceipt::Request`] is ready to apply. Answer it
    /// with [`Self::respond_name_id_management_redirect`]. After a
    /// [`NameIdChange::NewId`], expect the new value as the `NameID` content
    /// of later assertions, and use it wherever the changed identifier would
    /// have been used with the identity provider. An `EncryptedID` or
    /// `NewEncryptedID` is decrypted with this service provider's decryption
    /// key. A
    /// [`NameIdManagementReceipt::Refused`] already carries the browser
    /// action that answers the request. It reports a decryption failure, a
    /// request outside the configured age window, an unsupported newer
    /// version, or an identifier and change that do not follow
    /// `ManageNameIDRequestType`. A newer major version adds
    /// `RequestVersionTooHigh` to `VersionMismatch`. Only a request whose
    /// signature verifies, from the identity provider, and at this service
    /// provider's endpoint is refused this way: any other request returns an
    /// error. Version, content, and age refusals come before replay detection,
    /// so a repeated one is refused again. A decryption refusal comes after the
    /// request `ID` is stored, so a repeated one returns
    /// [`SamlError::ReplayDetected`]. A configured
    /// [`SchemaValidator`](crate::SchemaValidator) that rejects the request
    /// returns its error first. The action goes to the identity provider's
    /// `ManageNameIDService` that
    /// [`Self::respond_name_id_management_redirect`] would choose.
    ///
    /// The caller's duties after the exchange, such as which identifier to
    /// use next, are listed in `docs/conformance/name-id-management.md#after-the-exchange`.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when relay state is invalid, the signature is missing or does not verify, the issuer is
    /// not the identity provider, `Destination` is missing or is not the
    /// receiving `ManageNameIDService`, this service provider publishes no
    /// HTTP-Redirect `ManageNameIDService` or several without
    /// [`SamlValidationContext::with_recipient_endpoint`], the message lacks a
    /// readable `ID`, `Version`, `IssueInstant`, or `Issuer`, its version is
    /// too low for a SAML 2.0 response, or replay
    /// validation detects a duplicate. Returns the endpoint errors of
    /// [`Self::respond_name_id_management_redirect`], under `options`, when a
    /// refused request would be answered. A request that would be refused
    /// returns [`SamlError::Invalid`] instead when its `ID` is not an
    /// `xs:NCName`, because the response cannot name it in `InResponseTo`.
    /// Returns [`SamlError::TimeWindowInvalid`] when
    /// [`ReplayPolicy::RequireCache`](crate::ReplayPolicy::RequireCache) is
    /// selected and `validation` has no
    /// [`SamlValidationContext::with_replay_retention`].
    pub fn receive_name_id_management_redirect(
        &self,
        idp: &IdpDescriptor,
        input: Inbound<ManageNameIdRequest>,
        options: ReceiveNameIdManagement,
        validation: SamlValidationContext<'_>,
    ) -> Result<NameIdManagementRedirectReceipt, SamlError> {
        let peer = Peer::from_idp(idp, validation.now())?;
        receive(
            self.local(),
            peer,
            input,
            options.into_transport(),
            validation,
        )
    }

    /// Answer a received `ManageNameIDRequest` over HTTP-Redirect.
    ///
    /// The response is signed and carries the RelayState of the request.
    /// `status` is what the response reports. Pass [`Status::success`] after
    /// applying the change. For an identifier this service provider does not
    /// recognize, pass an error status: [`Status::requester`] or
    /// [`Status::responder`], optionally with
    /// [`SubordinateStatusCode::unknown_principal`](crate::SubordinateStatusCode::unknown_principal).
    ///
    /// The response goes to the first of the identity provider's
    /// HTTP-Redirect `ManageNameIDService` endpoints whose `ResponseLocation`,
    /// or `Location` when it has none, is `https`. With
    /// [`RespondNameIdManagement::allow_http`], it goes to the first one.
    ///
    /// The caller's duties after the exchange, such as which identifier to
    /// use next, are listed in `docs/conformance/name-id-management.md#after-the-exchange`.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::UnsupportedBinding`] when the request arrived over
    /// SOAP.
    /// Returns [`SamlError`] when the request was not received from `idp`,
    /// the identity provider publishes no HTTP-Redirect `ManageNameIDService`,
    /// the signing key is missing, or no crypto provider is enabled. When none
    /// of its endpoints is `https` and
    /// [`RespondNameIdManagement::allow_http`] is not selected, the first
    /// endpoint decides the error: [`SamlError::ProtocolProfile`] for a
    /// URL that is not `https`, [`SamlError::Invalid`] for a value that is not
    /// a URL. With
    /// `allow_http`, returns [`SamlError::Invalid`] when the first endpoint is
    /// not an `http` or `https` URL. Returns [`SamlError::Invalid`] when
    /// `status` has a subordinate code that is not an absolute URI, such as a
    /// relative code read from a peer's response, or when the request `ID` is
    /// not an `xs:NCName`, because the response cannot name it in
    /// `InResponseTo`.
    pub fn respond_name_id_management_redirect(
        &self,
        idp: &IdpDescriptor,
        request: &Received<ManageNameIdRequest>,
        status: &Status,
        options: RespondNameIdManagement,
    ) -> Result<Outbound<ManageNameIdResponse>, SamlError> {
        let peer = Peer::from_idp(idp, SystemTime::now())?;
        respond(
            self.local(),
            peer,
            request,
            status,
            options.into_transport(),
        )
    }

    /// Read the identity provider's `ManageNameIDResponse` to a request this
    /// service provider sent over HTTP-Redirect.
    ///
    /// `Ok` means the identity provider applied the change. It carries the
    /// RelayState received with the response: the value the request carried,
    /// or, when it carried none, whatever the identity provider supplied.
    ///
    /// With [`ReplayPolicy::RequireCache`](crate::ReplayPolicy::RequireCache),
    /// the `ID` of a `Success` response is stored for
    /// [`SamlValidationContext::with_replay_retention`], and a repeated `ID`
    /// returns [`SamlError::ReplayDetected`]. A response with another status is
    /// not stored. [`ReplayPolicy::NoCache`](crate::ReplayPolicy::NoCache) is
    /// enough when your store hands out each pending request once.
    ///
    /// The caller's duties after the exchange, such as which identifier to
    /// use next, are listed in `docs/conformance/name-id-management.md#after-the-exchange`.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::StatusNotSuccess`] with the identity provider's
    /// status codes when it did not apply the change. That status is read
    /// only after the signature, issuer, `InResponseTo`, and `Destination`
    /// checks pass. Returns another [`SamlError`] when the response does not
    /// answer `pending`, its RelayState differs from one the request carried,
    /// or any of those checks or replay validation fails. Returns
    /// [`SamlError::TimeWindowInvalid`] for a `Success` response when
    /// [`ReplayPolicy::RequireCache`](crate::ReplayPolicy::RequireCache) is
    /// selected and `validation` has no
    /// [`SamlValidationContext::with_replay_retention`].
    pub fn finish_name_id_management_redirect(
        &self,
        idp: &IdpDescriptor,
        pending: &PendingManageNameIdRequest,
        input: Inbound<ManageNameIdResponse>,
        validation: SamlValidationContext<'_>,
    ) -> Result<Option<RelayState>, SamlError> {
        let peer = Peer::from_idp(idp, validation.now())?;
        finish(self.local(), peer, pending, input, validation)
    }

    fn local(&self) -> Local<'_> {
        let sp = self.engine();
        Local {
            setting: &sp.setting,
            metadata: sp.metadata.as_metadata(),
            requester: Requester::ServiceProvider,
        }
    }
}

impl IdentityProvider {
    /// Send `ManageNameIDRequest` to the service provider over HTTP-Redirect.
    ///
    /// `name_id` is the identifier as both providers know it, with the
    /// `SPProvidedID` the service provider most recently set, if any. A
    /// `NameId` without a format is sent with the first configured NameID
    /// format, if any, the one [`Self::respond_sso`] writes for it. Pass an
    /// identifier established in another format with that format:
    /// [`NameIdFormat::Unspecified`](crate::NameIdFormat::Unspecified) for
    /// one established without `Format`. A persistent
    /// identifier without `NameQualifier` is sent with this identity
    /// provider's entity ID, and one without `SPNameQualifier` with the
    /// service provider's. [`NameIdChange::NewId`] replaces the `NameID`
    /// value this identity provider sends from now on.
    /// [`NameIdChange::Terminate`] says it no longer issues assertions with
    /// the identifier. To end the principal's sessions too, send
    /// `LogoutRequest` first: a `LogoutRequest` must not follow the
    /// termination.
    /// The caller's duties after the exchange, such as which identifier to
    /// use next, are listed in `docs/conformance/name-id-management.md#after-the-exchange`.
    ///
    /// The request goes to the service provider's first HTTP-Redirect
    /// `ManageNameIDService` with an `https` `Location`. With
    /// [`StartNameIdManagement::allow_http`], it goes to the first one.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::MissingMetadata`] when this identity provider or
    /// the service provider publishes no HTTP-Redirect `ManageNameIDService`.
    /// Returns [`SamlError::ProtocolProfile`] for a transient identifier.
    /// When no service-provider endpoint is `https` and
    /// [`StartNameIdManagement::allow_http`] is not selected, the first
    /// endpoint decides the error: [`SamlError::ProtocolProfile`] for a
    /// URL that is not `https`, [`SamlError::Invalid`] for a value that is not
    /// a URL.
    /// Returns [`SamlError::Invalid`] when the `name_id` value, a qualifier, or
    /// a new value is made only of XML whitespace, a persistent value is
    /// longer than 256 characters, an `entity` value or new value is not an
    /// absolute URI reference of at most 1024 characters with collapsed
    /// whitespace, an `entity` `name_id` has a qualifier, the NameID format is
    /// not an absolute URI reference, or `allow_http` is selected and the first
    /// endpoint is not an `http` or `https` URL.
    /// With
    /// [`IdentifierEncryptionPolicy::EncryptIdentifiers`](crate::IdentifierEncryptionPolicy::EncryptIdentifiers),
    /// returns [`SamlError::MissingMetadata`] when the service provider role
    /// that publishes the receiving `ManageNameIDService` has no encryption
    /// certificate. Returns another [`SamlError`] when
    /// relay state is invalid, the signing key is missing, or no crypto
    /// provider is enabled.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{IdentityProvider, NameId, NameIdChange, SpDescriptor, StartNameIdManagement};
    ///
    /// # fn manage(
    /// #     idp: &IdentityProvider,
    /// #     sp: &SpDescriptor,
    /// #     name_id: &NameId,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let started = idp.start_name_id_management_redirect(
    ///     sp,
    ///     name_id,
    ///     &NameIdChange::Terminate,
    ///     StartNameIdManagement::new(),
    /// )?;
    /// let location = started.outbound.redirect_url()?;
    /// # let _ = location;
    /// # Ok(()) }
    /// ```
    pub fn start_name_id_management_redirect(
        &self,
        sp: &SpDescriptor,
        name_id: &NameId,
        change: &NameIdChange,
        options: StartNameIdManagement,
    ) -> Result<Started<ManageNameIdRequest>, SamlError> {
        let peer = Peer::from_sp(sp, SystemTime::now())?;
        start(self.local(), peer, name_id, change, options)
    }

    /// Read a service provider's `ManageNameIDRequest` sent over
    /// HTTP-Redirect.
    ///
    /// A [`NameIdManagementReceipt::Request`] is ready to apply. Answer it
    /// with [`Self::respond_name_id_management_redirect`]. After a
    /// [`NameIdChange::NewId`], send that value as the identifier's
    /// `SPProvidedID`: [`Self::respond_sso`] writes it from
    /// [`NameId::with_sp_provided_id`]. An `EncryptedID` or `NewEncryptedID` is
    /// decrypted with this identity provider's decryption key. A
    /// [`NameIdManagementReceipt::Refused`] already carries the browser
    /// action that answers the request.
    ///
    /// The caller's duties after the exchange, such as which identifier to
    /// use next, are listed in `docs/conformance/name-id-management.md#after-the-exchange`.
    ///
    /// # Errors
    ///
    /// Returns the errors documented on
    /// [`ServiceProvider::receive_name_id_management_redirect`], with the service
    /// provider as the peer.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     Inbound, ReceiveNameIdManagement, NameIdManagementReceipt, ReplayPolicy,
    ///     RespondNameIdManagement, SamlValidationContext, SpDescriptor, Status,
    ///     SubordinateStatusCode, IdentityProvider,
    /// };
    /// use std::time::SystemTime;
    ///
    /// # fn respond(
    /// #     idp: &IdentityProvider,
    /// #     sp: &SpDescriptor,
    /// #     raw_query: String,
    /// #     recognized: bool,
    /// #     apply: impl Fn(&saml_rs::NameIdChange) -> std::io::Result<()>,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let validation =
    ///     SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache);
    /// let input = Inbound::redirect(raw_query);
    /// let received = idp.receive_name_id_management_redirect(
    ///     sp,
    ///     input,
    ///     ReceiveNameIdManagement::new(),
    ///     validation,
    /// )?;
    /// let response = match received {
    ///     NameIdManagementReceipt::Request(request) => {
    ///         let status = if !recognized {
    ///             Status::requester().with_subordinate(SubordinateStatusCode::unknown_principal())
    ///         } else if apply(request.message().change()).is_ok() {
    ///             Status::success()
    ///         } else {
    ///             Status::responder()
    ///         };
    ///         idp.respond_name_id_management_redirect(
    ///             sp,
    ///             &request,
    ///             &status,
    ///             RespondNameIdManagement::new(),
    ///         )?
    ///     }
    ///     NameIdManagementReceipt::Refused(refused) => refused.response().clone(),
    /// };
    /// let location = response.redirect_url()?;
    /// # let _ = location;
    /// # Ok(()) }
    /// ```
    pub fn receive_name_id_management_redirect(
        &self,
        sp: &SpDescriptor,
        input: Inbound<ManageNameIdRequest>,
        options: ReceiveNameIdManagement,
        validation: SamlValidationContext<'_>,
    ) -> Result<NameIdManagementRedirectReceipt, SamlError> {
        let peer = Peer::from_sp(sp, validation.now())?;
        receive(
            self.local(),
            peer,
            input,
            options.into_transport(),
            validation,
        )
    }

    /// Answer a received `ManageNameIDRequest` over HTTP-Redirect.
    ///
    /// The response is signed and carries the RelayState of the request.
    /// `status` is what the response reports. Pass [`Status::success`] after
    /// applying the change. For an identifier this identity provider does not
    /// recognize, pass an error status:
    /// [`Status::requester`] or [`Status::responder`], optionally with
    /// [`SubordinateStatusCode::unknown_principal`](crate::SubordinateStatusCode::unknown_principal).
    /// The service provider's endpoint is chosen as in
    /// [`ServiceProvider::respond_name_id_management_redirect`].
    ///
    /// # Errors
    ///
    /// Returns the errors documented on
    /// [`ServiceProvider::respond_name_id_management_redirect`], with the service
    /// provider as the peer.
    pub fn respond_name_id_management_redirect(
        &self,
        sp: &SpDescriptor,
        request: &Received<ManageNameIdRequest>,
        status: &Status,
        options: RespondNameIdManagement,
    ) -> Result<Outbound<ManageNameIdResponse>, SamlError> {
        let peer = Peer::from_sp(sp, SystemTime::now())?;
        respond(
            self.local(),
            peer,
            request,
            status,
            options.into_transport(),
        )
    }

    /// Read the service provider's `ManageNameIDResponse` to a request this
    /// identity provider sent over HTTP-Redirect.
    ///
    /// `Ok` means the service provider applied the change. It carries the
    /// RelayState received with the response, as on
    /// [`ServiceProvider::finish_name_id_management_redirect`].
    ///
    /// # Errors
    ///
    /// Returns the errors documented on
    /// [`ServiceProvider::finish_name_id_management_redirect`], with the service
    /// provider as the peer.
    pub fn finish_name_id_management_redirect(
        &self,
        sp: &SpDescriptor,
        pending: &PendingManageNameIdRequest,
        input: Inbound<ManageNameIdResponse>,
        validation: SamlValidationContext<'_>,
    ) -> Result<Option<RelayState>, SamlError> {
        let peer = Peer::from_sp(sp, validation.now())?;
        finish(self.local(), peer, pending, input, validation)
    }

    fn local(&self) -> Local<'_> {
        let idp = self.engine();
        Local {
            setting: &idp.setting,
            metadata: idp.metadata.as_metadata(),
            requester: Requester::IdentityProvider,
        }
    }
}

#[derive(Clone, Copy)]
struct Local<'a> {
    setting: &'a EntitySetting,
    metadata: &'a Metadata,
    requester: Requester,
}

impl Local<'_> {
    fn entity_id(&self) -> Result<String, SamlError> {
        self.setting
            .entity_id
            .clone()
            .or_else(|| self.metadata.entity_id().map(str::to_string))
            .ok_or_else(|| SamlError::MissingMetadata("entityID".into()))
    }
}

fn start(
    local: Local<'_>,
    peer: Peer<'_>,
    name_id: &NameId,
    change: &NameIdChange,
    options: StartNameIdManagement,
) -> Result<Started<ManageNameIdRequest>, SamlError> {
    if let Some(relay_state) = &options.relay_state {
        relay_state.ensure_sendable()?;
    }
    local_locations(local.metadata, EndpointDirection::Response)?;
    let receiver = peer_destination(&peer, EndpointDirection::Request, options.transport())?;
    let issuer = local.entity_id()?;
    let (idp_entity_id, sp_entity_id) = match local.requester {
        Requester::IdentityProvider => (issuer.as_str(), peer.entity_id.as_str()),
        Requester::ServiceProvider => (peer.entity_id.as_str(), issuer.as_str()),
    };
    let id = generate_id();
    let context = create_request(
        local.setting,
        peer.metadata,
        receiver.role,
        &RequestXml {
            id: &id,
            issuer: &issuer,
            destination: &receiver.location,
            name_id,
            change,
            requester: local.requester,
            default_format: local.setting.default_name_id_format(),
            idp_entity_id,
            sp_entity_id,
        },
        options.identifier_encryption,
        options.relay_state.as_ref().map(RelayState::as_str),
    )?;
    let outbound = Outbound::<ManageNameIdRequest>::from_context(context)?;
    let pending = PendingManageNameIdRequest::new(
        outbound.id().clone(),
        options.relay_state,
        peer.entity_id.clone(),
    );
    Ok(Started { pending, outbound })
}

fn receive(
    local: Local<'_>,
    peer: Peer<'_>,
    input: Inbound<ManageNameIdRequest>,
    transport: PeerEndpointTransport,
    validation: SamlValidationContext<'_>,
) -> Result<NameIdManagementRedirectReceipt, SamlError> {
    require_redirect_input(&input)?;
    let relay_state = relay_state_from_input(&input)?;
    let locations = local_locations(local.metadata, EndpointDirection::Request)?;
    let expected_recipient = validation.resolve_recipient_endpoint(&locations)?;
    let request = input.into_http_request()?;
    let flow = parse_request(
        local.setting,
        peer.metadata,
        &request,
        InboundValidation {
            expected_recipient: &expected_recipient,
            peer_hmac_secret: peer.hmac_secret,
            now: validation.now(),
            clock_skew: validation.clock_skew(),
        },
    )?;
    let request = request_from_flow(&flow, local.setting)?;
    ensure_entity_id(&request.issuer, peer.entity_id)?;
    let id = request.id.clone();
    match request.validate_and_decrypt(&flow, local.setting, validation)? {
        ParsedRequest::Plain(message) => {
            Ok(NameIdManagementReceipt::Request(Box::new(Received::new(
                message,
                Binding::Redirect,
                relay_state,
                MessageAuthentication::Authenticated,
            ))))
        }
        ParsedRequest::Refused(refusal) => refuse(
            local,
            &peer,
            &id,
            relay_state.as_ref().map(RelayState::as_str),
            refusal,
            transport,
        ),
    }
}

fn refuse(
    local: Local<'_>,
    peer: &Peer<'_>,
    in_response_to: &MessageId,
    relay_state: Option<&str>,
    refusal: Refusal,
    transport: PeerEndpointTransport,
) -> Result<NameIdManagementRedirectReceipt, SamlError> {
    let response = response_outbound(
        local,
        peer,
        in_response_to.as_str(),
        &refusal.status(),
        relay_state,
        transport,
    )?;
    Ok(NameIdManagementReceipt::Refused(
        RefusedNameIdManagement::new(response, refusal),
    ))
}

fn respond(
    local: Local<'_>,
    peer: Peer<'_>,
    request: &Received<ManageNameIdRequest>,
    status: &Status,
    transport: PeerEndpointTransport,
) -> Result<Outbound<ManageNameIdResponse>, SamlError> {
    if request.binding() != Binding::Redirect {
        return Err(SamlError::UnsupportedBinding {
            binding: Binding::Redirect,
        });
    }
    ensure_entity_id(request.message().issuer(), peer.entity_id)?;
    response_outbound(
        local,
        &peer,
        request.message().id().as_str(),
        status,
        request.relay_state().map(RelayState::as_str),
        transport,
    )
}

fn response_outbound(
    local: Local<'_>,
    peer: &Peer<'_>,
    in_response_to: &str,
    status: &Status,
    relay_state: Option<&str>,
    transport: PeerEndpointTransport,
) -> Result<Outbound<ManageNameIdResponse>, SamlError> {
    let destination = peer_destination(peer, EndpointDirection::Response, transport)?.location;
    let context = create_response(
        local.setting,
        &ResponseXml {
            id: &generate_id(),
            issuer: &local.entity_id()?,
            destination: Some(&destination),
            in_response_to,
            status,
        },
        relay_state,
    )?;
    Outbound::<ManageNameIdResponse>::echoing_received_relay_state(context)
}

fn finish(
    local: Local<'_>,
    peer: Peer<'_>,
    pending: &PendingManageNameIdRequest,
    input: Inbound<ManageNameIdResponse>,
    mut validation: SamlValidationContext<'_>,
) -> Result<Option<RelayState>, SamlError> {
    ensure_entity_id(pending.peer_entity_id(), peer.entity_id)?;
    require_redirect_input(&input)?;
    let relay_state = relay_state_from_input(&input)?;
    ensure_relay_state(pending.relay_state(), relay_state.as_ref())?;
    let locations = local_locations(local.metadata, EndpointDirection::Response)?;
    let expected_recipient = validation.resolve_recipient_endpoint(&locations)?;
    let request = input.into_http_request()?;
    let flow = parse_response(
        local.setting,
        peer.metadata,
        &request,
        pending.request_id().as_str(),
        InboundValidation {
            expected_recipient: &expected_recipient,
            peer_hmac_secret: peer.hmac_secret,
            now: validation.now(),
            clock_skew: validation.clock_skew(),
        },
    )?;
    validation.check_and_store_message_replay(ReplayKey::ManageNameIdResponse(
        response_id_from_flow(&flow, local.setting.xml_limits)?,
    ))?;
    Ok(relay_state)
}

fn require_redirect_input<Message>(input: &Inbound<Message>) -> Result<(), SamlError> {
    let binding = input.binding();
    if binding == Binding::from(NameIdManagementBinding::Redirect) {
        return Ok(());
    }
    Err(SamlError::UnsupportedBinding { binding })
}

fn peer_destination(
    peer: &Peer<'_>,
    direction: EndpointDirection,
    transport: PeerEndpointTransport,
) -> Result<RoleLocation, SamlError> {
    let endpoints = peer
        .metadata
        .manage_name_id_services(Binding::from(NameIdManagementBinding::Redirect), direction);
    peer_endpoint_for_transport(
        endpoints,
        transport,
        "name identifier management",
        "ManageNameIDService",
    )
}

fn local_locations(
    metadata: &Metadata,
    direction: EndpointDirection,
) -> Result<Vec<String>, SamlError> {
    let locations = metadata.manage_name_id_service_locations(
        Binding::from(NameIdManagementBinding::Redirect),
        direction,
    );
    if locations.is_empty() {
        return Err(SamlError::MissingMetadata("ManageNameIDService".into()));
    }
    Ok(locations)
}
