use crate::browser::{
    BrowserInput, NameIdManagementBinding, Outbound, PendingManageNameIdRequest, Started,
};
use crate::config::{EntityId, HmacSecret, IdpDescriptor, SpDescriptor};
use crate::entity::{generate_id, EntitySetting};
use crate::error::SamlError as Error;
use crate::flow::HttpRequest;
use crate::metadata::{EndpointDirection, Metadata};
use crate::model::{MessageId, NameId, Received, ReplayKey, SamlValidationContext, Status};
use crate::name_id_management::redirect::{
    create_request, create_response, parse_request, parse_response, request_from_flow,
    response_id_from_flow, InboundValidation, ParsedRequest,
};
use crate::name_id_management::xml::{RequestXml, Requester, ResponseXml};
use crate::name_id_management::{
    ManageNameIdRequest, ManageNameIdResponse, NameIdChange, NameIdManagementRefusal,
    ReceivedNameIdManagement, RefusedNameIdManagement,
};

use super::super::raw_mapping::{
    ensure_entity_id, ensure_relay_state, input_binding, raw_idp_descriptor, raw_sp_descriptor,
    relay_state_from_input,
};
use super::super::{
    Idp, ReceiveNameIdManagement, RespondNameIdManagement, Saml, SamlError, Sp,
    StartNameIdManagement,
};

/// Answer to a `ManageNameIDRequest` received over HTTP-Redirect.
pub type ReceivedNameIdManagementRedirect =
    ReceivedNameIdManagement<Outbound<ManageNameIdResponse>>;

impl Saml<Sp> {
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
    ///
    /// Store [`Started::pending`] and redirect the browser to
    /// [`Started::outbound`]. [`Self::finish_name_id_management_redirect`]
    /// reads the answer.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::MissingMetadata`] when this service provider or
    /// the identity provider publishes no HTTP-Redirect `ManageNameIDService`.
    /// Returns [`SamlError::ProtocolProfile`] for a transient identifier, and
    /// for an `http` identity-provider endpoint unless
    /// [`StartNameIdManagement::allow_http_name_id_management`] is selected.
    /// Returns [`SamlError::Invalid`] when the NameID format is not an
    /// absolute URI reference. Returns another [`SamlError`] when relay state
    /// is invalid, the signing key is missing, or no crypto provider is
    /// enabled.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{IdpDescriptor, NameId, NameIdChange, Saml, StartNameIdManagement};
    ///
    /// # fn manage(
    /// #     sp: &Saml<saml_rs::Sp>,
    /// #     idp: &IdpDescriptor,
    /// #     name_id: &NameId,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let started = sp.start_name_id_management_redirect(
    ///     idp,
    ///     name_id,
    ///     &NameIdChange::NewId("alias-42".into()),
    ///     StartNameIdManagement::redirect(),
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
        let raw_idp = raw_idp_descriptor(idp)?;
        start(
            self.local(),
            Peer::new(idp.entity_id(), &raw_idp.metadata, &raw_idp.setting),
            name_id,
            change,
            options,
        )
    }

    /// Read an identity provider's `ManageNameIDRequest` sent over
    /// HTTP-Redirect.
    ///
    /// A [`ReceivedNameIdManagement::Request`] is ready to apply. Answer it
    /// with [`Self::respond_name_id_management_redirect`]. After a
    /// [`NameIdChange::NewId`], expect the new value as the `NameID` content
    /// of later assertions. An `EncryptedID` or `NewEncryptedID` is decrypted
    /// with this service provider's decryption key. A
    /// [`ReceivedNameIdManagement::Refused`] already carries the browser
    /// action that answers the request: one of those elements does not
    /// decrypt, or the `Version` is not `2.0`. That action goes to the
    /// identity provider's `ManageNameIDService` under `options`.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the input is not HTTP-Redirect, relay state
    /// is invalid, the signature is missing or does not verify, the issuer is
    /// not the identity provider, `Destination` is missing or is not the
    /// receiving `ManageNameIDService`, this service provider publishes no
    /// HTTP-Redirect `ManageNameIDService` or several without
    /// [`SamlValidationContext::with_recipient_endpoint`], the message is
    /// malformed, or replay validation detects a duplicate. Returns
    /// [`SamlError::ProtocolProfile`] when a refused request would be answered
    /// at an `http` endpoint and
    /// [`ReceiveNameIdManagement::allow_http_name_id_management`] is not
    /// selected.
    pub fn receive_name_id_management_redirect(
        &self,
        idp: &IdpDescriptor,
        input: BrowserInput<ManageNameIdRequest>,
        options: ReceiveNameIdManagement,
        validation: SamlValidationContext<'_>,
    ) -> Result<ReceivedNameIdManagementRedirect, SamlError> {
        let raw_idp = raw_idp_descriptor(idp)?;
        receive(
            self.local(),
            Peer::new(idp.entity_id(), &raw_idp.metadata, &raw_idp.setting),
            input,
            options,
            validation,
        )
    }

    /// Answer a received `ManageNameIDRequest` over HTTP-Redirect.
    ///
    /// The response is signed and carries the RelayState of the request.
    /// Pass [`RespondNameIdManagement::status`] with an error status for an
    /// identifier this service provider does not recognize.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the request was not received from `idp`,
    /// the identity provider publishes no HTTP-Redirect `ManageNameIDService`,
    /// that endpoint is `http` and
    /// [`RespondNameIdManagement::allow_http_name_id_management`] is not
    /// selected, the signing key is missing, or no crypto provider is
    /// enabled.
    pub fn respond_name_id_management_redirect(
        &self,
        idp: &IdpDescriptor,
        request: &Received<ManageNameIdRequest>,
        options: RespondNameIdManagement,
    ) -> Result<Outbound<ManageNameIdResponse>, SamlError> {
        let raw_idp = raw_idp_descriptor(idp)?;
        respond(
            self.local(),
            Peer::new(idp.entity_id(), &raw_idp.metadata, &raw_idp.setting),
            request,
            options,
        )
    }

    /// Read the identity provider's `ManageNameIDResponse` to a request this
    /// service provider sent over HTTP-Redirect.
    ///
    /// `Ok` means the identity provider applied the change.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::StatusNotSuccess`] with the identity provider's
    /// status codes when it did not apply the change. That status is read
    /// only after the signature, issuer, `InResponseTo`, and `Destination`
    /// checks pass. Returns another [`SamlError`] when the response does not
    /// answer `pending`, its RelayState differs, or any of those checks or
    /// replay validation fails.
    pub fn finish_name_id_management_redirect(
        &self,
        idp: &IdpDescriptor,
        pending: &PendingManageNameIdRequest,
        input: BrowserInput<ManageNameIdResponse>,
        validation: SamlValidationContext<'_>,
    ) -> Result<(), SamlError> {
        let raw_idp = raw_idp_descriptor(idp)?;
        finish(
            self.local(),
            Peer::new(idp.entity_id(), &raw_idp.metadata, &raw_idp.setting),
            pending,
            input,
            validation,
        )
    }

    fn local(&self) -> Local<'_> {
        let sp = self.raw_service_provider();
        Local {
            setting: &sp.setting,
            metadata: &sp.metadata,
            requester: Requester::ServiceProvider,
        }
    }
}

impl Saml<Idp> {
    /// Send `ManageNameIDRequest` to the service provider over HTTP-Redirect.
    ///
    /// `name_id` is the identifier as both providers know it, with the
    /// `SPProvidedID` the service provider most recently set, if any. A
    /// `NameId` without a format is sent with the first configured NameID
    /// format, the one [`Self::respond_sso`] writes for it. A persistent
    /// identifier without `NameQualifier` is sent with this identity
    /// provider's entity ID, and one without `SPNameQualifier` with the
    /// service provider's. [`NameIdChange::NewId`] replaces the `NameID`
    /// value this identity provider sends from now on.
    /// [`NameIdChange::Terminate`] says it no longer issues assertions with
    /// the identifier. To end the principal's sessions too, send
    /// `LogoutRequest` first: a `LogoutRequest` must not follow the
    /// termination.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::MissingMetadata`] when this identity provider or
    /// the service provider publishes no HTTP-Redirect `ManageNameIDService`.
    /// Returns [`SamlError::ProtocolProfile`] for a transient identifier, and
    /// for an `http` service-provider endpoint unless
    /// [`StartNameIdManagement::allow_http_name_id_management`] is selected.
    /// Returns [`SamlError::Invalid`] when a persistent value is longer than
    /// 256 characters or the NameID format is not an absolute URI reference.
    /// Returns another [`SamlError`] when relay state is
    /// invalid, the signing key is missing, or no crypto provider is
    /// enabled.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{NameId, NameIdChange, Saml, SpDescriptor, StartNameIdManagement};
    ///
    /// # fn manage(
    /// #     idp: &Saml<saml_rs::Idp>,
    /// #     sp: &SpDescriptor,
    /// #     name_id: &NameId,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let started = idp.start_name_id_management_redirect(
    ///     sp,
    ///     name_id,
    ///     &NameIdChange::Terminate,
    ///     StartNameIdManagement::redirect(),
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
        let raw_sp = raw_sp_descriptor(sp)?;
        start(
            self.local(),
            Peer::new(sp.entity_id(), &raw_sp.metadata, &raw_sp.setting),
            name_id,
            change,
            options,
        )
    }

    /// Read a service provider's `ManageNameIDRequest` sent over
    /// HTTP-Redirect.
    ///
    /// A [`ReceivedNameIdManagement::Request`] is ready to apply. Answer it
    /// with [`Self::respond_name_id_management_redirect`]. After a
    /// [`NameIdChange::NewId`], send that value as the identifier's
    /// `SPProvidedID`: [`Self::respond_sso`] writes it from
    /// [`NameId::with_qualifiers`]. An `EncryptedID` or `NewEncryptedID` is
    /// decrypted with this identity provider's decryption key. A
    /// [`ReceivedNameIdManagement::Refused`] already carries the browser
    /// action that answers the request.
    ///
    /// # Errors
    ///
    /// Returns the errors documented on
    /// [`Saml::<Sp>::receive_name_id_management_redirect`], with the service
    /// provider as the peer.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     BrowserInput, ManageNameIdRequest, ReceiveNameIdManagement, ReceivedNameIdManagement,
    ///     ReplayPolicy, RespondNameIdManagement, Saml, SamlValidationContext, SpDescriptor,
    /// };
    /// use std::time::SystemTime;
    ///
    /// # fn respond(
    /// #     idp: &Saml<saml_rs::Idp>,
    /// #     sp: &SpDescriptor,
    /// #     raw_query: String,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let validation =
    ///     SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility);
    /// let input = BrowserInput::<ManageNameIdRequest>::redirect(raw_query);
    /// let received = idp.receive_name_id_management_redirect(
    ///     sp,
    ///     input,
    ///     ReceiveNameIdManagement::redirect(),
    ///     validation,
    /// )?;
    /// let response = match received {
    ///     ReceivedNameIdManagement::Request(request) => idp
    ///         .respond_name_id_management_redirect(sp, &request, RespondNameIdManagement::redirect())?,
    ///     ReceivedNameIdManagement::Refused(refused) => refused.response().clone(),
    /// };
    /// let location = response.redirect_url()?;
    /// # let _ = location;
    /// # Ok(()) }
    /// ```
    pub fn receive_name_id_management_redirect(
        &self,
        sp: &SpDescriptor,
        input: BrowserInput<ManageNameIdRequest>,
        options: ReceiveNameIdManagement,
        validation: SamlValidationContext<'_>,
    ) -> Result<ReceivedNameIdManagementRedirect, SamlError> {
        let raw_sp = raw_sp_descriptor(sp)?;
        receive(
            self.local(),
            Peer::new(sp.entity_id(), &raw_sp.metadata, &raw_sp.setting),
            input,
            options,
            validation,
        )
    }

    /// Answer a received `ManageNameIDRequest` over HTTP-Redirect.
    ///
    /// The response is signed and carries the RelayState of the request.
    ///
    /// # Errors
    ///
    /// Returns the errors documented on
    /// [`Saml::<Sp>::respond_name_id_management_redirect`], with the service
    /// provider as the peer.
    pub fn respond_name_id_management_redirect(
        &self,
        sp: &SpDescriptor,
        request: &Received<ManageNameIdRequest>,
        options: RespondNameIdManagement,
    ) -> Result<Outbound<ManageNameIdResponse>, SamlError> {
        let raw_sp = raw_sp_descriptor(sp)?;
        respond(
            self.local(),
            Peer::new(sp.entity_id(), &raw_sp.metadata, &raw_sp.setting),
            request,
            options,
        )
    }

    /// Read the service provider's `ManageNameIDResponse` to a request this
    /// identity provider sent over HTTP-Redirect.
    ///
    /// `Ok` means the service provider applied the change.
    ///
    /// # Errors
    ///
    /// Returns the errors documented on
    /// [`Saml::<Sp>::finish_name_id_management_redirect`], with the service
    /// provider as the peer.
    pub fn finish_name_id_management_redirect(
        &self,
        sp: &SpDescriptor,
        pending: &PendingManageNameIdRequest,
        input: BrowserInput<ManageNameIdResponse>,
        validation: SamlValidationContext<'_>,
    ) -> Result<(), SamlError> {
        let raw_sp = raw_sp_descriptor(sp)?;
        finish(
            self.local(),
            Peer::new(sp.entity_id(), &raw_sp.metadata, &raw_sp.setting),
            pending,
            input,
            validation,
        )
    }

    fn local(&self) -> Local<'_> {
        let idp = self.raw_identity_provider();
        Local {
            setting: &idp.setting,
            metadata: &idp.metadata,
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
            .or_else(|| self.metadata.get_entity_id().map(str::to_string))
            .ok_or_else(|| Error::MissingMetadata("entityID".into()))
    }
}

struct Peer<'a> {
    entity_id: &'a EntityId,
    metadata: &'a Metadata,
    hmac_secret: Option<&'a HmacSecret>,
}

impl<'a> Peer<'a> {
    fn new(entity_id: &'a EntityId, metadata: &'a Metadata, setting: &'a EntitySetting) -> Self {
        Self {
            entity_id,
            metadata,
            hmac_secret: setting.hmac_secret.as_ref(),
        }
    }
}

fn start(
    local: Local<'_>,
    peer: Peer<'_>,
    name_id: &NameId,
    change: &NameIdChange,
    options: StartNameIdManagement,
) -> Result<Started<ManageNameIdRequest>, SamlError> {
    options.relay_state.validate()?;
    local_locations(local.metadata, EndpointDirection::Response)?;
    let destination = peer_location(&peer, EndpointDirection::Request)?;
    if !options.allows_http() {
        require_https(&destination)?;
    }
    let issuer = local.entity_id()?;
    let (idp_entity_id, sp_entity_id) = match local.requester {
        Requester::IdentityProvider => (issuer.as_str(), peer.entity_id.as_str()),
        Requester::ServiceProvider => (peer.entity_id.as_str(), issuer.as_str()),
    };
    let id = generate_id();
    let context = create_request(
        local.setting,
        peer.metadata,
        &RequestXml {
            id: &id,
            issuer: &issuer,
            destination: &destination,
            name_id,
            change,
            requester: local.requester,
            default_format: local.setting.default_name_id_format(),
            idp_entity_id,
            sp_entity_id,
        },
        options.identifier_encryption,
        options.relay_state.as_deref(),
    )?;
    let outbound = Outbound::<ManageNameIdRequest>::try_from(context)?;
    let pending = PendingManageNameIdRequest::try_new(
        outbound.id().clone(),
        options.relay_state,
        NameIdManagementBinding::Redirect,
        peer.entity_id.clone(),
    )?;
    Ok(Started { pending, outbound })
}

fn receive(
    local: Local<'_>,
    peer: Peer<'_>,
    input: BrowserInput<ManageNameIdRequest>,
    options: ReceiveNameIdManagement,
    mut validation: SamlValidationContext<'_>,
) -> Result<ReceivedNameIdManagementRedirect, SamlError> {
    require_redirect_input(&input)?;
    let relay_state = relay_state_from_input(&input)?;
    let locations = local_locations(local.metadata, EndpointDirection::Request)?;
    let expected_recipient = validation.resolve_recipient_endpoint(&locations)?;
    let request = HttpRequest::try_from(input)?;
    let flow = parse_request(
        local.setting,
        peer.metadata,
        &request,
        InboundValidation {
            expected_recipient: &expected_recipient,
            peer_hmac_secret: peer.hmac_secret,
            now: validation.now(),
            clock_drifts: validation.clock_skew().as_millis(),
        },
    )?;
    let parsed = request_from_flow(&flow, local.setting)?;
    let (id, issuer) = match &parsed {
        ParsedRequest::Plain(message) => (message.id().clone(), message.issuer().clone()),
        ParsedRequest::Refused { id, issuer, .. } => (id.clone(), issuer.clone()),
    };
    ensure_entity_id(&issuer, peer.entity_id)?;
    validation.check_and_store_message_replay(ReplayKey::ManageNameIdRequestId(id.clone()))?;
    match parsed {
        ParsedRequest::Plain(message) => Ok(ReceivedNameIdManagement::Request(Box::new(
            Received::new(message).with_relay_state(relay_state),
        ))),
        ParsedRequest::Refused {
            reason,
            decryption_error,
            ..
        } => refuse(
            local,
            &peer,
            &id,
            relay_state.as_deref(),
            reason,
            decryption_error,
            options.allows_http(),
        ),
    }
}

fn refuse(
    local: Local<'_>,
    peer: &Peer<'_>,
    in_response_to: &MessageId,
    relay_state: Option<&str>,
    reason: NameIdManagementRefusal,
    decryption_error: Option<SamlError>,
    allows_http: bool,
) -> Result<ReceivedNameIdManagementRedirect, SamlError> {
    let response = response_outbound(
        local,
        peer,
        in_response_to.as_str(),
        &reason.status(),
        relay_state,
        allows_http,
    )?;
    Ok(ReceivedNameIdManagement::Refused(
        RefusedNameIdManagement::new(response, reason, decryption_error),
    ))
}

fn respond(
    local: Local<'_>,
    peer: Peer<'_>,
    request: &Received<ManageNameIdRequest>,
    options: RespondNameIdManagement,
) -> Result<Outbound<ManageNameIdResponse>, SamlError> {
    ensure_entity_id(request.message().issuer(), peer.entity_id)?;
    let status = options.status.clone().unwrap_or_else(Status::success);
    response_outbound(
        local,
        &peer,
        request.message().id().as_str(),
        &status,
        request.relay_state().as_deref(),
        options.allows_http(),
    )
}

fn response_outbound(
    local: Local<'_>,
    peer: &Peer<'_>,
    in_response_to: &str,
    status: &Status,
    relay_state: Option<&str>,
    allows_http: bool,
) -> Result<Outbound<ManageNameIdResponse>, SamlError> {
    let destination = peer_location(peer, EndpointDirection::Response)?;
    if !allows_http {
        require_https(&destination)?;
    }
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
    Outbound::<ManageNameIdResponse>::try_from(context)
}

fn finish(
    local: Local<'_>,
    peer: Peer<'_>,
    pending: &PendingManageNameIdRequest,
    input: BrowserInput<ManageNameIdResponse>,
    mut validation: SamlValidationContext<'_>,
) -> Result<(), SamlError> {
    ensure_entity_id(pending.peer_entity_id(), peer.entity_id)?;
    require_redirect_input(&input)?;
    ensure_relay_state(pending.relay_state(), &relay_state_from_input(&input)?)?;
    let locations = local_locations(local.metadata, EndpointDirection::Response)?;
    let expected_recipient = validation.resolve_recipient_endpoint(&locations)?;
    let request = HttpRequest::try_from(input)?;
    let flow = parse_response(
        local.setting,
        peer.metadata,
        &request,
        pending.id().as_str(),
        InboundValidation {
            expected_recipient: &expected_recipient,
            peer_hmac_secret: peer.hmac_secret,
            now: validation.now(),
            clock_drifts: validation.clock_skew().as_millis(),
        },
    )?;
    validation.check_and_store_message_replay(ReplayKey::ManageNameIdResponseId(
        response_id_from_flow(&flow, local.setting.xml_limits)?,
    ))
}

fn require_redirect_input<Message>(input: &BrowserInput<Message>) -> Result<(), SamlError> {
    let binding = input_binding(input);
    if binding == NameIdManagementBinding::Redirect.as_binding() {
        return Ok(());
    }
    Err(Error::UnsupportedBinding { binding })
}

fn peer_location(peer: &Peer<'_>, direction: EndpointDirection) -> Result<String, SamlError> {
    peer.metadata
        .manage_name_id_service_locations(NameIdManagementBinding::Redirect.as_binding(), direction)
        .into_iter()
        .next()
        .ok_or_else(|| Error::MissingMetadata("ManageNameIDService".into()))
}

fn local_locations(
    metadata: &Metadata,
    direction: EndpointDirection,
) -> Result<Vec<String>, SamlError> {
    let locations = metadata.manage_name_id_service_locations(
        NameIdManagementBinding::Redirect.as_binding(),
        direction,
    );
    if locations.is_empty() {
        return Err(Error::MissingMetadata("ManageNameIDService".into()));
    }
    Ok(locations)
}

fn require_https(endpoint: &str) -> Result<(), SamlError> {
    let url = url::Url::parse(endpoint).map_err(|error| {
        Error::Invalid(format!(
            "ManageNameIDService location is not a URL: {error}"
        ))
    })?;
    if url.scheme() == "https" {
        return Ok(());
    }
    Err(Error::ProtocolProfile(
        "name identifier management sends the user agent to an https ManageNameIDService unless allow_http_name_id_management is selected".into(),
    ))
}
