use crate::browser::{Inbound, LogoutBinding, Outbound, PendingLogoutRequest, Started};
use crate::config::{IdpDescriptor, NameIdFormat, SpDescriptor};
use crate::constants::Binding;
use crate::entity::{capture_idp_issuance_window, now_iso8601, EntitySetting};
use crate::logout::{
    create_logout_request_for_subject_inner, create_logout_response_inner, decrypt_encrypted_id,
    has_async_slo_marker, parse_logout_request_at, parse_logout_response_at, CreatedLogoutRequest,
    LogoutFlowValidation, LogoutReceipt, LogoutRequestInput, LogoutRequestSubject,
    LogoutRequestValidation, LogoutResponseInput,
};
use crate::metadata::{EndpointDirection, Metadata};
use crate::model::{
    IdpLogoutAction, LogoutCompleted, LogoutRequest, LogoutResponse, LogoutSubject, Received,
    RefusedLogoutRequest, RelayState, ReplayKey, SamlInstant, SamlValidationContext, SessionIndex,
    Status,
};
use crate::xml::protocol_element::parse_saml_with_limits;
use crate::xml::OutboundNameIdQualifiers;
use std::time::SystemTime;

use super::options::PeerEndpointTransport;
use super::peer::{
    ensure_entity_id, ensure_https_endpoint, ensure_relay_state, relay_state_from_input, Peer,
};
use super::{IdentityProvider, RespondSlo, SamlError, ServiceProvider, StartSlo};

impl ServiceProvider {
    /// Start SP-initiated Single Logout.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when relay state is invalid, IdP metadata cannot
    /// be parsed, a compatible logout endpoint or signing key is missing, the
    /// selected binding is unsupported, the subject's NameID format is not an
    /// absolute URI reference, or logout request creation fails.
    /// The participant must supply a `SessionIndex`. A browser endpoint must
    /// use HTTPS unless [`StartSlo::allow_http`] is selected.
    /// [`StartSlo::identifier_encryption`] returns
    /// [`SamlError::MissingMetadata`] when the peer metadata has no encryption
    /// certificate.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{IdpDescriptor, LogoutSubject, ServiceProvider, StartSlo};
    ///
    /// # fn logout(
    /// #     sp: &ServiceProvider,
    /// #     idp: &IdpDescriptor,
    /// #     subject: LogoutSubject,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let started = sp.start_slo(idp, subject, StartSlo::post())?;
    /// let form = started.outbound.post_form()?;
    /// let snapshot = started.pending.snapshot();
    /// # let _ = (form, snapshot);
    /// # Ok(()) }
    /// ```
    #[expect(
        clippy::needless_pass_by_value,
        reason = "This public operation takes ownership of the logout subject"
    )]
    pub fn start_slo(
        &self,
        idp: &IdpDescriptor,
        subject: LogoutSubject,
        options: StartSlo,
    ) -> Result<Started<LogoutRequest>, SamlError> {
        let peer = Peer::from_idp(idp, SystemTime::now())?;
        start_slo_impl(
            &self.engine().setting,
            self.engine().metadata.as_metadata(),
            peer,
            &subject,
            options,
            StartSloRole::SessionParticipant {
                asynchronous: false,
            },
        )
    }

    /// Start SP-initiated Asynchronous Single Logout with HTTP-Redirect or HTTP-POST.
    ///
    /// Use this with an IdP endpoint known to support the OASIS Asynchronous
    /// Single Logout extension. The IdP presents the logout result to the user.
    /// Send the returned message without storing pending state for
    /// [`Self::finish_slo`].
    ///
    /// # Errors
    ///
    /// Applies the request and peer checks of [`Self::start_slo`].
    /// Returns [`SamlError::UnsupportedBinding`] for SOAP or HTTP-POST-SimpleSign.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "This public operation takes the subject and options by value, as start_slo does"
    )]
    pub fn start_async_slo(
        &self,
        idp: &IdpDescriptor,
        subject: LogoutSubject,
        options: StartSlo,
    ) -> Result<Outbound<LogoutRequest>, SamlError> {
        match options.binding {
            LogoutBinding::Redirect | LogoutBinding::Post => {}
            LogoutBinding::SimpleSign | LogoutBinding::Soap => {
                return Err(SamlError::UnsupportedBinding {
                    binding: options.binding.into(),
                });
            }
        }
        let peer = Peer::from_idp(idp, SystemTime::now())?;
        let created = issue_logout_request(
            &self.engine().setting,
            self.engine().metadata.as_metadata(),
            peer,
            &subject,
            &options,
            StartSloRole::SessionParticipant { asynchronous: true },
        )?;
        Outbound::<LogoutRequest>::from_context(created.context)
    }

    /// Receive an IdP LogoutRequest.
    ///
    /// Browser requests require a verified signature. SOAP also accepts an
    /// unsigned request over a mutually authenticated, integrity-protected channel.
    ///
    /// A request must carry exactly one `<BaseID>`, `<NameID>`, or
    /// `<EncryptedID>` as a direct child in the SAML assertion namespace.
    /// Any other count returns [`SamlError::ProtocolProfile`].
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the inbound message or relay state is invalid,
    /// the binding is unsupported for logout, IdP metadata cannot be parsed,
    /// XML parsing or signature/trust validation fails, required
    /// `IssueInstant` or optional `NotOnOrAfter` is not conformant,
    /// `NotOnOrAfter` has expired under saml-rs' fail-closed policy, the
    /// destination does not match the receiving `SingleLogoutService` location,
    /// the receiving URL is unpublished, multiple local endpoints have no
    /// explicit receiving URL, or replay
    /// validation detects a duplicate or unusable expiration.
    /// Returns [`SamlError::LogoutRequestRefused`] for an authenticated newer
    /// version. Send its refusal with [`Self::respond_slo_refusal`].
    /// A version below 2.0 returns [`SamlError::ProtocolProfile`].
    ///
    /// A decrypted `<NameID>` is available through [`LogoutRequest::name_id`].
    /// If no configured key decrypts the `<EncryptedID>`, or it contains a
    /// `<BaseID>`, the request has no `NameID`. You can still answer it with
    /// [`Self::respond_slo`]. If decryption succeeds, plaintext other than
    /// one `<NameID>` or `<BaseID>` returns [`SamlError::ProtocolProfile`].
    pub fn receive_slo(
        &self,
        idp: &IdpDescriptor,
        input: Inbound<LogoutRequest>,
        validation: SamlValidationContext<'_>,
    ) -> Result<Received<LogoutRequest>, SamlError> {
        let peer = Peer::from_idp(idp, validation.now())?;
        receive_slo_impl(
            &self.engine().setting,
            self.engine().metadata.as_metadata(),
            peer,
            input,
            validation,
            SloReceiveMode::Standard,
        )
        .map(|(request, _)| request)
    }

    /// Respond to a received IdP LogoutRequest.
    ///
    /// Return a SOAP response on the request's HTTP exchange. For a browser
    /// request, choose a browser binding supported by the peer.
    /// The response carries the exact RelayState received with the request.
    /// `status` is what the response reports. Pass [`Status::success`] after
    /// invalidating the sessions the request names that this identity
    /// provider's assertions established. Otherwise, pass an error status,
    /// such as [`Status::responder`].
    /// Use [`RespondSlo::status_message`] to include a diagnostic.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the `LogoutRequest` issuer does not match the
    /// IdP descriptor, IdP metadata cannot be parsed, relay state is invalid,
    /// a compatible logout endpoint or signing key is missing, the selected
    /// binding is unsupported, or logout response creation fails.
    /// Returns [`SamlError::UnsupportedBinding`] when the selected response
    /// binding crosses between SOAP and browser delivery.
    /// Browser bindings also reject an
    /// `http` peer endpoint unless
    /// [`RespondSlo::allow_http`] is
    /// selected.
    pub fn respond_slo(
        &self,
        idp: &IdpDescriptor,
        request: &Received<LogoutRequest>,
        status: &Status,
        options: RespondSlo,
    ) -> Result<Outbound<LogoutResponse>, SamlError> {
        let peer = Peer::from_idp(idp, SystemTime::now())?;
        respond_slo_impl(
            &self.engine().setting,
            self.engine().metadata.as_metadata(),
            peer,
            LogoutResponseTo::Request { request, status },
            options,
            LogoutResponseTransport::SessionParticipant,
        )
    }

    /// Answer an authenticated IdP LogoutRequest with a version mismatch.
    ///
    /// The response uses the built-in XML and the request's RelayState. It
    /// carries `VersionMismatch`, with `RequestVersionTooHigh` for a newer
    /// major version.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the issuer does not match the descriptor, the
    /// response cannot use the selected binding or endpoint, or signing fails.
    pub fn respond_slo_refusal(
        &self,
        idp: &IdpDescriptor,
        refusal: &RefusedLogoutRequest,
        options: RespondSlo,
    ) -> Result<Outbound<LogoutResponse>, SamlError> {
        let peer = Peer::from_idp(idp, SystemTime::now())?;
        respond_slo_impl(
            &self.engine().setting,
            self.engine().metadata.as_metadata(),
            peer,
            LogoutResponseTo::Refusal(refusal),
            options,
            LogoutResponseTransport::SessionParticipant,
        )
    }

    /// Finish SP-initiated Single Logout using stored pending LogoutRequest state.
    ///
    /// A request sent over HTTP-Redirect, HTTP-POST, or HTTP-POST-SimpleSign
    /// accepts a response over any of those bindings that the local metadata
    /// publishes. A SOAP request accepts only its SOAP response.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the response does not match the pending
    /// request, including issuer, relay state, destination, or
    /// `InResponseTo` mismatches; [`SamlError::UnsupportedBinding`] for a SOAP
    /// response to a front-channel request or a front-channel response to a
    /// SOAP request; when IdP metadata cannot be parsed; when XML,
    /// signature, trust, status, or time validation fails; when the receiving
    /// URL is unpublished or multiple local endpoints have no explicit
    /// receiving URL; or when replay
    /// validation detects a duplicate or expired message. Browser responses require a verified signature.
    /// A status other than `Success` returns [`SamlError::StatusNotSuccess`]
    /// after authentication and the issuer, correlation, and recipient checks.
    /// The error carries the peer's operator diagnostic when present.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     FormField, IdpDescriptor, Inbound, PendingLogoutRequest, ReplayPolicy,
    ///     SamlValidationContext, ServiceProvider,
    /// };
    /// use std::time::SystemTime;
    ///
    /// # fn finish(
    /// #     sp: &ServiceProvider,
    /// #     idp: &IdpDescriptor,
    /// #     pending: &PendingLogoutRequest,
    /// #     fields: Vec<FormField>,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let validation = SamlValidationContext::new(
    ///     SystemTime::now(),
    ///     ReplayPolicy::NoCache,
    /// );
    /// let completed = sp.finish_slo(
    ///     idp,
    ///     pending,
    ///     Inbound::post(fields),
    ///     validation,
    /// )?;
    ///
    /// let peer = completed.peer_entity_id().as_str();
    /// # let _ = peer;
    /// # Ok(()) }
    /// ```
    pub fn finish_slo(
        &self,
        idp: &IdpDescriptor,
        pending: &PendingLogoutRequest,
        input: Inbound<LogoutResponse>,
        validation: SamlValidationContext<'_>,
    ) -> Result<LogoutCompleted, SamlError> {
        let peer = Peer::from_idp(idp, validation.now())?;
        finish_slo_impl(
            &self.engine().setting,
            self.engine().metadata.as_metadata(),
            peer,
            pending,
            input,
            validation,
        )
    }
}

impl IdentityProvider {
    /// Start Session Authority Single Logout.
    ///
    /// The generated `LogoutRequest` always carries a UTC `NotOnOrAfter`
    /// derived from the configured [`crate::IdpConfig::issuance_lifetime`] and
    /// the same captured `IssueInstant`. That attribute cannot be omitted.
    /// The authority signs the request and may omit `SessionIndex`.
    ///
    /// A subject `NameId` without a format is sent with the first configured
    /// NameID format, the one [`Self::respond_sso`] writes for that `NameId`.
    /// With no configured format, `Format` is omitted, as in the assertion.
    ///
    /// `NameQualifier`, `SPNameQualifier`, and `SPProvidedID` on the subject
    /// `NameId` are sent as given. Use the identifier from the issued
    /// assertion, including any of those attributes that [`Self::respond_sso`]
    /// wrote.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when relay state is invalid, SP metadata cannot be
    /// parsed, a compatible logout endpoint or signing key is missing, the
    /// selected binding is unsupported, the NameID format sent for the subject
    /// is not an absolute URI reference, logout request creation fails, or the
    /// configured issuance lifetime cannot be added to the current issue
    /// instant.
    /// [`StartSlo::identifier_encryption`] returns
    /// [`SamlError::MissingMetadata`] when the peer metadata has no encryption
    /// certificate.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{IdentityProvider, LogoutSubject, SpDescriptor, StartSlo};
    ///
    /// # fn logout(
    /// #     idp: &IdentityProvider,
    /// #     sp: &SpDescriptor,
    /// #     subject: LogoutSubject,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let started = idp.start_slo(sp, subject, StartSlo::post())?;
    /// let form = started.outbound.post_form()?;
    /// let snapshot = started.pending.snapshot();
    /// # let _ = (form, snapshot);
    /// # Ok(()) }
    /// ```
    #[expect(
        clippy::needless_pass_by_value,
        reason = "This public operation takes ownership of the logout subject"
    )]
    pub fn start_slo(
        &self,
        sp: &SpDescriptor,
        subject: LogoutSubject,
        options: StartSlo,
    ) -> Result<Started<LogoutRequest>, SamlError> {
        let peer = Peer::from_sp(sp, SystemTime::now())?;
        start_slo_impl(
            &self.engine().setting,
            self.engine().metadata.as_metadata(),
            peer,
            &subject,
            options,
            StartSloRole::SessionAuthority {
                issuance_lifetime: self.issuance_lifetime(),
            },
        )
    }

    /// Receive an SP LogoutRequest.
    ///
    /// Browser requests require a verified signature. SOAP also accepts an
    /// unsigned request over a mutually authenticated, integrity-protected channel.
    /// To support browser requests with the Asynchronous Single Logout
    /// extension, use [`Self::receive_slo_with_async`].
    ///
    /// The identifier requirement is the same as for [`ServiceProvider::receive_slo`].
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the inbound message or relay state is invalid,
    /// the binding is unsupported for logout, SP metadata cannot be parsed, XML
    /// parsing or signature/trust validation fails, required `IssueInstant` or
    /// optional `NotOnOrAfter` is not conformant, `NotOnOrAfter` has expired
    /// under saml-rs' fail-closed policy, the destination does not match the
    /// receiving `SingleLogoutService` location, the receiving URL is
    /// unpublished, multiple local endpoints have
    /// no explicit receiving URL, or replay validation detects
    /// a duplicate or unusable expiration. The identity provider processes an
    /// `<EncryptedID>` as described in [`ServiceProvider::receive_slo`].
    /// Returns [`SamlError::LogoutRequestRefused`] for an authenticated newer
    /// version. Send its refusal with [`Self::respond_slo_refusal`].
    /// A version below 2.0 returns [`SamlError::ProtocolProfile`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     FormField, IdentityProvider, Inbound, ReplayPolicy, RespondSlo, SamlValidationContext,
    ///     SpDescriptor, Status,
    /// };
    /// use std::time::SystemTime;
    ///
    /// # fn respond(
    /// #     idp: &IdentityProvider,
    /// #     sp: &SpDescriptor,
    /// #     fields: Vec<FormField>,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let validation = SamlValidationContext::new(
    ///     SystemTime::now(),
    ///     ReplayPolicy::NoCache,
    /// );
    /// let input = Inbound::post(fields);
    /// let request = idp.receive_slo(sp, input, validation)?;
    /// let response = idp.respond_slo(sp, &request, &Status::success(), RespondSlo::post())?;
    ///
    /// let form = response.post_form()?;
    /// # let _ = form;
    /// # Ok(()) }
    /// ```
    pub fn receive_slo(
        &self,
        sp: &SpDescriptor,
        input: Inbound<LogoutRequest>,
        validation: SamlValidationContext<'_>,
    ) -> Result<Received<LogoutRequest>, SamlError> {
        let peer = Peer::from_sp(sp, validation.now())?;
        receive_slo_impl(
            &self.engine().setting,
            self.engine().metadata.as_metadata(),
            peer,
            input,
            validation,
            SloReceiveMode::Standard,
        )
        .map(|(request, _)| request)
    }

    /// Receive an SP LogoutRequest with support for Asynchronous Single Logout
    /// on HTTP-Redirect and HTTP-POST.
    ///
    /// For [`IdpLogoutAction::CompleteLocally`], use the request's issuer,
    /// `NameID`, and session indexes to find the relevant sessions. End those
    /// sessions and present the outcome at the IdP, including on failure.
    /// Session lookup, termination, and propagation to other SPs belong to
    /// the application.
    ///
    /// For [`IdpLogoutAction::Respond`], process the request and pass it to
    /// [`Self::respond_slo`] with the outcome.
    ///
    /// # Errors
    ///
    /// Applies the same validation as [`Self::receive_slo`]. An authenticated
    /// newer version with the asynchronous marker returns
    /// [`SamlError::ProtocolProfile`] for local error feedback. An ordinary
    /// request with a newer version still returns a refusal to send.
    pub fn receive_slo_with_async(
        &self,
        sp: &SpDescriptor,
        input: Inbound<LogoutRequest>,
        validation: SamlValidationContext<'_>,
    ) -> Result<IdpLogoutAction, SamlError> {
        let peer = Peer::from_sp(sp, validation.now())?;
        let (request, asynchronous) = receive_slo_impl(
            &self.engine().setting,
            self.engine().metadata.as_metadata(),
            peer,
            input,
            validation,
            SloReceiveMode::RecognizeAsynchronous,
        )?;
        Ok(if asynchronous {
            IdpLogoutAction::CompleteLocally(request.into_message())
        } else {
            IdpLogoutAction::Respond(request)
        })
    }

    /// Respond to a received SP LogoutRequest.
    ///
    /// Return a SOAP response on the request's HTTP exchange. For a browser
    /// request, choose a browser binding supported by the peer.
    /// The response carries the exact RelayState received with the request.
    /// `status` is what the response reports. Pass [`Status::success`] after
    /// ending this identity provider's own session with the principal. When
    /// another session participant did not confirm its logout, add
    /// [`SubordinateStatusCode::partial_logout`](crate::SubordinateStatusCode::partial_logout)
    /// with [`Status::with_subordinate`]. Pass an error status, such as
    /// [`Status::responder`], when the session could not be ended.
    /// Use [`RespondSlo::status_message`] to include a diagnostic.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the `LogoutRequest` issuer does not match the
    /// SP descriptor, SP metadata cannot be parsed, relay state is invalid, a
    /// compatible logout endpoint or signing key is missing, the selected
    /// binding is unsupported, or logout response creation fails.
    /// Returns [`SamlError::UnsupportedBinding`] when the selected response
    /// binding crosses between SOAP and browser delivery.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{IdentityProvider, LogoutRequest, Received, RespondSlo, SpDescriptor, Status};
    ///
    /// # fn respond(
    /// #     idp: &IdentityProvider,
    /// #     sp: &SpDescriptor,
    /// #     request: &Received<LogoutRequest>,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let response = idp.respond_slo(sp, request, &Status::success(), RespondSlo::post())?;
    /// let form = response.post_form()?;
    /// # let _ = form;
    /// # Ok(()) }
    /// ```
    pub fn respond_slo(
        &self,
        sp: &SpDescriptor,
        request: &Received<LogoutRequest>,
        status: &Status,
        options: RespondSlo,
    ) -> Result<Outbound<LogoutResponse>, SamlError> {
        let peer = Peer::from_sp(sp, SystemTime::now())?;
        respond_slo_impl(
            &self.engine().setting,
            self.engine().metadata.as_metadata(),
            peer,
            LogoutResponseTo::Request { request, status },
            options,
            LogoutResponseTransport::SessionAuthority,
        )
    }

    /// Answer an authenticated SP LogoutRequest with a version mismatch.
    ///
    /// The response uses the built-in XML and the request's RelayState. Its
    /// status codes are the same as for [`ServiceProvider::respond_slo_refusal`].
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the issuer does not match the descriptor, the
    /// response cannot use the selected binding or endpoint, or signing fails.
    pub fn respond_slo_refusal(
        &self,
        sp: &SpDescriptor,
        refusal: &RefusedLogoutRequest,
        options: RespondSlo,
    ) -> Result<Outbound<LogoutResponse>, SamlError> {
        let peer = Peer::from_sp(sp, SystemTime::now())?;
        respond_slo_impl(
            &self.engine().setting,
            self.engine().metadata.as_metadata(),
            peer,
            LogoutResponseTo::Refusal(refusal),
            options,
            LogoutResponseTransport::SessionAuthority,
        )
    }

    /// Finish IdP-initiated Single Logout using stored pending LogoutRequest state.
    ///
    /// A request sent over HTTP-Redirect, HTTP-POST, or HTTP-POST-SimpleSign
    /// accepts a response over any of those bindings that the local metadata
    /// publishes. A SOAP request accepts only its SOAP response.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the response does not match the pending
    /// request, including issuer, relay state, destination, or
    /// `InResponseTo` mismatches; [`SamlError::UnsupportedBinding`] for a SOAP
    /// response to a front-channel request or a front-channel response to a
    /// SOAP request; when SP metadata cannot be parsed; when XML,
    /// signature, trust, status, or time validation fails; when the receiving
    /// URL is unpublished or multiple local endpoints have no explicit
    /// receiving URL; or when replay
    /// validation detects a duplicate or expired message. Browser responses require a verified signature.
    /// A status other than `Success` returns [`SamlError::StatusNotSuccess`]
    /// after authentication and the issuer, correlation, and recipient checks.
    /// The error carries the peer's operator diagnostic when present.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     FormField, IdentityProvider, Inbound, PendingLogoutRequest, ReplayPolicy,
    ///     SamlValidationContext, SpDescriptor,
    /// };
    /// use std::time::SystemTime;
    ///
    /// # fn finish(
    /// #     idp: &IdentityProvider,
    /// #     sp: &SpDescriptor,
    /// #     pending: &PendingLogoutRequest,
    /// #     fields: Vec<FormField>,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let validation = SamlValidationContext::new(
    ///     SystemTime::now(),
    ///     ReplayPolicy::NoCache,
    /// );
    /// let completed = idp.finish_slo(
    ///     sp,
    ///     pending,
    ///     Inbound::post(fields),
    ///     validation,
    /// )?;
    ///
    /// let peer = completed.peer_entity_id().as_str();
    /// # let _ = peer;
    /// # Ok(()) }
    /// ```
    pub fn finish_slo(
        &self,
        sp: &SpDescriptor,
        pending: &PendingLogoutRequest,
        input: Inbound<LogoutResponse>,
        validation: SamlValidationContext<'_>,
    ) -> Result<LogoutCompleted, SamlError> {
        let peer = Peer::from_sp(sp, validation.now())?;
        finish_slo_impl(
            &self.engine().setting,
            self.engine().metadata.as_metadata(),
            peer,
            pending,
            input,
            validation,
        )
    }
}

#[derive(Debug, Clone, Copy)]
enum StartSloRole {
    SessionParticipant { asynchronous: bool },
    SessionAuthority { issuance_lifetime: time::Duration },
}

fn start_slo_impl(
    local_setting: &EntitySetting,
    local_metadata: &Metadata,
    peer: Peer<'_>,
    subject: &LogoutSubject,
    options: StartSlo,
    role: StartSloRole,
) -> Result<Started<LogoutRequest>, SamlError> {
    let created =
        issue_logout_request(local_setting, local_metadata, peer, subject, &options, role)?;
    let outbound = Outbound::<LogoutRequest>::from_context(created.context)?;
    let pending = PendingLogoutRequest::new(
        outbound.id().clone(),
        options.relay_state,
        peer.entity_id.clone(),
        options.binding,
        created
            .not_on_or_after
            .map(SamlInstant::try_new)
            .transpose()?,
    );
    Ok(Started { pending, outbound })
}

fn issue_logout_request(
    local_setting: &EntitySetting,
    local_metadata: &Metadata,
    peer: Peer<'_>,
    subject: &LogoutSubject,
    options: &StartSlo,
    role: StartSloRole,
) -> Result<CreatedLogoutRequest, SamlError> {
    if let Some(relay_state) = &options.relay_state {
        relay_state.ensure_sendable()?;
    }
    if matches!(role, StartSloRole::SessionParticipant { .. }) {
        enforce_participant_https(
            peer.metadata,
            options.binding,
            options.transport(),
            EndpointDirection::Request,
        )?;
    }
    let (issue_instant, not_on_or_after, request_validation) = match role {
        StartSloRole::SessionParticipant { .. } => (
            now_iso8601(),
            None,
            LogoutRequestValidation::SessionParticipant,
        ),
        StartSloRole::SessionAuthority { issuance_lifetime } => {
            let window = capture_idp_issuance_window(issuance_lifetime)?;
            (
                window.issue_instant,
                Some(window.expiration),
                LogoutRequestValidation::SessionAuthority,
            )
        }
    };
    let name_id = subject.name_id();
    let name_id_format = name_id.format().map(NameIdFormat::as_uri);
    let name_id_format = match role {
        StartSloRole::SessionParticipant { .. } => name_id_format,
        StartSloRole::SessionAuthority { .. } => {
            name_id_format.or_else(|| local_setting.default_name_id_format())
        }
    };
    let request_subject = LogoutRequestSubject {
        name_id: name_id.value(),
        qualifiers: OutboundNameIdQualifiers::from(name_id),
        session_indexes: subject
            .session_indexes()
            .iter()
            .map(SessionIndex::as_str)
            .collect(),
    };
    create_logout_request_for_subject_inner(&LogoutRequestInput {
        init_setting: local_setting,
        init_meta: local_metadata,
        target_meta: peer.metadata,
        binding: Binding::from(options.binding),
        subject: &request_subject,
        relay_state: options.relay_state.as_ref().map(RelayState::as_str),
        name_id_format,
        issue_instant: &issue_instant,
        not_on_or_after: not_on_or_after.as_deref(),
        reason: options.reason.as_deref(),
        asynchronous: matches!(
            role,
            StartSloRole::SessionParticipant { asynchronous: true }
        ),
        validation: request_validation,
        name_id_encryption: options.identifier_encryption,
    })
}

#[derive(Clone, Copy)]
enum SloReceiveMode {
    Standard,
    RecognizeAsynchronous,
}

fn receive_slo_impl(
    local_setting: &EntitySetting,
    local_metadata: &Metadata,
    peer: Peer<'_>,
    input: Inbound<LogoutRequest>,
    mut validation: SamlValidationContext<'_>,
    mode: SloReceiveMode,
) -> Result<(Received<LogoutRequest>, bool), SamlError> {
    let relay_state = relay_state_from_input(&input)?;
    let binding = LogoutBinding::try_from(input.binding())?;
    let expected_recipient = logout_recipient_endpoint(
        local_metadata,
        binding,
        EndpointDirection::Request,
        &validation,
    )?;
    let receipt = LogoutReceipt::of_input(&input)?;
    let request =
        input.into_http_request(local_setting.xml_limits, local_setting.schema_validator)?;
    let flow = parse_logout_request_at(
        local_setting,
        peer.metadata,
        receipt,
        &request,
        LogoutFlowValidation::typed(
            Some(&expected_recipient),
            validation.now(),
            validation.clock_skew(),
            peer.hmac_secret,
        ),
    )?;
    let recognizes_async = matches!(
        (mode, binding),
        (
            SloReceiveMode::RecognizeAsynchronous,
            LogoutBinding::Redirect | LogoutBinding::Post
        )
    );
    let parse_document = || parse_saml_with_limits(&flow.saml_content, local_setting.xml_limits);
    let async_document = recognizes_async.then(parse_document).transpose()?;
    let asynchronous = async_document.as_ref().is_some_and(has_async_slo_marker);
    if let Some(refusal) =
        RefusedLogoutRequest::for_version(&flow, peer.entity_id, relay_state.as_ref(), binding)?
    {
        if asynchronous {
            return Err(SamlError::ProtocolProfile(
                "Asynchronous LogoutRequest uses an unsupported SAML version".into(),
            ));
        }
        return Err(SamlError::LogoutRequestRefused {
            refusal: Box::new(refusal),
        });
    }
    let replay_deadline = crate::validator::logout_request_not_on_or_after_deadline(
        &flow.extract,
        validation.now_offset()?,
        validation.clock_skew().not_on_or_after_millis(),
    )?;
    let document = match async_document {
        Some(document) => document,
        None => parse_document()?,
    };
    let reason = document.attr("Reason").map(str::to_owned);
    let logout = LogoutRequest::from_flow(flow, reason)?;
    validation.check_and_store_message_replay_until(
        ReplayKey::LogoutRequest(logout.id().clone()),
        replay_deadline,
    )?;
    let logout = decrypt_encrypted_id(logout, local_setting, &document)?;
    Ok((
        Received::new(logout, binding.into(), relay_state),
        asynchronous,
    ))
}

#[derive(Clone, Copy)]
enum LogoutResponseTo<'a> {
    Request {
        request: &'a Received<LogoutRequest>,
        status: &'a Status,
    },
    Refusal(&'a RefusedLogoutRequest),
}

fn respond_slo_impl(
    local_setting: &EntitySetting,
    local_metadata: &Metadata,
    peer: Peer<'_>,
    response_to: LogoutResponseTo<'_>,
    options: RespondSlo,
    transport: LogoutResponseTransport,
) -> Result<Outbound<LogoutResponse>, SamlError> {
    let (request_binding, issuer, in_response_to, relay_state, status) = match response_to {
        LogoutResponseTo::Request { request, status } => (
            LogoutBinding::try_from(request.binding())?,
            request.message().issuer(),
            request.message().id(),
            request.relay_state(),
            status,
        ),
        LogoutResponseTo::Refusal(refusal) => (
            refusal.binding,
            &refusal.issuer,
            &refusal.id,
            refusal.relay_state.as_ref(),
            refusal.status(),
        ),
    };
    let binding = logout_response_binding(options.binding.into(), request_binding)?;
    ensure_entity_id(issuer, peer.entity_id)?;
    if matches!(transport, LogoutResponseTransport::SessionParticipant) {
        enforce_participant_https(
            peer.metadata,
            binding,
            options.transport(),
            EndpointDirection::Response,
        )?;
    }
    let status_message = options.status_message;
    let context = create_logout_response_inner(&LogoutResponseInput {
        init_setting: local_setting,
        init_meta: local_metadata,
        target_meta: peer.metadata,
        binding: binding.into(),
        in_response_to: Some(in_response_to.as_str()),
        relay_state: relay_state.map(RelayState::as_str),
        status,
        status_message: status_message.as_deref(),
    })?;
    Outbound::<LogoutResponse>::echoing_received_relay_state(context)
}

fn finish_slo_impl(
    local_setting: &EntitySetting,
    local_metadata: &Metadata,
    peer: Peer<'_>,
    pending: &PendingLogoutRequest,
    input: Inbound<LogoutResponse>,
    mut validation: SamlValidationContext<'_>,
) -> Result<LogoutCompleted, SamlError> {
    ensure_entity_id(pending.peer_entity_id(), peer.entity_id)?;
    let binding = logout_response_binding(input.binding(), pending.request_binding())?;
    let relay_state = relay_state_from_input(&input)?;
    ensure_relay_state(pending.relay_state(), relay_state.as_ref())?;
    // A SOAP response returns on this party's own HTTP exchange, so no local
    // endpoint received it.
    let expected_recipient = match binding {
        LogoutBinding::Soap => None,
        binding @ (LogoutBinding::Redirect | LogoutBinding::Post | LogoutBinding::SimpleSign) => {
            Some(logout_recipient_endpoint(
                local_metadata,
                binding,
                EndpointDirection::Response,
                &validation,
            )?)
        }
    };
    let receipt = LogoutReceipt::of_input(&input)?;
    let request =
        input.into_http_request(local_setting.xml_limits, local_setting.schema_validator)?;
    let parsed = parse_logout_response_at(
        local_setting,
        peer.metadata,
        receipt,
        &request,
        pending.request_id().as_str(),
        LogoutFlowValidation::typed(
            expected_recipient.as_deref(),
            validation.now(),
            validation.clock_skew(),
            peer.hmac_secret,
        ),
    )?;
    let response = LogoutResponse::from_flow(&parsed.flow, parsed.status_message)?;
    validation.check_and_store_message_replay(ReplayKey::LogoutResponse(response.id().clone()))?;
    Ok(LogoutCompleted::new(response, relay_state))
}

#[derive(Debug, Clone, Copy)]
enum LogoutResponseTransport {
    SessionParticipant,
    SessionAuthority,
}

fn enforce_participant_https(
    peer_metadata: &Metadata,
    binding: LogoutBinding,
    transport: PeerEndpointTransport,
    direction: EndpointDirection,
) -> Result<(), SamlError> {
    match binding {
        LogoutBinding::Soap => return Ok(()),
        LogoutBinding::Redirect | LogoutBinding::Post | LogoutBinding::SimpleSign => {}
    }
    match transport {
        PeerEndpointTransport::AllowHttp => Ok(()),
        PeerEndpointTransport::RequireHttps => {
            let destination =
                peer_logout_endpoint(peer_metadata, Binding::from(binding), direction)?;
            ensure_https_endpoint(&destination, "Single Logout", "SingleLogoutService")
        }
    }
}

fn peer_logout_endpoint(
    peer_metadata: &Metadata,
    binding: Binding,
    direction: EndpointDirection,
) -> Result<String, SamlError> {
    peer_metadata
        .single_logout_service_location(binding, direction)
        .ok_or_else(|| SamlError::MissingMetadata("SingleLogoutService".into()))
}

fn logout_response_binding(
    actual: Binding,
    request: LogoutBinding,
) -> Result<LogoutBinding, SamlError> {
    let response = LogoutBinding::try_from(actual)?;
    match (request, response) {
        (LogoutBinding::Soap, LogoutBinding::Soap)
        | (
            LogoutBinding::Redirect | LogoutBinding::Post | LogoutBinding::SimpleSign,
            LogoutBinding::Redirect | LogoutBinding::Post | LogoutBinding::SimpleSign,
        ) => Ok(response),
        (
            LogoutBinding::Soap,
            LogoutBinding::Redirect | LogoutBinding::Post | LogoutBinding::SimpleSign,
        )
        | (
            LogoutBinding::Redirect | LogoutBinding::Post | LogoutBinding::SimpleSign,
            LogoutBinding::Soap,
        ) => Err(SamlError::UnsupportedBinding { binding: actual }),
    }
}

fn logout_recipient_endpoint(
    local_metadata: &Metadata,
    binding: LogoutBinding,
    direction: EndpointDirection,
    validation: &SamlValidationContext<'_>,
) -> Result<String, SamlError> {
    let locations =
        local_metadata.single_logout_service_locations(Binding::from(binding), direction);
    if locations.is_empty() {
        return Err(SamlError::MissingMetadata("SingleLogoutService".into()));
    }
    validation.resolve_recipient_endpoint(&locations)
}
