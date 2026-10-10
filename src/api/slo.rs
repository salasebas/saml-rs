use crate::browser::{BrowserInput, LogoutBinding, Outbound, PendingLogoutRequest, Started};
use crate::config::{EntityId, IdpDescriptor, SpDescriptor};
use crate::constants::Binding;
use crate::entity::{capture_idp_issuance_window, now_iso8601, EntitySetting};
use crate::error::SamlError as Error;
use crate::flow::HttpRequest;
use crate::logout::{
    create_logout_request_with_session_indexes, create_logout_response_with_status,
    parse_logout_request_at, parse_logout_response_at, LogoutFlowValidation,
    LogoutRequestSessionIndexes, LogoutRequestValidation,
};
use crate::metadata::Metadata;
use crate::model::{
    LogoutCompleted, LogoutRequest, LogoutResponse, LogoutSubject, Received, ReplayKey,
    SamlInstant, SamlValidationContext, Status,
};

use super::raw_mapping::{
    ensure_entity_id, ensure_relay_state, input_binding, raw_idp_descriptor, raw_sp_descriptor,
    relay_state_from_input,
};
use super::{Idp, LogoutSigning, RespondSlo, Saml, SamlError, Sp, StartSlo};

impl Saml<Sp> {
    /// Start SP-initiated Single Logout.
    ///
    /// The `LogoutRequest` `NameID` uses the subject's format and qualifiers.
    /// When the subject has no format, the first configured NameID format is
    /// used.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when relay state is invalid, IdP metadata cannot
    /// be parsed, a compatible logout endpoint or signing key is missing, the
    /// selected binding is unsupported, or logout request creation fails.
    /// [`StartSlo::apply_single_logout_generation_rules`] also rejects a
    /// missing `SessionIndex`, an `http` peer endpoint unless
    /// [`StartSlo::allow_http_single_logout`] is selected, and rejects the
    /// samlify-port [`LogoutSigning::DoNotSignForCompatibility`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{IdpDescriptor, LogoutSubject, Saml, StartSlo};
    ///
    /// # fn logout(
    /// #     sp: &Saml<saml_rs::Sp>,
    /// #     idp: &IdpDescriptor,
    /// #     subject: LogoutSubject,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let started = sp.start_slo(idp, subject, StartSlo::post())?;
    /// let form = started.outbound.post_form()?;
    /// let snapshot = started.pending.snapshot();
    /// # let _ = (form, snapshot);
    /// # Ok(()) }
    /// ```
    pub fn start_slo(
        &self,
        idp: &IdpDescriptor,
        subject: LogoutSubject,
        options: StartSlo,
    ) -> Result<Started<LogoutRequest>, SamlError> {
        let raw_idp = raw_idp_descriptor(idp)?;
        start_slo_impl(
            &self.raw_service_provider().setting,
            &self.raw_service_provider().metadata,
            idp.entity_id(),
            &raw_idp.metadata,
            subject,
            options,
            StartSloRole::SessionParticipant,
        )
    }

    /// Receive an IdP LogoutRequest.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the browser input or relay state is invalid,
    /// the binding is unsupported for logout, IdP metadata cannot be parsed,
    /// XML parsing or signature/trust validation fails, required
    /// `IssueInstant` or optional `NotOnOrAfter` is not conformant,
    /// `NotOnOrAfter` has expired under saml-rs' fail-closed policy, the
    /// destination does not match a published `SingleLogoutService` location,
    /// or replay validation detects a duplicate or unusable expiration.
    pub fn receive_slo(
        &self,
        idp: &IdpDescriptor,
        input: BrowserInput<LogoutRequest>,
        validation: SamlValidationContext<'_>,
    ) -> Result<Received<LogoutRequest>, SamlError> {
        let raw_idp = raw_idp_descriptor(idp)?;
        receive_slo_impl(
            &self.raw_service_provider().setting,
            &self.raw_service_provider().metadata,
            &raw_idp.metadata,
            input,
            validation,
        )
    }

    /// Respond to a received IdP LogoutRequest.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the `LogoutRequest` issuer does not match the
    /// IdP descriptor, IdP metadata cannot be parsed, relay state is invalid,
    /// a compatible logout endpoint or signing key is missing, the selected
    /// binding is unsupported, or logout response creation fails.
    /// [`RespondSlo::apply_single_logout_generation_rules`] also rejects an
    /// `http` peer endpoint unless
    /// [`RespondSlo::allow_http_single_logout`] is
    /// selected.
    pub fn respond_slo(
        &self,
        idp: &IdpDescriptor,
        request: &Received<LogoutRequest>,
        options: RespondSlo,
    ) -> Result<Outbound<LogoutResponse>, SamlError> {
        let raw_idp = raw_idp_descriptor(idp)?;
        respond_slo_impl(
            &self.raw_service_provider().setting,
            &self.raw_service_provider().metadata,
            idp.entity_id(),
            &raw_idp.metadata,
            request,
            options,
            LogoutResponseTransport::SessionParticipant,
        )
    }

    /// Finish SP-initiated Single Logout using stored pending LogoutRequest state.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the response does not match the pending
    /// request, including issuer, binding, relay state, destination, or
    /// `InResponseTo` mismatches; when IdP metadata cannot be parsed; when XML,
    /// signature, trust, status, or time validation fails; or when replay
    /// validation detects a duplicate or expired message. Response signatures
    /// follow [`crate::LogoutPolicy::responses`]. The Single Logout accept
    /// combination sets that field to [`crate::LogoutSignaturePolicy::RequireSigned`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     BrowserInput, FormField, IdpDescriptor, LogoutResponse, PendingLogoutRequest,
    ///     ReplayPolicy, Saml, SamlValidationContext,
    /// };
    /// use std::time::SystemTime;
    ///
    /// # fn finish(
    /// #     sp: &Saml<saml_rs::Sp>,
    /// #     idp: &IdpDescriptor,
    /// #     pending: &PendingLogoutRequest,
    /// #     fields: Vec<FormField>,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let validation = SamlValidationContext::new(
    ///     SystemTime::now(),
    ///     ReplayPolicy::DisabledForCompatibility,
    /// );
    /// let completed = sp.finish_slo(
    ///     idp,
    ///     pending,
    ///     BrowserInput::<LogoutResponse>::post(fields),
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
        input: BrowserInput<LogoutResponse>,
        validation: SamlValidationContext<'_>,
    ) -> Result<LogoutCompleted, SamlError> {
        let raw_idp = raw_idp_descriptor(idp)?;
        finish_slo_impl(
            &self.raw_service_provider().setting,
            &self.raw_service_provider().metadata,
            idp.entity_id(),
            &raw_idp.metadata,
            pending,
            input,
            validation,
        )
    }
}

impl Saml<Idp> {
    /// Start Session Authority Single Logout.
    ///
    /// The generated `LogoutRequest` always carries a UTC `NotOnOrAfter`
    /// derived from the configured [`crate::IdpConfig::issuance_lifetime`] and
    /// the same captured `IssueInstant`. That attribute cannot be omitted.
    /// [`StartSlo::apply_single_logout_generation_rules`] signs the request
    /// and still allows `SessionIndex` to be omitted. It does not require an
    /// `https` peer endpoint. The `LogoutRequest` `NameID` uses the subject's
    /// format and qualifiers. When the subject has no format, the first
    /// configured NameID format is used.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when relay state is invalid, SP metadata cannot be
    /// parsed, a compatible logout endpoint or signing key is missing, the
    /// selected binding is unsupported, logout request creation fails, or the
    /// configured issuance lifetime cannot be added to the current issue
    /// instant. [`StartSlo::apply_single_logout_generation_rules`] also
    /// rejects [`LogoutSigning::DoNotSignForCompatibility`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{LogoutSubject, Saml, SpDescriptor, StartSlo};
    ///
    /// # fn logout(
    /// #     idp: &Saml<saml_rs::Idp>,
    /// #     sp: &SpDescriptor,
    /// #     subject: LogoutSubject,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let started = idp.start_slo(sp, subject, StartSlo::post())?;
    /// let form = started.outbound.post_form()?;
    /// let snapshot = started.pending.snapshot();
    /// # let _ = (form, snapshot);
    /// # Ok(()) }
    /// ```
    pub fn start_slo(
        &self,
        sp: &SpDescriptor,
        subject: LogoutSubject,
        options: StartSlo,
    ) -> Result<Started<LogoutRequest>, SamlError> {
        let raw_sp = raw_sp_descriptor(sp)?;
        start_slo_impl(
            &self.raw_identity_provider().setting,
            &self.raw_identity_provider().metadata,
            sp.entity_id(),
            &raw_sp.metadata,
            subject,
            options,
            StartSloRole::SessionAuthority {
                issuance_lifetime: self.0.issuance_lifetime,
            },
        )
    }

    /// Receive an SP LogoutRequest.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the browser input or relay state is invalid,
    /// the binding is unsupported for logout, SP metadata cannot be parsed, XML
    /// parsing or signature/trust validation fails, required `IssueInstant` or
    /// optional `NotOnOrAfter` is not conformant, `NotOnOrAfter` has expired
    /// under saml-rs' fail-closed policy, the destination does not match a
    /// published `SingleLogoutService` location, or replay validation detects
    /// a duplicate or unusable expiration.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     BrowserInput, FormField, LogoutRequest, ReplayPolicy, RespondSlo, Saml,
    ///     SamlValidationContext, SpDescriptor,
    /// };
    /// use std::time::SystemTime;
    ///
    /// # fn respond(
    /// #     idp: &Saml<saml_rs::Idp>,
    /// #     sp: &SpDescriptor,
    /// #     fields: Vec<FormField>,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let validation = SamlValidationContext::new(
    ///     SystemTime::now(),
    ///     ReplayPolicy::DisabledForCompatibility,
    /// );
    /// let input = BrowserInput::<LogoutRequest>::post(fields);
    /// let request = idp.receive_slo(sp, input, validation)?;
    /// let response = idp.respond_slo(sp, &request, RespondSlo::post())?;
    ///
    /// let form = response.post_form()?;
    /// # let _ = form;
    /// # Ok(()) }
    /// ```
    pub fn receive_slo(
        &self,
        sp: &SpDescriptor,
        input: BrowserInput<LogoutRequest>,
        validation: SamlValidationContext<'_>,
    ) -> Result<Received<LogoutRequest>, SamlError> {
        let raw_sp = raw_sp_descriptor(sp)?;
        receive_slo_impl(
            &self.raw_identity_provider().setting,
            &self.raw_identity_provider().metadata,
            &raw_sp.metadata,
            input,
            validation,
        )
    }

    /// Respond to a received SP LogoutRequest.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the `LogoutRequest` issuer does not match the
    /// SP descriptor, SP metadata cannot be parsed, relay state is invalid, a
    /// compatible logout endpoint or signing key is missing, the selected
    /// binding is unsupported, or logout response creation fails.
    /// [`RespondSlo::apply_single_logout_generation_rules`] does not add an
    /// `https` requirement for this role.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{LogoutRequest, Received, RespondSlo, Saml, SpDescriptor};
    ///
    /// # fn respond(
    /// #     idp: &Saml<saml_rs::Idp>,
    /// #     sp: &SpDescriptor,
    /// #     request: &Received<LogoutRequest>,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let response = idp.respond_slo(sp, request, RespondSlo::post())?;
    /// let form = response.post_form()?;
    /// # let _ = form;
    /// # Ok(()) }
    /// ```
    pub fn respond_slo(
        &self,
        sp: &SpDescriptor,
        request: &Received<LogoutRequest>,
        options: RespondSlo,
    ) -> Result<Outbound<LogoutResponse>, SamlError> {
        let raw_sp = raw_sp_descriptor(sp)?;
        respond_slo_impl(
            &self.raw_identity_provider().setting,
            &self.raw_identity_provider().metadata,
            sp.entity_id(),
            &raw_sp.metadata,
            request,
            options,
            LogoutResponseTransport::SessionAuthority,
        )
    }

    /// Finish IdP-initiated Single Logout using stored pending LogoutRequest state.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the response does not match the pending
    /// request, including issuer, binding, relay state, destination, or
    /// `InResponseTo` mismatches; when SP metadata cannot be parsed; when XML,
    /// signature, trust, status, or time validation fails; or when replay
    /// validation detects a duplicate or expired message. Response signatures
    /// follow [`crate::LogoutPolicy::responses`]. The Single Logout accept
    /// combination sets that field to [`crate::LogoutSignaturePolicy::RequireSigned`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     BrowserInput, FormField, LogoutResponse, PendingLogoutRequest, ReplayPolicy,
    ///     Saml, SamlValidationContext, SpDescriptor,
    /// };
    /// use std::time::SystemTime;
    ///
    /// # fn finish(
    /// #     idp: &Saml<saml_rs::Idp>,
    /// #     sp: &SpDescriptor,
    /// #     pending: &PendingLogoutRequest,
    /// #     fields: Vec<FormField>,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let validation = SamlValidationContext::new(
    ///     SystemTime::now(),
    ///     ReplayPolicy::DisabledForCompatibility,
    /// );
    /// let completed = idp.finish_slo(
    ///     sp,
    ///     pending,
    ///     BrowserInput::<LogoutResponse>::post(fields),
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
        input: BrowserInput<LogoutResponse>,
        validation: SamlValidationContext<'_>,
    ) -> Result<LogoutCompleted, SamlError> {
        let raw_sp = raw_sp_descriptor(sp)?;
        finish_slo_impl(
            &self.raw_identity_provider().setting,
            &self.raw_identity_provider().metadata,
            sp.entity_id(),
            &raw_sp.metadata,
            pending,
            input,
            validation,
        )
    }
}

struct TypedLogoutSubject {
    name_id: String,
    name_id_format: Option<String>,
    name_qualifier: Option<String>,
    sp_name_qualifier: Option<String>,
    sp_provided_id: Option<String>,
    session_indexes: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
enum LogoutMessageDirection {
    Request,
    Response,
}

#[derive(Debug, Clone, Copy)]
enum StartSloRole {
    SessionParticipant,
    SessionAuthority { issuance_lifetime: time::Duration },
}

fn start_slo_impl(
    local_setting: &EntitySetting,
    local_metadata: &Metadata,
    peer_entity_id: &EntityId,
    peer_metadata: &Metadata,
    subject: LogoutSubject,
    options: StartSlo,
    role: StartSloRole,
) -> Result<Started<LogoutRequest>, SamlError> {
    options.relay_state.validate()?;
    let subject = typed_logout_subject(subject);
    let follows_rules = options.follows_generation_rules();
    if follows_rules && matches!(options.signing, LogoutSigning::DoNotSignForCompatibility) {
        return Err(Error::ProtocolProfile(
            "a LogoutRequest signature cannot be disabled for HTTP-Redirect, HTTP-POST, or HTTP-POST-SimpleSign when Single Logout generation rules are selected".into(),
        ));
    }
    if matches!(role, StartSloRole::SessionParticipant) {
        enforce_participant_https(
            peer_metadata,
            options.binding.as_binding(),
            follows_rules,
            options.allows_http(),
            LogoutMessageDirection::Request,
        )?;
    }
    let (issue_instant, not_on_or_after, request_validation) = match role {
        StartSloRole::SessionParticipant => (
            now_iso8601(),
            None,
            if follows_rules {
                LogoutRequestValidation::SessionParticipant
            } else {
                LogoutRequestValidation::Compatibility
            },
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
    let want_signed = if follows_rules {
        true
    } else {
        logout_request_signing(local_setting, options.signing)
    };
    let created = create_logout_request_with_session_indexes(LogoutRequestSessionIndexes {
        init_setting: local_setting,
        init_meta: local_metadata,
        target_meta: peer_metadata,
        binding: options.binding.as_binding(),
        name_id: &subject.name_id,
        name_id_format: subject.name_id_format.as_deref(),
        name_qualifier: subject.name_qualifier.as_deref(),
        sp_name_qualifier: subject.sp_name_qualifier.as_deref(),
        sp_provided_id: subject.sp_provided_id.as_deref(),
        session_indexes: &subject.session_indexes,
        relay_state: options.relay_state.as_deref(),
        want_signed,
        issue_instant: &issue_instant,
        not_on_or_after: not_on_or_after.as_deref(),
        validation: request_validation,
    })?;
    let outbound = Outbound::<LogoutRequest>::try_from(created.context)?;
    let mut pending = PendingLogoutRequest::try_new(
        outbound.id().clone(),
        options.relay_state,
        options.binding,
        peer_entity_id.clone(),
    )?;
    if matches!(role, StartSloRole::SessionAuthority { .. }) {
        pending = pending.with_issue_instant(SamlInstant::try_new(created.issue_instant)?);
        let expiration = created.not_on_or_after.ok_or_else(|| {
            SamlError::Invalid(
                "Session Authority LogoutRequest is missing its generated expiration".into(),
            )
        })?;
        pending = pending.with_expiration(SamlInstant::try_new(expiration)?);
    }
    Ok(Started { pending, outbound })
}

fn receive_slo_impl(
    local_setting: &EntitySetting,
    local_metadata: &Metadata,
    peer_metadata: &Metadata,
    input: BrowserInput<LogoutRequest>,
    mut validation: SamlValidationContext<'_>,
) -> Result<Received<LogoutRequest>, SamlError> {
    let relay_state = relay_state_from_input(&input)?;
    let binding = LogoutBinding::try_from(input_binding(&input))?;
    let expected_recipients = logout_recipient_endpoints(local_metadata, binding)?;
    let expected_refs: Vec<&str> = expected_recipients.iter().map(String::as_str).collect();
    let request = HttpRequest::try_from(input)?;
    let flow = parse_logout_request_at(
        local_setting,
        peer_metadata,
        binding.as_binding(),
        &request,
        LogoutFlowValidation::typed_destinations(
            &expected_refs,
            validation.now(),
            validation.clock_skew().as_millis(),
        ),
    )?;
    let replay_deadline = crate::validator::logout_request_not_on_or_after_deadline(
        &flow.extract,
        validation.now_offset()?,
        validation.clock_skew().not_on_or_after_millis(),
    )?;
    let logout = LogoutRequest::try_from(flow)?;
    validation.check_and_store_message_replay_until(
        ReplayKey::LogoutRequestId(logout.id().clone()),
        replay_deadline,
    )?;
    Ok(Received::new(logout).with_relay_state(relay_state))
}

fn respond_slo_impl(
    local_setting: &EntitySetting,
    local_metadata: &Metadata,
    peer_entity_id: &EntityId,
    peer_metadata: &Metadata,
    request: &Received<LogoutRequest>,
    options: RespondSlo,
    transport: LogoutResponseTransport,
) -> Result<Outbound<LogoutResponse>, SamlError> {
    ensure_entity_id(request.message().issuer(), peer_entity_id)?;
    if matches!(transport, LogoutResponseTransport::SessionParticipant) {
        enforce_participant_https(
            peer_metadata,
            options.binding.as_binding(),
            options.follows_generation_rules(),
            options.allows_http(),
            LogoutMessageDirection::Response,
        )?;
    }
    let relay_state = options
        .relay_state
        .unwrap_or_else(|| request.relay_state().clone());
    relay_state.validate()?;
    let status = options.status.clone().unwrap_or_else(Status::success);
    let context = create_logout_response_with_status(
        local_setting,
        local_metadata,
        peer_metadata,
        options.binding.as_binding(),
        Some(request.message().id().as_str()),
        relay_state.as_deref(),
        // SAML Profiles 2.0 §§4.4.3.4 and 4.4.4.2 require front-channel
        // LogoutResponses to authenticate the responder and protect integrity.
        true,
        None,
        &status,
    )?;
    Outbound::<LogoutResponse>::try_from(context)
}

fn finish_slo_impl(
    local_setting: &EntitySetting,
    local_metadata: &Metadata,
    peer_entity_id: &EntityId,
    peer_metadata: &Metadata,
    pending: &PendingLogoutRequest,
    input: BrowserInput<LogoutResponse>,
    mut validation: SamlValidationContext<'_>,
) -> Result<LogoutCompleted, SamlError> {
    ensure_entity_id(pending.peer_entity_id(), peer_entity_id)?;
    ensure_logout_response_binding(input_binding(&input), pending.response_binding())?;
    ensure_relay_state(pending.relay_state(), &relay_state_from_input(&input)?)?;
    let expected_recipients =
        logout_recipient_endpoints(local_metadata, pending.response_binding())?;
    let expected_refs: Vec<&str> = expected_recipients.iter().map(String::as_str).collect();
    let request = HttpRequest::try_from(input)?;
    let flow = parse_logout_response_at(
        local_setting,
        peer_metadata,
        pending.response_binding().as_binding(),
        &request,
        pending.id().as_str(),
        LogoutFlowValidation::typed_destinations(
            &expected_refs,
            validation.now(),
            validation.clock_skew().as_millis(),
        ),
    )?;
    let response = LogoutResponse::try_from(flow)?;
    validation
        .check_and_store_message_replay(ReplayKey::LogoutResponseId(response.id().clone()))?;
    Ok(LogoutCompleted::from_response(
        peer_entity_id.clone(),
        response,
    ))
}

#[derive(Debug, Clone, Copy)]
enum LogoutResponseTransport {
    SessionParticipant,
    SessionAuthority,
}

fn enforce_participant_https(
    peer_metadata: &Metadata,
    binding: Binding,
    follows_rules: bool,
    allow_http: bool,
    direction: LogoutMessageDirection,
) -> Result<(), SamlError> {
    if !follows_rules || allow_http {
        return Ok(());
    }
    let destination = peer_logout_endpoint(peer_metadata, binding, direction)?;
    require_https_logout_endpoint(&destination)
}

fn peer_logout_endpoint(
    peer_metadata: &Metadata,
    binding: Binding,
    direction: LogoutMessageDirection,
) -> Result<String, SamlError> {
    let endpoint = match direction {
        LogoutMessageDirection::Request => peer_metadata.get_single_logout_service(binding),
        LogoutMessageDirection::Response => {
            peer_metadata.get_single_logout_response_service(binding)
        }
    };
    endpoint.ok_or_else(|| Error::MissingMetadata("SingleLogoutService".into()))
}

fn require_https_logout_endpoint(endpoint: &str) -> Result<(), SamlError> {
    let url = url::Url::parse(endpoint).map_err(|error| {
        Error::Invalid(format!(
            "SingleLogoutService location is not a URL: {error}"
        ))
    })?;
    if url.scheme() == "https" {
        return Ok(());
    }
    Err(Error::ProtocolProfile(
        "Single Logout sends the user agent to an https SingleLogoutService unless allow_http_single_logout is selected".into(),
    ))
}

fn logout_request_signing(setting: &EntitySetting, signing: LogoutSigning) -> bool {
    match signing {
        LogoutSigning::FollowLocalPolicy => setting.want_logout_request_signed,
        LogoutSigning::Sign => true,
        LogoutSigning::DoNotSignForCompatibility => false,
    }
}

fn ensure_logout_response_binding(
    actual: Binding,
    expected: LogoutBinding,
) -> Result<(), SamlError> {
    if actual == expected.as_binding() {
        return Ok(());
    }
    Err(Error::UnsupportedBinding { binding: actual })
}

fn logout_recipient_endpoints(
    local_metadata: &Metadata,
    binding: LogoutBinding,
) -> Result<Vec<String>, SamlError> {
    let locations = local_metadata.single_logout_service_locations(binding.as_binding());
    if locations.is_empty() {
        return Err(Error::MissingMetadata("SingleLogoutService".into()));
    }
    Ok(locations)
}

fn typed_logout_subject(subject: LogoutSubject) -> TypedLogoutSubject {
    let name_id = subject.name_id();
    TypedLogoutSubject {
        name_id: name_id.value().to_string(),
        name_id_format: name_id.format().map(|format| format.as_uri().to_string()),
        name_qualifier: name_id.name_qualifier().map(str::to_string),
        sp_name_qualifier: name_id.sp_name_qualifier().map(str::to_string),
        sp_provided_id: name_id.sp_provided_id().map(str::to_string),
        session_indexes: subject
            .session_indexes()
            .iter()
            .map(|session_index| session_index.as_str().to_string())
            .collect(),
    }
}
