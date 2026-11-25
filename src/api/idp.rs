use crate::artifact::{self, ArtifactStore};
use crate::browser::{ArtifactDelivery, Inbound, Outbound, SsoRequestBinding};
use crate::config::{IdpConfig, SpDescriptor};
use crate::constants::Binding;
use crate::discovery::{self, CommonDomainCookie, RememberIdentityProvider};
use crate::flow::MessageAuthentication;
use crate::idp::{self, LoginResponseOptions, LoginResponseOverrides};
use crate::model::{
    AuthnRequest, AuthnRequestRefusalReason, EndpointUrl, Received, RefusedAuthnRequest,
    RelayState, ReplayKey, RequestAge, SamlValidationContext, SsoResponse, Status,
};
use std::time::SystemTime;

use super::peer::{ensure_entity_id, relay_state_from_input, sp_engine_at};
use super::requested_subject::decrypt_requested_subject;
use super::response_acs::resolve_response_acs;
use super::sso_outcome::OutcomeParts;
use super::{RespondSso, SamlError, SsoOutcome};

pub(super) enum ResponseTransport<'a> {
    Browser,
    Artifact(ArtifactDelivery, &'a mut dyn ArtifactStore),
}

pub(super) enum SsoResponseTo<'a> {
    Request(&'a Received<AuthnRequest>, &'a SsoOutcome),
    Refusal(&'a RefusedAuthnRequest),
    Unsolicited(&'a SsoOutcome),
}

/// A SAML identity provider built from an [`IdpConfig`].
///
/// It answers and initiates Web Browser SSO, single logout, artifact
/// resolution, and name identifier management with the service providers it
/// is given as [`SpDescriptor`]s.
#[derive(Debug)]
pub struct IdentityProvider {
    config: IdpConfig,
}

impl IdentityProvider {
    /// An identity provider that runs on `config`.
    ///
    /// [`IdpConfigBuilder::build`](crate::IdpConfigBuilder::build) has
    /// already validated `config`, so this cannot fail.
    pub fn new(config: IdpConfig) -> Self {
        Self { config }
    }

    /// Local IdP metadata XML.
    pub fn metadata_xml(&self) -> &str {
        self.engine().metadata_xml()
    }

    pub(crate) fn engine(&self) -> &idp::Engine {
        &self.config.engine
    }

    pub(crate) fn issuance_lifetime(&self) -> time::Duration {
        self.config.issuance_lifetime
    }

    /// Receive an SP AuthnRequest.
    ///
    /// It returns [`SamlError::AuthnRequestRefused`] for a request it will not
    /// fulfil: an unsigned request when the SP declares `AuthnRequestsSigned`
    /// or this identity provider requires signed requests, and a request
    /// outside an enabled [`crate::RequestAgePolicy`] window.
    /// [`RefusedAuthnRequest::reason`](crate::RefusedAuthnRequest::reason)
    /// says which. Send the refusal as a correlated error response with
    /// [`Self::respond_sso_refusal`] or [`Self::respond_sso_refusal_artifact`].
    /// Show a local error page only when that call fails because no trusted
    /// assertion consumer service can receive the response.
    ///
    /// Unless the identity provider requires signed requests, it also accepts
    /// an unsigned request. [`Received::authentication`] tells you whether a
    /// verified signature covered it. Treat the content of an
    /// [`MessageAuthentication::Unauthenticated`](crate::MessageAuthentication::Unauthenticated)
    /// request as advice.
    ///
    /// With [`ReplayPolicy::RequireCache`](crate::ReplayPolicy::RequireCache),
    /// the `ID` of an authenticated request that this method returns is stored
    /// for [`SamlValidationContext::with_replay_retention`]. An unauthenticated
    /// request and a refused request are not stored.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the inbound message or relay state is invalid, the
    /// request binding is unsupported, SP metadata cannot be parsed, XML
    /// parsing or signature/trust validation fails, the request destination
    /// does not match the receiving `SingleSignOnService` location for the
    /// binding, the receiving URL is unpublished, multiple local endpoints
    /// have no explicit receiving URL, or replay validation fails for an
    /// authenticated request: [`SamlError::ReplayDetected`] for a stored `ID`,
    /// and [`SamlError::TimeWindowInvalid`] when the context has no positive
    /// replay retention. A request whose `Destination` does not match returns
    /// [`SamlError::DestinationMismatch`], not a refusal, even when it is
    /// unsigned or outside the age window.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     FormField, IdentityProvider, Inbound, NameId, ReplayPolicy, RespondSso,
    ///     SamlValidationContext, SpDescriptor, SsoAssertion,
    /// };
    /// use std::time::SystemTime;
    ///
    /// # fn respond(
    /// #     idp: &IdentityProvider,
    /// #     sp: &SpDescriptor,
    /// #     fields: Vec<FormField>,
    /// #     name_id: NameId,
    /// #     authenticated_at: SystemTime,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let validation = SamlValidationContext::new(
    ///     SystemTime::now(),
    ///     ReplayPolicy::NoCache,
    /// );
    /// let input = Inbound::post(fields);
    /// let request = idp.receive_sso(sp, input, validation)?;
    /// let assertion = SsoAssertion::new(name_id, authenticated_at);
    /// let response = idp.respond_sso(sp, &request, assertion, RespondSso::post())?;
    ///
    /// let form = response.post_form()?;
    /// # let _ = form;
    /// # Ok(()) }
    /// ```
    pub fn receive_sso(
        &self,
        sp: &SpDescriptor,
        input: Inbound<AuthnRequest>,
        validation: SamlValidationContext<'_>,
    ) -> Result<Received<AuthnRequest>, SamlError> {
        let relay_state = relay_state_from_input(&input)?;
        let binding = SsoRequestBinding::try_from(input.binding())?;
        let peer_sp = sp_engine_at(sp, validation.now())?;
        let (encoding, request) = input.into_http_request(self.engine().setting.xml_limits)?;
        let received = self.engine().parse_login_request_at(
            peer_sp,
            encoding,
            &request,
            validation.now(),
            validation.clock_skew(),
        )?;
        let authentication = received.authentication();
        let unsigned_refusal = authentication == MessageAuthentication::Unauthenticated
            && (peer_sp.metadata.authn_requests_signed()
                || self.engine().metadata.want_authn_requests_signed());
        let flow = received.into_flow_result();
        let flow = if unsigned_refusal {
            flow
        } else {
            decrypt_requested_subject(flow, &self.engine().setting, authentication)?
        };
        let authn = AuthnRequest::from_flow(&flow)?;
        if authn.destination().is_some() || authentication == MessageAuthentication::Authenticated {
            let locations = self
                .engine()
                .metadata
                .single_sign_on_service_locations(Binding::from(binding));
            if locations.is_empty() {
                return Err(SamlError::MissingMetadata("SingleSignOnService".into()));
            }
            let expected = validation.resolve_recipient_endpoint(&locations)?;
            let actual = authn.destination().map(EndpointUrl::as_str);
            if actual != Some(expected.as_str()) {
                return Err(SamlError::destination_mismatch(&expected, actual));
            }
        }
        let mut validation = validation;
        let refusal_reason = if unsigned_refusal {
            Some(AuthnRequestRefusalReason::Unsigned)
        } else {
            match validation.authn_request_issue_instant_age(authn.issue_instant())? {
                RequestAge::WithinWindow => None,
                RequestAge::OutsideWindow => Some(AuthnRequestRefusalReason::OutsideAgeWindow),
            }
        };
        if let Some(reason) = refusal_reason {
            return Err(SamlError::AuthnRequestRefused {
                refusal: Box::new(RefusedAuthnRequest {
                    request: authn,
                    relay_state,
                    reason,
                }),
            });
        }
        if authentication == MessageAuthentication::Authenticated {
            validation
                .check_and_store_message_replay(ReplayKey::AuthnRequest(authn.id().clone()))?;
        }
        Ok(Received::new(
            authn,
            binding.into(),
            relay_state,
            authentication,
        ))
    }

    /// Respond to a received SP AuthnRequest.
    ///
    /// `outcome` says what the response reports: an
    /// [`SsoAssertion`](crate::SsoAssertion) or [`SsoOutcome::Success`] writes
    /// a `Success` response with that assertion, and [`SsoOutcome::Failure`]
    /// writes a response with that error status and no assertion. `options`
    /// selects delivery and response signing. Set
    /// [`RespondSso::status_message`] to include a diagnostic on failure.
    /// If the request's ACS index is absent from current SP metadata, an error
    /// response uses the metadata default ACS if it supports the chosen binding.
    ///
    /// This does not write the Identity Provider Discovery cookie. Call
    /// [`Self::common_domain_cookie`] after authentication when the
    /// caller wants this identity provider remembered.
    ///
    /// The assertion `Subject` uses the assertion's `NameId`,
    /// with its value, `Format`, `NameQualifier`, `SPNameQualifier`, and
    /// `SPProvidedID`, and the bearer `SubjectConfirmation` this identity
    /// provider writes. A `NameId` without a format is written with the first
    /// configured NameID format; with none configured, `Format` is omitted.
    /// When `NameIDPolicy` requests `encrypted`, enable identifier encryption
    /// and use a service provider that publishes an encryption certificate.
    /// If you cannot meet the requested policy, answer with
    /// [`SsoOutcome::Failure`] and an error status.
    /// After a service provider sets its alternative identifier through
    /// [`Self::receive_name_id_management`], pass that value with
    /// [`NameId::with_sp_provided_id`](crate::NameId::with_sp_provided_id).
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when `outcome` is
    /// [`SsoOutcome::Failure`] with a top-level `Success` status or a
    /// subordinate code that is not an absolute URI reference, an error
    /// diagnostic contains characters XML 1.0 forbids or has no
    /// non-whitespace character, or the request `ID` is not an `xs:NCName`.
    /// Returns [`SamlError`] when the request issuer does not match the SP
    /// descriptor, relay state is invalid, the request ACS selection conflicts
    /// with the response binding or SP metadata, required metadata or signing
    /// keys are missing, a request without ACS or binding selection has an
    /// unsupported metadata default or a default incompatible with the chosen
    /// response binding, the configured issuance expiration overflows the
    /// supported timestamp range, or response creation fails.
    /// Returns [`SamlError::Invalid`] when one SAML 2.0 `SPSSODescriptor`
    /// publishes the request's ACS index twice, or more than one publishes it.
    /// Returns [`SamlError::NameIdPolicyFormatMismatch`] if the effective
    /// identifier format differs from a specific standard format in the
    /// request's `NameIDPolicy`. Returns
    /// [`SamlError::NameIdPolicyRequiresEncryptedId`] if the request asks for
    /// `encrypted` and identifier encryption is disabled.
    ///
    /// For an assertion, it also returns [`SamlError`] when an attribute
    /// breaks the rules of
    /// [`SsoAssertion::attributes`](crate::SsoAssertion::attributes), the
    /// `NameId` value or a qualifier is made only of XML whitespace, the
    /// persistent or transient `NameId` is longer than 256 characters, also
    /// when the format is the first configured NameID format, an `entity`
    /// `NameId` breaks the rules of [`NameId`](crate::NameId), the
    /// NameID format is not an absolute URI reference,
    /// [`SsoAssertion::authn_context`](crate::SsoAssertion::authn_context) is
    /// not an absolute URI reference or does not meet an exact
    /// `RequestedAuthnContext`,
    /// the authentication instant passed to
    /// [`SsoAssertion::new`](crate::SsoAssertion::new) is later than the
    /// moment the response is issued, or is before year 1, or the issued
    /// `Subject` does not strongly match the request's `Subject`, in its
    /// identifier or its `SubjectConfirmation` (see
    /// [`RequestedSubject`](crate::RequestedSubject)).
    /// When `NameIDPolicy` requests an `SPNameQualifier`, a specific standard
    /// format requires the issued `NameId` to carry that qualifier. An omitted
    /// or `unspecified` format requires the identifier to belong to the
    /// requested namespace. A persistent or pairwise transient identifier
    /// can omit the qualifier when the namespace is the direct recipient.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     AuthnRequest, IdentityProvider, NameId, Received, RespondSso, SpDescriptor,
    ///     SsoAssertion, SsoOutcome, Status,
    /// };
    /// use std::time::SystemTime;
    ///
    /// // The subject and the time it authenticated, from the identity
    /// // provider's login session.
    /// # fn respond(
    /// #     idp: &IdentityProvider,
    /// #     sp: &SpDescriptor,
    /// #     request: &Received<AuthnRequest>,
    /// #     authenticated: Option<(NameId, SystemTime)>,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let outcome = match authenticated {
    ///     Some((name_id, authenticated_at)) => {
    ///         SsoOutcome::Success(SsoAssertion::new(name_id, authenticated_at))
    ///     }
    ///     None => SsoOutcome::Failure(Status::responder()),
    /// };
    /// let response = idp.respond_sso(sp, request, outcome, RespondSso::post())?;
    /// let form = response.post_form()?;
    /// # let _ = form;
    /// # Ok(()) }
    /// ```
    pub fn respond_sso(
        &self,
        sp: &SpDescriptor,
        request: &Received<AuthnRequest>,
        outcome: impl Into<SsoOutcome>,
        options: RespondSso,
    ) -> Result<Outbound<SsoResponse>, SamlError> {
        self.issue_sso(
            sp,
            SsoResponseTo::Request(request, &outcome.into()),
            options.delivered(ResponseTransport::Browser),
        )
    }

    /// Send a signed, correlated `Requester` response for a refused AuthnRequest.
    ///
    /// Pass the refusal from [`SamlError::AuthnRequestRefused`] and the same
    /// SP descriptor used to receive the request. The response carries the
    /// original RelayState and has no assertion.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     AuthnRequest, IdentityProvider, Inbound, RespondSso, SamlError,
    ///     SamlValidationContext, SpDescriptor,
    /// };
    ///
    /// # fn receive(
    /// #     idp: &IdentityProvider,
    /// #     sp: &SpDescriptor,
    /// #     input: Inbound<AuthnRequest>,
    /// #     validation: SamlValidationContext<'_>,
    /// # ) -> Result<(), SamlError> {
    /// match idp.receive_sso(sp, input, validation) {
    ///     Err(SamlError::AuthnRequestRefused { refusal, .. }) => {
    ///         let response = idp.respond_sso_refusal(sp, &refusal, RespondSso::post())?;
    ///         let form = response.post_form()?;
    /// #         let _ = form;
    ///     }
    ///     Ok(request) => {
    ///         // Continue with user authentication.
    /// #         let _ = request;
    ///     }
    ///     Err(error) => return Err(error),
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the descriptor or delivery endpoint cannot
    /// be used, the selected binding conflicts with the ACS, the caller sets
    /// RelayState, the request `ID` is not an `xs:NCName`, or the response
    /// cannot be created or signed.
    pub fn respond_sso_refusal(
        &self,
        sp: &SpDescriptor,
        refusal: &RefusedAuthnRequest,
        options: RespondSso,
    ) -> Result<Outbound<SsoResponse>, SamlError> {
        self.issue_sso(
            sp,
            SsoResponseTo::Refusal(refusal),
            options.delivered(ResponseTransport::Browser),
        )
    }

    /// Initiate IdP-initiated SSO.
    ///
    /// `outcome` says what the unsolicited response reports, as for
    /// [`Self::respond_sso`]. An [`SsoOutcome::Failure`] writes an error
    /// response with no `InResponseTo` and no assertion. Use it for a login
    /// this identity provider started, or for a request whose `ID` cannot be
    /// read. Answer a request that [`Self::receive_sso`] returned with
    /// [`Self::respond_sso`], and one it refused with
    /// [`Self::respond_sso_refusal`]; both write the request `ID` as
    /// `InResponseTo`.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when `outcome` is
    /// [`SsoOutcome::Failure`] with a top-level `Success` status or a
    /// subordinate code that is not an absolute URI reference, or an error
    /// diagnostic contains characters XML 1.0 forbids or has no
    /// non-whitespace character. Returns
    /// [`SamlError`] when relay state is invalid, SP metadata cannot be
    /// parsed, the metadata default ACS is unsupported or incompatible with
    /// the selected response binding, a signing key is missing, the
    /// selected binding is unsupported, the configured issuance expiration
    /// overflows the supported timestamp range, or response creation fails.
    ///
    /// For an assertion, it also returns [`SamlError`] when an attribute
    /// breaks the rules of
    /// [`SsoAssertion::attributes`](crate::SsoAssertion::attributes),
    /// [`SsoAssertion::authn_context`](crate::SsoAssertion::authn_context) is
    /// not an absolute URI reference,
    /// the authentication instant passed to
    /// [`SsoAssertion::new`](crate::SsoAssertion::new) is later than the
    /// moment the response is issued, or is before year 1, the `NameId` value
    /// or a qualifier is made only of XML whitespace, the persistent or
    /// transient `NameId` is longer
    /// than 256 characters, or an `entity` `NameId` breaks the rules of
    /// [`NameId`](crate::NameId).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     FormField, IdentityProvider, IdpDescriptor, Inbound, NameId, ReplayPolicy, RespondSso,
    ///     SamlValidationContext, ServiceProvider, SpDescriptor, SsoAssertion,
    /// };
    /// use std::time::SystemTime;
    ///
    /// # fn initiate(
    /// #     idp: &IdentityProvider,
    /// #     sp: &ServiceProvider,
    /// #     sp_descriptor: &SpDescriptor,
    /// #     idp_descriptor: &IdpDescriptor,
    /// #     name_id: NameId,
    /// #     authenticated_at: SystemTime,
    /// #     form_fields: Vec<FormField>,
    /// #     replay_cache: &mut dyn saml_rs::ReplayCache,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let response = idp.initiate_sso(
    ///     sp_descriptor,
    ///     SsoAssertion::new(name_id, authenticated_at),
    ///     RespondSso::post(),
    /// )?;
    /// let form = response.post_form()?;
    /// # let _ = form;
    ///
    /// let validation = SamlValidationContext::new(
    ///     SystemTime::now(),
    ///     ReplayPolicy::RequireCache(replay_cache),
    /// );
    /// let session = sp.accept_unsolicited_sso(
    ///     idp_descriptor,
    ///     Inbound::post(form_fields),
    ///     validation,
    /// )?;
    /// let issuer = session.issuer().as_str();
    /// # let _ = issuer;
    /// # Ok(()) }
    /// ```
    pub fn initiate_sso(
        &self,
        sp: &SpDescriptor,
        outcome: impl Into<SsoOutcome>,
        options: RespondSso,
    ) -> Result<Outbound<SsoResponse>, SamlError> {
        self.issue_sso(
            sp,
            SsoResponseTo::Unsolicited(&outcome.into()),
            options.delivered(ResponseTransport::Browser),
        )
    }

    pub(super) fn issue_sso(
        &self,
        sp: &SpDescriptor,
        response_to: SsoResponseTo<'_>,
        options: RespondSso<ResponseTransport<'_>>,
    ) -> Result<Outbound<SsoResponse>, SamlError> {
        let refusal_outcome;
        let (request, received_relay_state, outcome) = match response_to {
            SsoResponseTo::Request(request, outcome) => {
                (Some(request.message()), request.relay_state(), outcome)
            }
            SsoResponseTo::Refusal(refusal) => {
                if options.relay_state.is_some() {
                    return Err(SamlError::ProtocolProfile(
                        "a refusal uses only the RelayState of its AuthnRequest".into(),
                    ));
                }
                refusal_outcome = SsoOutcome::Failure(Status::requester());
                (
                    Some(&refusal.request),
                    refusal.relay_state.as_ref(),
                    &refusal_outcome,
                )
            }
            SsoResponseTo::Unsolicited(outcome) => (None, None, outcome),
        };
        let OutcomeParts {
            user,
            name_id_format,
            name_id_qualifiers,
            status,
            typed_attributes,
            authn_context,
            authn_instant,
            session_not_on_or_after,
        } = outcome.parts()?;
        if let Some(request) = request {
            ensure_entity_id(request.issuer(), sp.entity_id())?;
        }
        let idp_setting = &self.engine().setting;
        let response_signature = options.response_signature(
            idp_setting.is_assertion_encrypted,
            &idp_setting.data_encryption_algorithm,
        );
        let relay_state = match (received_relay_state, options.relay_state) {
            (Some(_), Some(_)) => {
                return Err(SamlError::ProtocolProfile(
                    "a response returns the RelayState its AuthnRequest carried".into(),
                ))
            }
            (Some(received), None) => Some(received.clone()),
            (None, Some(chosen)) => {
                chosen.ensure_sendable()?;
                Some(chosen)
            }
            (None, None) => None,
        };
        let peer_sp = sp_engine_at(sp, SystemTime::now())?;
        let binding = options.binding;
        let acs = resolve_response_acs(&peer_sp.metadata, request, binding, outcome)?;
        let in_response_to = request.map(|request| request.id().as_str());
        let overrides = LoginResponseOverrides {
            acs: Some(&acs),
            name_id_format,
            name_id_qualifiers,
            issuance_lifetime: Some(self.issuance_lifetime()),
            status,
            status_message: options.status_message.as_deref(),
            typed_attributes,
            authn_context,
            authn_instant,
            session_not_on_or_after,
            requested_authn_context: request.and_then(AuthnRequest::requested_authn_context),
            requested_name_id_policy: request.and_then(AuthnRequest::name_id_policy),
            requested_subject: request.and_then(AuthnRequest::requested_subject),
            response_signature: Some(response_signature),
            transformation_algorithms: None,
        };
        match options.delivery {
            ResponseTransport::Browser => {
                let issued = self.engine().create_login_response_with_overrides(
                    peer_sp,
                    Binding::from(binding),
                    &user,
                    &LoginResponseOptions {
                        in_response_to,
                        relay_state: relay_state.as_ref().map(RelayState::as_str),
                    },
                    LoginResponseOverrides {
                        transformation_algorithms: Some(&idp_setting.transformation_algorithms),
                        ..overrides
                    },
                )?;
                Outbound::<SsoResponse>::echoing_received_relay_state(issued.context)
                    .map(|outbound| outbound.with_session_index(issued.session_index))
            }
            ResponseTransport::Artifact(delivery, issued) => {
                let rendered = self.engine().render_posted_sso_response(
                    peer_sp,
                    &user,
                    in_response_to,
                    overrides,
                )?;
                let (artifact, entry) = artifact::prepare_sso_response(
                    &self.engine().metadata,
                    sp,
                    &rendered.xml,
                    delivery.endpoint_index(),
                    issued,
                    idp_setting,
                )?;
                let outbound = Outbound::<SsoResponse>::artifact(
                    rendered.id,
                    relay_state,
                    &acs.location,
                    &artifact,
                    delivery.encoding(),
                )?
                .with_session_index(rendered.session_index);
                issued.store(&artifact, entry)?;
                Ok(outbound)
            }
        }
    }

    /// Build the `_saml_idp` cookie that remembers this identity provider.
    ///
    /// The caller writes the cookie. [`Self::respond_sso`] does not. Pass the
    /// current cookie value when the browser sent one; this identity provider
    /// is appended, or moved to the end when it is already listed. The oldest
    /// entries are dropped when the cookie name and value together would be
    /// larger than 4096 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the common domain is not a hostname
    /// without a leading period, the persistent lifetime is not a whole number
    /// of seconds, is shorter than one second, or is longer than 2147483647
    /// seconds, the existing cookie is larger than 8192 bytes, is not
    /// percent-encoded text, or has an empty entry or an entry that is not
    /// base64, or this identity provider's entity identifier cannot be stored
    /// in that list.
    ///
    /// # Examples
    ///
    /// ```
    /// use saml_rs::{
    ///     CommonDomainCookieLifetime, EntityId, IdentityProvider, IdpConfig,
    ///     RememberIdentityProvider, SsoEndpoint,
    /// };
    ///
    /// # if cfg!(not(crypto)) { return Ok::<(), saml_rs::SamlError>(()); }
    /// let idp = IdentityProvider::new(
    ///     IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?, SsoEndpoint::post("https://idp.example.com/sso")?)
    ///         .build()?,
    /// );
    /// let cookie = idp.common_domain_cookie(RememberIdentityProvider::new(
    ///     "example.org",
    ///     CommonDomainCookieLifetime::Session,
    /// ))?;
    ///
    /// assert_eq!(cookie.domain(), ".example.org");
    /// assert!(cookie
    ///     .set_cookie_header()
    ///     .ends_with("; Path=/; Domain=.example.org; Secure"));
    /// # Ok::<(), saml_rs::SamlError>(())
    /// ```
    pub fn common_domain_cookie(
        &self,
        options: RememberIdentityProvider<'_>,
    ) -> Result<CommonDomainCookie, SamlError> {
        discovery::common_domain_cookie(&self.engine().entity_id(), options)
    }
}
