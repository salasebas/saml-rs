use crate::browser::{
    Inbound, Outbound, PendingAuthnRequest, SsoResponseBinding, Started, Transport,
};
use crate::config::{IdpDescriptor, SpConfig};
use crate::constants::Binding;
use crate::flow::{FlowResultWithSignatureEvidence, HttpRequest, SignedMessageDestination};
use crate::model::{
    AuthnRequest, OutstandingLogout, RelayState, SamlValidationContext, SsoResponse, SsoSession,
    VerifiedXmlSignature,
};
use crate::sp::{self, AuthnRequestPreferences, LoginRequestOptions, LoginResponseParseOptions};
use crate::xml::XmlLimits;
use std::time::SystemTime;

use super::peer::{
    ensure_entity_id, ensure_relay_state, ensure_sso_response_binding, idp_engine_at,
    relay_state_from_input, selected_acs,
};
use super::{ForceAuthn, SamlError, StartSso};

pub(super) fn session_from_verified_flow(
    result: FlowResultWithSignatureEvidence,
    relay_state: Option<RelayState>,
) -> Result<SsoSession, SamlError> {
    let (flow, evidence) = result.into_parts();
    let verified_xml_signatures = evidence
        .into_iter()
        .filter_map(|signature| {
            VerifiedXmlSignature::from_verified_coverage(
                signature.algorithm_uri().to_string(),
                signature.response_covered(),
                signature.assertion_directly_covered(),
            )
        })
        .collect();
    SsoSession::try_from_with_verified_xml_signatures(flow, verified_xml_signatures, relay_state)
}

/// Raw parse input for a typed SSO response.
struct ResponseParseInput {
    binding: Binding,
    request: HttpRequest,
    signed_destination: SignedMessageDestination,
}

impl ResponseParseInput {
    /// An artifact input is accepted only when `idp` returned the message
    /// for the delivered artifact. Its XML is parsed as an HTTP-POST response.
    fn try_new(
        idp: &IdpDescriptor,
        input: Inbound<SsoResponse>,
        limits: XmlLimits,
    ) -> Result<Self, SamlError> {
        let (delivered, resolved) = match input.transport {
            Transport::Artifact {
                delivered,
                resolved,
            } => (delivered, resolved),
            Transport::Soap { .. } => {
                return Err(SamlError::UnsupportedBinding {
                    binding: Binding::Soap,
                })
            }
            Transport::Redirect { .. } | Transport::Post { .. } | Transport::SimpleSign { .. } => {
                return Ok(Self {
                    binding: input.binding(),
                    request: input.into_http_request(limits)?,
                    signed_destination: SignedMessageDestination::Required,
                });
            }
        };
        if resolved.identity_provider() != idp.entity_id().as_str() {
            return Err(SamlError::issuer_mismatch(
                idp.entity_id().as_str(),
                Some(resolved.identity_provider()),
            ));
        }
        if resolved.artifact() != delivered.artifact().as_str() {
            return Err(SamlError::Invalid(
                "resolved message does not belong to the delivered artifact".into(),
            ));
        }
        if resolved.local_name() != "Response" {
            return Err(SamlError::ProtocolProfile(
                "artifact must resolve to a protocol Response".into(),
            ));
        }
        Ok(Self {
            binding: Binding::Post,
            request: HttpRequest::post(vec![(
                crate::constants::url_params::SAML_RESPONSE.into(),
                crate::binding::encode_base64(resolved.xml().as_bytes()),
            )]),
            signed_destination: SignedMessageDestination::Optional,
        })
    }

    fn options<'a>(
        &self,
        validation: &SamlValidationContext<'_>,
        expected_recipient: &'a str,
    ) -> LoginResponseParseOptions<'a> {
        LoginResponseParseOptions::at(validation.now(), validation.clock_skew())
            .signed_destination(self.signed_destination)
            .expected_recipient(expected_recipient)
    }
}

/// A SAML service provider built from an [`SpConfig`].
///
/// It starts and finishes Web Browser SSO, single logout, artifact
/// resolution, and name identifier management with the identity providers it
/// is given as [`IdpDescriptor`]s.
#[derive(Debug)]
pub struct ServiceProvider {
    config: SpConfig,
}

impl ServiceProvider {
    /// A service provider that runs on `config`.
    ///
    /// [`SpConfigBuilder::build`](crate::SpConfigBuilder::build) has already
    /// validated `config`, so this cannot fail.
    pub fn new(config: SpConfig) -> Self {
        Self { config }
    }

    /// Local SP metadata XML.
    pub fn metadata_xml(&self) -> &str {
        self.engine().metadata_xml()
    }

    pub(crate) fn engine(&self) -> &sp::Engine {
        &self.config.engine
    }

    /// Start SP-initiated Web SSO.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when relay state is invalid, the IdP metadata
    /// cannot be parsed or trusted, the requested ACS is missing or conflicts
    /// with the selected binding, a requested authentication reference is not an absolute URI,
    /// `ProviderName` contains invalid XML characters, or request creation fails
    /// because required metadata, signing keys, or supported bindings are unavailable.
    /// Returns [`SamlError::Invalid`] for [`StartSso::simple_sign`] when the
    /// service provider's [`AuthnRequestSigningPolicy`](crate::AuthnRequestSigningPolicy)
    /// is `DoNotSign`.
    ///
    /// # Examples
    ///
    /// ```
    /// use saml_rs::{
    ///     AcsEndpoint, EntityId, IdentityProvider, IdpConfig, IdpDescriptor, MetadataTrustPolicy,
    ///     RelayState, ServiceProvider, SpConfig, SsoEndpoint, StartSso,
    /// };
    ///
    /// # fn main() -> Result<(), saml_rs::SamlError> {
    /// # if cfg!(not(crypto)) { return Ok(()); }
    /// let sp_config = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?, AcsEndpoint::post("https://sp.example.com/acs")?)
    ///     .build()?;
    /// let idp_config = IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?, SsoEndpoint::redirect("https://idp.example.com/sso")?)
    ///     .build()?;
    ///
    /// let sp = ServiceProvider::new(sp_config);
    /// let idp = IdentityProvider::new(idp_config);
    /// let idp = IdpDescriptor::from_metadata_xml(
    ///     EntityId::try_new("https://idp.example.com/metadata")?,
    ///     idp.metadata_xml(),
    ///     MetadataTrustPolicy::AllowUnsigned,
    /// )?;
    /// let relay_state = RelayState::try_new("state")?;
    /// let started = sp.start_sso(&idp, StartSso::redirect().relay_state(relay_state))?;
    ///
    /// let redirect_url = started.outbound.redirect_url()?;
    /// # let _ = redirect_url;
    /// # Ok(()) }
    /// ```
    pub fn start_sso(
        &self,
        idp: &IdpDescriptor,
        options: StartSso,
    ) -> Result<Started<AuthnRequest>, SamlError> {
        if let Some(relay_state) = &options.relay_state {
            relay_state.ensure_sendable()?;
        }
        let peer_idp = idp_engine_at(idp, SystemTime::now())?;
        let acs = selected_acs(self.engine(), options.response_binding, options.acs_index)?;
        let response_binding = acs.binding();
        let raw_options = LoginRequestOptions {
            relay_state: options.relay_state.as_ref().map(RelayState::as_str),
            force_authn: options.force_authn.map(ForceAuthn::as_bool),
            assertion_consumer_service_index: options.acs_index,
            response_binding: Some(Binding::from(response_binding)),
        };
        let context = self.engine().create_typed_login_request(
            peer_idp,
            Binding::from(options.binding),
            &raw_options,
            &AuthnRequestPreferences {
                is_passive: options.passive.map(super::IsPassive::as_bool),
                provider_name: options.provider_name.as_deref(),
                requested_authn_context: options.requested_authn_context.as_ref(),
                extensions: &options.extensions,
            },
        )?;
        let outbound = Outbound::<AuthnRequest>::from_context(context)?;
        let pending = PendingAuthnRequest::new(
            outbound.id().clone(),
            outbound.relay_state().cloned(),
            idp.entity_id().clone(),
            acs,
        );
        Ok(Started { pending, outbound })
    }

    /// Finish SP-initiated SSO using stored pending AuthnRequest state.
    ///
    /// This accepts the response without applying an outstanding logout. Use
    /// [`Self::finish_sso_with_outstanding_logout`] to reject a later assertion
    /// that matches one.
    ///
    /// The service provider verifies every signature on the response and its
    /// assertions, including any embedded signatures on HTTP-POST-SimpleSign.
    ///
    /// HTTP-POST requires [`crate::ReplayPolicy::RequireCache`]. After response
    /// parsing and verification, a missing cache returns
    /// [`SamlError::ReplayCacheRequired`]. A storage failure returns
    /// [`SamlError::ReplayCacheUnavailable`].
    ///
    /// A response delivered as an HTTP-Artifact is passed as
    /// [`Inbound::artifact`], after [`Self::resolve_artifact`]. It needs
    /// an XML signature on the `Response` or on each assertion, as an
    /// HTTP-POST response does.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the response does not match the pending
    /// request, including issuer, binding, relay state, destination, recipient,
    /// or `InResponseTo` mismatches; when an artifact input pairs the artifact
    /// with a message resolved from another artifact or another identity
    /// provider; when XML, signature, certificate trust,
    /// audience, condition, or time validation fails; when the assertions do
    /// not share one issuer and one principal; or when replay validation
    /// fails. See [`crate::ReplayCache`] for replay storage errors. A status
    /// other than `Success` returns [`SamlError::StatusNotSuccess`] once all present
    /// signatures verify and the issuer and destination checks pass. An error
    /// response can omit `InResponseTo`. If present, it must match the pending
    /// request ID. An error response does not need a signature. Only a
    /// validated success reaches the comparison with the pending request's
    /// `RelayState`. A successful HTTP-Artifact response with no XML signature
    /// on the `Response` or on each assertion returns [`SamlError::SignatureMissing`].
    /// An `Attribute` without an unqualified `Name` returns
    /// [`SamlError::ProtocolProfile`]. The `Conditions` time window returns
    /// [`SamlError::TimeWindowInvalid`] when both bounds are present and
    /// `NotBefore` is at or after `NotOnOrAfter`. The same bounds in bearer
    /// `SubjectConfirmationData` leave that confirmation unsatisfied.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     FormField, IdpDescriptor, Inbound, PendingAuthnRequest, ReplayPolicy,
    ///     SamlValidationContext, ServiceProvider,
    /// };
    /// use std::time::SystemTime;
    ///
    /// # fn finish(
    /// #     sp: &ServiceProvider,
    /// #     idp: &IdpDescriptor,
    /// #     pending: &PendingAuthnRequest,
    /// #     fields: Vec<FormField>,
    /// #     replay_cache: &mut dyn saml_rs::ReplayCache,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let validation = SamlValidationContext::new(
    ///     SystemTime::now(),
    ///     ReplayPolicy::RequireCache(replay_cache),
    /// );
    /// let input = Inbound::post(fields);
    /// let session = sp.finish_sso(idp, pending, input, validation)?;
    ///
    /// let name_id = session.name_id().value();
    /// # let _ = name_id;
    /// # Ok(()) }
    /// ```
    pub fn finish_sso(
        &self,
        idp: &IdpDescriptor,
        pending: &PendingAuthnRequest,
        input: Inbound<SsoResponse>,
        mut validation: SamlValidationContext<'_>,
    ) -> Result<SsoSession, SamlError> {
        let session = self.parsed_sso_session(idp, pending, input, &validation)?;
        self.finish_validated_session(session, &mut validation, None)
    }

    /// Finish SP-initiated SSO and apply an [`OutstandingLogout`].
    ///
    /// A match is rejected. The assertion identifier is still recorded for
    /// replay.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::AssertionMatchesOutstandingLogout`] when the logout
    /// matches. Also returns the errors documented on [`Self::finish_sso`].
    pub fn finish_sso_with_outstanding_logout(
        &self,
        idp: &IdpDescriptor,
        pending: &PendingAuthnRequest,
        input: Inbound<SsoResponse>,
        mut validation: SamlValidationContext<'_>,
        outstanding_logout: &OutstandingLogout,
    ) -> Result<SsoSession, SamlError> {
        let session = self.parsed_sso_session(idp, pending, input, &validation)?;
        self.finish_validated_session(session, &mut validation, Some(outstanding_logout))
    }

    /// Accept an IdP-initiated SSO response explicitly.
    ///
    /// This accepts the response without applying an outstanding logout. Use
    /// [`Self::accept_unsolicited_sso_with_outstanding_logout`] to reject a
    /// later assertion that matches one.
    ///
    /// The same signature and replay checks apply as in [`Self::finish_sso`].
    ///
    /// A present `Destination` and the bearer `Recipient` must name the
    /// assertion consumer that received the response. Supply that URL with
    /// [`SamlValidationContext::with_recipient_endpoint`]; it must be published
    /// for the incoming binding. When omitted, the expected URL is this service
    /// provider's default assertion consumer for the incoming binding, and the
    /// default HTTP-Artifact consumer for a [`Inbound::artifact`] response.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the browser binding is not valid for SSO
    /// responses, `RelayState` exceeds
    /// [`MAX_RECEIVED_RELAY_STATE_BYTES`](crate::MAX_RECEIVED_RELAY_STATE_BYTES),
    /// the IdP metadata cannot be parsed or trusted, XML parsing or signature
    /// verification fails, destination, recipient, audience, condition, or
    /// time validation fails,
    /// the assertions do not share one issuer and one principal, or replay
    /// validation fails. After response parsing and verification, HTTP-POST
    /// returns [`SamlError::ReplayCacheRequired`] if the cache is absent. Returns
    /// [`SamlError::InResponseToMismatch`] when the response or a bearer
    /// `SubjectConfirmationData` carries an `InResponseTo` attribute, including
    /// an empty one. A status other than `Success` returns
    /// [`SamlError::StatusNotSuccess`] once all present signatures verify and
    /// the issuer and destination checks pass. An error response does not need
    /// a signature. Returns [`SamlError::RecipientEndpointNotPublished`] when
    /// the supplied recipient endpoint is not an assertion consumer published
    /// for the incoming binding. An `Attribute` without an unqualified `Name`
    /// returns [`SamlError::ProtocolProfile`]. The assertion time window rules
    /// are the same as for [`Self::finish_sso`].
    pub fn accept_unsolicited_sso(
        &self,
        idp: &IdpDescriptor,
        input: Inbound<SsoResponse>,
        mut validation: SamlValidationContext<'_>,
    ) -> Result<SsoSession, SamlError> {
        let session = self.parsed_unsolicited_session(idp, input, &validation)?;
        self.finish_validated_session(session, &mut validation, None)
    }

    /// Accept an IdP-initiated SSO response and apply an [`OutstandingLogout`].
    ///
    /// # Errors
    ///
    /// Returns the errors documented on [`Self::finish_sso_with_outstanding_logout`]
    /// and [`Self::accept_unsolicited_sso`].
    pub fn accept_unsolicited_sso_with_outstanding_logout(
        &self,
        idp: &IdpDescriptor,
        input: Inbound<SsoResponse>,
        mut validation: SamlValidationContext<'_>,
        outstanding_logout: &OutstandingLogout,
    ) -> Result<SsoSession, SamlError> {
        let session = self.parsed_unsolicited_session(idp, input, &validation)?;
        self.finish_validated_session(session, &mut validation, Some(outstanding_logout))
    }

    pub(super) fn finish_validated_session(
        &self,
        session: SsoSession,
        validation: &mut SamlValidationContext<'_>,
        outstanding_logout: Option<&OutstandingLogout>,
    ) -> Result<SsoSession, SamlError> {
        let matches_outstanding_logout = match outstanding_logout {
            Some(logout) => logout.matches_unexpired(&session, validation)?,
            None => false,
        };
        session.check_and_store_replay(validation, self.engine().setting.xml_limits)?;
        if matches_outstanding_logout {
            return Err(SamlError::AssertionMatchesOutstandingLogout);
        }
        Ok(session)
    }

    fn parsed_sso_session(
        &self,
        idp: &IdpDescriptor,
        pending: &PendingAuthnRequest,
        input: Inbound<SsoResponse>,
        validation: &SamlValidationContext<'_>,
    ) -> Result<SsoSession, SamlError> {
        ensure_entity_id(pending.idp_entity_id(), idp.entity_id())?;
        ensure_sso_response_binding(input.binding(), pending.acs().binding())?;
        let relay_state = relay_state_from_input(&input)?;
        let peer_idp = idp_engine_at(idp, validation.now())?;
        let parse = ResponseParseInput::try_new(idp, input, self.engine().setting.xml_limits)?;
        let flow = self.engine().parse_login_response_with_request_id_at(
            peer_idp,
            parse.binding,
            &parse.request,
            pending.request_id().as_str(),
            parse.options(validation, pending.acs().location().as_str()),
        )?;
        ensure_relay_state(pending.relay_state(), relay_state.as_ref())?;
        validation.check_sso_replay_policy(pending.acs().binding())?;
        session_from_verified_flow(flow, relay_state)
    }

    fn parsed_unsolicited_session(
        &self,
        idp: &IdpDescriptor,
        input: Inbound<SsoResponse>,
        validation: &SamlValidationContext<'_>,
    ) -> Result<SsoSession, SamlError> {
        let relay_state = relay_state_from_input(&input)?;
        let binding = SsoResponseBinding::try_from(input.binding())?;
        let peer_idp = idp_engine_at(idp, validation.now())?;
        let metadata = &self.engine().metadata;
        let expected_recipient = match validation.recipient_endpoint() {
            Some(_) => validation.resolve_recipient_endpoint(
                &metadata.assertion_consumer_service_locations(Binding::from(binding)),
            )?,
            None => metadata
                .assertion_consumer_location(Binding::from(binding))
                .ok_or_else(|| SamlError::MissingMetadata("AssertionConsumerService".into()))?,
        };
        let parse = ResponseParseInput::try_new(idp, input, self.engine().setting.xml_limits)?;
        let flow = self.engine().parse_unsolicited_login_response_at(
            peer_idp,
            parse.binding,
            &parse.request,
            parse.options(validation, &expected_recipient),
        )?;
        validation.check_sso_replay_policy(binding)?;
        session_from_verified_flow(flow, relay_state)
    }
}
