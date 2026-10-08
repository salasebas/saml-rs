use crate::browser::{BrowserInput, Outbound, PendingAuthnRequest, SsoResponseBinding, Started};
use crate::config::IdpDescriptor;
use crate::constants::Binding;
use crate::flow::{FlowResultWithSignatureEvidence, HttpRequest, SignedMessageDestination};
use crate::model::{
    AuthnRequest, OutstandingLogout, SamlValidationContext, SsoResponse, SsoSession,
    VerifiedXmlSignature,
};
use crate::sp::{LoginRequestOptions, LoginResponseParseOptions, ServiceProvider};

use super::raw_mapping::{
    ensure_entity_id, ensure_relay_state, ensure_sso_response_binding, input_binding,
    raw_idp_descriptor, relay_state_from_input, selected_acs,
};
use super::{ForceAuthn, Saml, SamlError, Sp, StartSso};

pub(super) fn session_from_verified_flow(
    result: FlowResultWithSignatureEvidence,
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
    SsoSession::try_from_with_verified_xml_signatures(flow, verified_xml_signatures)
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
    fn try_new(idp: &IdpDescriptor, input: BrowserInput<SsoResponse>) -> Result<Self, SamlError> {
        let (delivered, resolved) = match input {
            BrowserInput::Artifact {
                delivered,
                resolved,
                ..
            } => (delivered, resolved),
            BrowserInput::Redirect { .. }
            | BrowserInput::Post { .. }
            | BrowserInput::SimpleSignPost { .. } => {
                return Ok(Self {
                    binding: input_binding(&input),
                    request: HttpRequest::try_from(input)?,
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
                crate::binding::base64_encode(resolved.xml().as_bytes()),
            )]),
            signed_destination: SignedMessageDestination::Optional,
        })
    }

    fn options<'a>(
        &self,
        validation: &SamlValidationContext<'_>,
        expected_recipient: Option<&'a str>,
    ) -> LoginResponseParseOptions<'a> {
        let options =
            LoginResponseParseOptions::at(validation.now(), validation.clock_skew().as_millis())
                .with_signed_destination(self.signed_destination);
        match expected_recipient {
            Some(expected_recipient) => options.with_expected_recipient(expected_recipient),
            None => options,
        }
    }
}

pub(super) fn finish_validated_session(
    session: SsoSession,
    validation: &mut SamlValidationContext<'_>,
    outstanding_logout: Option<&OutstandingLogout>,
) -> Result<SsoSession, SamlError> {
    let matches_outstanding_logout = match outstanding_logout {
        Some(logout) => logout.matches_unexpired(&session, validation)?,
        None => false,
    };
    session.check_and_store_replay(validation)?;
    if matches_outstanding_logout {
        return Err(SamlError::AssertionMatchesOutstandingLogout);
    }
    Ok(session)
}

impl Saml<Sp> {
    /// Local SP metadata XML.
    pub fn metadata_xml(&self) -> &str {
        self.raw_service_provider().metadata_xml()
    }

    /// Raw compatibility Service Provider.
    pub fn raw_service_provider(&self) -> &ServiceProvider {
        &self.0.service_provider
    }

    /// Start SP-initiated Web SSO.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when relay state is invalid, the IdP metadata
    /// cannot be parsed or trusted, the requested ACS is missing or conflicts
    /// with the selected binding, producer rules are combined with a custom
    /// AuthnRequest template, or request creation fails because required
    /// metadata, signing keys, or supported bindings are unavailable.
    ///
    /// # Examples
    ///
    /// ```
    /// use saml_rs::{
    ///     AcsEndpoint, EntityId, IdpConfig, IdpDescriptor, IdpValidationPolicy,
    ///     MetadataTrustPolicy, RelayStateParam, Saml, SpConfig, SpValidationPolicy,
    ///     SsoEndpoint, StartSso,
    /// };
    ///
    /// # fn main() -> Result<(), saml_rs::SamlError> {
    /// let sp_config = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
    ///     .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
    ///     .validation(SpValidationPolicy::compatibility())
    ///     .build()?;
    /// let idp_config = IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
    ///     .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso")?)
    ///     .validation(IdpValidationPolicy::compatibility())
    ///     .build()?;
    ///
    /// let sp = Saml::sp(sp_config)?;
    /// let idp = Saml::idp(idp_config)?;
    /// let idp = IdpDescriptor::from_metadata_xml(
    ///     idp.metadata_xml(),
    ///     MetadataTrustPolicy::UnsignedForCompatibility,
    /// )?;
    /// let relay_state = RelayStateParam::try_from_option(Some("state".to_string()))?;
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
        options.relay_state.validate()?;
        let raw_idp = raw_idp_descriptor(idp)?;
        let acs = selected_acs(
            self.raw_service_provider(),
            options.response_binding,
            options.acs_index,
        )?;
        let response_binding = acs.binding();
        let raw_options = LoginRequestOptions {
            relay_state: options.relay_state.as_deref(),
            force_authn: options.force_authn.map(ForceAuthn::as_bool),
            assertion_consumer_service_index: options.acs_index,
            response_binding: Some(response_binding.as_binding()),
            ..Default::default()
        };
        let context = self.raw_service_provider().create_typed_login_request(
            &raw_idp,
            options.binding.as_binding(),
            &raw_options,
            options.web_browser_sso_producer,
        )?;
        let outbound = Outbound::<AuthnRequest>::try_from(context)?;
        let pending = PendingAuthnRequest::try_new(
            outbound.id().clone(),
            options.relay_state,
            acs,
            response_binding,
            idp.entity_id().clone(),
        )?
        .with_request_binding(options.binding);
        Ok(Started { pending, outbound })
    }

    /// Finish SP-initiated SSO using stored pending AuthnRequest state.
    ///
    /// This accepts the response without applying an outstanding logout. Use
    /// [`Self::finish_sso_with_outstanding_logout`] to reject a later assertion
    /// that matches one.
    ///
    /// A response delivered as an HTTP-Artifact is passed as
    /// [`BrowserInput::artifact`], after [`Self::resolve_artifact`]. It needs
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
    /// returns `ReplayDetected` or `TimeWindowInvalid`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     BrowserInput, FormField, IdpDescriptor, PendingAuthnRequest, ReplayPolicy, Saml,
    ///     SamlValidationContext, SsoResponse,
    /// };
    /// use std::time::SystemTime;
    ///
    /// # fn finish(
    /// #     sp: &Saml<saml_rs::Sp>,
    /// #     idp: &IdpDescriptor,
    /// #     pending: &PendingAuthnRequest,
    /// #     fields: Vec<FormField>,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let validation = SamlValidationContext::new(
    ///     SystemTime::now(),
    ///     ReplayPolicy::DisabledForCompatibility,
    /// );
    /// let input = BrowserInput::<SsoResponse>::post(fields);
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
        input: BrowserInput<SsoResponse>,
        mut validation: SamlValidationContext<'_>,
    ) -> Result<SsoSession, SamlError> {
        let session = self.parsed_sso_session(idp, pending, input, &validation)?;
        finish_validated_session(session, &mut validation, None)
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
        input: BrowserInput<SsoResponse>,
        mut validation: SamlValidationContext<'_>,
        outstanding_logout: &OutstandingLogout,
    ) -> Result<SsoSession, SamlError> {
        let session = self.parsed_sso_session(idp, pending, input, &validation)?;
        finish_validated_session(session, &mut validation, Some(outstanding_logout))
    }

    /// Accept an IdP-initiated SSO response explicitly.
    ///
    /// This accepts the response without applying an outstanding logout. Use
    /// [`Self::accept_unsolicited_sso_with_outstanding_logout`] to reject a
    /// later assertion that matches one.
    ///
    /// A [`BrowserInput::artifact`] response must name this service
    /// provider's default HTTP-Artifact assertion consumer as its recipient,
    /// or the first one when none is default.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the browser binding is not valid for SSO
    /// responses, `RelayState` exceeds 80 bytes, the IdP metadata cannot be
    /// parsed or trusted, XML parsing or signature verification fails,
    /// destination, recipient, audience, condition, or time validation fails,
    /// the assertions do not share one issuer and one principal, or replay
    /// validation returns `ReplayDetected` or `TimeWindowInvalid`.
    pub fn accept_unsolicited_sso(
        &self,
        idp: &IdpDescriptor,
        input: BrowserInput<SsoResponse>,
        mut validation: SamlValidationContext<'_>,
    ) -> Result<SsoSession, SamlError> {
        let session = self.parsed_unsolicited_session(idp, input, &validation)?;
        finish_validated_session(session, &mut validation, None)
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
        input: BrowserInput<SsoResponse>,
        mut validation: SamlValidationContext<'_>,
        outstanding_logout: &OutstandingLogout,
    ) -> Result<SsoSession, SamlError> {
        let session = self.parsed_unsolicited_session(idp, input, &validation)?;
        finish_validated_session(session, &mut validation, Some(outstanding_logout))
    }

    fn parsed_sso_session(
        &self,
        idp: &IdpDescriptor,
        pending: &PendingAuthnRequest,
        input: BrowserInput<SsoResponse>,
        validation: &SamlValidationContext<'_>,
    ) -> Result<SsoSession, SamlError> {
        ensure_entity_id(pending.idp_entity_id(), idp.entity_id())?;
        ensure_sso_response_binding(input_binding(&input), pending.response_binding())?;
        ensure_relay_state(pending.relay_state(), &relay_state_from_input(&input)?)?;
        let raw_idp = raw_idp_descriptor(idp)?;
        let parse = ResponseParseInput::try_new(idp, input)?;
        let flow = self
            .raw_service_provider()
            .parse_login_response_with_request_id_at(
                &raw_idp,
                parse.binding,
                &parse.request,
                pending.request_id().as_str(),
                parse.options(validation, Some(pending.acs().location().as_str())),
            )?;
        session_from_verified_flow(flow)
    }

    fn parsed_unsolicited_session(
        &self,
        idp: &IdpDescriptor,
        input: BrowserInput<SsoResponse>,
        validation: &SamlValidationContext<'_>,
    ) -> Result<SsoSession, SamlError> {
        relay_state_from_input(&input)?;
        let binding = SsoResponseBinding::try_from(input_binding(&input))?;
        let raw_idp = raw_idp_descriptor(idp)?;
        let artifact_consumer = match binding {
            SsoResponseBinding::Artifact => Some(
                self.raw_service_provider()
                    .metadata
                    .artifact_assertion_consumer_location()
                    .ok_or_else(|| SamlError::MissingMetadata("AssertionConsumerService".into()))?,
            ),
            SsoResponseBinding::Post | SsoResponseBinding::SimpleSign => None,
        };
        let parse = ResponseParseInput::try_new(idp, input)?;
        let flow = self
            .raw_service_provider()
            .parse_unsolicited_login_response_at(
                &raw_idp,
                parse.binding,
                &parse.request,
                parse.options(validation, artifact_consumer.as_deref()),
            )?;
        session_from_verified_flow(flow)
    }
}
