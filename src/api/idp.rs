use crate::artifact::{self, IssuedArtifacts};
use crate::browser::{ArtifactDelivery, Inbound, Outbound, SsoRequestBinding};
use crate::config::{IdpConfig, SpDescriptor};
use crate::constants::Binding;
use crate::discovery::{self, CommonDomainCookie, RememberIdentityProvider};
use crate::idp::{self, LoginResponseOptions, LoginResponseOverrides};
use crate::model::{
    AuthnRequest, Received, RelayState, ReplayKey, SamlValidationContext, SsoResponse,
};
use std::time::SystemTime;

use super::raw_mapping::{ensure_entity_id, raw_sp_descriptor, relay_state_from_input};
use super::requested_subject::decrypt_requested_subject;
use super::response_acs::{resolve_response_acs, ResponseAcsBindings};
use super::sso_outcome::OutcomeParts;
use super::{RespondSso, SamlError, SsoOutcome};

/// Where an issued response goes.
pub(super) enum ResponseTransport<'a> {
    /// The browser action carries the response.
    Browser,
    /// The response is stored, and the browser action carries its artifact.
    Artifact(ArtifactDelivery, &'a mut IssuedArtifacts),
}

/// A SAML identity provider built from an [`IdpConfig`].
///
/// It answers and initiates Web Browser SSO, single logout, artifact
/// resolution, name identifier management, and ECP with the service
/// providers it is given as [`SpDescriptor`]s.
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
    /// # Errors
    ///
    /// Returns [`SamlError`] when the inbound message or relay state is invalid, the
    /// request binding is unsupported, SP metadata cannot be parsed, XML
    /// parsing or signature/trust validation fails, the request is unsigned
    /// while the SP metadata sets `AuthnRequestsSigned` under
    /// [`AuthnRequestValidationPolicy::AllowUnsignedVerifyIfPresent`](crate::AuthnRequestValidationPolicy::AllowUnsignedVerifyIfPresent),
    /// the request destination
    /// does not match the receiving `SingleSignOnService` location for the
    /// binding, the receiving URL is unpublished, multiple local endpoints
    /// have no explicit receiving URL,
    /// an enabled [`crate::RequestAgePolicy`]
    /// rejects `IssueInstant`, or replay validation detects a duplicate or
    /// expired request.
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
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let validation = SamlValidationContext::new(
    ///     SystemTime::now(),
    ///     ReplayPolicy::Disabled,
    /// );
    /// let input = Inbound::post(fields);
    /// let request = idp.receive_sso(sp, input, validation)?;
    /// let response = idp.respond_sso(sp, &request, SsoAssertion::new(name_id), RespondSso::post())?;
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
        let raw_sp = raw_sp_descriptor(sp, validation.now())?;
        let request = input.into_http_request(self.engine().setting.xml_limits)?;
        let (flow, message_authenticated) = self.engine().parse_login_request_at(
            raw_sp,
            Binding::from(binding),
            &request,
            validation.now(),
            validation.clock_skew(),
        )?;
        let flow = decrypt_requested_subject(flow, &self.engine().setting, message_authenticated)?;
        let authn = AuthnRequest::from_flow(flow)?;
        if authn.destination().is_some() || message_authenticated {
            let locations = self
                .engine()
                .metadata
                .single_sign_on_service_locations(Binding::from(binding));
            if locations.is_empty() {
                return Err(SamlError::MissingMetadata("SingleSignOnService".into()));
            }
            let expected = validation.resolve_recipient_endpoint(&locations)?;
            let actual = authn.destination().map(|destination| destination.as_str());
            if actual != Some(expected.as_str()) {
                return Err(SamlError::destination_mismatch(&expected, actual));
            }
        }
        let mut validation = validation;
        validation.check_authn_request_issue_instant(authn.issue_instant())?;
        validation.check_and_store_message_replay(ReplayKey::AuthnRequest(authn.id().clone()))?;
        Ok(Received::new(authn, relay_state))
    }

    /// Respond to a received SP AuthnRequest.
    ///
    /// `outcome` says what the response reports: an
    /// [`SsoAssertion`](crate::SsoAssertion) or [`SsoOutcome::Success`] writes
    /// a `Success` response with that assertion, and [`SsoOutcome::Failure`]
    /// writes a response with that error status and no assertion. `options`
    /// selects the delivery and response signing.
    ///
    /// This does not write the Identity Provider Discovery cookie. Call
    /// [`Self::common_domain_cookie`] after authentication when the
    /// caller wants this identity provider remembered.
    ///
    /// The assertion `Subject` has the assertion's `NameId` as its `NameID`,
    /// with its value, `Format`, `NameQualifier`, `SPNameQualifier`, and
    /// `SPProvidedID`, and the bearer `SubjectConfirmation` this identity
    /// provider writes. A `NameId` without a format is written with the first
    /// configured NameID format; with none configured, `Format` is omitted.
    /// After a service provider sets its alternative identifier through
    /// [`Self::receive_name_id_management`], pass that value with
    /// [`NameId::with_sp_provided_id`](crate::NameId::with_sp_provided_id).
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when `outcome` is
    /// [`SsoOutcome::Failure`] with a top-level `Success` status. Returns
    /// [`SamlError`] when the request issuer does not match the SP
    /// descriptor, relay state is invalid, the request ACS selection conflicts
    /// with the response binding or SP metadata, required metadata or signing
    /// keys are missing, a request without ACS or binding selection has an
    /// unsupported metadata default or a default incompatible with the chosen
    /// response binding, the configured issuance expiration overflows the
    /// supported timestamp range, or response creation fails.
    ///
    /// For an assertion, it also returns [`SamlError`] when a basic attribute
    /// name is not an XML name, its format is not an absolute URI, the
    /// persistent or transient `NameId` is longer than 256 characters, the
    /// NameID format is not an absolute URI reference,
    /// [`SsoAssertion::with_authn_context`](crate::SsoAssertion::with_authn_context) does not meet an exact
    /// `RequestedAuthnContext`,
    /// [`SsoAssertion::with_authn_instant`](crate::SsoAssertion::with_authn_instant) is
    /// later than the response `IssueInstant`,
    /// or is before year 1, the `NameId`
    /// `SPNameQualifier` is not the one the request's `NameIDPolicy` asks for
    /// with a SAML-defined format other than `unspecified` or `encrypted`, or
    /// the `NameId` does not strongly match the
    /// request's `Subject` (see [`RequestedSubject`](crate::RequestedSubject)).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     AuthnRequest, IdentityProvider, NameId, Received, RespondSso, SpDescriptor,
    ///     SsoAssertion, SsoOutcome, Status,
    /// };
    ///
    /// # fn respond(
    /// #     idp: &IdentityProvider,
    /// #     sp: &SpDescriptor,
    /// #     request: &Received<AuthnRequest>,
    /// #     authenticated: Option<NameId>,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let outcome = match authenticated {
    ///     Some(name_id) => SsoOutcome::Success(SsoAssertion::new(name_id)),
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
            Some(request),
            &outcome.into(),
            options.delivered(ResponseTransport::Browser),
        )
    }

    /// Initiate IdP-initiated SSO.
    ///
    /// `outcome` says what the unsolicited response reports, as for
    /// [`Self::respond_sso`]. An [`SsoOutcome::Failure`] writes an error
    /// response with no `InResponseTo` and no assertion.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when `outcome` is
    /// [`SsoOutcome::Failure`] with a top-level `Success` status. Returns
    /// [`SamlError`] when relay state is invalid, SP metadata cannot be
    /// parsed, the metadata default ACS is unsupported or incompatible with
    /// the selected response binding, a signing key is missing, the
    /// selected binding is unsupported, the configured issuance expiration
    /// overflows the supported timestamp range, or response creation fails.
    ///
    /// For an assertion, it also returns [`SamlError`] when a basic attribute
    /// name is not an XML name, its format is not an absolute URI,
    /// [`SsoAssertion::with_authn_instant`](crate::SsoAssertion::with_authn_instant) is
    /// later than the response `IssueInstant`,
    /// or is before year 1, or the persistent or transient `NameId` is longer
    /// than 256 characters.
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
    /// #     form_fields: Vec<FormField>,
    /// #     replay_cache: &mut dyn saml_rs::ReplayCache,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let response = idp.initiate_sso(
    ///     sp_descriptor,
    ///     SsoAssertion::new(name_id),
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
            None,
            &outcome.into(),
            options.delivered(ResponseTransport::Browser),
        )
    }

    pub(super) fn issue_sso(
        &self,
        sp: &SpDescriptor,
        request: Option<&Received<AuthnRequest>>,
        outcome: &SsoOutcome,
        options: RespondSso<ResponseTransport<'_>>,
    ) -> Result<Outbound<SsoResponse>, SamlError> {
        let OutcomeParts {
            user,
            name_id_format,
            name_id_qualifiers,
            status,
            typed_attributes,
            authn_context,
            authn_instant,
        } = outcome.parts()?;
        if let Some(request) = request {
            ensure_entity_id(request.message().issuer(), sp.entity_id())?;
        }
        let idp_setting = &self.engine().setting;
        let sign_response = options.should_sign_response(
            idp_setting.is_assertion_encrypted,
            &idp_setting.data_encryption_algorithm,
        );
        let relay_state = match (request.and_then(Received::relay_state), options.relay_state) {
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
        let raw_sp = raw_sp_descriptor(sp, SystemTime::now())?;
        let transformation_algorithms = match &options.delivery {
            ResponseTransport::Browser => Some(idp_setting.transformation_algorithms.as_slice()),
            ResponseTransport::Artifact(..) => None,
        };
        let binding = options.binding;
        let acs = resolve_response_acs(
            &raw_sp.metadata,
            request.map(Received::message),
            ResponseAcsBindings::Browser(binding),
        )?;
        let in_response_to = request.map(|request| request.message().id().as_str());
        let overrides = LoginResponseOverrides {
            acs: Some(&acs),
            name_id_format,
            name_id_qualifiers,
            issuance_lifetime: Some(self.issuance_lifetime()),
            status,
            typed_attributes,
            authn_context,
            authn_instant,
            requested_authn_context: request
                .and_then(|request| request.message().requested_authn_context()),
            requested_name_id_policy: request
                .and_then(|request| request.message().name_id_policy()),
            requested_subject: request.and_then(|request| request.message().requested_subject()),
            want_message_signed: Some(sign_response),
            transformation_algorithms,
        };
        let (delivery, issued) = match options.delivery {
            ResponseTransport::Browser => {
                let issued = self.engine().create_login_response_with_overrides(
                    raw_sp,
                    Binding::from(binding),
                    &user,
                    &LoginResponseOptions {
                        in_response_to,
                        relay_state: relay_state.as_ref().map(RelayState::as_str),
                    },
                    overrides,
                )?;
                return Outbound::<SsoResponse>::echoing_received_relay_state(issued.context)
                    .map(|outbound| outbound.with_session_index(issued.session_index));
            }
            ResponseTransport::Artifact(delivery, issued) => (delivery, issued),
        };
        let rendered =
            self.engine()
                .render_posted_sso_response(raw_sp, &user, in_response_to, overrides)?;
        let artifact = artifact::issue_sso_response(
            &self.engine().metadata,
            sp,
            &rendered.xml,
            delivery.endpoint_index(),
            issued,
        )?;
        Outbound::<SsoResponse>::artifact(
            rendered.id,
            relay_state,
            &acs,
            &artifact,
            delivery.encoding(),
        )
        .map(|outbound| outbound.with_session_index(rendered.session_index))
        .inspect_err(|_| {
            issued.remove(&artifact);
        })
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
    /// seconds, the existing cookie is not a list of base64 entries, or this
    /// identity provider's entity identifier cannot be stored in that list.
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
