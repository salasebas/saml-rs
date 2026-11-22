//! Enhanced Client/Proxy SSO at the service-provider and identity-provider ends.
//!
//! The enhanced client is not a facade. It carries SOAP between these calls.

mod protocol;

use std::marker::PhantomData;
use std::time::SystemTime;

use crate::config::{EntityId, IdpDescriptor, SpDescriptor};
use crate::flow::HttpRequest;
use crate::idp::LoginResponseOverrides;
use crate::model::{
    AuthnRequest, EndpointUrl, ForceAuthn, IsPassive, MessageId, OutstandingLogout, Received,
    RelayState, SamlValidationContext, SessionIndex, SsoResponse, SsoSession,
};
use crate::sp::{validate_provider_name, LoginResponseParseOptions, PaosAuthnRequestInput};
use crate::xml::is_xml_char;

use super::raw_mapping::{ensure_entity_id, raw_idp_descriptor, raw_sp_descriptor};
use super::response_acs::{resolve_response_acs, ResponseAcsBindings};
use super::sso_outcome::OutcomeParts;
use super::{IdentityProvider, SamlError, ServiceProvider, SsoOutcome};
use crate::http_header::{HttpHeader, PRAGMA};
use crate::soap::{RESPONSE_CACHE_CONTROL, RESPONSE_HEADERS as SOAP_RESPONSE_HEADERS};
use protocol::{
    idp_to_ecp_envelope, read_soap_body, soap_fault_envelope, sp_to_ecp_envelope, IdpToEcp,
    SpToEcp, PAOS_MEDIA_TYPE, SP_UNDERSTOOD_HEADERS,
};

pub use protocol::check_paos_client_headers;

/// Options for a service provider starting PAOS login.
#[derive(Debug, Clone)]
pub struct StartPaosSso {
    soap_endpoint: EndpointUrl,
    relay_state: Option<RelayState>,
    force_authn: Option<ForceAuthn>,
    passive: Option<IsPassive>,
    provider_name: Option<String>,
    acs_url: Option<EndpointUrl>,
    sign_authn_request: bool,
}

impl StartPaosSso {
    /// Start PAOS login at the identity provider's SOAP single sign-on
    /// endpoint.
    ///
    /// `soap_endpoint` is the AuthnRequest `Destination` and the `Loc` of the
    /// identity provider entry on `ecp:Request`. The AuthnRequest is signed by
    /// default.
    pub fn new(soap_endpoint: EndpointUrl) -> Self {
        Self {
            soap_endpoint,
            relay_state: None,
            force_authn: None,
            passive: None,
            provider_name: None,
            acs_url: None,
            sign_authn_request: true,
        }
    }

    /// Set the `ecp:RelayState` value the enhanced client must bring back.
    /// The request carries none by default.
    pub fn relay_state(mut self, relay_state: RelayState) -> Self {
        self.relay_state = Some(relay_state);
        self
    }

    /// Set `ForceAuthn` on the AuthnRequest.
    pub fn force_authn(mut self, force_authn: ForceAuthn) -> Self {
        self.force_authn = Some(force_authn);
        self
    }

    /// Set `IsPassive` on the AuthnRequest and on `ecp:Request`.
    ///
    /// A start that omits this sends `IsPassive="false"` on `ecp:Request`.
    /// An omitted value means passive to the enhanced client, so a normal
    /// login states false. The AuthnRequest attribute is written only when
    /// this is set.
    pub fn passive(mut self, passive: IsPassive) -> Self {
        self.passive = Some(passive);
        self
    }

    /// Set the human-readable service-provider `ProviderName` on
    /// `ecp:Request`. Omitted by default.
    ///
    /// The name may be empty and may contain any character XML 1.0 allows.
    /// [`ServiceProvider::start_paos_sso`] returns [`SamlError::Invalid`] for a name
    /// with a character XML 1.0 forbids, as
    /// [`ServiceProvider::start_sso`] does for
    /// [`StartSso::provider_name`](crate::StartSso::provider_name).
    pub fn provider_name(mut self, provider_name: impl Into<String>) -> Self {
        self.provider_name = Some(provider_name.into());
        self
    }

    /// Set the assertion consumer the response is posted to, in place of the
    /// default one.
    ///
    /// [`ServiceProvider::start_paos_sso`] returns [`SamlError::Invalid`] for a URL
    /// the service provider metadata does not publish for HTTP-POST or
    /// HTTP-POST-SimpleSign.
    pub fn acs_url(mut self, url: EndpointUrl) -> Self {
        self.acs_url = Some(url);
        self
    }

    /// Leave the AuthnRequest unsigned.
    ///
    /// This profile recommends a signature. An identity provider that requires
    /// one will reject the request.
    pub fn allow_unsigned_authn_request(mut self) -> Self {
        self.sign_authn_request = false;
        self
    }
}

/// Correlation state for a PAOS login the service provider has started.
///
/// Store its snapshot until the enhanced client returns the response, and
/// rebuild it with [`Self::from_snapshot`] for the finish operation.
///
/// The finish operation checks the response against the pending state you
/// pass it: the request ID, the identity-provider entity ID, the RelayState,
/// and the assertion consumer URL. It trusts that state, so the stored
/// snapshot must come back unchanged and stay tied to the session that started
/// the request. Keep it in server-side session storage. If the client carries
/// it, for example in a cookie, authenticate the value so that a changed
/// snapshot is refused. A snapshot holds no key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPaosSso {
    request_id: MessageId,
    relay_state: Option<RelayState>,
    idp_entity_id: EntityId,
    acs_url: EndpointUrl,
}

impl PendingPaosSso {
    /// AuthnRequest ID the response must cite.
    pub fn request_id(&self) -> &MessageId {
        &self.request_id
    }

    /// RelayState the service provider asked the enhanced client to return.
    pub fn relay_state(&self) -> Option<&RelayState> {
        self.relay_state.as_ref()
    }

    /// Identity provider this login was addressed to.
    pub fn idp_entity_id(&self) -> &EntityId {
        &self.idp_entity_id
    }

    /// Assertion consumer the response must target.
    pub fn acs_url(&self) -> &EndpointUrl {
        &self.acs_url
    }

    /// Correlation fields for the caller to store.
    ///
    /// With the `serde` feature, the snapshot serializes to JSON for your session
    /// store.
    pub fn snapshot(&self) -> PendingPaosSsoSnapshot {
        PendingPaosSsoSnapshot {
            request_id: self.request_id.as_str().to_string(),
            relay_state: self
                .relay_state
                .as_ref()
                .map(|relay_state| relay_state.as_str().to_string()),
            idp_entity_id: self.idp_entity_id.as_str().to_string(),
            acs_url: self.acs_url.as_str().to_string(),
        }
    }

    /// Rebuild pending state from stored correlation fields.
    ///
    /// A deserialized snapshot gets the same checks as one built with
    /// [`PendingPaosSsoSnapshot::new`].
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the request ID, RelayState,
    /// identity-provider entity ID, or assertion consumer URL is not usable.
    pub fn from_snapshot(snapshot: PendingPaosSsoSnapshot) -> Result<Self, SamlError> {
        Ok(Self {
            request_id: MessageId::try_new(snapshot.request_id)?,
            relay_state: snapshot.relay_state.map(RelayState::try_new).transpose()?,
            idp_entity_id: EntityId::try_new(snapshot.idp_entity_id)?,
            acs_url: EndpointUrl::try_new(snapshot.acs_url)?,
        })
    }
}

/// Stored correlation fields for [`PendingPaosSso`].
///
/// Build one with [`Self::new`], or take one from [`PendingPaosSso::snapshot`].
/// The optional fields are public: assign them directly. The struct is
/// non-exhaustive, so a later release can add an optional field without
/// breaking your code.
///
/// With the `serde` feature, the snapshot implements `Serialize` and
/// `Deserialize`. In JSON it reads:
///
/// ```json
/// {
///   "request_id": "_paos123",
///   "relay_state": null,
///   "idp_entity_id": "https://idp.example.com/metadata",
///   "acs_url": "https://sp.example.com/acs/paos"
/// }
/// ```
///
/// Reading JSON requires `request_id`, `idp_entity_id`, and `acs_url`. A
/// missing `relay_state` reads as `None`. Unknown fields are ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct PendingPaosSsoSnapshot {
    /// AuthnRequest ID.
    pub request_id: String,
    /// `ecp:RelayState` the service provider sent. `None` when it sent none,
    /// and an empty string when it sent an empty one.
    #[cfg_attr(feature = "serde", serde(default))]
    pub relay_state: Option<String>,
    /// Identity provider entity ID.
    pub idp_entity_id: String,
    /// Assertion consumer URL placed on the AuthnRequest.
    pub acs_url: String,
}

impl PendingPaosSsoSnapshot {
    /// Build a snapshot from the AuthnRequest ID, the identity-provider entity
    /// ID, and the assertion consumer URL.
    ///
    /// `relay_state` starts as `None`. Assign it to match the request. `new`
    /// does not check the values. [`PendingPaosSso::from_snapshot`] checks
    /// them.
    pub fn new(
        request_id: impl Into<String>,
        idp_entity_id: impl Into<String>,
        acs_url: impl Into<String>,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            relay_state: None,
            idp_entity_id: idp_entity_id.into(),
            acs_url: acs_url.into(),
        }
    }
}

/// PAOS login the service provider has handed to the enhanced client.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct StartedPaosSso {
    /// State to store until the enhanced client returns the response.
    pub pending: PendingPaosSso,
    /// HTTP 200 response whose body is the SOAP AuthnRequest.
    pub http_response: PaosHttpResponse<AuthnRequest>,
}

const PAOS_REQUEST_HEADERS: &[HttpHeader] = &[
    HttpHeader::new("Content-Type", PAOS_MEDIA_TYPE),
    RESPONSE_CACHE_CONTROL,
    PRAGMA,
];

/// HTTP response carrying a SOAP envelope.
#[derive(Debug, Clone)]
pub struct PaosHttpResponse<Message> {
    status: u16,
    headers: &'static [HttpHeader],
    soap_envelope: String,
    session_index: Option<SessionIndex>,
    _message: PhantomData<Message>,
}

impl<Message> PaosHttpResponse<Message> {
    /// HTTP status. A SAML error status is still HTTP 200. A SOAP fault is
    /// HTTP 500.
    pub fn http_status(&self) -> u16 {
        self.status
    }

    /// HTTP headers to send with the envelope.
    pub fn headers(&self) -> &[HttpHeader] {
        self.headers
    }

    /// SOAP envelope body.
    pub fn envelope(&self) -> &str {
        &self.soap_envelope
    }

    fn from_parts(headers: &'static [HttpHeader], soap_envelope: String) -> Self {
        Self {
            status: 200,
            headers,
            soap_envelope,
            session_index: None,
            _message: PhantomData,
        }
    }
}

impl PaosHttpResponse<SoapFault> {
    /// HTTP 500 SOAP fault for an envelope that is not a SAML request.
    ///
    /// Send this when [`IdentityProvider::receive_paos_sso`] fails before it returns
    /// a request. A failed login is answered by [`IdentityProvider::respond_paos_sso`]
    /// with an [`SsoOutcome::Failure`] instead, and that response stays HTTP
    /// 200.
    pub fn soap_fault() -> Self {
        let mut response = Self::from_parts(SOAP_RESPONSE_HEADERS, soap_fault_envelope());
        response.status = 500;
        response
    }
}

impl PaosHttpResponse<SsoResponse> {
    /// `SessionIndex` this library wrote in the issued assertion's
    /// `AuthnStatement`.
    ///
    /// Record it with the user's session to match the `SessionIndex` of a
    /// later `LogoutRequest`. `None` when this library wrote no
    /// `SessionIndex`.
    pub fn session_index(&self) -> Option<&SessionIndex> {
        self.session_index.as_ref()
    }
}

/// Marker for the SOAP fault [`PaosHttpResponse::soap_fault`] returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoapFault;

impl ServiceProvider {
    /// Start Enhanced Client/Proxy login for an enhanced client.
    ///
    /// Return [`StartedPaosSso::http_response`] as HTTP 200. Store
    /// [`StartedPaosSso::pending`] until that client posts the response.
    ///
    /// This method does not read HTTP headers. To decide whether the HTTP
    /// client that asked for a resource is an enhanced client, call
    /// [`check_paos_client_headers`] with its `Accept` and `PAOS` headers
    /// first.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when [`StartPaosSso::provider_name`]
    /// contains a character XML 1.0 forbids, or when the
    /// [`StartPaosSso::acs_url`] is not published. Returns [`SamlError`] when
    /// the default assertion consumer is missing, relay state is invalid or
    /// contains a character XML 1.0 forbids, or the AuthnRequest cannot be
    /// signed.
    ///
    /// # Examples
    ///
    /// ```
    /// use saml_rs::{
    ///     check_paos_client_headers, AcsEndpoint, EndpointUrl, EntityId, IdentityProvider,
    ///     IdpConfig, IdpDescriptor, MetadataTrustPolicy, ServiceProvider, SpConfig, SsoEndpoint,
    ///     StartPaosSso,
    /// };
    ///
    /// # fn main() -> Result<(), saml_rs::SamlError> {
    /// # if cfg!(not(crypto)) { return Ok(()); }
    /// let sp = ServiceProvider::new(
    ///     SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?, AcsEndpoint::post("https://sp.example.com/acs")?)
    ///         .build()?,
    /// );
    /// let idp = IdentityProvider::new(
    ///     IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?, SsoEndpoint::redirect("https://idp.example.com/sso")?)
    ///         .build()?,
    /// );
    /// let idp = IdpDescriptor::from_metadata_xml(
    ///     EntityId::try_new("https://idp.example.com/metadata")?,
    ///     idp.metadata_xml(),
    ///     MetadataTrustPolicy::AllowUnsigned,
    /// )?;
    /// // The headers of the HTTP request that asked for a resource.
    /// let accept = "text/html, application/vnd.paos+xml";
    /// let paos = r#"ver="urn:liberty:paos:2003-08";"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp""#;
    /// check_paos_client_headers(accept, paos)?;
    ///
    /// let started = sp.start_paos_sso(
    ///     &idp,
    ///     StartPaosSso::new(EndpointUrl::try_new("https://idp.example.com/soap")?)
    ///         .allow_unsigned_authn_request(),
    /// )?;
    /// assert_eq!(started.http_response.http_status(), 200);
    /// # let _ = started.http_response.envelope();
    /// # Ok(()) }
    /// ```
    pub fn start_paos_sso(
        &self,
        idp: &IdpDescriptor,
        options: StartPaosSso,
    ) -> Result<StartedPaosSso, SamlError> {
        idp.ensure_valid_at(SystemTime::now())?;
        if let Some(relay_state) = &options.relay_state {
            relay_state.ensure_sendable()?;
            if !relay_state.as_str().chars().all(is_xml_char) {
                return Err(SamlError::Invalid(
                    "relay state must not contain a character XML 1.0 forbids".into(),
                ));
            }
        }
        if let Some(provider_name) = &options.provider_name {
            validate_provider_name(provider_name)?;
        }
        let assertion_consumer = assertion_consumer_url(self, options.acs_url)?;
        let issuer = self
            .engine()
            .metadata
            .as_metadata()
            .entity_id()
            .ok_or_else(|| SamlError::MissingMetadata("entityID".into()))?
            .to_string();
        let (request_id, authn_request_xml) =
            self.engine()
                .render_paos_authn_request(&PaosAuthnRequestInput {
                    destination: options.soap_endpoint.as_str(),
                    assertion_consumer_service_url: assertion_consumer.as_str(),
                    force_authn: options.force_authn.map(ForceAuthn::as_bool),
                    is_passive: options.passive.map(IsPassive::as_bool),
                    sign: options.sign_authn_request,
                })?;
        let envelope = sp_to_ecp_envelope(&SpToEcp {
            response_consumer_url: assertion_consumer.as_str(),
            provider_name: options.provider_name.as_deref(),
            is_passive: options.passive.map(IsPassive::as_bool),
            issuer: &issuer,
            identity_provider_id: idp.entity_id().as_str(),
            identity_provider_loc: options.soap_endpoint.as_str(),
            relay_state: options.relay_state.as_ref().map(RelayState::as_str),
            authn_request_xml: &authn_request_xml,
        });
        Ok(StartedPaosSso {
            pending: PendingPaosSso {
                request_id: MessageId::try_new(request_id)?,
                relay_state: options.relay_state,
                idp_entity_id: idp.entity_id().clone(),
                acs_url: assertion_consumer,
            },
            http_response: PaosHttpResponse::from_parts(PAOS_REQUEST_HEADERS, envelope),
        })
    }

    /// Finish Enhanced Client/Proxy login from the SOAP response.
    ///
    /// `response_envelope` is the SOAP envelope the enhanced client posted to
    /// the assertion consumer. A SAML error status does not return a session.
    /// This accepts the response without applying an outstanding logout. Use
    /// [`Self::finish_paos_sso_with_outstanding_logout`] to reject a later
    /// assertion that matches one.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Xml`] when `response_envelope` is empty, blank, or
    /// not a SOAP 1.1 envelope, and [`SamlError::LimitExceeded`] when it is
    /// larger than the configured XML limits. Returns [`SamlError`] when the response does
    /// not match the pending login, including issuer, relay state,
    /// destination, recipient, or `InResponseTo`, when signature, audience,
    /// condition, time, or status checks fail, or when a SOAP header entry
    /// other than `ecp:RelayState` or `paos:Response` sets `mustUnderstand`.
    pub fn finish_paos_sso(
        &self,
        idp: &IdpDescriptor,
        pending: &PendingPaosSso,
        response_envelope: &str,
        mut validation: SamlValidationContext<'_>,
    ) -> Result<SsoSession, SamlError> {
        let session = self.parsed_paos_session(idp, pending, response_envelope, &validation)?;
        super::sp::finish_validated_session(session, &mut validation, None)
    }

    /// Finish Enhanced Client/Proxy login and apply an [`OutstandingLogout`].
    ///
    /// A match is rejected. The assertion identifier is still recorded for
    /// replay.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::AssertionMatchesOutstandingLogout`] when the logout
    /// matches. Also returns the errors documented on [`Self::finish_paos_sso`].
    pub fn finish_paos_sso_with_outstanding_logout(
        &self,
        idp: &IdpDescriptor,
        pending: &PendingPaosSso,
        response_envelope: &str,
        mut validation: SamlValidationContext<'_>,
        outstanding_logout: &OutstandingLogout,
    ) -> Result<SsoSession, SamlError> {
        let session = self.parsed_paos_session(idp, pending, response_envelope, &validation)?;
        super::sp::finish_validated_session(session, &mut validation, Some(outstanding_logout))
    }

    fn parsed_paos_session(
        &self,
        idp: &IdpDescriptor,
        pending: &PendingPaosSso,
        response_envelope: &str,
        validation: &SamlValidationContext<'_>,
    ) -> Result<SsoSession, SamlError> {
        ensure_entity_id(pending.idp_entity_id(), idp.entity_id())?;
        let limits = self.engine().setting.xml_limits;
        let body = read_soap_body(response_envelope, "Response", limits, SP_UNDERSTOOD_HEADERS)?;
        crate::schema::validate(response_envelope, self.engine().setting.schema_validator)?;
        let raw_idp = raw_idp_descriptor(idp, validation.now())?;
        let request = HttpRequest::post(vec![(
            "SAMLResponse".into(),
            crate::binding::encode_base64(body.element_xml.as_bytes()),
        )]);
        let parsed = self.engine().parse_login_response_with_request_id_at(
            raw_idp,
            crate::constants::Binding::Post,
            &request,
            pending.request_id().as_str(),
            LoginResponseParseOptions::at(validation.now(), validation.clock_skew())
                .with_expected_recipient(pending.acs_url().as_str()),
        )?;
        // The expected value is compared after the response signature verifies.
        super::raw_mapping::ensure_relay_state(pending.relay_state(), body.relay_state.as_ref())?;
        super::sp::session_from_verified_flow(parsed, body.relay_state)
    }
}

impl IdentityProvider {
    /// Read the SOAP AuthnRequest an enhanced client forwarded.
    ///
    /// `request_envelope` is the SOAP envelope posted to `soap_endpoint`, the
    /// URL that received this POST. A `Destination` on the AuthnRequest, when
    /// that attribute is present, must match it. A `ProtocolBinding` that
    /// names the PAOS binding is accepted, and
    /// [`AuthnRequest::protocol_binding`] then reports none.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Xml`] when `request_envelope` is empty, blank, or
    /// not a SOAP 1.1 envelope, and [`SamlError::LimitExceeded`] when it is
    /// larger than the configured XML limits. Returns [`SamlError`] when the envelope is not
    /// one AuthnRequest, a SOAP header entry sets `mustUnderstand`, the issuer
    /// or destination does not match, the request is unsigned while the SP
    /// metadata sets `AuthnRequestsSigned`,
    /// or signature, time, or replay checks fail. Answer those errors with
    /// [`PaosHttpResponse::soap_fault`].
    pub fn receive_paos_sso(
        &self,
        sp: &SpDescriptor,
        request_envelope: &str,
        soap_endpoint: &EndpointUrl,
        validation: SamlValidationContext<'_>,
    ) -> Result<Received<AuthnRequest>, SamlError> {
        let limits = self.engine().setting.xml_limits;
        let body = read_soap_body(request_envelope, "AuthnRequest", limits, &[])?;
        crate::schema::validate(request_envelope, self.engine().setting.schema_validator)?;
        let raw_sp = raw_sp_descriptor(sp, validation.now())?;
        let http = HttpRequest::post(vec![(
            "SAMLRequest".into(),
            crate::binding::encode_base64(body.element_xml.as_bytes()),
        )]);
        let (flow, message_authenticated) = self.engine().parse_login_request_at(
            raw_sp,
            crate::constants::Binding::Post,
            &http,
            validation.now(),
            validation.clock_skew(),
        )?;
        let flow = super::requested_subject::decrypt_requested_subject(
            flow,
            &self.engine().setting,
            message_authenticated,
        )?;
        let authn = AuthnRequest::try_from_paos_flow(flow)?;
        if let Some(destination) = authn.destination() {
            if destination.as_str() != soap_endpoint.as_str() {
                return Err(SamlError::destination_mismatch(
                    soap_endpoint.as_str(),
                    Some(destination.as_str()),
                ));
            }
        }
        let mut validation = validation;
        validation.check_authn_request_issue_instant(authn.issue_instant())?;
        validation.check_and_store_message_replay(crate::model::ReplayKey::AuthnRequest(
            authn.id().clone(),
        ))?;
        Ok(Received::new(authn, None))
    }

    /// Answer a PAOS login with a SOAP response.
    ///
    /// `outcome` says what the response reports. An
    /// [`SsoAssertion`](crate::SsoAssertion) or [`SsoOutcome::Success`] answers
    /// with that assertion. [`SsoOutcome::Failure`] ends the login with its
    /// SAML error status and no assertion, and the service provider
    /// establishes no session from it. Both are HTTP 200. The response always
    /// follows the Web Browser SSO producer rules.
    ///
    /// A request that names no assertion consumer URL or index is answered at
    /// the service provider role's default assertion consumer. A default that
    /// is not HTTP-POST or HTTP-POST-SimpleSign is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when `outcome` is
    /// [`SsoOutcome::Failure`] with a top-level `Success` status. Returns
    /// [`SamlError`] when the request has no usable assertion consumer, the
    /// issuer does not match, or the response cannot be signed. For an
    /// assertion, also returns [`SamlError`] when a persistent or transient
    /// `NameId` is longer than 256 characters, the NameID format is not an
    /// absolute URI reference,
    /// [`SsoAssertion::with_attributes`](crate::SsoAssertion::with_attributes) names a basic attribute that
    /// is not an XML name, or has a `NameFormat` that is not an absolute URI
    /// reference, the authentication context does not meet an exact
    /// `RequestedAuthnContext`,
    /// [`SsoAssertion::with_authn_instant`](crate::SsoAssertion::with_authn_instant) is
    /// later than the response `IssueInstant` or before year 1, the `NameId`
    /// `SPNameQualifier` is not the one the request's `NameIDPolicy` asks for
    /// with a SAML-defined format other than `unspecified` or `encrypted`, or
    /// the `NameId` does not strongly match the request's `Subject` (see
    /// [`RequestedSubject`](crate::RequestedSubject)).
    /// Returns [`SamlError::NameIdPolicyFormatMismatch`] or
    /// [`SamlError::NameIdPolicyRequiresEncryptedId`] under the same conditions
    /// as [`Self::respond_sso`].
    pub fn respond_paos_sso(
        &self,
        sp: &SpDescriptor,
        request: &Received<AuthnRequest>,
        outcome: impl Into<SsoOutcome>,
    ) -> Result<PaosHttpResponse<SsoResponse>, SamlError> {
        self.issue_paos_sso(sp, request, &outcome.into())
    }

    fn issue_paos_sso(
        &self,
        sp: &SpDescriptor,
        request: &Received<AuthnRequest>,
        outcome: &SsoOutcome,
    ) -> Result<PaosHttpResponse<SsoResponse>, SamlError> {
        let OutcomeParts {
            user,
            name_id_format,
            name_id_qualifiers,
            status,
            typed_attributes,
            authn_context,
            authn_instant,
        } = outcome.parts()?;
        ensure_entity_id(request.message().issuer(), sp.entity_id())?;
        let acs = EndpointUrl::try_new(resolve_response_acs(
            sp.metadata(),
            Some(request.message()),
            ResponseAcsBindings::Paos,
        )?)?;
        let raw_sp = raw_sp_descriptor(sp, SystemTime::now())?;
        let sign_encrypted_cbc = {
            let setting = &self.engine().setting;
            super::options::RespondSso::post().should_sign_response(
                setting.is_assertion_encrypted,
                &setting.data_encryption_algorithm,
            )
        };
        let overrides = LoginResponseOverrides {
            acs: Some(acs.as_str()),
            name_id_format,
            name_id_qualifiers,
            issuance_lifetime: Some(self.issuance_lifetime()),
            status,
            typed_attributes,
            authn_context,
            authn_instant,
            requested_authn_context: request.message().requested_authn_context(),
            requested_name_id_policy: request.message().name_id_policy(),
            requested_subject: request.message().requested_subject(),
            want_message_signed: Some(sign_encrypted_cbc),
            transformation_algorithms: None,
        };
        let issued = self.engine().render_posted_sso_response(
            raw_sp,
            &user,
            Some(request.message().id().as_str()),
            overrides,
        )?;
        let envelope = idp_to_ecp_envelope(&IdpToEcp {
            assertion_consumer_service_url: acs.as_str(),
            response_xml: &issued.xml,
        });
        let mut response = PaosHttpResponse::from_parts(SOAP_RESPONSE_HEADERS, envelope);
        response.session_index = issued.session_index;
        Ok(response)
    }
}

fn assertion_consumer_url(
    sp: &ServiceProvider,
    selected: Option<EndpointUrl>,
) -> Result<EndpointUrl, SamlError> {
    let metadata = &sp.engine().metadata;
    let locations = metadata.assertion_consumer_locations();
    if let Some(selected) = selected {
        if locations
            .iter()
            .any(|location| location == selected.as_str())
        {
            return Ok(selected);
        }
        return Err(SamlError::Invalid(
            "assertion consumer URL is not published in service provider metadata".into(),
        ));
    }
    let location = metadata
        .default_assertion_consumer_location()
        .ok_or_else(|| SamlError::MissingMetadata("AssertionConsumerService".into()))?;
    EndpointUrl::try_new(location)
}
