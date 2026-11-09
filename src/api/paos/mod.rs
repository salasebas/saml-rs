//! Enhanced Client/Proxy SSO at the service-provider and identity-provider ends.
//!
//! The enhanced client is not a facade. It carries SOAP between these calls.

mod protocol;

use std::marker::PhantomData;

use crate::config::{EntityId, IdpDescriptor, SpDescriptor};
use crate::entity::User;
use crate::flow::HttpRequest;
use crate::idp::PaosSsoResponseInput;
use crate::model::{
    AuthnRequest, EndpointUrl, ForceAuthn, IsPassive, MessageId, OutstandingLogout,
    RelayStateParam, SamlValidationContext, SsoResponse, SsoSession, Status, Subject,
    TopLevelStatusCode,
};
use crate::sp::{LoginResponseParseOptions, PaosAuthnRequestInput};

use super::raw_mapping::{ensure_entity_id, raw_idp_descriptor, raw_sp_descriptor};
use super::{Idp, Saml, SamlError, Sp};
use protocol::{
    idp_to_ecp_envelope, parse_client_headers, read_soap_body, soap_fault_envelope,
    sp_to_ecp_envelope, IdpToEcp, SpToEcp, E54_PAOS_HEADER, PAOS_MEDIA_TYPE, SOAP_MEDIA_TYPE,
};

/// HTTP headers an enhanced client sends when it can carry this login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaosClientRequest {
    _private: (),
}

impl PaosClientRequest {
    /// `Accept` value that advertises `application/vnd.paos+xml`.
    pub const ACCEPT: &'static str = PAOS_MEDIA_TYPE;

    /// `PAOS` header value. The version and the ECP service use double quotes.
    pub const PAOS_HEADER: &'static str = E54_PAOS_HEADER;

    /// Enhanced client whose `Accept` and `PAOS` headers the caller already
    /// checked.
    ///
    /// Nothing is checked here. [`Self::from_headers`] checks them.
    pub fn headers_checked_by_caller() -> Self {
        Self { _private: () }
    }

    /// Read the `Accept` and `PAOS` field values the enhanced client sent.
    ///
    /// A leading `Accept:` or `PAOS:` name is ignored. The PAOS version and
    /// the ECP service value must use double quotes.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::ProtocolProfile`] when `Accept` omits
    /// `application/vnd.paos+xml`, or when the PAOS header omits the
    /// double-quoted version or the double-quoted ECP service value.
    pub fn from_headers(accept: &str, paos: &str) -> Result<Self, SamlError> {
        parse_client_headers(accept, paos)?;
        Ok(Self { _private: () })
    }
}

/// Options for a service provider starting PAOS login.
#[derive(Debug, Clone)]
pub struct StartPaosSso {
    soap_endpoint: EndpointUrl,
    relay_state: RelayStateParam,
    force_authn: Option<ForceAuthn>,
    is_passive: Option<IsPassive>,
    provider_name: Option<String>,
    acs_url: Option<EndpointUrl>,
    sign_authn_request: bool,
}

impl StartPaosSso {
    /// Address the identity provider's SOAP single sign-on endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when `soap_endpoint` is not an absolute HTTP(S) URL.
    pub fn to_soap_endpoint(soap_endpoint: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self {
            soap_endpoint: EndpointUrl::try_new(soap_endpoint)?,
            relay_state: RelayStateParam::absent(),
            force_authn: None,
            is_passive: None,
            provider_name: None,
            acs_url: None,
            sign_authn_request: true,
        })
    }

    /// Set the `ecp:RelayState` value the enhanced client must bring back.
    pub fn relay_state(mut self, relay_state: RelayStateParam) -> Self {
        self.relay_state = relay_state;
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
    #[allow(
        clippy::wrong_self_convention,
        reason = "the builder name is the SAML IsPassive attribute, and it takes self by value like force_authn"
    )]
    pub fn is_passive(mut self, is_passive: IsPassive) -> Self {
        self.is_passive = Some(is_passive);
        self
    }

    /// Set the human-readable service-provider name on `ecp:Request`.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when `name` is empty or contains a
    /// character XML 1.0 forbids.
    pub fn provider_name(mut self, name: impl Into<String>) -> Result<Self, SamlError> {
        let name = name.into();
        if name.is_empty() || !name.chars().all(is_xml_char) {
            return Err(SamlError::Invalid(
                "provider name must not be empty or contain a character XML 1.0 forbids".into(),
            ));
        }
        self.provider_name = Some(name);
        Ok(self)
    }

    /// Post the response to this assertion consumer instead of the default one.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when `url` is not an absolute HTTP(S) URL.
    /// [`Saml<Sp>::start_paos_sso`] also rejects a URL the service provider
    /// metadata does not publish for HTTP-POST or HTTP-POST-SimpleSign.
    pub fn acs_url(mut self, url: impl Into<String>) -> Result<Self, SamlError> {
        self.acs_url = Some(EndpointUrl::try_new(url)?);
        Ok(self)
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPaosSso {
    request_id: MessageId,
    relay_state: RelayStateParam,
    idp_entity_id: EntityId,
    acs_url: EndpointUrl,
}

impl PendingPaosSso {
    /// AuthnRequest ID the response must cite.
    pub fn request_id(&self) -> &MessageId {
        &self.request_id
    }

    /// RelayState the service provider asked the enhanced client to return.
    pub fn relay_state(&self) -> &RelayStateParam {
        &self.relay_state
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
    pub fn snapshot(&self) -> PendingPaosSsoSnapshot {
        PendingPaosSsoSnapshot {
            request_id: self.request_id.as_str().to_string(),
            relay_state: self.relay_state.clone(),
            idp_entity_id: self.idp_entity_id.as_str().to_string(),
            acs_url: self.acs_url.as_str().to_string(),
        }
    }

    /// Rebuild pending state from stored correlation fields.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the request ID, identity-provider entity ID,
    /// or assertion consumer URL is not usable.
    pub fn from_snapshot(snapshot: PendingPaosSsoSnapshot) -> Result<Self, SamlError> {
        snapshot.relay_state.validate()?;
        Ok(Self {
            request_id: MessageId::try_new(snapshot.request_id)?,
            relay_state: snapshot.relay_state,
            idp_entity_id: EntityId::try_new(snapshot.idp_entity_id)?,
            acs_url: EndpointUrl::try_new(snapshot.acs_url)?,
        })
    }
}

/// Stored correlation fields for [`PendingPaosSso`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPaosSsoSnapshot {
    /// AuthnRequest ID.
    pub request_id: String,
    /// RelayState the service provider sent, including absent and empty.
    pub relay_state: RelayStateParam,
    /// Identity provider entity ID.
    pub idp_entity_id: String,
    /// Assertion consumer URL placed on the AuthnRequest.
    pub acs_url: String,
}

/// PAOS login the service provider has handed to the enhanced client.
#[derive(Debug, Clone)]
pub struct StartedPaosSso {
    /// State to store until the enhanced client returns the response.
    pub pending: PendingPaosSso,
    /// HTTP 200 response whose body is the SOAP AuthnRequest.
    pub http_response: PaosHttpResponse<AuthnRequest>,
}

/// One HTTP header on a PAOS or SOAP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHeader {
    name: String,
    value: String,
}

impl HttpHeader {
    /// Header field name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Header field value.
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// HTTP response carrying a SOAP envelope.
#[derive(Debug, Clone)]
pub struct PaosHttpResponse<Message> {
    status: u16,
    headers: Vec<HttpHeader>,
    soap_envelope: String,
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
        &self.headers
    }

    /// SOAP envelope body.
    pub fn envelope(&self) -> &str {
        &self.soap_envelope
    }

    fn from_parts(content_type: &str, soap_envelope: String) -> Self {
        Self {
            status: 200,
            headers: vec![
                HttpHeader {
                    name: "Content-Type".into(),
                    value: content_type.into(),
                },
                HttpHeader {
                    name: "Cache-Control".into(),
                    value: "no-cache, no-store, must-revalidate, private".into(),
                },
                HttpHeader {
                    name: "Pragma".into(),
                    value: "no-cache".into(),
                },
            ],
            soap_envelope,
            _message: PhantomData,
        }
    }

    fn fault(content_type: &str, soap_envelope: String) -> Self {
        let mut response = Self::from_parts(content_type, soap_envelope);
        response.status = 500;
        response
    }
}

/// Marker for the SOAP fault [`Saml<Idp>::paos_soap_fault`] returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoapFault;

/// SOAP AuthnRequest delivered to an identity provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaosAuthnRequest {
    envelope: String,
    soap_endpoint: EndpointUrl,
}

impl PaosAuthnRequest {
    /// SOAP envelope posted to `soap_endpoint`.
    ///
    /// `soap_endpoint` is the URL that received this POST. A `Destination` on
    /// the AuthnRequest, when that attribute is present, must match it.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the envelope is empty or `soap_endpoint` is
    /// not an absolute HTTP(S) URL.
    pub fn from_envelope(
        soap_envelope: impl Into<String>,
        soap_endpoint: impl Into<String>,
    ) -> Result<Self, SamlError> {
        let envelope = soap_envelope.into();
        if envelope.trim().is_empty() {
            return Err(SamlError::Invalid("SOAP envelope must not be empty".into()));
        }
        Ok(Self {
            envelope,
            soap_endpoint: EndpointUrl::try_new(soap_endpoint)?,
        })
    }
}

/// SOAP response delivered to a service provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaosSsoResponse {
    envelope: String,
}

impl PaosSsoResponse {
    /// SOAP envelope the enhanced client posted to the assertion consumer.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the envelope is empty.
    pub fn from_envelope(soap_envelope: impl Into<String>) -> Result<Self, SamlError> {
        let envelope = soap_envelope.into();
        if envelope.trim().is_empty() {
            return Err(SamlError::Invalid("SOAP envelope must not be empty".into()));
        }
        Ok(Self { envelope })
    }
}

impl Saml<Sp> {
    /// Start Enhanced Client/Proxy login for an enhanced client.
    ///
    /// Return [`StartedPaosSso::http_response`] as HTTP 200. Store
    /// [`StartedPaosSso::pending`] until that client posts the response.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the assertion consumer is missing or
    /// unpublished, relay state is invalid or contains a character XML 1.0
    /// forbids, or the AuthnRequest cannot be signed.
    ///
    /// # Examples
    ///
    /// The builders start on [`crate::SpValidationPolicy::recommended`] and
    /// [`crate::IdpValidationPolicy::recommended`]. This example passes
    /// [`crate::SpValidationPolicy::compatibility`] and
    /// [`crate::IdpValidationPolicy::compatibility`] so it builds without a
    /// crypto provider.
    ///
    /// ```
    /// use saml_rs::{
    ///     AcsEndpoint, EntityId, IdpConfig, IdpDescriptor, IdpValidationPolicy,
    ///     MetadataTrustPolicy, PaosClientRequest, Saml, SpConfig, SpValidationPolicy,
    ///     SsoEndpoint, StartPaosSso,
    /// };
    ///
    /// # fn main() -> Result<(), saml_rs::SamlError> {
    /// let sp = Saml::sp(
    ///     SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
    ///         .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
    ///         .validation(SpValidationPolicy::compatibility())
    ///         .build()?,
    /// )?;
    /// let idp = Saml::idp(
    ///     IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
    ///         .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso")?)
    ///         .validation(IdpValidationPolicy::compatibility())
    ///         .build()?,
    /// )?;
    /// let idp = IdpDescriptor::from_metadata_xml(
    ///     idp.metadata_xml(),
    ///     MetadataTrustPolicy::UnsignedForCompatibility,
    /// )?;
    /// let started = sp.start_paos_sso(
    ///     &idp,
    ///     PaosClientRequest::headers_checked_by_caller(),
    ///     StartPaosSso::to_soap_endpoint("https://idp.example.com/soap")?
    ///         .allow_unsigned_authn_request(),
    /// )?;
    /// assert_eq!(started.http_response.http_status(), 200);
    /// # let _ = started.http_response.envelope();
    /// # Ok(()) }
    /// ```
    pub fn start_paos_sso(
        &self,
        idp: &IdpDescriptor,
        _client: PaosClientRequest,
        options: StartPaosSso,
    ) -> Result<StartedPaosSso, SamlError> {
        options.relay_state.validate()?;
        if let Some(relay_state) = options.relay_state.as_deref() {
            if !relay_state.chars().all(is_xml_char) {
                return Err(SamlError::Invalid(
                    "relay state must not contain a character XML 1.0 forbids".into(),
                ));
            }
        }
        let assertion_consumer = assertion_consumer_url(self, options.acs_url)?;
        let issuer = self
            .raw_service_provider()
            .metadata
            .get_entity_id()
            .ok_or_else(|| SamlError::MissingMetadata("entityID".into()))?
            .to_string();
        let (request_id, authn_request_xml) = self
            .raw_service_provider()
            .render_paos_authn_request(&PaosAuthnRequestInput {
                destination: options.soap_endpoint.as_str(),
                assertion_consumer_service_url: assertion_consumer.as_str(),
                force_authn: options.force_authn.map(ForceAuthn::as_bool),
                is_passive: options.is_passive.map(IsPassive::as_bool),
                sign: options.sign_authn_request,
            })?;
        let envelope = sp_to_ecp_envelope(&SpToEcp {
            response_consumer_url: assertion_consumer.as_str(),
            provider_name: options.provider_name.as_deref(),
            is_passive: options.is_passive.map(IsPassive::as_bool),
            issuer: &issuer,
            identity_provider_id: idp.entity_id().as_str(),
            identity_provider_loc: options.soap_endpoint.as_str(),
            relay_state: options.relay_state.as_deref(),
            authn_request_xml: &authn_request_xml,
        });
        Ok(StartedPaosSso {
            pending: PendingPaosSso {
                request_id: MessageId::try_new(request_id)?,
                relay_state: options.relay_state,
                idp_entity_id: idp.entity_id().clone(),
                acs_url: assertion_consumer,
            },
            http_response: PaosHttpResponse::from_parts(PAOS_MEDIA_TYPE, envelope),
        })
    }

    /// Finish Enhanced Client/Proxy login from the SOAP response.
    ///
    /// A SAML error status does not return a session. This accepts the
    /// response without applying an outstanding logout. Use
    /// [`Self::finish_paos_sso_with_outstanding_logout`] to reject a later
    /// assertion that matches one.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the response does not match the pending
    /// login, including issuer, relay state, destination, recipient, or
    /// `InResponseTo`, or when signature, audience, condition, time, or status
    /// checks fail.
    pub fn finish_paos_sso(
        &self,
        idp: &IdpDescriptor,
        pending: &PendingPaosSso,
        response: &PaosSsoResponse,
        mut validation: SamlValidationContext<'_>,
    ) -> Result<SsoSession, SamlError> {
        let session = self.parsed_paos_session(idp, pending, response, &validation)?;
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
        response: &PaosSsoResponse,
        mut validation: SamlValidationContext<'_>,
        outstanding_logout: &OutstandingLogout,
    ) -> Result<SsoSession, SamlError> {
        let session = self.parsed_paos_session(idp, pending, response, &validation)?;
        super::sp::finish_validated_session(session, &mut validation, Some(outstanding_logout))
    }

    fn parsed_paos_session(
        &self,
        idp: &IdpDescriptor,
        pending: &PendingPaosSso,
        response: &PaosSsoResponse,
        validation: &SamlValidationContext<'_>,
    ) -> Result<SsoSession, SamlError> {
        ensure_entity_id(pending.idp_entity_id(), idp.entity_id())?;
        let limits = self.raw_service_provider().setting.xml_limits;
        let body = read_soap_body(&response.envelope, "Response", limits)?;
        let raw_idp = raw_idp_descriptor(idp)?;
        let request = HttpRequest::post(vec![(
            "SAMLResponse".into(),
            crate::binding::base64_encode(body.element_xml.as_bytes()),
        )]);
        let parsed = self
            .raw_service_provider()
            .parse_login_response_with_request_id_at(
                &raw_idp,
                crate::constants::Binding::Post,
                &request,
                pending.request_id().as_str(),
                LoginResponseParseOptions::at(
                    validation.now(),
                    validation.clock_skew().as_millis(),
                )
                .with_expected_recipient(pending.acs_url().as_str()),
            )?;
        // The expected value is compared after the response signature verifies.
        if pending.relay_state() != &RelayStateParam::absent() {
            super::raw_mapping::ensure_relay_state(pending.relay_state(), &body.relay_state)?;
        }
        super::sp::session_from_verified_flow(parsed)
    }
}

impl Saml<Idp> {
    /// HTTP 500 SOAP fault for an envelope that is not a SAML request.
    ///
    /// Send this when [`Self::receive_paos_sso`] fails before it returns a
    /// request. A failed login still uses [`Self::reject_paos_sso`], and that
    /// response stays HTTP 200.
    pub fn paos_soap_fault(&self) -> PaosHttpResponse<SoapFault> {
        let _ = self;
        PaosHttpResponse::fault(SOAP_MEDIA_TYPE, soap_fault_envelope())
    }

    /// Read the SOAP AuthnRequest an enhanced client forwarded.
    ///
    /// A `ProtocolBinding` that names the PAOS binding is accepted, and
    /// [`AuthnRequest::protocol_binding`] then reports none. The raw flow
    /// keeps the attribute.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the envelope is not one AuthnRequest, the
    /// issuer or destination does not match, or signature, time, or replay
    /// checks fail.
    pub fn receive_paos_sso(
        &self,
        sp: &SpDescriptor,
        request: &PaosAuthnRequest,
        validation: SamlValidationContext<'_>,
    ) -> Result<crate::model::Received<AuthnRequest>, SamlError> {
        let limits = self.raw_identity_provider().setting.xml_limits;
        let body = read_soap_body(&request.envelope, "AuthnRequest", limits)?;
        let raw_sp = raw_sp_descriptor(sp)?;
        let http = HttpRequest::post(vec![(
            "SAMLRequest".into(),
            crate::binding::base64_encode(body.element_xml.as_bytes()),
        )]);
        let (flow, message_authenticated) = self.raw_identity_provider().parse_login_request_at(
            &raw_sp,
            crate::constants::Binding::Post,
            &http,
            validation.now(),
            validation.clock_skew().as_millis(),
        )?;
        let authn = AuthnRequest::try_from_paos_flow(flow)?;
        let verify_present_signature = self
            .raw_identity_provider()
            .setting
            .verify_authn_request_signature_if_present;
        if authn.destination().is_some() || (message_authenticated && verify_present_signature) {
            let actual = authn.destination().map(EndpointUrl::as_str);
            if actual != Some(request.soap_endpoint.as_str()) {
                return Err(SamlError::destination_mismatch(
                    request.soap_endpoint.as_str(),
                    actual,
                ));
            }
        }
        let mut validation = validation;
        validation.check_authn_request_issue_instant(authn.issue_instant())?;
        validation.check_and_store_message_replay(crate::model::ReplayKey::AuthnRequestId(
            authn.id().clone(),
        ))?;
        Ok(crate::model::Received::new(authn))
    }

    /// Answer a PAOS login with a success response for `subject`.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the request has no usable assertion consumer,
    /// the issuer does not match, or the response cannot be signed.
    pub fn respond_paos_sso(
        &self,
        sp: &SpDescriptor,
        request: &crate::model::Received<AuthnRequest>,
        subject: Subject,
    ) -> Result<PaosHttpResponse<SsoResponse>, SamlError> {
        self.issue_paos_sso(sp, request, Some(subject), None)
    }

    /// End a PAOS login with a SAML error status and no assertion.
    ///
    /// The HTTP status stays 200. The caller does not receive a session when
    /// the service provider finishes this response.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when `status` is top-level success.
    /// Also returns the response-creation errors of [`Self::respond_paos_sso`].
    pub fn reject_paos_sso(
        &self,
        sp: &SpDescriptor,
        request: &crate::model::Received<AuthnRequest>,
        status: Status,
    ) -> Result<PaosHttpResponse<SsoResponse>, SamlError> {
        if status.top_level() == TopLevelStatusCode::Success {
            return Err(SamlError::Invalid(
                "reject_paos_sso requires an error status".into(),
            ));
        }
        self.issue_paos_sso(sp, request, None, Some(status))
    }

    fn issue_paos_sso(
        &self,
        sp: &SpDescriptor,
        request: &crate::model::Received<AuthnRequest>,
        subject: Option<Subject>,
        status: Option<Status>,
    ) -> Result<PaosHttpResponse<SsoResponse>, SamlError> {
        ensure_entity_id(request.message().issuer(), sp.entity_id())?;
        let acs = assertion_consumer_for_request(sp, request.message())?;
        let mut raw_sp = raw_sp_descriptor(sp)?;
        let sign_encrypted_cbc = {
            let setting = &self.raw_identity_provider().setting;
            super::options::RespondSso::post().should_sign_response(
                setting.is_assertion_encrypted,
                &setting.data_encryption_algorithm,
            )
        };
        raw_sp.setting.want_message_signed = sign_encrypted_cbc;
        let name_id_format = subject.as_ref().and_then(|subject| {
            subject
                .name_id()
                .format()
                .map(|format| format.as_uri().to_string())
        });
        let user = subject
            .as_ref()
            .map(|subject| User::new(subject.name_id().value()))
            .unwrap_or_else(|| User::new(""));
        let xml = self
            .raw_identity_provider()
            .render_paos_sso_response(&PaosSsoResponseInput {
                sp: &raw_sp,
                acs: acs.as_str(),
                in_response_to: request.message().id().as_str(),
                user: &user,
                name_id_format: name_id_format.as_deref(),
                issuance_lifetime: self.0.issuance_lifetime,
                status: status.as_ref(),
            })?;
        let envelope = idp_to_ecp_envelope(&IdpToEcp {
            assertion_consumer_service_url: acs.as_str(),
            response_xml: &xml,
        });
        Ok(PaosHttpResponse::from_parts(SOAP_MEDIA_TYPE, envelope))
    }
}

/// Whether XML 1.0 allows `character` in a document.
fn is_xml_char(character: char) -> bool {
    matches!(
        character,
        '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}'
    )
}

fn assertion_consumer_url(
    sp: &Saml<Sp>,
    selected: Option<EndpointUrl>,
) -> Result<EndpointUrl, SamlError> {
    let metadata = &sp.raw_service_provider().metadata;
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

fn assertion_consumer_for_request(
    sp: &SpDescriptor,
    request: &AuthnRequest,
) -> Result<EndpointUrl, SamlError> {
    if request.acs_url().is_some() && request.acs_index().is_some() {
        return Err(SamlError::Invalid(
            "AuthnRequest must not specify both an assertion consumer URL and an index".into(),
        ));
    }
    if let Some(url) = request.acs_url() {
        let published = sp.metadata().assertion_consumer_locations();
        if published.iter().any(|location| location == url.as_str()) {
            return Ok(url.clone());
        }
        return Err(SamlError::Invalid(
            "AuthnRequest AssertionConsumerServiceURL is not published for HTTP-POST or HTTP-POST-SimpleSign in service provider metadata"
                .into(),
        ));
    }
    let Some(index) = request.acs_index() else {
        return Err(SamlError::Invalid(
            "PAOS AuthnRequest needs AssertionConsumerServiceURL or AssertionConsumerServiceIndex"
                .into(),
        ));
    };
    let endpoint = sp
        .metadata()
        .get_assertion_consumer_service_by_index(index)?
        .ok_or_else(|| SamlError::MissingMetadata("AssertionConsumerService".into()))?;
    if !endpoint.accepts_posted_response() {
        return Err(SamlError::Invalid(
            "AuthnRequest AssertionConsumerServiceIndex is not published for HTTP-POST or HTTP-POST-SimpleSign in service provider metadata"
                .into(),
        ));
    }
    EndpointUrl::try_new(endpoint.location)
}
