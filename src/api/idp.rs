use crate::artifact::{self, IssuedArtifacts};
use crate::browser::{ArtifactDelivery, Inbound, Outbound, SsoRequestBinding};
use crate::config::{NameIdFormat, SpDescriptor};
use crate::constants::Binding;
use crate::discovery::{self, CommonDomainCookie, RememberIdentityProvider};
use crate::entity::User;
use crate::idp::{IdentityProvider, LoginResponseOptions, LoginResponseOverrides};
use crate::model::{
    AuthnRequest, NameId, Received, RelayState, ReplayKey, SamlValidationContext, SsoResponse,
};
use crate::xml::OutboundNameIdQualifiers;
use std::time::SystemTime;

use super::raw_mapping::{ensure_entity_id, raw_sp_descriptor, relay_state_from_input};
use super::requested_subject::decrypt_requested_subject;
use super::response_acs::{resolve_response_acs, ResponseAcsBindings};
use super::{Idp, RespondSso, Saml, SamlError};

/// Where an issued response goes.
pub(super) enum ResponseTransport<'a> {
    /// The browser action carries the response.
    Browser,
    /// The response is stored, and the browser action carries its artifact.
    Artifact(ArtifactDelivery, &'a mut IssuedArtifacts),
}

impl Saml<Idp> {
    /// Local IdP metadata XML.
    pub fn metadata_xml(&self) -> &str {
        self.raw_identity_provider().metadata_xml()
    }

    /// Raw compatibility Identity Provider.
    pub fn raw_identity_provider(&self) -> &IdentityProvider {
        &self.0.identity_provider
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
    ///     FormField, Inbound, NameId, ReplayPolicy, RespondSso, Saml, SamlValidationContext,
    ///     SpDescriptor,
    /// };
    /// use std::time::SystemTime;
    ///
    /// # fn respond(
    /// #     idp: &Saml<saml_rs::Idp>,
    /// #     sp: &SpDescriptor,
    /// #     fields: Vec<FormField>,
    /// #     name_id: &NameId,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let validation = SamlValidationContext::new(
    ///     SystemTime::now(),
    ///     ReplayPolicy::Disabled,
    /// );
    /// let input = Inbound::post(fields);
    /// let request = idp.receive_sso(sp, input, validation)?;
    /// let response = idp.respond_sso(sp, &request, name_id, RespondSso::post())?;
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
        let request = input.into_http_request(self.raw_identity_provider().setting.xml_limits)?;
        let (flow, message_authenticated) = self.raw_identity_provider().parse_login_request_at(
            raw_sp,
            Binding::from(binding),
            &request,
            validation.now(),
            validation.clock_skew(),
        )?;
        let flow = decrypt_requested_subject(
            flow,
            &self.raw_identity_provider().setting,
            message_authenticated,
        )?;
        let authn = AuthnRequest::try_from(flow)?;
        if authn.destination().is_some() || message_authenticated {
            let locations = self
                .raw_identity_provider()
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
    /// This does not write the Identity Provider Discovery cookie. Call
    /// [`Self::common_domain_cookie`] after authentication when the
    /// caller wants this identity provider remembered.
    ///
    /// The assertion `Subject` has `name_id` as its `NameID`, with its value,
    /// `Format`, `NameQualifier`, `SPNameQualifier`, and `SPProvidedID`, and
    /// the bearer `SubjectConfirmation` this identity provider writes. A
    /// `name_id` without a format is written with the first configured NameID
    /// format; with none configured, `Format` is omitted. After
    /// a service provider sets its alternative identifier through
    /// [`Self::receive_name_id_management`], pass that value with
    /// [`NameId::with_sp_provided_id`](crate::NameId::with_sp_provided_id).
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the request issuer does not match the SP
    /// descriptor, relay state is invalid, the request ACS selection conflicts
    /// with the response binding or SP metadata, required metadata or signing
    /// keys are missing, a request without ACS or binding selection has an
    /// unsupported metadata default or a default incompatible with the chosen
    /// response binding, the configured issuance expiration overflows the
    /// supported timestamp range, producer rules are combined with a custom
    /// login response template, an error status is combined with a login
    /// response template, [`RespondSso::attributes`] is combined with a login
    /// response template, names a basic attribute that is not an XML name, or
    /// has a `NameFormat` that is not an absolute URI reference,
    /// a `name_id` with `NameQualifier`, `SPNameQualifier`, or
    /// `SPProvidedID` is combined with a login response template, the
    /// persistent or transient `name_id` is longer than 256
    /// characters, the NameID format is not an absolute URI reference,
    /// [`RespondSso::authn_context`] is set without producer rules or does not
    /// meet an exact `RequestedAuthnContext`, [`RespondSso::authn_instant`] is
    /// set without producer rules, is later than the response `IssueInstant`,
    /// or is before year 1, producer rules are selected and
    /// the `name_id` `SPNameQualifier` is not the one the request's
    /// `NameIDPolicy` asks for with a SAML-defined format other than
    /// `unspecified` or `encrypted`, producer rules are selected and a success
    /// response's `name_id` does not strongly match the request's
    /// `Subject` (see [`RequestedSubject`](crate::RequestedSubject)), or
    /// response creation fails.
    pub fn respond_sso(
        &self,
        sp: &SpDescriptor,
        request: &Received<AuthnRequest>,
        name_id: &NameId,
        options: RespondSso,
    ) -> Result<Outbound<SsoResponse>, SamlError> {
        ensure_entity_id(request.message().issuer(), sp.entity_id())?;
        self.issue_sso(
            sp,
            Some(request),
            name_id,
            options.delivered(ResponseTransport::Browser),
        )
    }

    /// Initiate IdP-initiated SSO.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when relay state is invalid, SP metadata cannot be
    /// parsed, the metadata default ACS is unsupported or incompatible with
    /// the selected response binding, a signing key is missing, the
    /// selected binding is unsupported, the configured issuance expiration
    /// overflows the supported timestamp range, producer rules are combined
    /// with a custom login response template, an error status is combined with
    /// a login response template, [`RespondSso::attributes`] is combined with a
    /// login response template or names a basic attribute that is not an XML
    /// name, a `name_id` with `NameQualifier`, `SPNameQualifier`, or
    /// `SPProvidedID` is combined with a login response template,
    /// [`RespondSso::authn_context`] is set without producer rules,
    /// [`RespondSso::authn_instant`] is set without producer rules, is later
    /// than the response `IssueInstant`, or is before year 1, the
    /// persistent or transient `name_id` is longer than 256
    /// characters, or response creation fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     FormField, IdpDescriptor, Inbound, NameId, ReplayPolicy, RespondSso, Saml,
    ///     SamlValidationContext, SpDescriptor,
    /// };
    /// use std::time::SystemTime;
    ///
    /// # fn initiate(
    /// #     idp: &Saml<saml_rs::Idp>,
    /// #     sp: &Saml<saml_rs::Sp>,
    /// #     sp_descriptor: &SpDescriptor,
    /// #     idp_descriptor: &IdpDescriptor,
    /// #     name_id: &NameId,
    /// #     form_fields: Vec<FormField>,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let response = idp.initiate_sso(sp_descriptor, name_id, RespondSso::post())?;
    /// let form = response.post_form()?;
    /// # let _ = form;
    ///
    /// let validation = SamlValidationContext::new(
    ///     SystemTime::now(),
    ///     ReplayPolicy::Disabled,
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
        name_id: &NameId,
        options: RespondSso,
    ) -> Result<Outbound<SsoResponse>, SamlError> {
        self.issue_sso(
            sp,
            None,
            name_id,
            options.delivered(ResponseTransport::Browser),
        )
    }

    pub(super) fn issue_sso(
        &self,
        sp: &SpDescriptor,
        request: Option<&Received<AuthnRequest>>,
        name_id: &NameId,
        options: RespondSso<ResponseTransport<'_>>,
    ) -> Result<Outbound<SsoResponse>, SamlError> {
        let idp_setting = &self.raw_identity_provider().setting;
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
        let name_id_format = name_id.format().map(NameIdFormat::as_uri);
        let user = User::new(name_id.value());
        let in_response_to = request.map(|request| request.message().id().as_str());
        let overrides = LoginResponseOverrides {
            acs: Some(&acs),
            name_id_format,
            name_id_qualifiers: OutboundNameIdQualifiers::from(name_id),
            issuance_lifetime: Some(self.0.issuance_lifetime),
            web_browser_sso_producer: options.web_browser_sso_producer,
            status: options.status.as_ref(),
            typed_attributes: options.attributes.as_slice(),
            authn_context: options.authn_context.as_ref(),
            authn_instant: options.authn_instant,
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
                let issued = self
                    .raw_identity_provider()
                    .create_login_response_with_overrides(
                        raw_sp,
                        Binding::from(binding),
                        &user,
                        &LoginResponseOptions {
                            in_response_to,
                            relay_state: relay_state.as_ref().map(RelayState::as_str),
                            encrypt_then_sign: false,
                            custom: None,
                        },
                        overrides,
                    )?;
                return Outbound::<SsoResponse>::echoing_received_relay_state(issued.context)
                    .map(|outbound| outbound.with_session_index(issued.session_index));
            }
            ResponseTransport::Artifact(delivery, issued) => (delivery, issued),
        };
        let rendered = self.raw_identity_provider().render_posted_sso_response(
            raw_sp,
            &user,
            in_response_to,
            overrides,
        )?;
        let artifact = artifact::issue_sso_response(
            &self.raw_identity_provider().metadata,
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
    ///     CommonDomainCookieLifetime, EntityId, IdpConfig, IdpValidationPolicy,
    ///     RememberIdentityProvider, Saml, SsoEndpoint,
    /// };
    ///
    /// let idp = Saml::idp(
    ///     IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?, SsoEndpoint::post("https://idp.example.com/sso")?)
    ///         .validation(IdpValidationPolicy::compatibility())
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
        discovery::common_domain_cookie(&self.raw_identity_provider().entity_id(), options)
    }
}
