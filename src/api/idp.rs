use crate::artifact::{self, IssuedArtifacts, IssuedMessage};
use crate::browser::{ArtifactDelivery, BrowserInput, Outbound, SsoRequestBinding};
use crate::config::SpDescriptor;
use crate::constants::Binding;
use crate::discovery::{self, CommonDomainCookie, RememberIdentityProvider};
use crate::error::SamlError as Error;
use crate::flow::HttpRequest;
use crate::idp::{IdentityProvider, LoginResponseOptions, LoginResponseOverrides};
use crate::model::{
    AuthnRequest, Received, RelayStateParam, ReplayKey, SamlValidationContext, SsoResponse, Subject,
};
use crate::xml::OutboundNameIdQualifiers;
use std::time::SystemTime;

use super::raw_mapping::{
    default_response_target, ensure_entity_id, input_binding, raw_sp_descriptor,
    raw_sp_for_browser_response, relay_state_from_input, response_target, user_from_subject,
};
use super::requested_subject::decrypt_requested_subject;
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
    /// Returns [`SamlError`] when browser input or relay state is invalid, the
    /// request binding is unsupported, SP metadata cannot be parsed, XML
    /// parsing or signature/trust validation fails, the request destination
    /// does not match the receiving `SingleSignOnService` location for the
    /// binding, the receiving URL is unpublished, multiple local endpoints
    /// have no explicit receiving URL,
    /// an enabled [`crate::AuthnRequestAgePolicy`]
    /// rejects `IssueInstant`, or replay validation detects a duplicate or
    /// expired request.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     AuthnRequest, BrowserInput, FormField, ReplayPolicy, RespondSso, Saml,
    ///     SamlValidationContext, SpDescriptor, Subject,
    /// };
    /// use std::time::SystemTime;
    ///
    /// # fn respond(
    /// #     idp: &Saml<saml_rs::Idp>,
    /// #     sp: &SpDescriptor,
    /// #     fields: Vec<FormField>,
    /// #     subject: Subject,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let validation = SamlValidationContext::new(
    ///     SystemTime::now(),
    ///     ReplayPolicy::DisabledForCompatibility,
    /// );
    /// let input = BrowserInput::<AuthnRequest>::post(fields);
    /// let request = idp.receive_sso(sp, input, validation)?;
    /// let response = idp.respond_sso(sp, &request, subject, RespondSso::post())?;
    ///
    /// let form = response.post_form()?;
    /// # let _ = form;
    /// # Ok(()) }
    /// ```
    pub fn receive_sso(
        &self,
        sp: &SpDescriptor,
        input: BrowserInput<AuthnRequest>,
        validation: SamlValidationContext<'_>,
    ) -> Result<Received<AuthnRequest>, SamlError> {
        let relay_state = relay_state_from_input(&input)?;
        let binding = SsoRequestBinding::try_from(input_binding(&input))?;
        let raw_sp = raw_sp_descriptor(sp, validation.now())?;
        let request = HttpRequest::try_from(input)?;
        let (flow, message_authenticated) = self.raw_identity_provider().parse_login_request_at(
            &raw_sp,
            binding.as_binding(),
            &request,
            validation.now(),
            validation.clock_skew().as_millis(),
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
                .single_sign_on_service_locations(binding.as_binding());
            if locations.is_empty() {
                return Err(Error::MissingMetadata("SingleSignOnService".into()));
            }
            let expected = validation.resolve_recipient_endpoint(&locations)?;
            let actual = authn.destination().map(|destination| destination.as_str());
            if actual != Some(expected.as_str()) {
                return Err(Error::destination_mismatch(&expected, actual));
            }
        }
        let mut validation = validation;
        validation.check_authn_request_issue_instant(authn.issue_instant())?;
        validation.check_and_store_message_replay(ReplayKey::AuthnRequestId(authn.id().clone()))?;
        Ok(Received::new(authn).with_relay_state(relay_state))
    }

    /// Respond to a received SP AuthnRequest.
    ///
    /// This does not write the Identity Provider Discovery cookie. Call
    /// [`Self::remember_identity_provider`] after authentication when the
    /// caller wants this identity provider remembered.
    ///
    /// The assertion `NameID` carries the `subject` value, format,
    /// `NameQualifier`, `SPNameQualifier`, and `SPProvidedID`. After a service
    /// provider sets its alternative identifier through
    /// [`Self::receive_name_id_management`], pass that value as
    /// `SPProvidedID` with [`NameId::with_qualifiers`](crate::NameId::with_qualifiers).
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
    /// a `subject` `NameId` with `NameQualifier`, `SPNameQualifier`, or
    /// `SPProvidedID` is combined with a login response template, the
    /// persistent or transient `NameID` of `subject` is longer than 256
    /// characters, the NameID format is not an absolute URI reference,
    /// [`RespondSso::authn_context`] is set without producer rules or does not
    /// meet an exact `RequestedAuthnContext`, [`RespondSso::authn_instant`] is
    /// set without producer rules or is later than the response `IssueInstant`,
    /// producer rules are selected and
    /// the `subject` `SPNameQualifier` is not the one the request's
    /// `NameIDPolicy` asks for with a SAML-defined format other than
    /// `unspecified` or `encrypted`, or response creation fails. Returns
    /// [`SamlError::Unsupported`] when `subject` has confirmations.
    pub fn respond_sso(
        &self,
        sp: &SpDescriptor,
        request: &Received<AuthnRequest>,
        subject: Subject,
        options: RespondSso,
    ) -> Result<Outbound<SsoResponse>, SamlError> {
        ensure_entity_id(request.message().issuer(), sp.entity_id())?;
        self.issue_sso(
            sp,
            Some(request),
            subject,
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
    /// name, a `subject` `NameId` with `NameQualifier`, `SPNameQualifier`, or
    /// `SPProvidedID` is combined with a login response template,
    /// [`RespondSso::authn_context`] is set without producer rules,
    /// [`RespondSso::authn_instant`] is set without producer rules or is later
    /// than the response `IssueInstant`, the
    /// persistent or transient `NameID` of `subject` is longer than 256
    /// characters, or response creation fails. Returns
    /// [`SamlError::Unsupported`] when `subject` has confirmations.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     BrowserInput, FormField, IdpDescriptor, ReplayPolicy, RespondSso, Saml,
    ///     SamlValidationContext, SpDescriptor, SsoResponse, Subject,
    /// };
    /// use std::time::SystemTime;
    ///
    /// # fn initiate(
    /// #     idp: &Saml<saml_rs::Idp>,
    /// #     sp: &Saml<saml_rs::Sp>,
    /// #     sp_descriptor: &SpDescriptor,
    /// #     idp_descriptor: &IdpDescriptor,
    /// #     subject: Subject,
    /// #     form_fields: Vec<FormField>,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let response = idp.initiate_sso(sp_descriptor, subject, RespondSso::post())?;
    /// let form = response.post_form()?;
    /// # let _ = form;
    ///
    /// let validation = SamlValidationContext::new(
    ///     SystemTime::now(),
    ///     ReplayPolicy::DisabledForCompatibility,
    /// );
    /// let session = sp.accept_unsolicited_sso(
    ///     idp_descriptor,
    ///     BrowserInput::<SsoResponse>::post(form_fields),
    ///     validation,
    /// )?;
    /// let issuer = session.issuer().as_str();
    /// # let _ = issuer;
    /// # Ok(()) }
    /// ```
    pub fn initiate_sso(
        &self,
        sp: &SpDescriptor,
        subject: Subject,
        options: RespondSso,
    ) -> Result<Outbound<SsoResponse>, SamlError> {
        self.issue_sso(
            sp,
            None,
            subject,
            options.delivered(ResponseTransport::Browser),
        )
    }

    pub(super) fn issue_sso(
        &self,
        sp: &SpDescriptor,
        request: Option<&Received<AuthnRequest>>,
        subject: Subject,
        options: RespondSso<ResponseTransport<'_>>,
    ) -> Result<Outbound<SsoResponse>, SamlError> {
        let idp_setting = &self.raw_identity_provider().setting;
        let sign_response = options.should_sign_response(
            idp_setting.is_assertion_encrypted,
            &idp_setting.data_encryption_algorithm,
        );
        let relay_state = options.relay_state.unwrap_or_else(|| {
            request.map_or_else(RelayStateParam::absent, |request| {
                request.relay_state().clone()
            })
        });
        relay_state.validate()?;
        let mut raw_sp = match &options.delivery {
            ResponseTransport::Browser => {
                raw_sp_for_browser_response(sp, idp_setting, SystemTime::now())?
            }
            ResponseTransport::Artifact(..) => raw_sp_descriptor(sp, SystemTime::now())?,
        };
        raw_sp.setting.want_message_signed = sign_response;
        let (binding, explicit_acs) = match request {
            Some(request) => response_target(&raw_sp, request.message(), options.binding)?,
            None => default_response_target(&raw_sp, options.binding)?,
        };
        let name_id_format = subject
            .name_id()
            .format()
            .map(|format| format.as_uri().to_string());
        let user = user_from_subject(&subject)?;
        let in_response_to = request.map(|request| request.message().id().as_str());
        let overrides = |acs| LoginResponseOverrides {
            acs,
            name_id_format: name_id_format.as_deref(),
            name_id_qualifiers: OutboundNameIdQualifiers {
                name_qualifier: subject.name_id().name_qualifier(),
                sp_name_qualifier: subject.name_id().sp_name_qualifier(),
                sp_provided_id: subject.name_id().sp_provided_id(),
            },
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
        };
        let (delivery, issued) = match options.delivery {
            ResponseTransport::Browser => {
                let issued = self
                    .raw_identity_provider()
                    .create_login_response_with_overrides(
                        &raw_sp,
                        binding.as_binding(),
                        &user,
                        &LoginResponseOptions {
                            in_response_to,
                            relay_state: relay_state.as_deref(),
                            encrypt_then_sign: false,
                            custom: None,
                        },
                        overrides(explicit_acs.as_deref()),
                    )?;
                return Outbound::<SsoResponse>::try_from(issued.context)
                    .map(|outbound| outbound.with_session_index(issued.session_index));
            }
            ResponseTransport::Artifact(delivery, issued) => (delivery, issued),
        };
        let acs = match explicit_acs {
            Some(acs) => acs,
            None => raw_sp
                .metadata
                .get_assertion_consumer_service(Binding::Artifact)
                .ok_or_else(|| Error::MissingMetadata("AssertionConsumerService".into()))?,
        };
        let rendered = self.raw_identity_provider().render_artifact_sso_response(
            &raw_sp,
            &user,
            in_response_to,
            overrides(Some(acs.as_str())),
        )?;
        let artifact = artifact::issue(
            &self.raw_identity_provider().metadata,
            sp,
            IssuedMessage::web_browser_sso_response(rendered.xml)?,
            delivery.endpoint_index(),
            issued,
        )?;
        Outbound::<SsoResponse>::artifact(
            rendered.id,
            relay_state.as_deref().map(str::to_string),
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
    ///     IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
    ///         .sso_endpoint(SsoEndpoint::post("https://idp.example.com/sso")?)
    ///         .validation(IdpValidationPolicy::compatibility())
    ///         .build()?,
    /// )?;
    /// let cookie = idp.remember_identity_provider(RememberIdentityProvider::new(
    ///     "example.org",
    ///     CommonDomainCookieLifetime::Session,
    /// ))?;
    ///
    /// assert_eq!(cookie.name(), "_saml_idp");
    /// assert_eq!(cookie.domain(), ".example.org");
    /// assert!(cookie.secure());
    /// assert!(cookie.set_cookie_header().starts_with("_saml_idp="));
    /// # Ok::<(), saml_rs::SamlError>(())
    /// ```
    pub fn remember_identity_provider(
        &self,
        options: RememberIdentityProvider<'_>,
    ) -> Result<CommonDomainCookie, SamlError> {
        discovery::remember_identity_provider(&self.raw_identity_provider().entity_id(), options)
    }
}
