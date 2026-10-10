use crate::browser::{BrowserInput, Outbound, SsoRequestBinding};
use crate::config::SpDescriptor;
use crate::discovery::{self, CommonDomainCookie, RememberIdentityProvider};
use crate::error::SamlError as Error;
use crate::flow::HttpRequest;
use crate::idp::{IdentityProvider, LoginResponseOptions, LoginResponseOverrides};
use crate::model::{
    AuthnRequest, Received, RelayStateParam, ReplayKey, SamlValidationContext, SsoResponse, Subject,
};

use super::raw_mapping::{
    ensure_entity_id, input_binding, raw_sp_descriptor, relay_state_from_input, response_target,
};
use super::{Idp, RespondSso, Saml, SamlError};

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
    /// does not match a published `SingleSignOnService` location for the
    /// binding, an enabled [`crate::AuthnRequestAgePolicy`]
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
        let raw_sp = raw_sp_descriptor(sp)?;
        let request = HttpRequest::try_from(input)?;
        let (flow, message_authenticated) = self.raw_identity_provider().parse_login_request_at(
            &raw_sp,
            binding.as_binding(),
            &request,
            validation.now(),
            validation.clock_skew().as_millis(),
        )?;
        let authn = AuthnRequest::try_from(flow)?;
        let verify_present_signature = self
            .raw_identity_provider()
            .setting
            .verify_authn_request_signature_if_present;
        if authn.destination().is_some() || (message_authenticated && verify_present_signature) {
            let locations = self
                .raw_identity_provider()
                .metadata
                .single_sign_on_service_locations(binding.as_binding());
            let Some(expected) = locations.first() else {
                return Err(Error::MissingMetadata("SingleSignOnService".into()));
            };
            let actual = authn.destination().map(|destination| destination.as_str());
            let matches_published = actual.is_some_and(|destination| {
                locations
                    .iter()
                    .any(|location| location.as_str() == destination)
            });
            if !matches_published {
                return Err(Error::destination_mismatch(expected, actual));
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
    /// # Errors
    ///
    /// Returns [`SamlError`] when the request issuer does not match the SP
    /// descriptor, relay state is invalid, the request ACS selection conflicts
    /// with the response binding or SP metadata, required metadata or signing
    /// keys are missing, the configured issuance expiration overflows the
    /// supported timestamp range, producer rules are combined with a custom
    /// login response template, an error status is combined with a login
    /// response template, or response creation fails.
    pub fn respond_sso(
        &self,
        sp: &SpDescriptor,
        request: &Received<AuthnRequest>,
        subject: Subject,
        options: RespondSso,
    ) -> Result<Outbound<SsoResponse>, SamlError> {
        ensure_entity_id(request.message().issuer(), sp.entity_id())?;
        self.issue_sso(sp, Some(request), subject, options)
    }

    /// Initiate IdP-initiated SSO.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when relay state is invalid, SP metadata cannot be
    /// parsed, a compatible ACS endpoint or signing key is missing, the
    /// selected binding is unsupported, the configured issuance expiration
    /// overflows the supported timestamp range, producer rules are combined
    /// with a custom login response template, an error status is combined with
    /// a login response template, or response creation fails.
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
        self.issue_sso(sp, None, subject, options)
    }
    fn issue_sso(
        &self,
        sp: &SpDescriptor,
        request: Option<&Received<AuthnRequest>>,
        subject: Subject,
        options: RespondSso,
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
        let mut raw_sp = raw_sp_descriptor(sp)?;
        raw_sp.setting.want_message_signed = sign_response;
        let (binding, explicit_acs) = match request {
            Some(request) => response_target(&raw_sp, request.message(), options.binding)?,
            None => (options.binding, None),
        };
        let name_id_format = subject
            .name_id()
            .format()
            .map(|format| format.as_uri().to_string());
        let user = user_from_subject(subject);
        let raw_options = LoginResponseOptions {
            in_response_to: request.map(|request| request.message().id().as_str()),
            relay_state: relay_state.as_deref(),
            encrypt_then_sign: false,
            custom: None,
        };
        let context = self
            .raw_identity_provider()
            .create_login_response_with_overrides(
                &raw_sp,
                binding.as_binding(),
                &user,
                &raw_options,
                LoginResponseOverrides {
                    acs: explicit_acs.as_deref(),
                    name_id_format: name_id_format.as_deref(),
                    issuance_lifetime: Some(self.0.issuance_lifetime),
                    web_browser_sso_producer: options.web_browser_sso_producer,
                    status: options.status.as_ref(),
                },
            )?;
        Outbound::<SsoResponse>::try_from(context)
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
fn user_from_subject(subject: Subject) -> crate::entity::User {
    let name_id = subject.name_id().value().to_string();
    crate::entity::User::new(name_id)
}
