//! SAML Identity Provider entity.

use crate::config::{AssertionElementEncryption, ReceivedEncryptedElements};
use crate::constants::{Binding, ParserType};
use crate::entity::{
    capture_idp_issuance_window, format_saml_utc_date_time, generate_id, BindingContext,
    CustomTagReplacement, EntitySetting, IdpIssuanceWindow, User,
};
use crate::error::SamlError;
use crate::flow::{FlowOptions, FlowResult, HttpRequest};
use crate::metadata::{try_generate_idp_metadata, IdpMetadata, IdpMetadataConfig};
use crate::model::{
    validate_issued_name_id_length, validate_name_id_format, Attribute, AuthnContextReference,
    NameIdPolicy, RequestedAuthnContext, RequestedSubject, SessionIndex, Status,
    TopLevelStatusCode,
};
use crate::sp::{ServiceProvider, WebBrowserSsoProducer};
use crate::template::{
    apply_tag_prefixes, attr_tag, attribute_statement_builder, replace_tags_by_optional_value,
    validate_tag_prefixes, ATTRIBUTE_STATEMENT_TEMPLATE, ATTRIBUTE_TEMPLATE,
    LOGIN_RESPONSE_TEMPLATE,
};
use crate::validator::offset_datetime_from_system_time;
use crate::xml::OutboundNameIdQualifiers;

mod artifact;
mod login_response;
mod paos;

use login_response::{
    render_default_login_response, render_error_login_response, ErrorLoginResponseXml,
    LoginResponseXml,
};
pub(crate) use paos::PaosSsoResponseInput;
use std::time::SystemTime;

/// Optional inputs for [`IdentityProvider::create_login_response`].
#[derive(Default)]
pub struct LoginResponseOptions<'a> {
    /// `InResponseTo` — the SP request id being answered. `None` or an empty
    /// value omits the attribute.
    pub in_response_to: Option<&'a str>,
    /// RelayState to echo back to the SP.
    pub relay_state: Option<&'a str>,
    /// Request encrypt-then-sign ordering for encrypted responses.
    ///
    /// When message-signing encrypted assertions, the implementation resolves
    /// to the sound order required for verifiable signatures.
    pub encrypt_then_sign: bool,
    /// Custom template rendering hook.
    pub custom: Option<CustomTagReplacement<'a>>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct LoginResponseOverrides<'a> {
    pub(crate) acs: Option<&'a str>,
    pub(crate) name_id_format: Option<&'a str>,
    pub(crate) name_id_qualifiers: OutboundNameIdQualifiers<'a>,
    pub(crate) issuance_lifetime: Option<time::Duration>,
    pub(crate) web_browser_sso_producer: WebBrowserSsoProducer,
    pub(crate) status: Option<&'a Status>,
    pub(crate) typed_attributes: &'a [Attribute],
    pub(crate) authn_context: Option<&'a AuthnContextReference>,
    pub(crate) authn_instant: Option<SystemTime>,
    pub(crate) requested_authn_context: Option<&'a RequestedAuthnContext>,
    pub(crate) requested_name_id_policy: Option<&'a NameIdPolicy>,
    pub(crate) requested_subject: Option<&'a RequestedSubject>,
    pub(crate) want_message_signed: Option<bool>,
    pub(crate) transformation_algorithms: Option<&'a [String]>,
}

pub(crate) struct RenderedLoginResponse {
    pub(crate) id: String,
    pub(crate) xml: String,
    pub(crate) session_index: Option<SessionIndex>,
}

pub(crate) struct IssuedLoginResponse {
    pub(crate) context: BindingContext,
    pub(crate) session_index: Option<SessionIndex>,
}

#[derive(Clone, Copy)]
struct LoginResponseRendering<'a> {
    name_id_format: Option<&'a str>,
    name_id_qualifiers: OutboundNameIdQualifiers<'a>,
    custom: Option<CustomTagReplacement<'a>>,
    issuance_lifetime: time::Duration,
    web_browser_sso_producer: WebBrowserSsoProducer,
    status: Option<&'a Status>,
    typed_attributes: &'a [Attribute],
    authn_context: Option<&'a AuthnContextReference>,
    authn_instant: Option<SystemTime>,
    requested_authn_context: Option<&'a RequestedAuthnContext>,
    requested_name_id_policy: Option<&'a NameIdPolicy>,
    requested_subject: Option<&'a RequestedSubject>,
}

/// A SAML 2.0 Identity Provider: runtime [`EntitySetting`] plus parsed [`IdpMetadata`].
#[derive(Debug, Clone)]
pub struct IdentityProvider {
    /// Runtime configuration (keys, algorithms, flags).
    pub setting: EntitySetting,
    /// Parsed IdP metadata.
    pub metadata: IdpMetadata,
}

impl IdentityProvider {
    /// Build from IdP metadata XML, merging metadata-declared flags into `setting`.
    ///
    /// # Errors
    ///
    /// Returns an error when `xml` is malformed, exceeds XML limits, or cannot
    /// be parsed as IdP metadata. Metadata parser errors include invalid entity,
    /// SSO endpoint, certificate, or signing flag declarations.
    pub fn from_metadata(xml: &str, setting: EntitySetting) -> Result<Self, SamlError> {
        Ok(Self::from_parsed_metadata(
            IdpMetadata::from_xml(xml)?,
            setting,
        ))
    }

    pub(crate) fn from_parsed_metadata(metadata: IdpMetadata, mut setting: EntitySetting) -> Self {
        setting.want_authn_requests_signed = metadata.is_want_authn_requests_signed();
        let formats = metadata.get_name_id_format();
        if !formats.is_empty() {
            setting.name_id_format = formats;
        }
        if setting.entity_id.is_none() {
            setting.entity_id = metadata.get_entity_id().map(str::to_string);
        }
        Self { setting, metadata }
    }

    /// Build by generating IdP metadata from `config`, then importing it.
    ///
    /// # Errors
    ///
    /// Returns an error if `config` cannot produce valid IdP metadata, such as
    /// when `config.entity_id` is not an absolute URI reference of at most 1024
    /// characters with collapsed whitespace, required IdP SSO metadata is
    /// missing, or a configured
    /// `<NameIDFormat>` is not an absolute URI reference, or if the generated metadata
    /// cannot be parsed back into IdP metadata.
    pub fn from_config(
        config: &IdpMetadataConfig,
        setting: EntitySetting,
    ) -> Result<Self, SamlError> {
        let metadata_xml = try_generate_idp_metadata(config)?;
        Self::from_metadata(&metadata_xml, setting)
    }

    /// The IdP metadata XML.
    pub fn metadata_xml(&self) -> &str {
        self.metadata.get_metadata()
    }

    pub(crate) fn entity_id(&self) -> String {
        self.setting
            .entity_id
            .clone()
            .or_else(|| self.metadata.get_entity_id().map(str::to_string))
            .unwrap_or_default()
    }

    /// Render the login `<Response>` XML for `sp`.
    ///
    /// `custom` overrides tag filling: it receives the template with the
    /// `<AttributeStatement>` already injected.
    ///
    /// # Errors
    ///
    /// Returns an error when configured XML tag prefixes are invalid, a
    /// persistent or transient `NameID` is longer than 256 characters, the
    /// default response renderer cannot produce valid XML, or template
    /// rendering validation fails.
    fn render_login_response(
        &self,
        sp: &ServiceProvider,
        in_response_to: Option<&str>,
        user: &User,
        acs: &str,
        rendering: LoginResponseRendering<'_>,
    ) -> Result<RenderedLoginResponse, SamlError> {
        validate_tag_prefixes(
            &self.setting.tag_prefix_protocol,
            &self.setting.tag_prefix_assertion,
        )?;
        let in_response_to = in_response_to.filter(|id| !id.is_empty());
        let tmpl = self.setting.login_response_template.as_ref();
        let attributes = tmpl.map(|t| t.attributes.as_slice()).unwrap_or(&[]);
        let has_custom_context = tmpl.and_then(|t| t.context.as_ref()).is_some();
        let fallback_status = Status::success();
        let status = rendering.status.unwrap_or(&fallback_status);
        let error_response = status.top_level() != TopLevelStatusCode::Success;
        let uses_template = rendering.custom.is_some() || has_custom_context;
        if rendering.web_browser_sso_producer.follows() && uses_template {
            return Err(SamlError::Invalid(
                "Web Browser SSO generation rules require the built-in login response renderer"
                    .into(),
            ));
        }
        if error_response && uses_template {
            return Err(SamlError::Invalid(
                "an error Response omits assertions and cannot use a login response template"
                    .into(),
            ));
        }
        if status.subordinate().is_some() && uses_template {
            return Err(SamlError::Invalid(
                "login response template StatusCode placeholder cannot carry a subordinate status code"
                    .into(),
            ));
        }
        let qualifiers = rendering.name_id_qualifiers;
        if uses_template
            && (qualifiers.name_qualifier.is_some()
                || qualifiers.sp_name_qualifier.is_some()
                || qualifiers.sp_provided_id.is_some())
        {
            return Err(SamlError::Invalid(
                "a NameID NameQualifier, SPNameQualifier, or SPProvidedID cannot be combined with a login response template"
                    .into(),
            ));
        }
        if !rendering.typed_attributes.is_empty() && (uses_template || !attributes.is_empty()) {
            return Err(SamlError::Invalid(
                "response attributes cannot be combined with a login response template".into(),
            ));
        }
        if (rendering.authn_context.is_some() || rendering.authn_instant.is_some())
            && !rendering.web_browser_sso_producer.follows()
        {
            return Err(SamlError::Invalid(
                "an authentication context or instant is written only under Web Browser SSO generation rules"
                    .into(),
            ));
        }
        if error_response {
            let window = capture_idp_issuance_window(rendering.issuance_lifetime)?;
            let id = generate_id();
            let issuer = self.entity_id();
            let xml = render_error_login_response(&ErrorLoginResponseXml {
                protocol_prefix: &self.setting.tag_prefix_protocol,
                assertion_prefix: &self.setting.tag_prefix_assertion,
                response_id: &id,
                issue_instant: &window.issue_instant,
                destination: acs,
                issuer: &issuer,
                status,
                in_response_to,
            })?;
            return Ok(RenderedLoginResponse {
                id,
                xml,
                session_index: None,
            });
        }
        let name_id_format = rendering
            .name_id_format
            .or_else(|| self.setting.default_name_id_format());
        if rendering.custom.is_none() {
            validate_name_id_format(name_id_format)?;
            validate_issued_name_id_length(name_id_format, &user.name_id)?;
        }
        if rendering.custom.is_none() && !has_custom_context {
            let authn_context = rendering
                .authn_context
                .cloned()
                .unwrap_or_else(AuthnContextReference::unspecified_class);
            if rendering.web_browser_sso_producer.follows() {
                if let Some(requested) = rendering.requested_authn_context {
                    requested.ensure_met_by(&authn_context)?;
                }
                if let Some(policy) = rendering.requested_name_id_policy {
                    policy.ensure_sp_name_qualifier_met_by(qualifiers.sp_name_qualifier)?;
                }
                if let Some(requested) = rendering.requested_subject {
                    requested.ensure_strongly_matched_by(
                        &user.name_id,
                        name_id_format,
                        qualifiers,
                        rendering.requested_name_id_policy,
                    )?;
                }
            }
            let window = capture_idp_issuance_window(rendering.issuance_lifetime)?;
            let authn_instant = match rendering.authn_instant {
                Some(authenticated) => written_authn_instant(authenticated, &window)?,
                None => window.issue_instant.clone(),
            };
            let id = generate_id();
            let assertion_id = generate_id();
            let audience = sp.metadata.get_entity_id().unwrap_or_default().to_string();
            let issuer = self.entity_id();
            let supports_single_logout = !self.metadata.get_support_bindings().is_empty();
            let session_index = (rendering.web_browser_sso_producer.follows()
                && supports_single_logout)
                .then(|| SessionIndex::try_new(assertion_id.as_str()))
                .transpose()?;
            let xml = render_default_login_response(&LoginResponseXml {
                protocol_prefix: &self.setting.tag_prefix_protocol,
                assertion_prefix: &self.setting.tag_prefix_assertion,
                response_id: &id,
                assertion_id: &assertion_id,
                issue_instant: &window.issue_instant,
                destination: acs,
                subject_recipient: acs,
                issuer: &issuer,
                status,
                subject_confirmation_not_on_or_after: &window.expiration,
                conditions_not_before: &window.issue_instant,
                conditions_not_on_or_after: &window.expiration,
                audience: &audience,
                name_id_format,
                name_id: &user.name_id,
                name_id_qualifiers: qualifiers,
                in_response_to,
                authn_statement: rendering.web_browser_sso_producer.follows().then_some(
                    login_response::AuthnStatementXml {
                        authn_instant: &authn_instant,
                        session_index: session_index.as_ref().map(SessionIndex::as_str),
                        authn_context: &authn_context,
                    },
                ),
                attributes,
                user_attributes: &user.attributes,
                typed_attributes: rendering.typed_attributes,
            })?;
            return Ok(RenderedLoginResponse {
                id,
                xml,
                session_index,
            });
        }

        let base = tmpl
            .and_then(|t| t.context.as_deref())
            .unwrap_or(LOGIN_RESPONSE_TEMPLATE);
        let attribute_statement = if attributes.is_empty() {
            String::new()
        } else {
            attribute_statement_builder(
                attributes,
                ATTRIBUTE_TEMPLATE,
                ATTRIBUTE_STATEMENT_TEMPLATE,
            )
        };
        let prepared = base.replacen("{AttributeStatement}", &attribute_statement, 1);
        let prepared = apply_tag_prefixes(
            &prepared,
            &self.setting.tag_prefix_protocol,
            &self.setting.tag_prefix_assertion,
        );
        if let Some(f) = rendering.custom {
            let (id, xml) = f(&prepared);
            return Ok(RenderedLoginResponse {
                id,
                xml,
                session_index: None,
            });
        }
        let window = capture_idp_issuance_window(rendering.issuance_lifetime)?;
        let id = generate_id();
        let mut tags: Vec<(&str, String)> = vec![
            ("ID", id.clone()),
            ("AssertionID", generate_id()),
            ("Destination", acs.to_string()),
            ("SubjectRecipient", acs.to_string()),
            ("AssertionConsumerServiceURL", acs.to_string()),
            (
                "Audience",
                sp.metadata.get_entity_id().unwrap_or_default().to_string(),
            ),
            ("Issuer", self.entity_id()),
            ("IssueInstant", window.issue_instant.clone()),
            ("StatusCode", status.top_level().as_uri().to_string()),
            ("ConditionsNotBefore", window.issue_instant),
            ("ConditionsNotOnOrAfter", window.expiration.clone()),
            ("SubjectConfirmationDataNotOnOrAfter", window.expiration),
            ("NameID", user.name_id.clone()),
            ("AuthnStatement", String::new()),
        ];
        // Attribute value placeholders ({attr<Tag>}) are filled from the user's
        // attributes after the AttributeStatement is expanded into the legacy template.
        let attr_pairs: Vec<(String, String)> = user
            .attributes
            .iter()
            .map(|(tag, value)| (attr_tag(tag), value.clone()))
            .collect();
        for (key, value) in &attr_pairs {
            tags.push((key.as_str(), value.clone()));
        }
        let tags: Vec<(&str, Option<String>)> = [
            ("NameIDFormat", name_id_format.map(str::to_string)),
            ("InResponseTo", in_response_to.map(str::to_string)),
        ]
        .into_iter()
        .chain(tags.into_iter().map(|(key, value)| (key, Some(value))))
        .collect();
        Ok(RenderedLoginResponse {
            id,
            xml: replace_tags_by_optional_value(&prepared, &tags),
            session_index: None,
        })
    }

    /// Generate a login `<Response>` for `sp` over `binding`.
    ///
    /// Requires a crypto provider feature: the response is always signed
    /// (assertion- or message-level) and optionally encrypted. Attributes are
    /// taken from `user`; `options` carries `InResponseTo`, RelayState, the
    /// encrypt-then-sign toggle, and an optional `customTagReplacement` hook.
    ///
    /// # Errors
    ///
    /// Returns an error if `binding` is unsupported, the SP metadata has no ACS
    /// endpoint for `binding`, the persistent or transient `user.name_id` is
    /// longer than 256 characters or the first configured NameID format is not
    /// an absolute URI reference and `options.custom` is not set, response
    /// template rendering fails, the IdP
    /// signing key or certificate configuration is missing or invalid, the
    /// no crypto provider feature is enabled, XML signature construction
    /// fails, the SP encryption certificate is missing when assertion
    /// encryption is enabled, XML encryption fails, or detached-signature
    /// construction for Redirect/SimpleSign fails.
    pub fn create_login_response(
        &self,
        sp: &ServiceProvider,
        binding: Binding,
        user: &User,
        options: &LoginResponseOptions<'_>,
    ) -> Result<BindingContext, SamlError> {
        self.create_login_response_inner(
            sp,
            binding,
            user,
            options,
            LoginResponseOverrides::default(),
        )
        .map(|issued| issued.context)
    }

    pub(crate) fn create_login_response_with_overrides(
        &self,
        sp: &ServiceProvider,
        binding: Binding,
        user: &User,
        options: &LoginResponseOptions<'_>,
        overrides: LoginResponseOverrides<'_>,
    ) -> Result<IssuedLoginResponse, SamlError> {
        self.create_login_response_inner(sp, binding, user, options, overrides)
    }

    fn create_login_response_inner(
        &self,
        sp: &ServiceProvider,
        binding: Binding,
        user: &User,
        options: &LoginResponseOptions<'_>,
        overrides: LoginResponseOverrides<'_>,
    ) -> Result<IssuedLoginResponse, SamlError> {
        if matches!(binding, Binding::Artifact | Binding::Soap) {
            return Err(SamlError::UnsupportedBinding { binding });
        }
        let acs = match overrides.acs {
            Some(acs) => acs.to_string(),
            None => sp
                .metadata
                .get_assertion_consumer_service(binding)
                .ok_or_else(|| SamlError::MissingMetadata("AssertionConsumerService".into()))?,
        };
        let rendered = self.render_login_response(
            sp,
            options.in_response_to,
            user,
            &acs,
            LoginResponseRendering {
                name_id_format: overrides.name_id_format,
                name_id_qualifiers: overrides.name_id_qualifiers,
                custom: options.custom,
                issuance_lifetime: overrides
                    .issuance_lifetime
                    .unwrap_or(time::Duration::seconds(300)),
                web_browser_sso_producer: overrides.web_browser_sso_producer,
                status: overrides.status,
                typed_attributes: overrides.typed_attributes,
                authn_context: overrides.authn_context,
                authn_instant: overrides.authn_instant,
                requested_authn_context: overrides.requested_authn_context,
                requested_name_id_policy: overrides.requested_name_id_policy,
                requested_subject: overrides.requested_subject,
            },
        )?;
        let error_response = overrides
            .status
            .is_some_and(|status| status.top_level() != TopLevelStatusCode::Success);
        let signed = self.finalize_login_response(
            sp,
            binding,
            &rendered.xml,
            error_response,
            overrides
                .want_message_signed
                .unwrap_or(sp.setting.want_message_signed),
            overrides
                .transformation_algorithms
                .unwrap_or(&sp.setting.transformation_algorithms),
        )?;
        let relay = options.relay_state.map(str::to_string);
        let (context, signature, sig_alg) =
            self.bind_response(binding, &signed, &acs, relay.as_deref())?;
        Ok(IssuedLoginResponse {
            context: BindingContext {
                id: rendered.id,
                context,
                relay_state: relay,
                entity_endpoint: acs,
                binding,
                request_type: "SAMLResponse",
                signature,
                sig_alg,
            },
            session_index: rendered.session_index,
        })
    }

    /// Wrap the finalized response XML into the per-binding transport context.
    #[cfg(any(
        feature = "crypto-rustcrypto",
        feature = "crypto-aws-lc",
        feature = "crypto-fips"
    ))]
    fn bind_response(
        &self,
        binding: Binding,
        xml: &str,
        acs: &str,
        relay_state: Option<&str>,
    ) -> Result<(String, Option<String>, Option<String>), SamlError> {
        use crate::binding::{append_signature, base64_encode, build_redirect_octet};
        use crate::crypto::SigningCredential;

        match binding {
            Binding::Post => Ok((base64_encode(xml.as_bytes()), None, None)),
            Binding::Redirect => {
                let sig_alg = &self.setting.request_signature_algorithm;
                let credential = SigningCredential::from_setting(&self.setting)?;
                let octet =
                    build_redirect_octet(ParserType::SamlResponse, xml, relay_state, sig_alg)?;
                let sig = credential.sign_detached(&octet, sig_alg)?;
                Ok((append_signature(acs, &octet, &sig), None, None))
            }
            Binding::SimpleSign => {
                let sig_alg = &self.setting.request_signature_algorithm;
                let credential = SigningCredential::from_setting(&self.setting)?;
                let octet = crate::binding::build_simplesign_octet(
                    ParserType::SamlResponse.query_param(),
                    xml,
                    relay_state,
                    sig_alg,
                );
                let sig = credential.sign_detached(&octet, sig_alg)?;
                Ok((
                    base64_encode(xml.as_bytes()),
                    Some(sig),
                    Some(sig_alg.clone()),
                ))
            }
            Binding::Artifact | Binding::Soap => Err(SamlError::UnsupportedBinding { binding }),
        }
    }

    #[cfg(not(any(
        feature = "crypto-rustcrypto",
        feature = "crypto-aws-lc",
        feature = "crypto-fips"
    )))]
    fn bind_response(
        &self,
        _binding: Binding,
        _xml: &str,
        _acs: &str,
        _relay_state: Option<&str>,
    ) -> Result<(String, Option<String>, Option<String>), SamlError> {
        Err(SamlError::Unsupported(
            "createLoginResponse requires a crypto provider feature".into(),
        ))
    }

    #[cfg(any(
        feature = "crypto-rustcrypto",
        feature = "crypto-aws-lc",
        feature = "crypto-fips"
    ))]
    fn finalize_login_response(
        &self,
        sp: &ServiceProvider,
        binding: Binding,
        raw: &str,
        error_response: bool,
        want_message_signed: bool,
        transforms: &[String],
    ) -> Result<String, SamlError> {
        use crate::crypto::{
            enc::encrypt_assertion_elements, encrypt_assertion, SigningCredential,
        };

        let credential = SigningCredential::from_setting(&self.setting)?;
        credential.require_certificate()?;
        let sig_alg = &self.setting.request_signature_algorithm;

        let mut xml = raw.to_string();
        if error_response {
            // HTTP-POST signs the Response. There is no assertion to sign.
            if binding == Binding::Post {
                xml = credential.sign_xml(
                    &xml,
                    true,
                    sig_alg,
                    transforms,
                    self.setting.signature_config.as_ref(),
                )?;
            }
            return Ok(xml);
        }

        let want_assertions_signed = sp.metadata.is_want_assertions_signed();
        // POST embeds an XML-DSig message signature; redirect/SimpleSign use a
        // detached query signature added later in `bind_response`.
        let sign_message =
            binding == Binding::Post && (want_message_signed || !want_assertions_signed);

        // step: encrypt identifiers and attributes -> sign assertion -> (encrypt) -> sign message
        let element_encryption = self.setting.assertion_element_encryption;
        if element_encryption.is_selected() {
            xml = encrypt_assertion_elements(
                &xml,
                &sp_encryption_certificate(sp)?,
                &self.setting.data_encryption_algorithm,
                &self.setting.key_encryption_algorithm,
                element_encryption,
            )?;
        }
        if want_assertions_signed {
            xml = credential.sign_xml(&xml, false, sig_alg, transforms, None)?;
        }
        // Sign-then-encrypt of a sub-element would invalidate an outer message
        // signature, so when encrypting we always sign the message *after*
        // encryption (sound encrypt-then-sign). Without encryption, sign here.
        if sign_message && !self.setting.is_assertion_encrypted {
            xml = credential.sign_xml(
                &xml,
                true,
                sig_alg,
                transforms,
                self.setting.signature_config.as_ref(),
            )?;
        }
        if self.setting.is_assertion_encrypted {
            xml = encrypt_assertion(
                &xml,
                &sp_encryption_certificate(sp)?,
                &self.setting.data_encryption_algorithm,
                &self.setting.key_encryption_algorithm,
                &self.setting.tag_prefix_encrypted_assertion,
            )?;
        }
        if sign_message && self.setting.is_assertion_encrypted {
            xml = credential.sign_xml(
                &xml,
                true,
                sig_alg,
                transforms,
                self.setting.signature_config.as_ref(),
            )?;
        }
        Ok(xml)
    }

    #[cfg(not(any(
        feature = "crypto-rustcrypto",
        feature = "crypto-aws-lc",
        feature = "crypto-fips"
    )))]
    fn finalize_login_response(
        &self,
        _sp: &ServiceProvider,
        _binding: Binding,
        _raw: &str,
        _error_response: bool,
        _want_message_signed: bool,
        _transforms: &[String],
    ) -> Result<String, SamlError> {
        Err(SamlError::Unsupported(
            "createLoginResponse requires a crypto provider feature".into(),
        ))
    }

    /// Parse and validate an SP login `<AuthnRequest>`.
    ///
    /// # Errors
    ///
    /// Returns an error if `binding` is unsupported, the request is missing
    /// required binding parameters, the SAML payload cannot be base64/DEFLATE
    /// decoded, XML parsing or extraction fails, the status is invalid for the
    /// parser, the SP issuer does not match metadata, or AuthnRequest signature
    /// validation fails when this IdP metadata requires signed requests.
    /// Signature failures include missing signatures, untrusted SP signing
    /// certificates, invalid detached signatures, and XML signature validation
    /// errors.
    pub fn parse_login_request(
        &self,
        sp: &ServiceProvider,
        binding: Binding,
        request: &HttpRequest,
    ) -> Result<FlowResult, SamlError> {
        Ok(self
            .parse_login_request_at_inner(sp, binding, request, None, self.setting.clock_drifts)?
            .0)
    }

    pub(crate) fn parse_login_request_at(
        &self,
        sp: &ServiceProvider,
        binding: Binding,
        request: &HttpRequest,
        now: SystemTime,
        clock_drifts: (i64, i64),
    ) -> Result<(FlowResult, bool), SamlError> {
        self.parse_login_request_at_inner(sp, binding, request, Some(now), clock_drifts)
    }

    fn parse_login_request_at_inner(
        &self,
        sp: &ServiceProvider,
        binding: Binding,
        request: &HttpRequest,
        now: Option<SystemTime>,
        clock_drifts: (i64, i64),
    ) -> Result<(FlowResult, bool), SamlError> {
        let signing_certs = sp
            .metadata
            .x509_certificates(crate::constants::CertUse::Signing);
        crate::flow::flow_with_authentication(
            &FlowOptions {
                binding: Some(binding),
                parser_type: Some(ParserType::SamlRequest),
                check_signature: self.metadata.is_want_authn_requests_signed(),
                verify_signature_if_present: self.setting.verify_authn_request_signature_if_present,
                require_audience_restriction: true,
                xml_signatures: self.setting.xml_signatures,
                from_issuer: sp.metadata.get_entity_id(),
                signing_certs: &signing_certs,
                hmac_secret: sp.setting.hmac_secret.as_ref(),
                decrypt_key: None,
                decrypt_key_pass: None,
                additional_decrypt_keys: &[],
                assertion_elements: AssertionElementEncryption::default(),
                element_decrypt_key: None,
                received_encrypted_elements: ReceivedEncryptedElements::DecryptSelected,
                allow_rsa15_key_transport_decryption: false,
                clock_drifts,
                now,
                redirect_inflate_max_bytes: self.setting.redirect_inflate_max_bytes,
                xml_limits: self.setting.xml_limits,
                expected_audience: None,
                expected_in_response_to: None,
            },
            request,
        )
    }
}

fn written_authn_instant(
    authenticated: SystemTime,
    window: &IdpIssuanceWindow,
) -> Result<String, SamlError> {
    let authenticated = offset_datetime_from_system_time(authenticated)
        .ok()
        .filter(|instant| instant.year() >= 1)
        .ok_or_else(|| {
            SamlError::Invalid("AuthnInstant is outside the supported SAML time range".into())
        })?;
    let written = format_saml_utc_date_time(authenticated);
    if authenticated > window.issued_at {
        return Err(SamlError::Invalid(format!(
            "AuthnInstant {written} is later than the response IssueInstant {}",
            window.issue_instant
        )));
    }
    Ok(written)
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn sp_encryption_certificate(sp: &ServiceProvider) -> Result<String, SamlError> {
    sp.metadata
        .get_x509_certificate(crate::constants::CertUse::Encryption)
        .ok_or_else(|| SamlError::MissingMetadata("encryption certificate".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::Binding;
    use crate::metadata::{Endpoint, SpMetadataConfig};

    const IDPMETA: &str = include_str!("../tests/fixtures/misc/idpmeta.xml");

    fn unsigned_idp() -> Result<IdentityProvider, SamlError> {
        IdentityProvider::from_config(
            &IdpMetadataConfig {
                entity_id: "https://idp.example.com/metadata".into(),
                single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
                ..Default::default()
            },
            EntitySetting::default(),
        )
    }

    fn unsigned_sp(entity_id: &str) -> Result<ServiceProvider, SamlError> {
        ServiceProvider::from_config(
            &SpMetadataConfig {
                entity_id: entity_id.into(),
                assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
                ..Default::default()
            },
            EntitySetting::default(),
        )
    }

    #[test]
    fn from_metadata_merges_flags() -> Result<(), Box<dyn std::error::Error>> {
        let idp = IdentityProvider::from_metadata(IDPMETA, EntitySetting::default())?;
        assert!(idp.setting.want_authn_requests_signed);
        assert_eq!(
            idp.metadata
                .get_single_sign_on_service(Binding::Redirect)
                .as_deref(),
            Some("https://idp.example.org/sso/SingleSignOnService")
        );
        Ok(())
    }

    #[test]
    fn idp_from_config_rejects_missing_sso() {
        let cfg = IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            ..Default::default()
        };

        let result = IdentityProvider::from_config(&cfg, EntitySetting::default());

        assert!(matches!(
            result,
            Err(SamlError::MissingMetadata(name)) if name == "SingleSignOnService"
        ));
    }

    #[test]
    fn parse_login_request_accepts_matching_sp_issuer() -> Result<(), Box<dyn std::error::Error>> {
        let idp = unsigned_idp()?;
        let sp = unsigned_sp("https://sp.example.com/metadata")?;
        let ctx = sp.create_login_request(&idp, Binding::Post, None)?;
        let request = HttpRequest::post(vec![("SAMLRequest".into(), ctx.context)]);

        let result = idp.parse_login_request(&sp, Binding::Post, &request)?;

        assert_eq!(
            result.extract.get_str("issuer"),
            Some("https://sp.example.com/metadata")
        );
        Ok(())
    }

    #[test]
    fn parse_login_request_rejects_unexpected_sp_issuer() -> Result<(), Box<dyn std::error::Error>>
    {
        let idp = unsigned_idp()?;
        let expected_sp = unsigned_sp("https://expected-sp.example.com/metadata")?;
        let attacker_sp = unsigned_sp("https://attacker-sp.example.com/metadata")?;
        let ctx = attacker_sp.create_login_request(&idp, Binding::Post, None)?;
        let request = HttpRequest::post(vec![("SAMLRequest".into(), ctx.context)]);

        let result = idp.parse_login_request(&expected_sp, Binding::Post, &request);

        assert!(matches!(result, Err(SamlError::IssuerMismatch { .. })));
        Ok(())
    }
}

#[cfg(all(
    test,
    any(
        feature = "crypto-rustcrypto",
        feature = "crypto-aws-lc",
        feature = "crypto-fips"
    )
))]
mod crypto_tests {
    use super::*;
    use crate::constants::signature_algorithm::RSA_SHA256;
    use crate::metadata::{Endpoint, SpMetadataConfig};

    // A working RSA keypair (used as both IdP and SP signing material in tests).
    const PRIVKEY: &str = include_str!("../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
    const CERT: &str = include_str!("../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");

    fn signing_setting() -> EntitySetting {
        EntitySetting {
            private_key: Some(PRIVKEY.into()),
            signing_cert: Some(CERT.into()),
            request_signature_algorithm: RSA_SHA256.into(),
            ..Default::default()
        }
    }

    fn idp_with_setting(setting: EntitySetting) -> Result<IdentityProvider, SamlError> {
        IdentityProvider::from_config(
            &IdpMetadataConfig {
                entity_id: "https://idp.example.com/metadata".into(),
                signing_certs: vec![CERT.into()],
                want_authn_requests_signed: true,
                single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
                ..Default::default()
            },
            setting,
        )
    }

    fn idp() -> Result<IdentityProvider, SamlError> {
        idp_with_setting(signing_setting())
    }

    fn signed_sp(entity_id: &str) -> Result<ServiceProvider, SamlError> {
        ServiceProvider::from_config(
            &SpMetadataConfig {
                entity_id: entity_id.into(),
                authn_requests_signed: true,
                want_assertions_signed: true,
                signing_certs: vec![CERT.into()],
                assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
                ..Default::default()
            },
            signing_setting(),
        )
    }

    fn sp() -> Result<ServiceProvider, SamlError> {
        signed_sp("https://sp.example.com/metadata")
    }

    #[test]
    fn idp_response_consumed_by_sp() -> Result<(), Box<dyn std::error::Error>> {
        let (idp, sp) = (idp()?, sp()?);
        let ctx = idp.create_login_response(
            &sp,
            Binding::Post,
            &User::new("user@example.com"),
            &LoginResponseOptions {
                in_response_to: Some("_req123"),
                ..Default::default()
            },
        )?;
        let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);
        let result =
            sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, "_req123")?;
        assert_eq!(result.extract.get_str("nameID"), Some("user@example.com"));
        assert_eq!(
            result.extract.get_str("issuer"),
            Some("https://idp.example.com/metadata")
        );
        Ok(())
    }

    #[test]
    fn custom_login_response_template_keeps_placeholder_text_in_the_name_id_format(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::binding::base64_decode;
        use crate::template::{LoginResponseTemplate, LOGIN_RESPONSE_TEMPLATE};

        let mut setting = signing_setting();
        setting.name_id_format = vec!["urn:example:{InResponseTo}".into()];
        setting.login_response_template = Some(LoginResponseTemplate {
            context: Some(LOGIN_RESPONSE_TEMPLATE.into()),
            attributes: Vec::new(),
        });
        let idp = idp_with_setting(setting)?;
        let ctx = idp.create_login_response(
            &sp()?,
            Binding::Post,
            &User::new("user@example.com"),
            &LoginResponseOptions {
                in_response_to: Some("_req123"),
                ..Default::default()
            },
        )?;

        let xml = String::from_utf8(base64_decode(&ctx.context)?)?;
        assert!(xml.contains("Format=\"urn:example:{InResponseTo}\""));
        assert!(xml.contains("InResponseTo=\"_req123\""));
        Ok(())
    }

    #[test]
    fn raw_login_response_defaults_to_five_minute_issuance_window_for_standard_renderers(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::binding::base64_decode;
        use crate::template::{LoginResponseTemplate, LOGIN_RESPONSE_TEMPLATE};
        use crate::xml::dom::parse;
        use time::{format_description::well_known::Rfc3339, OffsetDateTime};

        let mut custom_template = signing_setting();
        custom_template.login_response_template = Some(LoginResponseTemplate {
            context: Some(LOGIN_RESPONSE_TEMPLATE.into()),
            attributes: Vec::new(),
        });

        for setting in [signing_setting(), custom_template] {
            let idp = idp_with_setting(setting)?;
            let sp = sp()?;
            let ctx = idp.create_login_response(
                &sp,
                Binding::Post,
                &User::new("user@example.com"),
                &LoginResponseOptions {
                    in_response_to: Some("_req123"),
                    ..Default::default()
                },
            )?;
            let xml = String::from_utf8(base64_decode(&ctx.context)?)?;
            let document = parse(&xml)?;
            let response_issue_instant = document
                .root
                .attr("IssueInstant")
                .ok_or("missing Response IssueInstant")?;
            let assertion = document
                .root
                .children
                .iter()
                .find(|node| node.local_name == "Assertion")
                .ok_or("missing Assertion")?;
            let assertion_issue_instant = assertion
                .attr("IssueInstant")
                .ok_or("missing Assertion IssueInstant")?;
            let conditions = assertion
                .children
                .iter()
                .find(|node| node.local_name == "Conditions")
                .ok_or("missing Conditions")?;
            let conditions_not_before = conditions
                .attr("NotBefore")
                .ok_or("missing Conditions NotBefore")?;
            let conditions_expiration = conditions
                .attr("NotOnOrAfter")
                .ok_or("missing Conditions NotOnOrAfter")?;
            let bearer_expiration = assertion
                .children
                .iter()
                .find(|node| node.local_name == "Subject")
                .and_then(|node| {
                    node.children
                        .iter()
                        .find(|node| node.local_name == "SubjectConfirmation")
                })
                .and_then(|node| {
                    node.children
                        .iter()
                        .find(|node| node.local_name == "SubjectConfirmationData")
                })
                .and_then(|node| node.attr("NotOnOrAfter"))
                .ok_or("missing SubjectConfirmationData NotOnOrAfter")?;

            assert_eq!(response_issue_instant, assertion_issue_instant);
            assert_eq!(response_issue_instant, conditions_not_before);
            assert_eq!(conditions_expiration, bearer_expiration);
            assert_eq!(
                OffsetDateTime::parse(conditions_expiration, &Rfc3339)?
                    - OffsetDateTime::parse(response_issue_instant, &Rfc3339)?,
                time::Duration::minutes(5)
            );
        }
        Ok(())
    }

    #[test]
    fn login_response_with_attributes() -> Result<(), Box<dyn std::error::Error>> {
        use crate::template::{LoginResponseAttribute, LoginResponseTemplate};
        let mut setting = signing_setting();
        setting.login_response_template = Some(LoginResponseTemplate {
            context: None,
            attributes: vec![LoginResponseAttribute {
                name: "mail".into(),
                name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".into(),
                value_xsi_type: "xs:string".into(),
                value_tag: "email".into(),
                value_xmlns_xs: None,
                value_xmlns_xsi: None,
            }],
        });
        let idp = IdentityProvider::from_config(
            &IdpMetadataConfig {
                entity_id: "https://idp.example.com/metadata".into(),
                signing_certs: vec![CERT.into()],
                want_authn_requests_signed: true,
                single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
                ..Default::default()
            },
            setting,
        )?;
        let sp = sp()?;
        let user = User {
            name_id: "alice@example.com".into(),
            attributes: vec![("email".into(), "alice@example.com".into())],
            session_index: None,
        };
        let ctx = idp.create_login_response(
            &sp,
            Binding::Post,
            &user,
            &LoginResponseOptions {
                in_response_to: Some("_r1"),
                ..Default::default()
            },
        )?;
        let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);
        let parsed =
            sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, "_r1")?;
        assert_eq!(
            parsed.extract.get_str("attributes.mail"),
            Some("alice@example.com")
        );
        Ok(())
    }

    #[test]
    fn login_response_escapes_attribute_xml_markup() -> Result<(), Box<dyn std::error::Error>> {
        use crate::binding::base64_decode;
        use crate::template::{LoginResponseAttribute, LoginResponseTemplate};

        let mut setting = signing_setting();
        setting.login_response_template = Some(LoginResponseTemplate {
            context: None,
            attributes: vec![LoginResponseAttribute {
                name: "mail".into(),
                name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".into(),
                value_xsi_type: "xs:string".into(),
                value_tag: "email".into(),
                value_xmlns_xs: None,
                value_xmlns_xsi: None,
            }],
        });
        let idp = IdentityProvider::from_config(
            &IdpMetadataConfig {
                entity_id: "https://idp.example.com/metadata".into(),
                signing_certs: vec![CERT.into()],
                want_authn_requests_signed: true,
                single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
                ..Default::default()
            },
            setting,
        )?;
        let sp = sp()?;
        let injection = "alpha</saml:AttributeValue><saml:AttributeValue xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">omega";
        let user = User {
            name_id: "alice@example.com".into(),
            attributes: vec![("email".into(), injection.into())],
            session_index: None,
        };
        let ctx = idp.create_login_response(
            &sp,
            Binding::Post,
            &user,
            &LoginResponseOptions {
                in_response_to: Some("_r1"),
                ..Default::default()
            },
        )?;

        let xml = String::from_utf8(base64_decode(&ctx.context)?)?;
        assert!(xml.contains("<ds:Signature"));
        assert!(xml.contains("alpha&lt;/saml:AttributeValue&gt;"));
        assert!(xml.contains("&lt;saml:AttributeValue xmlns:xs=&quot;"));
        assert!(!xml.contains("alpha</saml:AttributeValue><saml:AttributeValue"));
        assert_eq!(xml.matches("<saml:AttributeValue ").count(), 1);

        let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);
        let parsed =
            sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, "_r1")?;
        assert_eq!(parsed.extract.get_str("attributes.mail"), Some(injection));
        Ok(())
    }

    #[test]
    fn parse_signed_login_request() -> Result<(), Box<dyn std::error::Error>> {
        use crate::binding::base64_decode;
        let (idp, sp) = (idp()?, sp()?);
        let ctx = sp.create_login_request(&idp, Binding::Post, None)?;
        let request = HttpRequest::post(vec![("SAMLRequest".into(), ctx.context.clone())]);
        let result = idp.parse_login_request(&sp, Binding::Post, &request)?;
        let signed_xml = String::from_utf8(base64_decode(&ctx.context)?)?;
        assert!(signed_xml.contains("<ds:Signature"));
        assert_eq!(result.extract.get_str("request.id"), Some(ctx.id.as_str()));
        Ok(())
    }

    #[test]
    fn parse_signed_login_request_rejects_unexpected_sp_issuer(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let idp = idp()?;
        let expected_sp = sp()?;
        let attacker_sp = signed_sp("https://attacker-sp.example.com/metadata")?;
        let ctx = attacker_sp.create_login_request(&idp, Binding::Post, None)?;
        let request = HttpRequest::post(vec![("SAMLRequest".into(), ctx.context)]);

        let result = idp.parse_login_request(&expected_sp, Binding::Post, &request);

        assert!(matches!(result, Err(SamlError::IssuerMismatch { .. })));
        Ok(())
    }
}
