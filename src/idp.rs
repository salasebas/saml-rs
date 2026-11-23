//! SAML Identity Provider entity.

use crate::constants::{Binding, ParserType};
use crate::entity::{
    capture_idp_issuance_window, format_saml_utc_date_time, generate_id, BindingContext,
    EntitySetting, IdpIssuanceWindow, User,
};
use crate::error::SamlError;
use crate::flow::{FlowOptions, FlowResultWithSignatureEvidence, HttpRequest, SignatureCheck};
use crate::metadata::{generate_idp_metadata, IdpMetadata, IdpMetadataInput};
use crate::model::{
    validate_issued_name_id_length, validate_name_id_format, Attribute, AuthnContextReference,
    ClockSkew, NameIdPolicy, RequestedAuthnContext, RequestedSubject, SessionIndex, Status,
    TopLevelStatusCode,
};
use crate::sp;
use crate::template::validate_tag_prefixes;
use crate::validator::offset_datetime_from_system_time;
use crate::xml::OutboundNameIdQualifiers;

mod login_response;
mod posted_response;

use login_response::{
    render_default_login_response, render_error_login_response, ErrorLoginResponseXml,
    LoginResponseXml,
};
use std::time::SystemTime;

/// Optional inputs for a login `<Response>` the identity provider builds.
#[derive(Default)]
pub struct LoginResponseOptions<'a> {
    /// `InResponseTo` — the SP request id being answered. `None` or an empty
    /// value omits the attribute.
    pub in_response_to: Option<&'a str>,
    /// RelayState to echo back to the SP.
    pub relay_state: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct LoginResponseOverrides<'a> {
    pub(crate) acs: Option<&'a str>,
    pub(crate) name_id_format: Option<&'a str>,
    pub(crate) name_id_qualifiers: OutboundNameIdQualifiers<'a>,
    pub(crate) issuance_lifetime: Option<time::Duration>,
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
    issuance_lifetime: time::Duration,
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
pub struct Engine {
    /// Runtime configuration (keys, algorithms, flags).
    pub setting: EntitySetting,
    /// Parsed IdP metadata.
    pub metadata: IdpMetadata,
}

impl Engine {
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
        setting.want_authn_requests_signed = metadata.want_authn_requests_signed();
        let formats = metadata.as_metadata().name_id_formats();
        if !formats.is_empty() {
            setting.name_id_format = formats
                .iter()
                .map(|format| format.as_uri().to_string())
                .collect();
        }
        if setting.entity_id.is_none() {
            setting.entity_id = metadata.as_metadata().entity_id().map(str::to_string);
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
        config: &IdpMetadataInput,
        setting: EntitySetting,
    ) -> Result<Self, SamlError> {
        let metadata_xml = generate_idp_metadata(config)?;
        Self::from_metadata(&metadata_xml, setting)
    }

    /// The IdP metadata XML.
    pub fn metadata_xml(&self) -> &str {
        self.metadata.as_metadata().metadata_xml()
    }

    pub(crate) fn entity_id(&self) -> String {
        self.setting
            .entity_id
            .clone()
            .or_else(|| self.metadata.as_metadata().entity_id().map(str::to_string))
            .unwrap_or_default()
    }

    /// Render the login `<Response>` XML for `sp`.
    ///
    /// # Errors
    ///
    /// Returns an error when configured XML tag prefixes are invalid, a
    /// persistent or transient `NameID` is longer than 256 characters, or the
    /// response cannot represent the supplied authentication or assertion data.
    fn render_login_response(
        &self,
        sp: &sp::Engine,
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
        let fallback_status = Status::success();
        let status = rendering.status.unwrap_or(&fallback_status);
        if status.top_level() != TopLevelStatusCode::Success {
            return self.render_error_response(
                acs,
                in_response_to,
                status,
                rendering.issuance_lifetime,
            );
        }
        let qualifiers = rendering.name_id_qualifiers;
        let name_id_format = rendering
            .name_id_format
            .or_else(|| self.setting.default_name_id_format());
        validate_name_id_format(name_id_format)?;
        validate_issued_name_id_length(name_id_format, &user.name_id)?;
        let authn_context = rendering
            .authn_context
            .cloned()
            .unwrap_or_else(AuthnContextReference::unspecified_class);
        self.ensure_request_met(&rendering, &user.name_id, name_id_format, &authn_context)?;
        let window = capture_idp_issuance_window(rendering.issuance_lifetime)?;
        let authn_instant = match rendering.authn_instant {
            Some(authenticated) => written_authn_instant(authenticated, &window)?,
            None => window.issue_instant.clone(),
        };
        let id = generate_id();
        let assertion_id = generate_id();
        let audience = sp
            .metadata
            .as_metadata()
            .entity_id()
            .unwrap_or_default()
            .to_string();
        let issuer = self.entity_id();
        let supports_single_logout = !self
            .metadata
            .as_metadata()
            .single_logout_bindings()
            .is_empty();
        let session_index = supports_single_logout
            .then(|| SessionIndex::try_new(assertion_id.as_str()))
            .transpose()?;
        let response = LoginResponseXml {
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
            authn_statement: login_response::AuthnStatementXml {
                authn_instant: &authn_instant,
                session_index: session_index.as_ref().map(SessionIndex::as_str),
                authn_context: &authn_context,
            },
            typed_attributes: rendering.typed_attributes,
        };
        let xml = render_default_login_response(&response)?;
        Ok(RenderedLoginResponse {
            id,
            xml,
            session_index,
        })
    }

    fn render_error_response(
        &self,
        acs: &str,
        in_response_to: Option<&str>,
        status: &Status,
        issuance_lifetime: time::Duration,
    ) -> Result<RenderedLoginResponse, SamlError> {
        let window = capture_idp_issuance_window(issuance_lifetime)?;
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
        Ok(RenderedLoginResponse {
            id,
            xml,
            session_index: None,
        })
    }

    fn ensure_request_met(
        &self,
        rendering: &LoginResponseRendering<'_>,
        name_id: &str,
        name_id_format: Option<&str>,
        authn_context: &AuthnContextReference,
    ) -> Result<(), SamlError> {
        let qualifiers = rendering.name_id_qualifiers;
        if let Some(requested) = rendering.requested_authn_context {
            requested.ensure_met_by(authn_context)?;
        }
        if let Some(policy) = rendering.requested_name_id_policy {
            policy.ensure_met_by(
                name_id_format,
                qualifiers.sp_name_qualifier,
                self.setting.assertion_element_encryption.identifiers,
            )?;
        }
        if let Some(requested) = rendering.requested_subject {
            requested.ensure_strongly_matched_by(
                name_id,
                name_id_format,
                qualifiers,
                rendering.requested_name_id_policy,
            )?;
        }
        Ok(())
    }

    pub(crate) fn create_login_response_with_overrides(
        &self,
        sp: &sp::Engine,
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
                .assertion_consumer_location(binding)
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
                issuance_lifetime: overrides
                    .issuance_lifetime
                    .unwrap_or(time::Duration::seconds(300)),
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
    #[cfg(crypto)]
    pub(crate) fn bind_response(
        &self,
        binding: Binding,
        xml: &str,
        acs: &str,
        relay_state: Option<&str>,
    ) -> Result<(String, Option<String>, Option<String>), SamlError> {
        use crate::binding::{encode_base64, sign_detached_message};
        use crate::crypto::SigningCredential;

        match binding {
            Binding::Post => Ok((encode_base64(xml.as_bytes()), None, None)),
            Binding::Redirect | Binding::SimpleSign => {
                let sig_alg = &self.setting.request_signature_algorithm;
                let credential = SigningCredential::from_setting(&self.setting)?;
                sign_detached_message(
                    &credential,
                    binding,
                    xml,
                    acs,
                    relay_state,
                    ParserType::SamlResponse,
                    sig_alg,
                )
            }
            Binding::Artifact | Binding::Soap => Err(SamlError::UnsupportedBinding { binding }),
        }
    }

    #[cfg(not(crypto))]
    pub(crate) fn bind_response(
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

    #[cfg(crypto)]
    pub(crate) fn finalize_login_response(
        &self,
        sp: &sp::Engine,
        binding: Binding,
        raw: &str,
        error_response: bool,
        want_message_signed: bool,
        transforms: &[String],
    ) -> Result<String, SamlError> {
        use crate::crypto::{
            enc::{encrypt_assertion_elements, encrypt_assertion_with_key_transport, KeyTransport},
            SigningCredential,
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

        let want_assertions_signed = sp.metadata.want_assertions_signed();
        // POST embeds an XML-DSig message signature; redirect/SimpleSign use a
        // detached query signature added later in `bind_response`.
        let sign_message =
            binding == Binding::Post && (want_message_signed || !want_assertions_signed);

        // step: encrypt identifiers and attributes -> sign assertion -> (encrypt) -> sign message
        let element_encryption = self.setting.assertion_element_encryption;
        if element_encryption.is_selected() {
            xml = encrypt_assertion_elements(
                &xml,
                sp_encryption_certificate(sp)?,
                &self.setting.data_encryption_algorithm,
                KeyTransport::from_setting(&self.setting),
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
            xml = encrypt_assertion_with_key_transport(
                &xml,
                sp_encryption_certificate(sp)?,
                &self.setting.data_encryption_algorithm,
                KeyTransport::from_setting(&self.setting),
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

    #[cfg(not(crypto))]
    pub(crate) fn finalize_login_response(
        &self,
        _sp: &sp::Engine,
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

    pub(crate) fn parse_login_request_at(
        &self,
        sp: &sp::Engine,
        binding: Binding,
        request: &HttpRequest,
        now: SystemTime,
        clock_skew: ClockSkew,
    ) -> Result<FlowResultWithSignatureEvidence, SamlError> {
        self.parse_login_request_at_inner(sp, binding, request, Some(now), clock_skew)
    }

    fn parse_login_request_at_inner(
        &self,
        sp: &sp::Engine,
        binding: Binding,
        request: &HttpRequest,
        now: Option<SystemTime>,
        clock_skew: ClockSkew,
    ) -> Result<FlowResultWithSignatureEvidence, SamlError> {
        let signing_certs = sp
            .metadata
            .as_metadata()
            .x509_certificates(crate::constants::CertUse::Signing);
        let signature_check =
            if self.metadata.want_authn_requests_signed() || sp.metadata.authn_requests_signed() {
                SignatureCheck::Require
            } else {
                SignatureCheck::VerifyIfPresent
            };
        crate::flow::flow_with_authentication(
            &FlowOptions {
                binding: Some(binding),
                parser_type: Some(ParserType::SamlRequest),
                signature_check,
                require_audience_restriction: true,
                xml_signatures: self.setting.xml_signatures,
                from_issuer: sp.metadata.as_metadata().entity_id(),
                signing_certs,
                hmac_secret: sp.setting.hmac_secret.as_ref(),
                clock_skew,
                now,
                redirect_inflate_max_bytes: self.setting.redirect_inflate_max_bytes,
                xml_limits: self.setting.xml_limits,
                schema_validator: self.setting.schema_validator,
                expected_audience: None,
                expected_in_response_to: None,
                ..FlowOptions::default()
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

#[cfg(crypto)]
fn sp_encryption_certificate(sp: &sp::Engine) -> Result<&str, SamlError> {
    sp.metadata
        .as_metadata()
        .x509_certificates(crate::constants::CertUse::Encryption)
        .first()
        .map(String::as_str)
        .ok_or_else(|| SamlError::MissingMetadata("encryption certificate".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::Binding;
    use crate::metadata::{Endpoint, SpMetadataInput};
    use crate::sp::LoginRequestOptions;
    use crate::tests::engine::{IdpMessages, SpMessages};

    const IDPMETA: &str = include_str!("../tests/fixtures/misc/idpmeta.xml");

    fn unsigned_idp() -> Result<Engine, SamlError> {
        Engine::from_config(
            &IdpMetadataInput {
                entity_id: "https://idp.example.com/metadata".into(),
                single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
                ..Default::default()
            },
            EntitySetting::default(),
        )
    }

    fn unsigned_sp(entity_id: &str) -> Result<sp::Engine, SamlError> {
        sp::Engine::from_config(
            &SpMetadataInput {
                entity_id: entity_id.into(),
                assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
                ..Default::default()
            },
            EntitySetting::default(),
        )
    }

    #[test]
    fn from_metadata_merges_flags() -> Result<(), Box<dyn std::error::Error>> {
        let idp = Engine::from_metadata(IDPMETA, EntitySetting::default())?;
        assert!(idp.setting.want_authn_requests_signed);
        assert_eq!(
            idp.metadata
                .single_sign_on_location(Binding::Redirect)
                .as_deref(),
            Some("https://idp.example.org/sso/SingleSignOnService")
        );
        Ok(())
    }

    #[test]
    fn idp_from_config_rejects_missing_sso() {
        let cfg = IdpMetadataInput {
            entity_id: "https://idp.example.com/metadata".into(),
            ..Default::default()
        };

        let result = Engine::from_config(&cfg, EntitySetting::default());

        assert!(matches!(
            result,
            Err(SamlError::MissingMetadata(name)) if name == "SingleSignOnService"
        ));
    }

    #[test]
    fn parse_login_request_accepts_matching_sp_issuer() -> Result<(), Box<dyn std::error::Error>> {
        let idp = unsigned_idp()?;
        let sp = unsigned_sp("https://sp.example.com/metadata")?;
        let ctx = sp.create_login_request(&idp, Binding::Post, &LoginRequestOptions::default())?;
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
        let ctx = attacker_sp.create_login_request(
            &idp,
            Binding::Post,
            &LoginRequestOptions::default(),
        )?;
        let request = HttpRequest::post(vec![("SAMLRequest".into(), ctx.context)]);

        let result = idp.parse_login_request(&expected_sp, Binding::Post, &request);

        assert!(matches!(result, Err(SamlError::IssuerMismatch { .. })));
        Ok(())
    }
}

#[cfg(all(test, crypto))]
mod crypto_tests {
    use super::*;
    use crate::constants::signature_algorithm::RSA_SHA256;
    use crate::metadata::{Endpoint, SpMetadataInput};
    use crate::sp::LoginRequestOptions;
    use crate::tests::engine::{IdpMessages, SpMessages};

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

    fn idp_with_setting(setting: EntitySetting) -> Result<Engine, SamlError> {
        Engine::from_config(
            &IdpMetadataInput {
                entity_id: "https://idp.example.com/metadata".into(),
                signing_certs: vec![CERT.into()],
                want_authn_requests_signed: true,
                single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
                ..Default::default()
            },
            setting,
        )
    }

    fn idp() -> Result<Engine, SamlError> {
        idp_with_setting(signing_setting())
    }

    fn signed_sp(entity_id: &str) -> Result<sp::Engine, SamlError> {
        sp::Engine::from_config(
            &SpMetadataInput {
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

    fn sp() -> Result<sp::Engine, SamlError> {
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
    fn raw_login_response_defaults_to_a_five_minute_issuance_window(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::binding::decode_base64;
        use crate::xml::dom::parse_document;
        use time::{format_description::well_known::Rfc3339, OffsetDateTime};

        let idp = idp()?;
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
        let xml = String::from_utf8(decode_base64(&ctx.context)?)?;
        let document = parse_document(&xml, crate::XmlLimits::default())?;
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
        Ok(())
    }

    #[test]
    fn parse_signed_login_request() -> Result<(), Box<dyn std::error::Error>> {
        use crate::binding::decode_base64;
        let (idp, sp) = (idp()?, sp()?);
        let ctx = sp.create_login_request(&idp, Binding::Post, &LoginRequestOptions::default())?;
        let request = HttpRequest::post(vec![("SAMLRequest".into(), ctx.context.clone())]);
        let result = idp.parse_login_request(&sp, Binding::Post, &request)?;
        let signed_xml = String::from_utf8(decode_base64(&ctx.context)?)?;
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
        let ctx = attacker_sp.create_login_request(
            &idp,
            Binding::Post,
            &LoginRequestOptions::default(),
        )?;
        let request = HttpRequest::post(vec![("SAMLRequest".into(), ctx.context)]);

        let result = idp.parse_login_request(&expected_sp, Binding::Post, &request);

        assert!(matches!(result, Err(SamlError::IssuerMismatch { .. })));
        Ok(())
    }
}
