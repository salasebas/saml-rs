//! SAML Service Provider entity.

use crate::binding::{base64_encode, build_redirect_url};
use crate::constants::{namespace, Binding, CertUse, ParserType};
use crate::entity::{
    generate_id, now_iso8601, BindingContext, CustomTagReplacement, EntitySetting,
};
use crate::error::SamlError;
use crate::flow::{
    flow_with_expected_recipient_and_signature_evidence, AssertionSignatureRequirement,
    FlowOptions, FlowResult, FlowResultWithSignatureEvidence, HttpRequest,
    ResponseSignatureRequirement, SignedMessageDestination,
};
use crate::idp::IdentityProvider;
use crate::metadata::{generate_sp_metadata, SpMetadata, SpMetadataConfig};
use crate::template::{replace_tags_by_optional_value, LOGIN_REQUEST_TEMPLATE};
use crate::xml::write::XmlWriter;
use std::time::SystemTime;

mod paos;

pub(crate) use paos::PaosAuthnRequestInput;

/// A SAML 2.0 Service Provider: runtime [`EntitySetting`] plus parsed [`SpMetadata`].
#[derive(Debug, Clone)]
pub struct ServiceProvider {
    /// Runtime configuration (keys, algorithms, flags).
    pub setting: EntitySetting,
    /// Parsed SP metadata.
    pub metadata: SpMetadata,
}

/// Per-call options for [`ServiceProvider::create_login_request_with_options`].
#[derive(Default)]
pub struct LoginRequestOptions<'a> {
    /// RelayState for this request. `Some("")` is preserved as an empty RelayState.
    pub relay_state: Option<&'a str>,
    /// Custom request renderer.
    pub custom: Option<CustomTagReplacement<'a>>,
    /// Optional `ForceAuthn` attribute.
    pub force_authn: Option<bool>,
    /// Optional `AssertionConsumerServiceIndex`; when present, ACS URL and
    /// `ProtocolBinding` are omitted.
    pub assertion_consumer_service_index: Option<u16>,
    /// Expected SAML Response binding. Defaults to HTTP-POST.
    pub response_binding: Option<Binding>,
}

struct AuthnRequestXml<'a> {
    id: &'a str,
    issue_instant: &'a str,
    destination: &'a str,
    force_authn: Option<bool>,
    protocol_binding: Option<&'a str>,
    assertion_consumer_service_url: Option<&'a str>,
    assertion_consumer_service_index: Option<u16>,
    is_passive: Option<bool>,
    issuer: &'a str,
    name_id_format: Option<&'a str>,
    allow_create: AllowCreateAttribute,
}

enum AllowCreateAttribute {
    Include(bool),
    Omit,
}

/// Whether typed Web Browser SSO generation follows producer rules.
///
/// [`Self::Compatibility`] is the samlify-port output kept for a caller
/// leaving the raw API. [`Self::Follow`] applies the producer obligations
/// recorded for this flow. It is not a validation preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum WebBrowserSsoProducer {
    /// Keep the samlify-port generation.
    #[default]
    Compatibility,
    /// Emit the producer obligations for this flow.
    Follow,
}

impl WebBrowserSsoProducer {
    pub(crate) fn follows(self) -> bool {
        matches!(self, Self::Follow)
    }
}

#[derive(Debug, Clone, Copy)]
enum LoginResponseCorrelation<'a> {
    Unsolicited,
    MessageId(&'a str),
}

pub(crate) struct LoginResponseParseOptions<'a> {
    expected_recipient: Option<&'a str>,
    now: Option<SystemTime>,
    clock_drifts: (i64, i64),
    signed_destination: SignedMessageDestination,
}

impl<'a> LoginResponseParseOptions<'a> {
    fn compatibility(clock_drifts: (i64, i64)) -> Self {
        Self {
            expected_recipient: None,
            now: None,
            clock_drifts,
            signed_destination: SignedMessageDestination::Required,
        }
    }

    pub(crate) fn at(now: SystemTime, clock_drifts: (i64, i64)) -> Self {
        Self {
            expected_recipient: None,
            now: Some(now),
            clock_drifts,
            signed_destination: SignedMessageDestination::Required,
        }
    }

    /// Whether a signed response must carry `Destination`.
    pub(crate) fn with_signed_destination(
        mut self,
        signed_destination: SignedMessageDestination,
    ) -> Self {
        self.signed_destination = signed_destination;
        self
    }

    pub(crate) fn with_expected_recipient(mut self, expected_recipient: &'a str) -> Self {
        self.expected_recipient = Some(expected_recipient);
        self
    }
}

fn render_default_authn_request_xml(input: &AuthnRequestXml<'_>) -> String {
    let force_authn = input.force_authn.map(|value| value.to_string());
    let is_passive = input
        .is_passive
        .map(|value| if value { "true" } else { "false" });
    let assertion_consumer_service_index = input
        .assertion_consumer_service_index
        .map(|value| value.to_string());
    let allow_create = match input.allow_create {
        AllowCreateAttribute::Include(true) => Some("true"),
        AllowCreateAttribute::Include(false) => Some("false"),
        AllowCreateAttribute::Omit => None,
    };
    let mut name_id_policy_attrs = Vec::new();
    if let Some(format) = input.name_id_format {
        name_id_policy_attrs.push(("Format", format));
    }
    if let Some(allow_create) = allow_create {
        name_id_policy_attrs.push(("AllowCreate", allow_create));
    }

    let mut attrs = Vec::with_capacity(8);
    attrs.push(("xmlns:samlp", namespace::PROTOCOL));
    attrs.push(("xmlns:saml", namespace::ASSERTION));
    attrs.push(("ID", input.id));
    attrs.push(("Version", "2.0"));
    attrs.push(("IssueInstant", input.issue_instant));
    attrs.push(("Destination", input.destination));
    if let Some(force_authn) = force_authn.as_deref() {
        attrs.push(("ForceAuthn", force_authn));
    }
    if let Some(is_passive) = is_passive {
        attrs.push(("IsPassive", is_passive));
    }
    if let Some(protocol_binding) = input.protocol_binding {
        attrs.push(("ProtocolBinding", protocol_binding));
    }
    if let Some(assertion_consumer_service_url) = input.assertion_consumer_service_url {
        attrs.push((
            "AssertionConsumerServiceURL",
            assertion_consumer_service_url,
        ));
    }
    if let Some(assertion_consumer_service_index) = assertion_consumer_service_index.as_deref() {
        attrs.push((
            "AssertionConsumerServiceIndex",
            assertion_consumer_service_index,
        ));
    }

    let mut writer = XmlWriter::new();
    writer.start("samlp:AuthnRequest", &attrs);
    writer.text_element("saml:Issuer", &[], input.issuer);
    writer.empty("samlp:NameIDPolicy", &name_id_policy_attrs);
    writer.end("samlp:AuthnRequest");
    writer.finish()
}

impl ServiceProvider {
    /// Build from SP metadata XML, merging the metadata-declared flags into `setting`.
    ///
    /// # Errors
    ///
    /// Returns an error when `xml` is malformed, exceeds XML limits, or cannot
    /// be parsed as SP metadata. Metadata parser errors include invalid entity,
    /// endpoint, certificate, or signing flag declarations.
    pub fn from_metadata(xml: &str, mut setting: EntitySetting) -> Result<Self, SamlError> {
        let metadata = SpMetadata::from_xml(xml)?;
        setting.authn_requests_signed = metadata.is_authn_request_signed();
        setting.want_assertions_signed = metadata.is_want_assertions_signed();
        let formats = metadata.get_name_id_format();
        if !formats.is_empty() {
            setting.name_id_format = formats;
        }
        if setting.entity_id.is_none() {
            setting.entity_id = metadata.get_entity_id().map(str::to_string);
        }
        Ok(Self { setting, metadata })
    }

    /// Build by generating SP metadata from `config`, then importing it.
    ///
    /// # Errors
    ///
    /// Returns an error if the generated metadata cannot be parsed back into SP
    /// metadata, including invalid endpoint or certificate declarations.
    pub fn from_config(
        config: &SpMetadataConfig,
        setting: EntitySetting,
    ) -> Result<Self, SamlError> {
        Self::from_metadata(&generate_sp_metadata(config), setting)
    }

    /// The SP metadata XML.
    pub fn metadata_xml(&self) -> &str {
        self.metadata.get_metadata()
    }

    fn entity_id(&self) -> String {
        self.setting
            .entity_id
            .clone()
            .or_else(|| self.metadata.get_entity_id().map(str::to_string))
            .unwrap_or_default()
    }

    /// Build a login `<AuthnRequest>` for `idp` over `binding`.
    ///
    /// When both sides require signing, the request is signed (requires the
    /// a crypto provider feature and the SP's `private_key`/`signing_cert`).
    /// `custom` overrides template rendering, receiving the resolved template
    /// and returning `(id, xml)`.
    ///
    /// # Errors
    ///
    /// Returns an error if SP and IdP signing requirements conflict, the IdP
    /// metadata has no SSO endpoint for `binding`, the SP metadata has no ACS
    /// endpoint for the requested response binding, or `binding` is unsupported
    /// for AuthnRequest generation. When signing is required, key loading,
    /// missing `private_key`/`signing_cert`, unsupported crypto features, XML
    /// signature construction, and detached-signature construction errors are
    /// propagated.
    pub fn create_login_request(
        &self,
        idp: &IdentityProvider,
        binding: Binding,
        custom: Option<CustomTagReplacement<'_>>,
    ) -> Result<BindingContext, SamlError> {
        let options = LoginRequestOptions {
            custom,
            ..Default::default()
        };
        self.create_login_request_with_options(idp, binding, &options)
    }

    /// Build a login `<AuthnRequest>` for `idp` over `binding` with per-call options.
    ///
    /// # Errors
    ///
    /// Returns an error if SP and IdP signing requirements conflict, the IdP
    /// metadata has no SSO endpoint for `binding`, the SP metadata has no ACS
    /// endpoint for `options.response_binding` when ACS index mode is not used,
    /// or `binding` is unsupported. When signing is required, key loading,
    /// missing `private_key`/`signing_cert`, unsupported crypto features, XML
    /// signature construction, and detached-signature construction errors are
    /// propagated.
    pub fn create_login_request_with_options(
        &self,
        idp: &IdentityProvider,
        binding: Binding,
        options: &LoginRequestOptions<'_>,
    ) -> Result<BindingContext, SamlError> {
        self.create_login_request_inner(idp, binding, options, WebBrowserSsoProducer::Compatibility)
    }

    pub(crate) fn create_typed_login_request(
        &self,
        idp: &IdentityProvider,
        binding: Binding,
        options: &LoginRequestOptions<'_>,
        producer: WebBrowserSsoProducer,
    ) -> Result<BindingContext, SamlError> {
        self.create_login_request_inner(idp, binding, options, producer)
    }

    fn create_login_request_inner(
        &self,
        idp: &IdentityProvider,
        binding: Binding,
        options: &LoginRequestOptions<'_>,
        producer: WebBrowserSsoProducer,
    ) -> Result<BindingContext, SamlError> {
        if self.metadata.is_authn_request_signed() != idp.metadata.is_want_authn_requests_signed() {
            return Err(SamlError::Invalid(format!(
                "ERR_METADATA_CONFLICT_REQUEST_SIGNED_FLAG: SP AuthnRequestsSigned={} but IdP WantAuthnRequestsSigned={}",
                self.metadata.is_authn_request_signed(),
                idp.metadata.is_want_authn_requests_signed()
            )));
        }
        let destination = idp
            .metadata
            .get_single_sign_on_service(binding)
            .ok_or_else(|| SamlError::MissingMetadata("SingleSignOnService".into()))?;
        let custom_template = self.setting.login_request_template.as_deref();
        if producer.follows() && (options.custom.is_some() || custom_template.is_some()) {
            return Err(SamlError::Invalid(
                "Web Browser SSO generation rules require the built-in AuthnRequest renderer"
                    .into(),
            ));
        }
        let template = custom_template.unwrap_or(LOGIN_REQUEST_TEMPLATE);
        let (id, xml) = match (options.custom, custom_template) {
            (Some(f), _) => f(template),
            (None, _) => {
                let uses_acs_index = options.assertion_consumer_service_index.is_some();
                let response_binding = options.response_binding.unwrap_or(Binding::Post);
                let acs_url = if uses_acs_index {
                    None
                } else {
                    Some(
                        self.metadata
                            .get_assertion_consumer_service(response_binding)
                            .ok_or_else(|| {
                                SamlError::MissingMetadata("AssertionConsumerService".into())
                            })?,
                    )
                };
                let protocol_binding =
                    (!uses_acs_index).then(|| response_binding.urn().to_string());
                let acs_index = options
                    .assertion_consumer_service_index
                    .map(|index| index.to_string());
                let name_id_format = self
                    .setting
                    .name_id_format
                    .first()
                    .cloned()
                    .unwrap_or_default();
                let name_id_format_attr = if producer.follows() && name_id_format.is_empty() {
                    None
                } else {
                    Some(name_id_format.as_str())
                };
                let allow_create = if producer.follows()
                    && name_id_format == crate::constants::name_id_format::TRANSIENT
                {
                    AllowCreateAttribute::Omit
                } else {
                    AllowCreateAttribute::Include(self.setting.allow_create)
                };
                let id = generate_id();
                let xml = if custom_template.is_none() {
                    let issue_instant = now_iso8601();
                    let issuer = self.entity_id();
                    render_default_authn_request_xml(&AuthnRequestXml {
                        id: &id,
                        issue_instant: &issue_instant,
                        destination: &destination,
                        force_authn: options.force_authn,
                        protocol_binding: protocol_binding.as_deref(),
                        assertion_consumer_service_url: acs_url.as_deref(),
                        assertion_consumer_service_index: options.assertion_consumer_service_index,
                        is_passive: None,
                        issuer: &issuer,
                        name_id_format: name_id_format_attr,
                        allow_create,
                    })
                } else {
                    replace_tags_by_optional_value(
                        template,
                        &[
                            ("ID", Some(id.clone())),
                            ("IssueInstant", Some(now_iso8601())),
                            ("Destination", Some(destination.clone())),
                            (
                                "ForceAuthn",
                                options
                                    .force_authn
                                    .map(|force_authn| force_authn.to_string()),
                            ),
                            ("ProtocolBinding", protocol_binding),
                            ("AssertionConsumerServiceURL", acs_url),
                            ("AssertionConsumerServiceIndex", acs_index),
                            ("Issuer", Some(self.entity_id())),
                            ("NameIDFormat", Some(name_id_format)),
                            ("AllowCreate", Some(self.setting.allow_create.to_string())),
                        ],
                    )
                };
                (id, xml)
            }
        };
        let relay_state = match options.relay_state {
            Some(value) => Some(value.to_string()),
            None => {
                (!self.setting.relay_state.is_empty()).then(|| self.setting.relay_state.clone())
            }
        };

        if self.metadata.is_authn_request_signed() {
            return self.signed_request_context(binding, &xml, destination, relay_state, id);
        }

        let context = match binding {
            Binding::Redirect => build_redirect_url(
                &destination,
                ParserType::SamlRequest,
                &xml,
                relay_state.as_deref(),
            )?,
            Binding::Post | Binding::SimpleSign => base64_encode(xml.as_bytes()),
            Binding::Artifact => {
                return Err(SamlError::UnsupportedBinding {
                    binding: Binding::Artifact,
                });
            }
        };
        Ok(BindingContext {
            id,
            context,
            relay_state,
            entity_endpoint: destination,
            binding,
            request_type: "SAMLRequest",
            signature: None,
            sig_alg: None,
        })
    }

    #[cfg(any(
        feature = "crypto-rustcrypto",
        feature = "crypto-aws-lc",
        feature = "crypto-fips"
    ))]
    fn signed_request_context(
        &self,
        binding: Binding,
        xml: &str,
        destination: String,
        relay_state: Option<String>,
        id: String,
    ) -> Result<BindingContext, SamlError> {
        use crate::binding::{append_signature, build_redirect_octet};
        use crate::crypto::{
            construct_message_signature, construct_saml_signature, keys::load_private_key,
        };

        let key_pem = self
            .setting
            .private_key
            .as_deref()
            .ok_or_else(|| SamlError::MissingKey("private_key".into()))?;
        let cert = self
            .setting
            .signing_cert
            .as_deref()
            .ok_or_else(|| SamlError::MissingKey("signing_cert".into()))?;
        let sig_alg = &self.setting.request_signature_algorithm;
        let key = load_private_key(key_pem, self.setting.private_key_pass.as_deref())?;

        let (context, signature, sig_alg_out) = match binding {
            Binding::Redirect => {
                let octet = build_redirect_octet(
                    ParserType::SamlRequest,
                    xml,
                    relay_state.as_deref(),
                    sig_alg,
                )?;
                let sig = construct_message_signature(&octet, &key, sig_alg)?;
                (append_signature(&destination, &octet, &sig), None, None)
            }
            Binding::Post => {
                let signed = construct_saml_signature(
                    xml,
                    true,
                    &key,
                    cert,
                    sig_alg,
                    &self.setting.transformation_algorithms,
                    self.setting.signature_config.as_ref(),
                )?;
                (base64_encode(signed.as_bytes()), None, None)
            }
            Binding::SimpleSign => {
                let octet = crate::binding::build_simplesign_octet(
                    ParserType::SamlRequest.query_param(),
                    xml,
                    relay_state.as_deref(),
                    sig_alg,
                );
                let sig = construct_message_signature(&octet, &key, sig_alg)?;
                (
                    base64_encode(xml.as_bytes()),
                    Some(sig),
                    Some(sig_alg.clone()),
                )
            }
            Binding::Artifact => {
                return Err(SamlError::UnsupportedBinding {
                    binding: Binding::Artifact,
                });
            }
        };
        Ok(BindingContext {
            id,
            context,
            relay_state,
            entity_endpoint: destination,
            binding,
            request_type: "SAMLRequest",
            signature,
            sig_alg: sig_alg_out,
        })
    }

    #[cfg(not(any(
        feature = "crypto-rustcrypto",
        feature = "crypto-aws-lc",
        feature = "crypto-fips"
    )))]
    fn signed_request_context(
        &self,
        _binding: Binding,
        _xml: &str,
        _destination: String,
        _relay_state: Option<String>,
        _id: String,
    ) -> Result<BindingContext, SamlError> {
        Err(SamlError::Unsupported(
            "signing AuthnRequest requires a crypto provider feature".into(),
        ))
    }

    /// Parse and validate an unsolicited IdP login `<Response>` (signature required).
    ///
    /// This mode is for IdP-initiated SSO. It rejects a non-empty
    /// `InResponseTo`; for SP-initiated SSO use
    /// [`Self::parse_login_response_with_request_id`] to bind the response to
    /// the AuthnRequest ID you issued.
    ///
    /// When `setting.validate_audience` is set, the assertion's `<Audience>`
    /// must include this SP's entity ID.
    ///
    /// # Errors
    ///
    /// Returns an error for all unsolicited-response validation failures from
    /// [`Self::parse_unsolicited_login_response`], including malformed browser
    /// input, unsupported bindings, missing ACS metadata, XML parsing failures,
    /// missing or invalid signatures, untrusted signing certificates, issuer,
    /// destination, recipient, audience, status, time-window, and unexpected
    /// `InResponseTo` failures.
    pub fn parse_login_response(
        &self,
        idp: &IdentityProvider,
        binding: Binding,
        request: &HttpRequest,
    ) -> Result<FlowResult, SamlError> {
        self.parse_unsolicited_login_response(idp, binding, request)
    }

    /// Parse and validate an IdP-initiated login `<Response>` that is not bound
    /// to an outbound AuthnRequest.
    ///
    /// # Errors
    ///
    /// Returns an error if the SP metadata has no ACS endpoint for `binding`,
    /// `binding` is unsupported, the request is missing required binding
    /// parameters, the SAML payload cannot be base64/DEFLATE decoded, XML
    /// parsing or extraction fails, the status is not success, the required
    /// signature is missing or invalid, no trusted IdP signing key is available,
    /// or issuer, destination, bearer recipient, audience, subject-confirmation,
    /// or time-window validation fails. Because this path is unsolicited, any
    /// non-empty response or bearer `InResponseTo` also returns an error.
    pub fn parse_unsolicited_login_response(
        &self,
        idp: &IdentityProvider,
        binding: Binding,
        request: &HttpRequest,
    ) -> Result<FlowResult, SamlError> {
        self.parse_login_response_inner(
            idp,
            binding,
            request,
            LoginResponseCorrelation::Unsolicited,
            LoginResponseParseOptions::compatibility(self.setting.clock_drifts),
        )
    }

    pub(crate) fn parse_unsolicited_login_response_at(
        &self,
        idp: &IdentityProvider,
        binding: Binding,
        request: &HttpRequest,
        options: LoginResponseParseOptions<'_>,
    ) -> Result<FlowResultWithSignatureEvidence, SamlError> {
        self.parse_login_response_inner_with_signature_evidence(
            idp,
            binding,
            request,
            LoginResponseCorrelation::Unsolicited,
            options,
        )
    }

    /// Like [`Self::parse_login_response`] but also requires `InResponseTo` to
    /// equal `request_id` (anti-replay: bind the response to a request you sent).
    ///
    /// An empty caller-provided `request_id` is rejected as
    /// [`SamlError::InvalidInResponseTo`]. A non-empty `request_id` that does
    /// not match the SAML response returns [`SamlError::InResponseToMismatch`].
    ///
    /// # Errors
    ///
    /// Returns an error if `request_id` is empty, the SP metadata has no ACS
    /// endpoint for `binding`, `binding` is unsupported, the request is missing
    /// required binding parameters, the SAML payload cannot be base64/DEFLATE
    /// decoded, XML parsing or extraction fails, the status is not success, the
    /// required signature is missing or invalid, no trusted IdP signing key is
    /// available, or issuer, destination, bearer recipient, audience,
    /// `InResponseTo`, subject-confirmation, or time-window validation fails.
    pub fn parse_login_response_with_request_id(
        &self,
        idp: &IdentityProvider,
        binding: Binding,
        request: &HttpRequest,
        request_id: &str,
    ) -> Result<FlowResult, SamlError> {
        if request_id.is_empty() {
            return Err(SamlError::InvalidInResponseTo);
        }
        self.parse_login_response_inner(
            idp,
            binding,
            request,
            LoginResponseCorrelation::MessageId(request_id),
            LoginResponseParseOptions::compatibility(self.setting.clock_drifts),
        )
    }

    pub(crate) fn parse_login_response_with_request_id_at(
        &self,
        idp: &IdentityProvider,
        binding: Binding,
        request: &HttpRequest,
        request_id: &str,
        options: LoginResponseParseOptions<'_>,
    ) -> Result<FlowResultWithSignatureEvidence, SamlError> {
        if request_id.is_empty() {
            return Err(SamlError::InvalidInResponseTo);
        }
        self.parse_login_response_inner_with_signature_evidence(
            idp,
            binding,
            request,
            LoginResponseCorrelation::MessageId(request_id),
            options,
        )
    }

    fn parse_login_response_inner(
        &self,
        idp: &IdentityProvider,
        binding: Binding,
        request: &HttpRequest,
        correlation: LoginResponseCorrelation<'_>,
        options: LoginResponseParseOptions<'_>,
    ) -> Result<FlowResult, SamlError> {
        let result = self.parse_login_response_inner_with_signature_evidence(
            idp,
            binding,
            request,
            correlation,
            options,
        )?;
        Ok(result.into_parts().0)
    }

    fn parse_login_response_inner_with_signature_evidence(
        &self,
        idp: &IdentityProvider,
        binding: Binding,
        request: &HttpRequest,
        correlation: LoginResponseCorrelation<'_>,
        options: LoginResponseParseOptions<'_>,
    ) -> Result<FlowResultWithSignatureEvidence, SamlError> {
        let signing_certs = idp.metadata.x509_certificates(CertUse::Signing);
        let decrypt_key = if self.setting.is_assertion_encrypted {
            self.setting.enc_private_key.as_deref()
        } else {
            None
        };
        let audience = self.entity_id();
        let expected_in_response_to = match correlation {
            LoginResponseCorrelation::MessageId(request_id) => Some(request_id),
            LoginResponseCorrelation::Unsolicited => None,
        };
        let recipient = match options.expected_recipient {
            Some(recipient) => recipient.to_string(),
            None => self
                .metadata
                .get_assertion_consumer_service(binding)
                .ok_or_else(|| SamlError::MissingMetadata("AssertionConsumerService".into()))?,
        };
        let result = flow_with_expected_recipient_and_signature_evidence(
            &FlowOptions {
                binding: Some(binding),
                parser_type: Some(ParserType::SamlResponse),
                check_signature: true,
                verify_signature_if_present: false,
                require_audience_restriction: self.setting.require_audience_restriction,
                strict_xml_signature_profile: self.setting.strict_xml_signature_profile,
                from_issuer: idp.metadata.get_entity_id(),
                signing_certs: &signing_certs,
                decrypt_key,
                decrypt_key_pass: self.setting.enc_private_key_pass.as_deref(),
                allow_insecure_software_rsa_key_transport_decryption: self
                    .setting
                    .allow_insecure_software_rsa_key_transport_decryption,
                clock_drifts: options.clock_drifts,
                now: options.now,
                redirect_inflate_max_bytes: self.setting.redirect_inflate_max_bytes,
                xml_limits: self.setting.xml_limits,
                expected_audience: self.setting.validate_audience.then_some(audience.as_str()),
                expected_in_response_to,
            },
            request,
            recipient.as_str(),
            if self.setting.want_assertions_signed {
                AssertionSignatureRequirement::Direct
            } else {
                AssertionSignatureRequirement::Compatible
            },
            if self.setting.want_message_signed {
                ResponseSignatureRequirement::Required
            } else if self.setting.want_encrypted_cbc_response_signed {
                ResponseSignatureRequirement::RequiredForEncryptedCbc
            } else {
                ResponseSignatureRequirement::Optional
            },
            options.signed_destination,
        )?;
        if matches!(correlation, LoginResponseCorrelation::Unsolicited)
            && result
                .extract()
                .get_str("response.inResponseTo")
                .is_some_and(|actual| !actual.is_empty())
        {
            return Err(SamlError::in_response_to_mismatch(
                None,
                result.extract().get_str("response.inResponseTo"),
            ));
        }
        if matches!(correlation, LoginResponseCorrelation::Unsolicited) {
            crate::assertion_acceptance::reject_unsolicited_bearer_in_response_to(
                result.saml_content(),
                self.setting.xml_limits,
            )?;
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{base64_decode, deflate_raw_decode};
    use crate::metadata::{Endpoint, IdpMetadataConfig};
    use url::Url;

    fn unsigned_idp() -> Result<IdentityProvider, SamlError> {
        IdentityProvider::from_config(
            &IdpMetadataConfig {
                entity_id: "https://idp.example.com/metadata".into(),
                single_sign_on_service: vec![
                    Endpoint::new(Binding::Redirect, "https://idp.example.com/sso"),
                    Endpoint::new(Binding::Post, "https://idp.example.com/sso"),
                ],
                ..Default::default()
            },
            EntitySetting::default(),
        )
    }

    fn unsigned_sp() -> Result<ServiceProvider, SamlError> {
        ServiceProvider::from_config(
            &SpMetadataConfig {
                entity_id: "https://sp.example.com/metadata".into(),
                assertion_consumer_service: vec![Endpoint::new(
                    Binding::Post,
                    "https://sp.example.com/acs",
                )],
                ..Default::default()
            },
            EntitySetting::default(),
        )
    }

    #[test]
    fn create_unsigned_login_request_redirect_round_trips() -> Result<(), Box<dyn std::error::Error>>
    {
        let ctx = unsigned_sp()?.create_login_request(&unsigned_idp()?, Binding::Redirect, None)?;
        let url = Url::parse(&ctx.context)?;
        let (_, value) = url
            .query_pairs()
            .find(|(k, _)| k == "SAMLRequest")
            .ok_or("missing SAMLRequest")?;
        let xml = String::from_utf8(deflate_raw_decode(&base64_decode(&value)?)?)?;
        assert!(xml.contains("AssertionConsumerServiceURL=\"https://sp.example.com/acs\""));
        assert!(url.query_pairs().all(|(k, _)| k != "Signature"));
        Ok(())
    }

    #[test]
    fn create_unsigned_login_request_post_is_base64() -> Result<(), Box<dyn std::error::Error>> {
        let ctx = unsigned_sp()?.create_login_request(&unsigned_idp()?, Binding::Post, None)?;
        let xml = String::from_utf8(base64_decode(&ctx.context)?)?;
        assert!(xml.starts_with("<samlp:AuthnRequest"));
        Ok(())
    }

    #[test]
    fn custom_tag_replacement_overrides_request() -> Result<(), Box<dyn std::error::Error>> {
        let replace = |_t: &str| {
            (
                "_custom".to_string(),
                "<samlp:AuthnRequest ID=\"_custom\"/>".to_string(),
            )
        };
        let ctx = unsigned_sp()?.create_login_request(
            &unsigned_idp()?,
            Binding::Post,
            Some(&replace as &dyn Fn(&str) -> (String, String)),
        )?;
        assert_eq!(ctx.id, "_custom");
        let xml = String::from_utf8(base64_decode(&ctx.context)?)?;
        assert!(xml.contains("ID=\"_custom\""));
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
    use crate::binding::base64_decode;
    use crate::constants::signature_algorithm::RSA_SHA256;
    use crate::crypto::verify_signature;
    use crate::entity::User;
    use crate::idp::LoginResponseOptions;
    use crate::metadata::{Endpoint, IdpMetadataConfig};

    const IDP_CERT: &str = include_str!("../tests/fixtures/key/idp_cert.cer");
    const SP_PRIVKEY: &str = include_str!("../tests/fixtures/key/sp_privkey.pem");
    const SP_SIGNING_CERT: &str = include_str!("../tests/fixtures/key/sp_signing_cert.cer");

    fn signing_idp() -> Result<IdentityProvider, SamlError> {
        IdentityProvider::from_config(
            &IdpMetadataConfig {
                entity_id: "https://idp.example.com/metadata".into(),
                signing_certs: vec![IDP_CERT.into()],
                want_authn_requests_signed: true,
                single_sign_on_service: vec![
                    Endpoint::new(Binding::Redirect, "https://idp/sso"),
                    Endpoint::new(Binding::Post, "https://idp/sso"),
                ],
                ..Default::default()
            },
            EntitySetting::default(),
        )
    }

    #[test]
    fn parse_signed_response_extracts_name_id() -> Result<(), Box<dyn std::error::Error>> {
        let idp = IdentityProvider::from_config(
            &IdpMetadataConfig {
                entity_id: "https://idp.example.com/metadata".into(),
                signing_certs: vec![SP_SIGNING_CERT.into()],
                single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
                ..Default::default()
            },
            EntitySetting {
                private_key: Some(SP_PRIVKEY.into()),
                signing_cert: Some(SP_SIGNING_CERT.into()),
                request_signature_algorithm: RSA_SHA256.into(),
                ..Default::default()
            },
        )?;
        let sp = ServiceProvider::from_config(
            &SpMetadataConfig {
                entity_id: "https://sp.example.com/metadata".into(),
                assertion_consumer_service: vec![Endpoint::new(
                    Binding::Post,
                    "http://sp.example.com/demo1/index.php?acs",
                )],
                ..Default::default()
            },
            EntitySetting::default(),
        )?;
        let request_id = "_41e758fee373d51639552c4b040b1090e97f6685";
        let name_id = "_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7";
        let ctx = idp.create_login_response(
            &sp,
            Binding::Post,
            &User::new(name_id),
            &LoginResponseOptions {
                in_response_to: Some(request_id),
                ..Default::default()
            },
        )?;
        let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);
        let result =
            sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, request_id)?;
        assert_eq!(result.extract.get_str("nameID"), Some(name_id));
        Ok(())
    }

    #[test]
    fn create_signed_post_request_verifies() -> Result<(), Box<dyn std::error::Error>> {
        let sp = ServiceProvider::from_config(
            &SpMetadataConfig {
                entity_id: "https://sp.example.com/metadata".into(),
                authn_requests_signed: true,
                assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
                ..Default::default()
            },
            EntitySetting {
                private_key: Some(SP_PRIVKEY.into()),
                signing_cert: Some(SP_SIGNING_CERT.into()),
                request_signature_algorithm: RSA_SHA256.into(),
                ..Default::default()
            },
        )?;
        let ctx = sp.create_login_request(&signing_idp()?, Binding::Post, None)?;
        let signed_xml = String::from_utf8(base64_decode(&ctx.context)?)?;
        let (verified, _) = verify_signature(&signed_xml, &[SP_SIGNING_CERT.to_string()])?;
        assert!(
            verified,
            "signed AuthnRequest should verify with the SP cert"
        );
        Ok(())
    }

    #[test]
    fn create_signed_redirect_request_has_signature() -> Result<(), Box<dyn std::error::Error>> {
        let sp = ServiceProvider::from_config(
            &SpMetadataConfig {
                entity_id: "https://sp.example.com/metadata".into(),
                authn_requests_signed: true,
                assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
                ..Default::default()
            },
            EntitySetting {
                private_key: Some(SP_PRIVKEY.into()),
                signing_cert: Some(SP_SIGNING_CERT.into()),
                request_signature_algorithm: RSA_SHA256.into(),
                ..Default::default()
            },
        )?;
        let ctx = sp.create_login_request(&signing_idp()?, Binding::Redirect, None)?;
        assert!(ctx.context.contains("&SigAlg="));
        assert!(ctx.context.contains("&Signature="));
        Ok(())
    }
}
