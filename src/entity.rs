//! Entity base settings shared by [`crate::sp::ServiceProvider`] and
//! [`crate::idp::IdentityProvider`].

use core::fmt;

use crate::binding::MAX_DEFLATE_RAW_DECODE_BYTES;
use crate::constants::{
    data_encryption_algorithm, key_encryption_algorithm, signature_algorithm, transform_algorithm,
    MessageSignatureOrder,
};
use crate::error::{SamlError, TimeWindowField};
use crate::xml::XmlLimits;

/// Runtime configuration for an entity (keys, algorithms, flags).
///
/// Use [`EntitySetting::default`] and tweak the fields you need.
#[non_exhaustive]
#[derive(Clone)]
pub struct EntitySetting {
    /// Override entity ID (otherwise taken from metadata).
    pub entity_id: Option<String>,
    /// Signature algorithm URI for outgoing signatures.
    pub request_signature_algorithm: String,
    /// Data encryption algorithm URI.
    pub data_encryption_algorithm: String,
    /// Key encryption algorithm URI.
    pub key_encryption_algorithm: String,
    /// Sign-then-encrypt vs encrypt-then-sign.
    pub message_signing_order: MessageSignatureOrder,
    /// `AllowCreate` for the NameIDPolicy.
    pub allow_create: bool,
    /// Whether assertions are encrypted.
    pub is_assertion_encrypted: bool,
    /// Allow XML-Enc RSA key-transport decryption with the bundled RustCrypto
    /// software RSA backend.
    ///
    /// This is disabled by default for `crypto-rustcrypto` because that provider
    /// reaches the RustCrypto `rsa` crate, which is affected by
    /// `RUSTSEC-2023-0071` when an attacker can observe timing. AWS-LC and FIPS
    /// ignore this flag because they use `aws-lc-rs`. Prefer an external/HSM
    /// decryptor once one is exposed through the public API; enable this only as
    /// an explicit compatibility exception for RustCrypto deployments that
    /// accept that risk.
    pub allow_insecure_software_rsa_key_transport_decryption: bool,
    /// Default RelayState.
    pub relay_state: String,
    /// SP: signs its AuthnRequests.
    pub authn_requests_signed: bool,
    /// SP: requires signed assertions.
    pub want_assertions_signed: bool,
    /// SP: reject a `<Response>` whose `<Audience>` is not this entity (default `true`).
    pub validate_audience: bool,
    /// SP: reject a bearer assertion that omits `<AudienceRestriction>`.
    ///
    /// Applies only when `validate_audience` is set. Default `true` preserves
    /// raw audience checking. Typed Web Browser SSO acceptance can evaluate
    /// restrictions that are present without requiring the element.
    pub(crate) require_audience_restriction: bool,
    /// SP: requires signed messages.
    pub want_message_signed: bool,
    /// Typed SP: enforce the strict RSA-SHA2 profile on embedded signatures that
    /// authenticate accepted SSO and Single Logout messages.
    pub(crate) strict_xml_signature_profile: bool,
    /// Typed SP: requires outer integrity for CBC-encrypted Assertions.
    pub(crate) want_encrypted_cbc_response_signed: bool,
    /// IdP: requires signed AuthnRequests.
    pub want_authn_requests_signed: bool,
    /// IdP: verify an AuthnRequest signature when one is present, without
    /// requiring a signature.
    pub(crate) verify_authn_request_signature_if_present: bool,
    /// Requires signed LogoutRequest (default `true`).
    pub want_logout_request_signed: bool,
    /// Requires signed LogoutResponse.
    pub want_logout_response_signed: bool,
    /// Supported NameID formats.
    pub name_id_format: Vec<String>,
    /// Signing private key (PEM).
    pub private_key: Option<String>,
    /// Passphrase for `private_key`.
    pub private_key_pass: Option<String>,
    /// Signing certificate (PEM/base64).
    pub signing_cert: Option<String>,
    /// Encryption certificate (PEM/base64).
    pub encrypt_cert: Option<String>,
    /// Decryption private key (PEM).
    pub enc_private_key: Option<String>,
    /// Passphrase for `enc_private_key`.
    pub enc_private_key_pass: Option<String>,
    /// Clock drift tolerance `(not_before_ms, not_on_or_after_ms)`.
    pub clock_drifts: (i64, i64),
    /// Maximum decoded compressed and inflated raw-DEFLATE bytes accepted for
    /// HTTP-Redirect input.
    ///
    /// SAML does not define this limit; the default is a conservative
    /// resource-exhaustion guard for unauthenticated Redirect messages.
    pub redirect_inflate_max_bytes: usize,
    /// XML parser resource limits for inbound messages and metadata parsing.
    pub xml_limits: XmlLimits,
    /// IdP: protocol tag prefix for generated IdP messages (default `samlp`).
    pub tag_prefix_protocol: String,
    /// IdP: assertion tag prefix for generated IdP messages (default `saml`).
    pub tag_prefix_assertion: String,
    /// IdP: tag prefix for the `<EncryptedAssertion>` element (default `saml`).
    pub tag_prefix_encrypted_assertion: String,
    /// IdP: login `<Response>` template + attribute configuration.
    pub login_response_template: Option<crate::template::LoginResponseTemplate>,
    /// SP: custom `<AuthnRequest>` template (`None` uses the default).
    pub login_request_template: Option<String>,
    /// Custom `<LogoutRequest>` template (`None` uses the default).
    ///
    /// Typed Session Authority generation requires a complete unqualified
    /// `NotOnOrAfter="{NotOnOrAfter}"` root attribute. Raw compatibility
    /// generation keeps that optional placeholder omitted.
    ///
    /// Typed generation fills `{NameQualifier}`, `{SPNameQualifier}`, and
    /// `{SPProvidedID}` from the logout subject's `NameID`, and
    /// `{NameIDFormat}` with the `Format` sent for it. An attribute whose
    /// complete value is one of these placeholders is omitted when there is
    /// no value for it. Raw compatibility generation fills `{NameIDFormat}`
    /// from `name_id_format` and omits the qualifier attributes.
    ///
    /// Typed Session Authority generation, and typed SP generation with
    /// Single Logout generation rules, reject a template whose `NameID`
    /// attributes differ from the ones sent for the subject.
    pub logout_request_template: Option<String>,
    /// Custom `<LogoutResponse>` template (`None` uses the default).
    ///
    /// After prefix and placeholder substitution, the final outbound XML must
    /// satisfy the enforced LogoutResponse structure, issuer, destination, and
    /// request-correlation requirements. A root `<ds:Signature>` is rejected
    /// before signing so the library owns signature construction. When
    /// `InResponseTo` is `None`, an attribute whose complete value is the
    /// `{InResponseTo}` placeholder is omitted.
    pub logout_response_template: Option<String>,
    /// Custom embedded-signature placement/prefix (`None` uses the default).
    pub signature_config: Option<SignatureConfig>,
    /// XML-DSig transforms applied to signed references (default
    /// enveloped-signature + exclusive C14N).
    pub transformation_algorithms: Vec<String>,
}

fn redacted_option(value: &Option<String>) -> Option<&'static str> {
    value.as_ref().map(|_| "<redacted>")
}

impl fmt::Debug for EntitySetting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntitySetting")
            .field("entity_id", &self.entity_id)
            .field(
                "request_signature_algorithm",
                &self.request_signature_algorithm,
            )
            .field("data_encryption_algorithm", &self.data_encryption_algorithm)
            .field("key_encryption_algorithm", &self.key_encryption_algorithm)
            .field("message_signing_order", &self.message_signing_order)
            .field("allow_create", &self.allow_create)
            .field("is_assertion_encrypted", &self.is_assertion_encrypted)
            .field(
                "allow_insecure_software_rsa_key_transport_decryption",
                &self.allow_insecure_software_rsa_key_transport_decryption,
            )
            .field("relay_state", &self.relay_state)
            .field("authn_requests_signed", &self.authn_requests_signed)
            .field("want_assertions_signed", &self.want_assertions_signed)
            .field("validate_audience", &self.validate_audience)
            .field(
                "require_audience_restriction",
                &self.require_audience_restriction,
            )
            .field("want_message_signed", &self.want_message_signed)
            .field(
                "strict_xml_signature_profile",
                &self.strict_xml_signature_profile,
            )
            .field(
                "want_encrypted_cbc_response_signed",
                &self.want_encrypted_cbc_response_signed,
            )
            .field(
                "want_authn_requests_signed",
                &self.want_authn_requests_signed,
            )
            .field(
                "verify_authn_request_signature_if_present",
                &self.verify_authn_request_signature_if_present,
            )
            .field(
                "want_logout_request_signed",
                &self.want_logout_request_signed,
            )
            .field(
                "want_logout_response_signed",
                &self.want_logout_response_signed,
            )
            .field("name_id_format", &self.name_id_format)
            .field("private_key", &redacted_option(&self.private_key))
            .field("private_key_pass", &redacted_option(&self.private_key_pass))
            .field("signing_cert", &redacted_option(&self.signing_cert))
            .field("encrypt_cert", &redacted_option(&self.encrypt_cert))
            .field("enc_private_key", &redacted_option(&self.enc_private_key))
            .field(
                "enc_private_key_pass",
                &redacted_option(&self.enc_private_key_pass),
            )
            .field("clock_drifts", &self.clock_drifts)
            .field(
                "redirect_inflate_max_bytes",
                &self.redirect_inflate_max_bytes,
            )
            .field("xml_limits", &self.xml_limits)
            .field("tag_prefix_protocol", &self.tag_prefix_protocol)
            .field("tag_prefix_assertion", &self.tag_prefix_assertion)
            .field(
                "tag_prefix_encrypted_assertion",
                &self.tag_prefix_encrypted_assertion,
            )
            .field("login_response_template", &self.login_response_template)
            .field("login_request_template", &self.login_request_template)
            .field("logout_request_template", &self.logout_request_template)
            .field("logout_response_template", &self.logout_response_template)
            .field("signature_config", &self.signature_config)
            .field("transformation_algorithms", &self.transformation_algorithms)
            .finish()
    }
}

/// Custom message rendering hook: given the resolved template, returns
/// `(id, rendered_xml)`.
pub type CustomTagReplacement<'a> = &'a dyn Fn(&str) -> (String, String);

/// Where to place the `<Signature>` relative to the reference element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignatureAction {
    /// Insert as the reference's next sibling.
    #[default]
    After,
    /// Insert as the reference's previous sibling.
    Before,
    /// Insert as the reference's first child.
    Prepend,
    /// Insert as the reference's last child.
    Append,
}

/// Customizes the embedded XML-DSig signature.
#[derive(Debug, Clone)]
pub struct SignatureConfig {
    /// Element prefix for the signature (default `ds`).
    pub prefix: String,
    /// `local-name()` XPath of the reference element; `None` keeps the default
    /// (after the signed target's `<Issuer>`).
    pub reference: Option<String>,
    /// Placement relative to `reference`.
    pub action: SignatureAction,
}

impl Default for SignatureConfig {
    fn default() -> Self {
        Self {
            prefix: "ds".to_string(),
            reference: None,
            action: SignatureAction::After,
        }
    }
}

impl Default for EntitySetting {
    fn default() -> Self {
        Self {
            entity_id: None,
            request_signature_algorithm: signature_algorithm::RSA_SHA256.to_string(),
            data_encryption_algorithm: data_encryption_algorithm::AES_256.to_string(),
            key_encryption_algorithm: key_encryption_algorithm::RSA_OAEP_MGF1P.to_string(),
            message_signing_order: MessageSignatureOrder::SignThenEncrypt,
            allow_create: false,
            is_assertion_encrypted: false,
            allow_insecure_software_rsa_key_transport_decryption: false,
            relay_state: String::new(),
            authn_requests_signed: false,
            want_assertions_signed: false,
            validate_audience: true,
            require_audience_restriction: true,
            want_message_signed: false,
            strict_xml_signature_profile: false,
            want_encrypted_cbc_response_signed: false,
            want_authn_requests_signed: false,
            verify_authn_request_signature_if_present: false,
            want_logout_request_signed: true,
            want_logout_response_signed: true,
            name_id_format: Vec::new(),
            private_key: None,
            private_key_pass: None,
            signing_cert: None,
            encrypt_cert: None,
            enc_private_key: None,
            enc_private_key_pass: None,
            clock_drifts: (0, 0),
            redirect_inflate_max_bytes: MAX_DEFLATE_RAW_DECODE_BYTES,
            xml_limits: XmlLimits::default(),
            tag_prefix_protocol: "samlp".to_string(),
            tag_prefix_assertion: "saml".to_string(),
            tag_prefix_encrypted_assertion: "saml".to_string(),
            login_response_template: None,
            login_request_template: None,
            logout_request_template: None,
            logout_response_template: None,
            signature_config: None,
            transformation_algorithms: vec![
                transform_algorithm::ENVELOPED_SIGNATURE.to_string(),
                transform_algorithm::EXC_C14N.to_string(),
            ],
        }
    }
}

/// Generate a SAML message ID (`_` + UUIDv4).
pub fn generate_id() -> String {
    format!("_{}", uuid::Uuid::new_v4())
}

/// The authenticated subject an IdP issues a response for.
#[derive(Debug, Clone, Default)]
pub struct User {
    /// `<NameID>` value.
    pub name_id: String,
    /// Attribute values keyed by their `LoginResponseAttribute.value_tag`;
    /// each fills the `{attr<Tag>}` placeholder produced for that attribute.
    pub attributes: Vec<(String, String)>,
    /// `SessionIndex` for Single Logout requests.
    pub session_index: Option<String>,
}

impl User {
    /// A subject with just a NameID and no attributes.
    pub fn new(name_id: impl Into<String>) -> Self {
        Self {
            name_id: name_id.into(),
            ..Default::default()
        }
    }
}

/// Current UTC time as an ISO-8601 `IssueInstant` (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn now_iso8601() -> String {
    iso8601_offset(0)
}

/// UTC time `seconds` from now as ISO-8601 (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn iso8601_offset(seconds: i64) -> String {
    let t = time::OffsetDateTime::now_utc() + time::Duration::seconds(seconds);
    format_saml_utc_date_time(t)
}

#[derive(Debug, Clone)]
pub(crate) struct IdpIssuanceWindow {
    pub(crate) issue_instant: String,
    pub(crate) expiration: String,
}

pub(crate) fn capture_idp_issuance_window(
    lifetime: time::Duration,
) -> Result<IdpIssuanceWindow, SamlError> {
    let issue_instant = time::OffsetDateTime::now_utc();
    let expiration = issue_instant
        .checked_add(lifetime)
        .ok_or(SamlError::TimeWindowInvalid {
            field: TimeWindowField::IdpIssuanceExpiration,
        })?;
    let preserve_subseconds = lifetime.subsec_nanoseconds() != 0;
    Ok(IdpIssuanceWindow {
        issue_instant: format_idp_issuance_instant(issue_instant, preserve_subseconds),
        expiration: format_idp_issuance_instant(expiration, preserve_subseconds),
    })
}

fn format_idp_issuance_instant(t: time::OffsetDateTime, preserve_subseconds: bool) -> String {
    if preserve_subseconds {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute(),
            t.second(),
            t.nanosecond(),
        )
    } else {
        format_saml_utc_date_time(t)
    }
}

// `OffsetDateTime` represents seconds in the range 0..=59, so this outbound
// formatter cannot emit the leap-second value prohibited by SAML Core §1.3.3.
pub(crate) fn format_saml_utc_date_time(t: time::OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
    )
}

#[cfg(test)]
mod tests {
    use super::format_saml_utc_date_time;

    #[test]
    fn outbound_saml_instants_do_not_generate_leap_seconds(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // The final representable second before the 2016 leap-second boundary.
        let last_second = time::OffsetDateTime::from_unix_timestamp(1_483_228_799)?;

        assert_eq!(
            format_saml_utc_date_time(last_second),
            "2016-12-31T23:59:59Z"
        );
        Ok(())
    }
}

/// The product of building an outbound message for a binding.
#[derive(Debug, Clone)]
pub struct BindingContext {
    /// Generated message ID.
    pub id: String,
    /// Redirect: the full URL. POST/SimpleSign: the base64 message.
    pub context: String,
    /// RelayState, if any.
    pub relay_state: Option<String>,
    /// Destination endpoint.
    pub entity_endpoint: String,
    /// Binding used.
    pub binding: crate::constants::Binding,
    /// `SAMLRequest` or `SAMLResponse`.
    pub request_type: &'static str,
    /// Detached signature (redirect/SimpleSign signed messages), if computed.
    pub signature: Option<String>,
    /// Signature algorithm URI accompanying `signature`.
    pub sig_alg: Option<String>,
}

impl BindingContext {
    /// Build the POST/SimpleSign auto-submit form (the `context` must be base64).
    ///
    /// If exactly one of `sig_alg` or `signature` is present, this infallible
    /// helper omits the detached SimpleSign fields. Use [`Self::try_post_form`]
    /// to reject partial detached signature state.
    pub fn post_form(&self) -> String {
        crate::binding::saml_post_binding_form_with_signature(
            &self.entity_endpoint,
            self.request_type,
            &self.context,
            self.relay_state.as_deref(),
            self.sig_alg.as_deref(),
            self.signature.as_deref(),
        )
    }

    /// Build the POST/SimpleSign auto-submit form after validating the endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::SamlError::Invalid`] when `entity_endpoint`
    /// is not an absolute HTTP(S) URL, or when detached SimpleSign state has
    /// only one of `sig_alg` or `signature`.
    pub fn try_post_form(&self) -> Result<String, crate::error::SamlError> {
        crate::binding::try_saml_post_binding_form_with_signature(
            &self.entity_endpoint,
            self.request_type,
            &self.context,
            self.relay_state.as_deref(),
            self.sig_alg.as_deref(),
            self.signature.as_deref(),
        )
    }
}
