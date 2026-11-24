use core::fmt;

use crate::binding::MAX_DEFLATE_RAW_DECODE_BYTES;
use crate::config::{AssertionElementEncryption, XmlSignatureProfile};
use crate::config::{DigestAlgorithm, HmacSecret, MaskGenerationFunction, X509Credential};
use crate::constants::{
    data_encryption_algorithm, key_encryption_algorithm, signature_algorithm, transform_algorithm,
};
use crate::error::{SamlError, TimeWindowField};
use crate::xml::XmlLimits;

#[non_exhaustive]
#[derive(Clone)]
pub struct EntitySetting {
    pub entity_id: Option<String>,
    pub request_signature_algorithm: String,
    pub data_encryption_algorithm: String,
    pub key_encryption_algorithm: String,
    pub(crate) rsa_oaep_parameters: Option<(DigestAlgorithm, MaskGenerationFunction)>,
    pub allow_create: bool,
    pub is_assertion_encrypted: bool,
    pub(crate) assertion_element_encryption: AssertionElementEncryption,
    pub allow_rsa15_key_transport_decryption: bool,
    pub max_decryption_work: usize,
    pub want_assertions_signed: bool,
    pub(crate) require_audience_restriction: bool,
    pub want_message_signed: bool,
    pub(crate) xml_signatures: XmlSignatureProfile,
    pub(crate) want_encrypted_cbc_response_signed: bool,
    pub name_id_format: Vec<String>,
    pub private_key: Option<String>,
    pub private_key_pass: Option<String>,
    pub signing_cert: Option<String>,
    pub hmac_secret: Option<HmacSecret>,
    pub encrypt_cert: Option<String>,
    pub enc_private_key: Option<String>,
    pub enc_private_key_pass: Option<String>,
    pub additional_decryption_keys: Vec<X509Credential>,
    pub redirect_inflate_max_bytes: usize,
    pub xml_limits: XmlLimits,
    pub schema_validator: Option<crate::SchemaValidator>,
    pub tag_prefix_protocol: String,
    pub tag_prefix_assertion: String,
    pub signature_config: Option<SignatureConfig>,
    pub transformation_algorithms: Vec<String>,
}

fn redacted_option<T>(value: Option<&T>) -> Option<&'static str> {
    value.map(|_| "<redacted>")
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
            .field("rsa_oaep_parameters", &self.rsa_oaep_parameters)
            .field("allow_create", &self.allow_create)
            .field("is_assertion_encrypted", &self.is_assertion_encrypted)
            .field(
                "assertion_element_encryption",
                &self.assertion_element_encryption,
            )
            .field(
                "allow_rsa15_key_transport_decryption",
                &self.allow_rsa15_key_transport_decryption,
            )
            .field("max_decryption_work", &self.max_decryption_work)
            .field("want_assertions_signed", &self.want_assertions_signed)
            .field(
                "require_audience_restriction",
                &self.require_audience_restriction,
            )
            .field("want_message_signed", &self.want_message_signed)
            .field("xml_signatures", &self.xml_signatures)
            .field(
                "want_encrypted_cbc_response_signed",
                &self.want_encrypted_cbc_response_signed,
            )
            .field("name_id_format", &self.name_id_format)
            .field("private_key", &redacted_option(self.private_key.as_ref()))
            .field(
                "private_key_pass",
                &redacted_option(self.private_key_pass.as_ref()),
            )
            .field("signing_cert", &redacted_option(self.signing_cert.as_ref()))
            .field("hmac_secret", &redacted_option(self.hmac_secret.as_ref()))
            .field("encrypt_cert", &redacted_option(self.encrypt_cert.as_ref()))
            .field(
                "enc_private_key",
                &redacted_option(self.enc_private_key.as_ref()),
            )
            .field(
                "enc_private_key_pass",
                &redacted_option(self.enc_private_key_pass.as_ref()),
            )
            .field(
                "additional_decryption_keys",
                &self.additional_decryption_keys,
            )
            .field(
                "redirect_inflate_max_bytes",
                &self.redirect_inflate_max_bytes,
            )
            .field("xml_limits", &self.xml_limits)
            .field("schema_validator", &self.schema_validator)
            .field("tag_prefix_protocol", &self.tag_prefix_protocol)
            .field("tag_prefix_assertion", &self.tag_prefix_assertion)
            .field("signature_config", &self.signature_config)
            .field("transformation_algorithms", &self.transformation_algorithms)
            .finish()
    }
}

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
///
/// Start from [`Default`](Default::default) and assign the fields you change.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SignatureConfig {
    /// Element prefix for the signature (default `ds`).
    ///
    /// Must be an XML NCName that does not begin with `xml` in any case.
    pub prefix: String,
    /// Element used as the anchor for signature placement.
    ///
    /// Use one or more literal `/*[local-name(.)='NCName']` steps, starting at
    /// the document element. Each step after the first selects direct children
    /// by local name. The first complete match in document order is used.
    /// The builders reject unsupported syntax. Signing fails if nothing matches.
    /// With `None`, the signature is placed after the signed target's `<Issuer>`.
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

impl EntitySetting {
    pub(crate) fn default_name_id_format(&self) -> Option<&str> {
        self.name_id_format.first().map(String::as_str)
    }
}

impl Default for EntitySetting {
    fn default() -> Self {
        Self {
            entity_id: None,
            request_signature_algorithm: signature_algorithm::RSA_SHA256.to_string(),
            data_encryption_algorithm: data_encryption_algorithm::AES_256_CBC.to_string(),
            key_encryption_algorithm: key_encryption_algorithm::RSA_OAEP_MGF1P.to_string(),
            rsa_oaep_parameters: None,
            allow_create: false,
            is_assertion_encrypted: false,
            assertion_element_encryption: AssertionElementEncryption::default(),
            allow_rsa15_key_transport_decryption: false,
            max_decryption_work: crate::constants::DEFAULT_MAX_DECRYPTION_WORK,
            want_assertions_signed: false,
            require_audience_restriction: true,
            want_message_signed: false,
            xml_signatures: XmlSignatureProfile::AllowWeakAlgorithms,
            want_encrypted_cbc_response_signed: false,
            name_id_format: Vec::new(),
            private_key: None,
            private_key_pass: None,
            signing_cert: None,
            hmac_secret: None,
            encrypt_cert: None,
            enc_private_key: None,
            enc_private_key_pass: None,
            additional_decryption_keys: Vec::new(),
            redirect_inflate_max_bytes: MAX_DEFLATE_RAW_DECODE_BYTES,
            xml_limits: XmlLimits::default(),
            schema_validator: None,
            tag_prefix_protocol: "samlp".to_string(),
            tag_prefix_assertion: "saml".to_string(),
            signature_config: None,
            transformation_algorithms: vec![
                transform_algorithm::ENVELOPED_SIGNATURE.to_string(),
                transform_algorithm::EXC_C14N.to_string(),
            ],
        }
    }
}

pub(crate) fn generate_id() -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut identifier = String::from("_");
    for byte in random_20_bytes() {
        identifier.push(char::from(HEX[usize::from(byte >> 4)]));
        identifier.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    identifier
}

pub(crate) fn random_20_bytes() -> [u8; 20] {
    let first = uuid::Uuid::new_v4().into_bytes();
    let second = uuid::Uuid::new_v4().into_bytes();
    let mut random = [0u8; 20];
    random[..6].copy_from_slice(&first[..6]);
    random[6..13].copy_from_slice(&first[9..]);
    random[13..19].copy_from_slice(&second[..6]);
    random[19] = second[9];
    random
}

#[derive(Debug, Clone, Default)]
pub struct User {
    pub name_id: String,
}

impl User {
    pub fn new(name_id: impl Into<String>) -> Self {
        Self {
            name_id: name_id.into(),
        }
    }
}

pub(crate) fn now_iso8601() -> String {
    iso8601_offset(0)
}

pub fn iso8601_offset(seconds: i64) -> String {
    let t = time::OffsetDateTime::now_utc() + time::Duration::seconds(seconds);
    format_saml_utc_date_time(t)
}

#[derive(Debug, Clone)]
pub(crate) struct IdpIssuanceWindow {
    pub(crate) issued_at: time::OffsetDateTime,
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
        issued_at: issue_instant,
        issue_instant: format_idp_issuance_instant(issue_instant, preserve_subseconds),
        expiration: format_idp_issuance_instant(expiration, preserve_subseconds),
    })
}

pub(crate) fn format_idp_issuance_instant(
    t: time::OffsetDateTime,
    preserve_subseconds: bool,
) -> String {
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
        let last_second = time::OffsetDateTime::from_unix_timestamp(1_483_228_799)?;

        assert_eq!(
            format_saml_utc_date_time(last_second),
            "2016-12-31T23:59:59Z"
        );
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct BindingContext {
    pub id: String,
    pub context: String,
    pub relay_state: Option<String>,
    pub entity_endpoint: String,
    pub binding: crate::constants::Binding,
    pub request_type: &'static str,
    pub signature: Option<String>,
    pub sig_alg: Option<String>,
}
