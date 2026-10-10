//! Inbound message flow: decode, validate XML/status, verify signatures,
//! optionally decrypt, extract fields, and validate issuer/time constraints.

use crate::binding::{
    base64_decode_with_limit, deflate_raw_decode_with_limit, MAX_DEFLATE_RAW_DECODE_BYTES,
};
use crate::constants::{Binding, ParserType};
use crate::context::is_valid_xml_with_limits;
use crate::error::SamlError;
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
use crate::error::SignatureVerificationReason;
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
use crate::model::RelayStateParam;
use crate::util::Value;
use crate::validator::{check_status_with_limits, logout_request_not_on_or_after_deadline};
use crate::xml::{
    extract_with_limits, fields, validate_protocol_profile, ExtractorField, XmlLimits,
};
use std::time::SystemTime;
use time::OffsetDateTime;

/// Decoded HTTP request inputs for a binding.
#[derive(Debug, Default, Clone)]
pub struct HttpRequest {
    /// URL-decoded query parameters (HTTP-Redirect).
    pub query: Vec<(String, String)>,
    /// Form body parameters (HTTP-POST / SimpleSign).
    pub body: Vec<(String, String)>,
    /// Signed octet string for detached-signature verification.
    pub octet_string: Option<String>,
}

impl HttpRequest {
    /// HTTP-Redirect request from query pairs.
    pub fn redirect(query: Vec<(String, String)>) -> Self {
        Self {
            query,
            ..Default::default()
        }
    }

    /// HTTP-POST/SimpleSign request from body pairs.
    pub fn post(body: Vec<(String, String)>) -> Self {
        Self {
            body,
            ..Default::default()
        }
    }

    fn query_get(&self, key: &str) -> Result<Option<&str>, SamlError> {
        single_param(&self.query, key)
    }

    fn body_get(&self, key: &str) -> Result<Option<&str>, SamlError> {
        single_param(&self.body, key)
    }
}

fn single_param<'a>(
    params: &'a [(String, String)],
    key: &str,
) -> Result<Option<&'a str>, SamlError> {
    let mut values = params
        .iter()
        .filter(|(candidate, _)| candidate == key)
        .map(|(_, value)| value.as_str());
    let first = values.next();
    if values.next().is_some() {
        return Err(SamlError::Invalid("ERR_AMBIGUOUS_FLOW_INPUT".into()));
    }
    Ok(first)
}

fn missing_binding_parameter(name: &'static str) -> SamlError {
    SamlError::MissingBindingParameter { name }
}

fn unsupported_binding(binding: Binding) -> SamlError {
    SamlError::UnsupportedBinding { binding }
}

/// Inputs controlling a flow run.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct FlowOptions<'a> {
    /// Protocol binding.
    pub binding: Option<Binding>,
    /// Message parser type.
    pub parser_type: Option<ParserType>,
    /// Maximum decoded compressed and inflated raw-DEFLATE bytes accepted for
    /// HTTP-Redirect input.
    pub redirect_inflate_max_bytes: usize,
    /// XML parser resource limits for decoded messages and DOM reparses.
    pub xml_limits: XmlLimits,
    /// Whether to require and verify a signature.
    pub check_signature: bool,
    /// Verify a signature when one is present, without requiring one.
    ///
    /// Ignored when `check_signature` is set.
    pub verify_signature_if_present: bool,
    /// Reject a bearer assertion that omits `<AudienceRestriction>`.
    ///
    /// Applies only when `expected_audience` is set. When false, a present
    /// restriction is still evaluated.
    pub require_audience_restriction: bool,
    /// Whether embedded SAML signatures must satisfy the strict RSA-SHA2 profile.
    pub strict_xml_signature_profile: bool,
    /// Expected issuer (peer `entityID`).
    pub from_issuer: Option<&'a str>,
    /// Peer signing certificate(s) for verification.
    pub signing_certs: &'a [String],
    /// Our decryption private key PEM (when assertions are encrypted).
    pub decrypt_key: Option<&'a str>,
    /// Passphrase for `decrypt_key`.
    pub decrypt_key_pass: Option<&'a str>,
    /// Allow XML-Enc RSA key-transport decryption with the bundled RustCrypto
    /// software RSA backend.
    ///
    /// Enforced only for `crypto-rustcrypto`, where that path reaches
    /// `RUSTSEC-2023-0071`-affected `rsa` code when an attacker can observe
    /// timing. AWS-LC and FIPS ignore this flag.
    pub allow_insecure_software_rsa_key_transport_decryption: bool,
    /// Clock drift tolerance `(not_before_ms, not_on_or_after_ms)`.
    pub clock_drifts: (i64, i64),
    /// Validation instant. `None` keeps raw compatibility behavior by reading
    /// the process clock during validation.
    pub now: Option<SystemTime>,
    /// Expected `<Audience>` (this SP's entity ID); `None` skips the check.
    pub expected_audience: Option<&'a str>,
    /// Expected `InResponseTo` (originating request ID); `None` skips the check.
    pub expected_in_response_to: Option<&'a str>,
}

impl<'a> Default for FlowOptions<'a> {
    fn default() -> Self {
        Self {
            binding: None,
            parser_type: None,
            redirect_inflate_max_bytes: MAX_DEFLATE_RAW_DECODE_BYTES,
            xml_limits: XmlLimits::default(),
            check_signature: false,
            verify_signature_if_present: false,
            require_audience_restriction: true,
            strict_xml_signature_profile: false,
            from_issuer: None,
            signing_certs: &[],
            decrypt_key: None,
            decrypt_key_pass: None,
            allow_insecure_software_rsa_key_transport_decryption: false,
            clock_drifts: (0, 0),
            now: None,
            expected_audience: None,
            expected_in_response_to: None,
        }
    }
}

impl FlowOptions<'_> {
    pub(crate) fn validation_now(&self) -> Result<OffsetDateTime, SamlError> {
        self.now.map_or_else(
            || Ok(OffsetDateTime::now_utc()),
            crate::validator::offset_datetime_from_system_time,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AssertionSignatureRequirement {
    Compatible,
    Direct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResponseSignatureRequirement {
    Optional,
    RequiredForEncryptedCbc,
    Required,
}

#[derive(Debug)]
struct PreparedMessage {
    saml_content: String,
    assertion: Option<String>,
    message_authenticated: bool,
    verified_xml_signatures: Vec<VerifiedXmlSignatureEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedXmlSignatureEvidence {
    algorithm_uri: String,
    assertion_directly_covered: bool,
    response_covered: bool,
}

impl VerifiedXmlSignatureEvidence {
    pub(crate) fn algorithm_uri(&self) -> &str {
        &self.algorithm_uri
    }

    pub(crate) fn assertion_directly_covered(&self) -> bool {
        self.assertion_directly_covered
    }

    pub(crate) fn response_covered(&self) -> bool {
        self.response_covered
    }
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
#[derive(Debug)]
struct EmbeddedSignatureEvidence {
    verified: bool,
    verified_node: Option<String>,
    assertion_directly_covered: bool,
    response_covered: bool,
    verified_xml_signatures: Vec<VerifiedXmlSignatureEvidence>,
}

/// Result of a successful low-level flow.
///
/// This records only validation supported by the supplied flow context. The
/// public raw flow has no actual receiving endpoint, so success does not imply
/// that a message `Destination` was compared with that endpoint. Typed
/// receivers supply the additional context before exposing this result.
#[derive(Debug, Clone)]
pub struct FlowResult {
    /// The decoded (and, when verified, authenticated) SAML XML.
    pub saml_content: String,
    /// Extracted fields.
    pub extract: Value,
    /// Verified signature algorithm, if a signature was checked.
    pub sig_alg: Option<String>,
}

#[derive(Debug)]
pub(crate) struct FlowResultWithSignatureEvidence {
    flow_result: FlowResult,
    verified_xml_signatures: Vec<VerifiedXmlSignatureEvidence>,
    message_authenticated: bool,
}

impl FlowResultWithSignatureEvidence {
    pub(crate) fn into_parts(self) -> (FlowResult, Vec<VerifiedXmlSignatureEvidence>) {
        (self.flow_result, self.verified_xml_signatures)
    }

    pub(crate) fn message_authenticated(&self) -> bool {
        self.message_authenticated
    }

    fn into_flow_result(self) -> FlowResult {
        self.flow_result
    }

    pub(crate) fn extract(&self) -> &Value {
        &self.flow_result.extract
    }

    pub(crate) fn saml_content(&self) -> &str {
        &self.flow_result.saml_content
    }
}

fn default_fields(
    parser_type: ParserType,
    assertion: Option<&str>,
) -> Result<Vec<ExtractorField>, SamlError> {
    Ok(match parser_type {
        ParserType::SamlRequest => fields::login_request_fields(),
        ParserType::SamlResponse => {
            let assertion =
                assertion.ok_or_else(|| SamlError::Xml("ERR_EMPTY_ASSERTION".into()))?;
            fields::login_response_fields(assertion)
        }
        ParserType::LogoutRequest => fields::logout_request_fields(),
        ParserType::LogoutResponse => fields::logout_response_fields(),
    })
}

fn decode_message(
    binding: Binding,
    parser_type: ParserType,
    request: &HttpRequest,
    redirect_inflate_max_bytes: usize,
    xml_limits: XmlLimits,
) -> Result<String, SamlError> {
    let direction = parser_type.query_param();
    let bytes = match binding {
        Binding::Redirect => {
            let content = request
                .query_get(direction)?
                .ok_or_else(|| missing_binding_parameter(direction))?;
            let redirect_max_bytes = redirect_inflate_max_bytes.min(xml_limits.max_bytes);
            let compressed = base64_decode_with_limit(content, redirect_max_bytes)?;
            deflate_raw_decode_with_limit(&compressed, redirect_max_bytes)?
        }
        Binding::Post | Binding::SimpleSign => {
            let content = request
                .body_get(direction)?
                .ok_or_else(|| missing_binding_parameter(direction))?;
            base64_decode_with_limit(content, xml_limits.max_bytes)?
        }
        Binding::Artifact => return Err(unsupported_binding(binding)),
    };
    xml_limits.check_input_bytes(bytes.len())?;
    String::from_utf8(bytes).map_err(|e| SamlError::Xml(e.to_string()))
}

fn assertion_shortcut(xml: &str, limits: XmlLimits) -> Result<Option<String>, SamlError> {
    crate::assertion_acceptance::first_login_assertion_xml(xml, limits)
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn verified_content_not_covered() -> SamlError {
    SamlError::SignedReferenceMismatch
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn decoded_octet_params(octet: &str) -> Vec<(String, String)> {
    url::form_urlencoded::parse(octet.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn detached_signature_verification() -> SamlError {
    SamlError::SignatureVerification {
        reason: SignatureVerificationReason::DetachedMessageSignature,
    }
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn relay_state_param(value: Option<&str>) -> Option<RelayStateParam> {
    RelayStateParam::try_from_option(value.map(str::to_string)).ok()
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn detached_relay_state_mismatch(expected: Option<&str>, actual: Option<&str>) -> SamlError {
    match (relay_state_param(expected), relay_state_param(actual)) {
        (Some(expected), Some(actual)) => SamlError::RelayStateMismatch { expected, actual },
        _ => SamlError::SignatureVerification {
            reason: SignatureVerificationReason::RelayStateCorrelation,
        },
    }
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn ensure_redirect_octet_matches_consumed_fields(
    parser_type: ParserType,
    request: &HttpRequest,
    sig_alg: &str,
    octet: &str,
) -> Result<(), SamlError> {
    let direction = parser_type.query_param();
    let signed = decoded_octet_params(octet);
    if single_param(&signed, "Signature")?.is_some() {
        return Err(detached_signature_verification());
    }

    let signed_message =
        single_param(&signed, direction)?.ok_or_else(|| missing_binding_parameter(direction))?;
    let consumed_message = request
        .query_get(direction)?
        .ok_or_else(|| missing_binding_parameter(direction))?;
    if signed_message != consumed_message {
        return Err(detached_signature_verification());
    }

    let signed_sig_alg =
        single_param(&signed, "SigAlg")?.ok_or_else(|| missing_binding_parameter("SigAlg"))?;
    if signed_sig_alg != sig_alg {
        return Err(detached_signature_verification());
    }

    let signed_relay_state = single_param(&signed, "RelayState")?;
    let consumed_relay_state = request.query_get("RelayState")?;
    if signed_relay_state != consumed_relay_state {
        return Err(detached_relay_state_mismatch(
            signed_relay_state,
            consumed_relay_state,
        ));
    }

    Ok(())
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn ensure_simplesign_octet_matches_consumed_fields(
    parser_type: ParserType,
    request: &HttpRequest,
    xml: &str,
    sig_alg: &str,
    octet: &str,
) -> Result<(), SamlError> {
    let direction = parser_type.query_param();
    request
        .body_get(direction)?
        .ok_or_else(|| missing_binding_parameter(direction))?;

    let message_and_sig_alg = format!("{direction}={xml}&SigAlg={sig_alg}");
    let message_empty_relay_and_sig_alg = format!("{direction}={xml}&RelayState=&SigAlg={sig_alg}");
    let matches = match request.body_get("RelayState")? {
        Some(relay_state) => {
            let expected = format!("{direction}={xml}&RelayState={relay_state}&SigAlg={sig_alg}");
            octet == expected
        }
        // Older saml-rs outbound SimpleSign signed an empty RelayState field
        // even when the form body omitted RelayState; keep accepting it for
        // compatibility.
        None => octet == message_and_sig_alg || octet == message_empty_relay_and_sig_alg,
    };

    if matches {
        Ok(())
    } else {
        Err(detached_signature_verification())
    }
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn ensure_detached_octet_matches_consumed_fields(
    binding: Binding,
    parser_type: ParserType,
    request: &HttpRequest,
    xml: &str,
    sig_alg: &str,
    octet: &str,
) -> Result<(), SamlError> {
    match binding {
        Binding::Redirect => {
            ensure_redirect_octet_matches_consumed_fields(parser_type, request, sig_alg, octet)
        }
        Binding::SimpleSign => ensure_simplesign_octet_matches_consumed_fields(
            parser_type,
            request,
            xml,
            sig_alg,
            octet,
        ),
        Binding::Post | Binding::Artifact => Ok(()),
    }
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn required_xml_signature_failed(signature_present: bool) -> SamlError {
    if signature_present {
        SamlError::SignatureVerification {
            reason: SignatureVerificationReason::XmlSignature,
        }
    } else {
        SamlError::SignatureMissing
    }
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn verify_embedded_signature(
    xml: &str,
    opts: &FlowOptions<'_>,
) -> Result<EmbeddedSignatureEvidence, SamlError> {
    let verification = crate::crypto::verify::verify_signatures_detailed_with_profile(
        xml,
        opts.signing_certs,
        opts.xml_limits,
        opts.strict_xml_signature_profile,
    )?;
    let verified_xml_signatures = verification
        .verified_embedded_signatures()
        .iter()
        .map(|signature| VerifiedXmlSignatureEvidence {
            algorithm_uri: signature.algorithm_uri().to_string(),
            assertion_directly_covered: signature.assertion_directly_covered(),
            response_covered: signature.response_covered(),
        })
        .collect();
    Ok(EmbeddedSignatureEvidence {
        verified: verification.verified(),
        assertion_directly_covered: verification.assertion_directly_covered(),
        response_covered: verification.response_covered(),
        verified_node: verification.into_signed_content(),
        verified_xml_signatures,
    })
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn require_direct_assertion_coverage(
    assertion_signature: AssertionSignatureRequirement,
    assertion_directly_covered: bool,
) -> Result<(), SamlError> {
    if assertion_signature == AssertionSignatureRequirement::Direct && !assertion_directly_covered {
        return Err(SamlError::AssertionSignatureRequired);
    }
    Ok(())
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn require_response_coverage(
    response_signature_required: bool,
    response_covered: bool,
) -> Result<(), SamlError> {
    if response_signature_required && !response_covered {
        return Err(SamlError::SignedReferenceMismatch);
    }
    Ok(())
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn response_uses_cbc_encrypted_assertion(xml: &str, limits: XmlLimits) -> Result<bool, SamlError> {
    let document = crate::xml::dom::parse_with_limits(xml, limits)?;
    Ok(document
        .root
        .children
        .iter()
        .filter(|child| child.local_name == "EncryptedAssertion")
        .filter_map(|encrypted_assertion| {
            encrypted_assertion
                .children
                .iter()
                .find(|child| child.local_name == "EncryptedData")
        })
        .filter_map(|encrypted_data| {
            encrypted_data
                .children
                .iter()
                .find(|child| child.local_name == "EncryptionMethod")
        })
        .filter_map(|encryption_method| encryption_method.attr("Algorithm"))
        .any(crate::constants::is_xml_encryption_cbc_algorithm))
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn response_signature_is_required(
    requirement: ResponseSignatureRequirement,
    xml: &str,
    limits: XmlLimits,
) -> Result<bool, SamlError> {
    match requirement {
        ResponseSignatureRequirement::Optional => Ok(false),
        ResponseSignatureRequirement::RequiredForEncryptedCbc => {
            response_uses_cbc_encrypted_assertion(xml, limits)
        }
        ResponseSignatureRequirement::Required => Ok(true),
    }
}

/// Verify and optionally decrypt the message, returning the authenticated
/// `(saml_content, assertion)`. Requires a crypto provider.
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn verify_and_prepare(
    xml: &str,
    parser_type: ParserType,
    opts: &FlowOptions<'_>,
    assertion_signature: AssertionSignatureRequirement,
    response_signature: ResponseSignatureRequirement,
) -> Result<PreparedMessage, SamlError> {
    use crate::crypto::{
        decrypt_assertion_with_limits,
        enc::{require_software_rsa_opt_in, AssertionDecryptionOptions},
        keys::load_private_key,
        verify::has_xml_signature_with_limits,
    };

    let signature_present = has_xml_signature_with_limits(xml, opts.xml_limits)?;
    let evidence = verify_embedded_signature(xml, opts)?;
    let response_signature_required =
        response_signature_is_required(response_signature, xml, opts.xml_limits)?;
    if response_signature_required {
        if !evidence.verified {
            return Err(required_xml_signature_failed(signature_present));
        }
        require_response_coverage(response_signature_required, evidence.response_covered)?;
    }
    let decrypt_required = opts.decrypt_key.is_some();
    let decrypt_options = AssertionDecryptionOptions {
        allow_insecure_software_rsa_key_transport_decryption: opts
            .allow_insecure_software_rsa_key_transport_decryption,
    };
    if decrypt_required {
        require_software_rsa_opt_in(decrypt_options)?;
    }
    let load_key = || load_private_key(opts.decrypt_key.unwrap_or_default(), opts.decrypt_key_pass);

    if decrypt_required && evidence.verified && parser_type == ParserType::SamlResponse {
        if let Some(node) = evidence.verified_node.as_deref() {
            let mut verified_xml_signatures = evidence.verified_xml_signatures.clone();
            // signed-then-encrypted: the verified content is a Response carrying
            // an EncryptedAssertion.
            let (content, assertion) = decrypt_assertion_with_limits(
                node,
                &load_key()?,
                decrypt_options,
                opts.xml_limits,
            )?;
            is_valid_xml_with_limits(&content, opts.xml_limits)?;
            validate_protocol_profile(&content, parser_type, opts.xml_limits)?;
            if assertion_signature == AssertionSignatureRequirement::Direct {
                let decrypted_signature_present =
                    has_xml_signature_with_limits(&assertion, opts.xml_limits)?;
                let decrypted_evidence = verify_embedded_signature(&assertion, opts)?;
                if !decrypted_evidence.verified {
                    return Err(required_xml_signature_failed(decrypted_signature_present));
                }
                require_direct_assertion_coverage(
                    assertion_signature,
                    decrypted_evidence.assertion_directly_covered,
                )?;
                verified_xml_signatures.extend(decrypted_evidence.verified_xml_signatures);
            }
            return Ok(PreparedMessage {
                saml_content: content,
                assertion: Some(assertion),
                message_authenticated: evidence.response_covered,
                verified_xml_signatures,
            });
        }
    }
    if decrypt_required && !evidence.verified {
        // encrypted-then-signed: decrypt first, then verify the result.
        let (content, assertion) =
            decrypt_assertion_with_limits(xml, &load_key()?, decrypt_options, opts.xml_limits)?;
        is_valid_xml_with_limits(&content, opts.xml_limits)?;
        validate_protocol_profile(&content, parser_type, opts.xml_limits)?;
        let verification_xml = if assertion_signature == AssertionSignatureRequirement::Direct {
            assertion.as_str()
        } else {
            content.as_str()
        };
        let signature_present = has_xml_signature_with_limits(verification_xml, opts.xml_limits)?;
        let re_evidence = verify_embedded_signature(verification_xml, opts)?;
        return if re_evidence.verified {
            require_direct_assertion_coverage(
                assertion_signature,
                re_evidence.assertion_directly_covered,
            )?;
            let verified_assertion = if assertion_signature == AssertionSignatureRequirement::Direct
            {
                Some(assertion)
            } else {
                re_evidence.verified_node
            };
            Ok(PreparedMessage {
                saml_content: content,
                assertion: verified_assertion,
                message_authenticated: false,
                verified_xml_signatures: re_evidence.verified_xml_signatures,
            })
        } else {
            Err(required_xml_signature_failed(signature_present))
        };
    }
    if evidence.verified {
        require_direct_assertion_coverage(
            assertion_signature,
            evidence.assertion_directly_covered,
        )?;
        if matches!(
            parser_type,
            ParserType::SamlRequest | ParserType::LogoutRequest | ParserType::LogoutResponse
        ) {
            let content = evidence
                .verified_node
                .ok_or_else(verified_content_not_covered)?;
            return Ok(PreparedMessage {
                saml_content: content,
                assertion: None,
                message_authenticated: true,
                verified_xml_signatures: evidence.verified_xml_signatures,
            });
        }
        return Ok(PreparedMessage {
            saml_content: xml.to_string(),
            assertion: evidence.verified_node,
            message_authenticated: evidence.response_covered,
            verified_xml_signatures: evidence.verified_xml_signatures,
        });
    }
    Err(required_xml_signature_failed(signature_present))
}

#[cfg(not(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
)))]
fn verify_and_prepare(
    _xml: &str,
    _parser_type: ParserType,
    _opts: &FlowOptions<'_>,
    _assertion_signature: AssertionSignatureRequirement,
    _response_signature: ResponseSignatureRequirement,
) -> Result<PreparedMessage, SamlError> {
    Err(SamlError::Unsupported(
        "signature verification requires a crypto provider feature".into(),
    ))
}

/// Verify a detached (redirect/SimpleSign) message signature, returning the
/// verified `SigAlg`. Requires a crypto provider.
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn verify_detached(
    binding: Binding,
    parser_type: ParserType,
    request: &HttpRequest,
    opts: &FlowOptions<'_>,
    xml: &str,
) -> Result<String, SamlError> {
    let get = |k: &str| -> Result<Option<&str>, SamlError> {
        match binding {
            Binding::Redirect => request.query_get(k),
            _ => request.body_get(k),
        }
    };
    let signature = get("Signature")?.ok_or(SamlError::SignatureMissing)?;
    let sig_alg = get("SigAlg")?.ok_or_else(|| missing_binding_parameter("SigAlg"))?;
    let octet = request
        .octet_string
        .as_deref()
        .ok_or_else(|| missing_binding_parameter("octet_string"))?;
    ensure_detached_octet_matches_consumed_fields(
        binding,
        parser_type,
        request,
        xml,
        sig_alg,
        octet,
    )?;
    crate::crypto::initialize_crypto_provider()?;

    let mut provider_error = None;
    let mut tried_invalid = false;
    for cert in opts.signing_certs {
        match crate::crypto::verify_message_signature(octet, signature, cert, sig_alg) {
            Ok(true) => return Ok(sig_alg.to_string()),
            Ok(false) => tried_invalid = true,
            Err(error @ SamlError::Crypto(_)) => {
                provider_error.get_or_insert(error);
            }
            Err(_) => {}
        }
    }

    // A leftover unloadable cert must not poison a rolling-cert verdict.
    match provider_error {
        Some(error) if !tried_invalid => Err(error),
        _ => Err(detached_signature_verification()),
    }
}

#[cfg(not(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
)))]
fn verify_detached(
    _binding: Binding,
    _parser_type: ParserType,
    _request: &HttpRequest,
    _opts: &FlowOptions<'_>,
    _xml: &str,
) -> Result<String, SamlError> {
    Err(SamlError::Unsupported(
        "signature verification requires a crypto provider feature".into(),
    ))
}

fn validate_message_destination(
    parser_type: ParserType,
    extracted: &Value,
    expected_recipient: Option<&str>,
    additional_recipients: &[&str],
    message_authenticated: bool,
) -> Result<(), SamlError> {
    let Some(expected) = expected_recipient else {
        return Ok(());
    };
    let destination = match parser_type {
        ParserType::SamlResponse | ParserType::LogoutResponse => {
            extracted.get_str("response.destination")
        }
        ParserType::LogoutRequest => extracted.get_str("request.destination"),
        ParserType::SamlRequest => return Ok(()),
    };
    // SAML Bindings 2.0 §§3.4.5.2 and 3.5.5.2, and SimpleSign §2.4,
    // require Destination on a signed message received through these bindings.
    if message_authenticated && destination.is_none() {
        return Err(SamlError::destination_mismatch(expected, None));
    }
    // SAML Core 2.0 §§3.2.1 and 3.2.2 require the actual recipient to discard
    // any protocol message whose present Destination does not match itself.
    // Metadata may publish more than one endpoint for the binding; each
    // published location is this recipient.
    let matches_recipient = destination.is_some_and(|destination| {
        destination == expected || additional_recipients.contains(&destination)
    });
    if destination.is_some() && !matches_recipient {
        return Err(SamlError::destination_mismatch(expected, destination));
    }
    Ok(())
}

fn validate_context(
    parser_type: ParserType,
    saml_content: &str,
    extracted: &Value,
    opts: &FlowOptions<'_>,
    expected_recipient: Option<&str>,
    additional_recipients: &[&str],
    message_authenticated: bool,
) -> Result<(), SamlError> {
    let should_validate_issuer = matches!(
        parser_type,
        ParserType::SamlRequest
            | ParserType::SamlResponse
            | ParserType::LogoutRequest
            | ParserType::LogoutResponse
    );
    if should_validate_issuer {
        if let Some(expected) = opts.from_issuer {
            let actual = extracted.get_str("issuer");
            if actual != Some(expected) {
                return Err(SamlError::issuer_mismatch(expected, actual));
            }
        }
    }
    let is_response = matches!(
        parser_type,
        ParserType::SamlResponse | ParserType::LogoutResponse
    );
    if is_response {
        if let Some(expected) = opts.expected_in_response_to {
            let actual = extracted.get_str("response.inResponseTo");
            if actual != Some(expected) {
                return Err(SamlError::in_response_to_mismatch(Some(expected), actual));
            }
        }
    }
    validate_message_destination(
        parser_type,
        extracted,
        expected_recipient,
        additional_recipients,
        message_authenticated,
    )?;
    if parser_type == ParserType::SamlResponse {
        crate::assertion_acceptance::accept_response_assertions(
            saml_content,
            opts,
            expected_recipient,
        )?;
    }
    if parser_type == ParserType::LogoutRequest {
        logout_request_not_on_or_after_deadline(
            extracted,
            opts.validation_now()?,
            opts.clock_drifts.1,
        )?;
    }
    Ok(())
}

fn signature_is_present(
    binding: Binding,
    request: &HttpRequest,
    xml: &str,
    limits: XmlLimits,
) -> Result<bool, SamlError> {
    let detached = match binding {
        Binding::Redirect => request.query.iter().any(|(name, _)| name == "Signature"),
        Binding::SimpleSign => request.body.iter().any(|(name, _)| name == "Signature"),
        Binding::Post | Binding::Artifact => false,
    };
    if detached {
        return Ok(true);
    }
    let document = crate::xml::dom::parse_with_limits(xml, limits)?;
    Ok(protocol_signature_candidate(&document.root))
}

/// Same placement as embedded-signature verification: a `Signature` child of
/// the protocol root, or of an `Assertion` child of that root.
fn protocol_signature_candidate(root: &crate::xml::dom::Node) -> bool {
    root.children
        .iter()
        .any(|child| child.local_name == "Signature")
        || root.children.iter().any(|child| {
            child.local_name == "Assertion"
                && child
                    .children
                    .iter()
                    .any(|nested| nested.local_name == "Signature")
        })
}

fn flow_inner(
    opts: &FlowOptions<'_>,
    request: &HttpRequest,
    expected_recipient: Option<&str>,
    additional_recipients: &[&str],
    assertion_signature: AssertionSignatureRequirement,
    response_signature: ResponseSignatureRequirement,
) -> Result<FlowResultWithSignatureEvidence, SamlError> {
    let binding = opts
        .binding
        .ok_or_else(|| missing_binding_parameter("binding"))?;
    let parser_type = opts
        .parser_type
        .ok_or_else(|| SamlError::Invalid("ERR_UNDEFINED_PARSERTYPE".into()))?;

    let xml = decode_message(
        binding,
        parser_type,
        request,
        opts.redirect_inflate_max_bytes,
        opts.xml_limits,
    )?;
    is_valid_xml_with_limits(&xml, opts.xml_limits)?;
    validate_protocol_profile(&xml, parser_type, opts.xml_limits)?;
    check_status_with_limits(&xml, parser_type, opts.xml_limits)?;

    let verify_signature = opts.check_signature
        || (opts.verify_signature_if_present
            && signature_is_present(binding, request, &xml, opts.xml_limits)?);
    let (saml_content, assertion, sig_alg, message_authenticated, verified_xml_signatures) =
        if verify_signature {
            match binding {
                Binding::Redirect | Binding::SimpleSign => {
                    let sig_alg = verify_detached(binding, parser_type, request, opts, &xml)?;
                    let prepared = if parser_type == ParserType::SamlResponse
                        && assertion_signature == AssertionSignatureRequirement::Direct
                    {
                        verify_and_prepare(
                            &xml,
                            parser_type,
                            opts,
                            assertion_signature,
                            ResponseSignatureRequirement::Optional,
                        )?
                    } else {
                        let assertion = if parser_type == ParserType::SamlResponse {
                            assertion_shortcut(&xml, opts.xml_limits)?
                        } else {
                            None
                        };
                        PreparedMessage {
                            saml_content: xml,
                            assertion,
                            message_authenticated: false,
                            verified_xml_signatures: Vec::new(),
                        }
                    };
                    (
                        prepared.saml_content,
                        prepared.assertion,
                        Some(sig_alg),
                        true,
                        prepared.verified_xml_signatures,
                    )
                }
                _ => {
                    let prepared = verify_and_prepare(
                        &xml,
                        parser_type,
                        opts,
                        assertion_signature,
                        response_signature,
                    )?;
                    (
                        prepared.saml_content,
                        prepared.assertion,
                        None,
                        prepared.message_authenticated,
                        prepared.verified_xml_signatures,
                    )
                }
            }
        } else {
            let assertion = if parser_type == ParserType::SamlResponse {
                assertion_shortcut(&xml, opts.xml_limits)?
            } else {
                None
            };
            (xml, assertion, None, false, Vec::new())
        };

    let fields = default_fields(parser_type, assertion.as_deref())?;
    let extracted = extract_with_limits(&saml_content, &fields, opts.xml_limits)?;
    validate_context(
        parser_type,
        &saml_content,
        &extracted,
        opts,
        expected_recipient,
        additional_recipients,
        message_authenticated,
    )?;

    Ok(FlowResultWithSignatureEvidence {
        flow_result: FlowResult {
            saml_content,
            extract: extracted,
            sig_alg,
        },
        verified_xml_signatures,
        message_authenticated,
    })
}

/// Run the inbound flow described by `opts` against `request`.
pub(crate) fn flow_with_authentication(
    opts: &FlowOptions<'_>,
    request: &HttpRequest,
) -> Result<(FlowResult, bool), SamlError> {
    let result = flow_inner(
        opts,
        request,
        None,
        &[],
        AssertionSignatureRequirement::Compatible,
        ResponseSignatureRequirement::Optional,
    )?;
    let message_authenticated = result.message_authenticated();
    Ok((result.into_flow_result(), message_authenticated))
}

pub fn flow(opts: &FlowOptions<'_>, request: &HttpRequest) -> Result<FlowResult, SamlError> {
    Ok(flow_inner(
        opts,
        request,
        None,
        &[],
        AssertionSignatureRequirement::Compatible,
        ResponseSignatureRequirement::Optional,
    )?
    .into_flow_result())
}

pub(crate) fn flow_with_expected_recipient_and_signature_evidence(
    opts: &FlowOptions<'_>,
    request: &HttpRequest,
    expected_recipient: &str,
    assertion_signature: AssertionSignatureRequirement,
    response_signature: ResponseSignatureRequirement,
) -> Result<FlowResultWithSignatureEvidence, SamlError> {
    flow_with_expected_recipient_allowing_additional(
        opts,
        request,
        expected_recipient,
        &[],
        assertion_signature,
        response_signature,
    )
}

pub(crate) fn flow_with_expected_recipient_allowing_additional(
    opts: &FlowOptions<'_>,
    request: &HttpRequest,
    expected_recipient: &str,
    additional_recipients: &[&str],
    assertion_signature: AssertionSignatureRequirement,
    response_signature: ResponseSignatureRequirement,
) -> Result<FlowResultWithSignatureEvidence, SamlError> {
    flow_inner(
        opts,
        request,
        Some(expected_recipient),
        additional_recipients,
        assertion_signature,
        response_signature,
    )
}

#[cfg(all(
    test,
    any(
        feature = "crypto-rustcrypto",
        feature = "crypto-aws-lc",
        feature = "crypto-fips"
    )
))]
mod tests {
    use super::*;
    use crate::constants::signature_algorithm::RSA_SHA256;

    #[test]
    fn detached_verification_preserves_provider_error() {
        let certificates = vec!["not a certificate".to_string()];
        let options = FlowOptions {
            signing_certs: &certificates,
            ..Default::default()
        };
        let octet = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("SAMLRequest", "payload")
            .append_pair("SigAlg", RSA_SHA256)
            .finish();
        let request = HttpRequest {
            query: vec![
                ("SAMLRequest".into(), "payload".into()),
                ("SigAlg".into(), RSA_SHA256.into()),
                ("Signature".into(), "AA==".into()),
            ],
            octet_string: Some(octet),
            ..Default::default()
        };

        assert!(matches!(
            verify_detached(
                Binding::Redirect,
                ParserType::SamlRequest,
                &request,
                &options,
                "<samlp:AuthnRequest/>",
            ),
            Err(SamlError::Crypto(_))
        ));
    }

    #[test]
    fn detached_rolling_cert_unloadable_peer_keeps_invalid_verdict(
    ) -> Result<(), Box<dyn std::error::Error>> {
        const SP_PRIVKEY: &str = include_str!("../tests/fixtures/key/sp_privkey.pem");
        const SP_CERT: &str = include_str!("../tests/fixtures/key/sp_signing_cert.cer");

        let key = crate::crypto::keys::load_private_key(SP_PRIVKEY, None)?;
        let signature =
            crate::crypto::construct_message_signature("SAMLRequest=other", &key, RSA_SHA256)?;
        let octet = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("SAMLRequest", "payload")
            .append_pair("SigAlg", RSA_SHA256)
            .finish();
        let request = HttpRequest {
            query: vec![
                ("SAMLRequest".into(), "payload".into()),
                ("SigAlg".into(), RSA_SHA256.into()),
                ("Signature".into(), signature),
            ],
            octet_string: Some(octet),
            ..Default::default()
        };
        let garbage = "not a certificate".to_string();
        let signer = SP_CERT.to_string();

        for certificates in [vec![garbage.clone(), signer.clone()], vec![signer, garbage]] {
            let options = FlowOptions {
                signing_certs: &certificates,
                ..Default::default()
            };
            assert!(
                matches!(
                    verify_detached(
                        Binding::Redirect,
                        ParserType::SamlRequest,
                        &request,
                        &options,
                        "<samlp:AuthnRequest/>",
                    ),
                    Err(SamlError::SignatureVerification {
                        reason: SignatureVerificationReason::DetachedMessageSignature,
                    })
                ),
                "unloadable leftover must not replace detached-invalid with Crypto"
            );
        }
        Ok(())
    }
}
