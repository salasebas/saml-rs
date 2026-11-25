use crate::assertion_acceptance::first_login_assertion_xml;
use crate::binding::{
    decode_base64_with_limit, deflate_raw_decode, single_parameter, MAX_DEFLATE_RAW_DECODE_BYTES,
};
use crate::config::{AssertionElementEncryption, XmlSignatureProfile};
use crate::config::{HmacSecret, X509Credential};
use crate::constants::{Binding, CertUse, ParserType};
use crate::entity::EntitySetting;
use crate::error::SamlError;
use crate::metadata::Metadata;
use crate::model::{ClockSkew, StatusMessage};
use crate::util::Value;
use crate::validator::{check_status, logout_request_not_on_or_after_deadline};
use crate::xml::any_uri::collapse_whitespace;
use crate::xml::protocol_element::{parse_saml_with_limits, read_status_message};
use crate::xml::signature_placement::saml_signature_candidates;
use crate::xml::{
    extract_with_limits, fields, validate_protocol_profile, ExtractorField, XmlLimits,
};
use std::time::SystemTime;
use time::OffsetDateTime;

#[cfg(crypto)]
mod detached;
#[cfg(crypto)]
mod embedded;
mod error_response;
mod response_issuer;

pub(crate) use response_issuer::issuer_for_idp_resolution;

#[cfg(crypto)]
use detached::verify_detached;
#[cfg(crypto)]
use embedded::{prepare_after_detached_signature, verify_and_prepare, verify_present_signatures};

#[derive(Debug, Default, Clone)]
pub struct HttpRequest {
    pub query: Vec<(String, String)>,
    pub body: Vec<(String, String)>,
    pub octet_string: Option<String>,
}

impl HttpRequest {
    pub fn post(body: Vec<(String, String)>) -> Self {
        Self {
            body,
            ..Default::default()
        }
    }

    fn query_get(&self, key: &'static str) -> Result<Option<&str>, SamlError> {
        single_param(&self.query, key)
    }

    fn body_get(&self, key: &'static str) -> Result<Option<&str>, SamlError> {
        single_param(&self.body, key)
    }
}

fn single_param<'a>(
    params: &'a [(String, String)],
    key: &'static str,
) -> Result<Option<&'a str>, SamlError> {
    single_parameter(
        params
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
        key,
    )
}

fn missing_binding_parameter(name: &'static str) -> SamlError {
    SamlError::MissingBindingParameter { name }
}

fn unsupported_binding(binding: Binding) -> SamlError {
    SamlError::UnsupportedBinding { binding }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureCheck {
    Skip,
    VerifyIfPresent,
    Require,
}

#[non_exhaustive]
#[derive(Debug, Clone)]
#[cfg_attr(not(crypto), allow(dead_code))]
pub struct FlowOptions<'a> {
    pub binding: Binding,
    pub parser_type: ParserType,
    pub(crate) defer_logout_request_version: bool,
    pub redirect_inflate_max_bytes: usize,
    pub xml_limits: XmlLimits,
    pub schema_validator: Option<crate::SchemaValidator>,
    pub signature_check: SignatureCheck,
    pub require_audience_restriction: bool,
    pub xml_signatures: XmlSignatureProfile,
    pub from_issuer: Option<&'a str>,
    pub signing_certs: &'a [String],
    pub hmac_secret: Option<&'a HmacSecret>,
    pub decrypt_key: Option<&'a str>,
    pub decrypt_key_pass: Option<&'a str>,
    pub additional_decrypt_keys: &'a [X509Credential],
    pub(crate) require_encrypted_assertions: bool,
    pub(crate) assertion_elements: AssertionElementEncryption,
    pub allow_rsa15_key_transport_decryption: bool,
    pub max_decryption_work: usize,
    pub clock_skew: ClockSkew,
    pub now: Option<SystemTime>,
    pub expected_audience: Option<&'a str>,
    pub expected_in_response_to: Option<&'a str>,
}

impl<'a> FlowOptions<'a> {
    pub(crate) fn new(binding: Binding, parser_type: ParserType) -> Self {
        Self {
            binding,
            parser_type,
            defer_logout_request_version: false,
            redirect_inflate_max_bytes: MAX_DEFLATE_RAW_DECODE_BYTES,
            xml_limits: XmlLimits::default(),
            schema_validator: None,
            signature_check: SignatureCheck::Skip,
            require_audience_restriction: true,
            xml_signatures: XmlSignatureProfile::AllowWeakAlgorithms,
            from_issuer: None,
            signing_certs: &[],
            hmac_secret: None,
            decrypt_key: None,
            decrypt_key_pass: None,
            additional_decrypt_keys: &[],
            assertion_elements: AssertionElementEncryption::default(),
            require_encrypted_assertions: false,
            allow_rsa15_key_transport_decryption: false,
            max_decryption_work: crate::constants::DEFAULT_MAX_DECRYPTION_WORK,
            clock_skew: ClockSkew::strict(),
            now: None,
            expected_audience: None,
            expected_in_response_to: None,
        }
    }

    pub(crate) fn for_peer(
        binding: Binding,
        parser_type: ParserType,
        setting: &EntitySetting,
        peer: &'a Metadata,
        hmac_secret: Option<&'a HmacSecret>,
        now: SystemTime,
        clock_skew: ClockSkew,
    ) -> Self {
        Self {
            redirect_inflate_max_bytes: setting.redirect_inflate_max_bytes,
            xml_limits: setting.xml_limits,
            schema_validator: setting.schema_validator,
            xml_signatures: setting.xml_signatures,
            from_issuer: peer.entity_id(),
            signing_certs: peer.x509_certificates(CertUse::Signing),
            hmac_secret,
            clock_skew,
            now: Some(now),
            ..Self::new(binding, parser_type)
        }
    }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignedMessageDestination {
    Required,
    Optional,
}

/// Whether a received request was authenticated.
///
/// [`Received::authentication`](crate::Received::authentication) reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageAuthentication {
    /// A verified signature covers the whole request, or the caller attested
    /// that the SOAP channel authenticated the peer.
    Authenticated,
    /// No verified signature covers the request.
    ///
    /// Anyone can send such a request in the name of the service provider.
    /// Treat its content as advice: decide from your own policy how to
    /// authenticate the user and what to issue.
    Unauthenticated,
}

#[derive(Debug)]
struct PreparedMessage {
    saml_content: String,
    assertion: Option<String>,
    authentication: MessageAuthentication,
    verified_xml_signatures: Vec<VerifiedXmlSignatureEvidence>,
}

impl PreparedMessage {
    fn received(
        xml: String,
        parser_type: ParserType,
        limits: XmlLimits,
    ) -> Result<Self, SamlError> {
        let assertion = if parser_type == ParserType::SamlResponse {
            first_login_assertion_xml(&xml, limits)?
        } else {
            None
        };
        Ok(Self {
            saml_content: xml,
            assertion,
            authentication: MessageAuthentication::Unauthenticated,
            verified_xml_signatures: Vec::new(),
        })
    }
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

#[derive(Debug, Clone)]
pub struct FlowResult {
    pub saml_content: String,
    pub extract: Value,
    pub sig_alg: Option<String>,
}

#[derive(Debug)]
pub(crate) struct FlowResultWithSignatureEvidence {
    flow_result: FlowResult,
    verified_xml_signatures: Vec<VerifiedXmlSignatureEvidence>,
    authentication: MessageAuthentication,
}

impl FlowResultWithSignatureEvidence {
    pub(crate) fn into_parts(self) -> (FlowResult, Vec<VerifiedXmlSignatureEvidence>) {
        (self.flow_result, self.verified_xml_signatures)
    }

    pub(crate) fn authentication(&self) -> MessageAuthentication {
        self.authentication
    }

    pub(crate) fn into_flow_result(self) -> FlowResult {
        self.flow_result
    }
}

fn default_fields(
    parser_type: ParserType,
    assertion: Option<&str>,
) -> Result<Vec<ExtractorField>, SamlError> {
    Ok(match parser_type {
        ParserType::SamlRequest => fields::login_request_fields(),
        ParserType::SamlResponse => {
            let assertion = assertion.ok_or(SamlError::AssertionMissing)?;
            fields::login_response_fields(assertion)
        }
        ParserType::LogoutRequest => fields::logout_request_fields(),
        ParserType::LogoutResponse => fields::logout_response_fields(),
        ParserType::ManageNameIdRequest => fields::manage_name_id_request_fields(),
        ParserType::ManageNameIdResponse => fields::manage_name_id_response_fields(),
    })
}

pub(crate) struct ReceivedMessage<'a> {
    request: &'a HttpRequest,
    binding: Binding,
    xml: String,
}

impl<'a> ReceivedMessage<'a> {
    pub(crate) fn decode(
        binding: Binding,
        parser_type: ParserType,
        request: &'a HttpRequest,
        redirect_inflate_max_bytes: usize,
        xml_limits: XmlLimits,
    ) -> Result<Self, SamlError> {
        let direction = parser_type.query_param();
        let bytes = match binding {
            Binding::Redirect => {
                let content = request
                    .query_get(direction)?
                    .ok_or_else(|| missing_binding_parameter(direction))?;
                let redirect_max_bytes = redirect_inflate_max_bytes.min(xml_limits.max_bytes);
                let compressed = decode_base64_with_limit(content, redirect_max_bytes)?;
                deflate_raw_decode(&compressed, redirect_max_bytes)?
            }
            Binding::Post | Binding::SimpleSign => {
                let content = request
                    .body_get(direction)?
                    .ok_or_else(|| missing_binding_parameter(direction))?;
                decode_base64_with_limit(content, xml_limits.max_bytes)?
            }
            Binding::Artifact | Binding::Soap => return Err(unsupported_binding(binding)),
        };
        xml_limits.check_input_bytes(bytes.len())?;
        let xml = crate::xml::decode_utf8(bytes)?;
        Ok(Self {
            request,
            binding,
            xml,
        })
    }

    pub(crate) fn binding(&self) -> Binding {
        self.binding
    }

    pub(crate) fn xml(&self) -> &str {
        &self.xml
    }
}

#[cfg(not(crypto))]
fn verify_present_signatures(
    _xml: &str,
    _opts: &FlowOptions<'_>,
) -> Result<Vec<VerifiedXmlSignatureEvidence>, SamlError> {
    Err(SamlError::Unsupported(
        "signature verification requires a crypto provider feature".into(),
    ))
}

#[cfg(not(crypto))]
fn prepare_after_detached_signature(
    _xml: String,
    _root: &crate::xml::dom::Node,
    _parser_type: ParserType,
    _opts: &FlowOptions<'_>,
    _assertion_signature: AssertionSignatureRequirement,
) -> Result<PreparedMessage, SamlError> {
    Err(SamlError::Unsupported(
        "signature verification requires a crypto provider feature".into(),
    ))
}

#[cfg(not(crypto))]
fn verify_and_prepare(
    _xml: String,
    _root: &crate::xml::dom::Node,
    _parser_type: ParserType,
    _opts: &FlowOptions<'_>,
    _assertion_signature: AssertionSignatureRequirement,
    _response_signature: ResponseSignatureRequirement,
) -> Result<PreparedMessage, SamlError> {
    Err(SamlError::Unsupported(
        "signature verification requires a crypto provider feature".into(),
    ))
}

#[cfg(not(crypto))]
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
    authentication: MessageAuthentication,
    signed_destination: SignedMessageDestination,
) -> Result<(), SamlError> {
    let destination = match parser_type {
        ParserType::SamlResponse
        | ParserType::LogoutResponse
        | ParserType::ManageNameIdResponse => extracted.get_str(fields::response::DESTINATION),
        ParserType::LogoutRequest | ParserType::ManageNameIdRequest => {
            extracted.get_str(fields::request::DESTINATION)
        }
        ParserType::SamlRequest => return Ok(()),
    };
    validate_destination(
        destination,
        expected_recipient,
        authentication,
        signed_destination,
    )
}

fn validate_destination(
    destination: Option<&str>,
    expected_recipient: Option<&str>,
    authentication: MessageAuthentication,
    signed_destination: SignedMessageDestination,
) -> Result<(), SamlError> {
    let Some(expected) = expected_recipient else {
        return Ok(());
    };
    // SAML Bindings 2.0 §§3.4.5.2 and 3.5.5.2, and SimpleSign §2.4,
    // require Destination on a signed message received through these bindings.
    if authentication == MessageAuthentication::Authenticated
        && signed_destination == SignedMessageDestination::Required
        && destination.is_none()
    {
        return Err(SamlError::destination_mismatch(expected, None));
    }
    // SAML Core 2.0 §§3.2.1 and 3.2.2 require the actual recipient to discard
    // any protocol message whose present Destination does not match itself.
    if destination.is_some_and(|destination| collapse_whitespace(destination) != expected) {
        return Err(SamlError::destination_mismatch(expected, destination));
    }
    Ok(())
}

pub(crate) fn correlated_status_message(
    xml: &str,
    limits: XmlLimits,
    expected_in_response_to: Option<&str>,
    expected_recipient: Option<&str>,
    signed_destination: SignedMessageDestination,
) -> Option<StatusMessage> {
    let response = parse_saml_with_limits(xml, limits).ok()?;
    if response
        .attr("InResponseTo")
        .map(collapse_whitespace)
        .as_deref()
        != expected_in_response_to
    {
        return None;
    }
    validate_destination(
        response.attr("Destination"),
        expected_recipient,
        MessageAuthentication::Authenticated,
        signed_destination,
    )
    .ok()?;
    read_status_message(response)
}

fn validate_context(
    parser_type: ParserType,
    saml_content: &str,
    extracted: &Value,
    opts: &FlowOptions<'_>,
    expected_recipient: Option<&str>,
    authentication: MessageAuthentication,
    signed_destination: SignedMessageDestination,
) -> Result<(), SamlError> {
    if let Some(expected) = opts.from_issuer {
        let issuer = match parser_type {
            ParserType::SamlResponse => fields::login_response::ASSERTION_ISSUER,
            ParserType::SamlRequest
            | ParserType::LogoutRequest
            | ParserType::LogoutResponse
            | ParserType::ManageNameIdRequest
            | ParserType::ManageNameIdResponse => fields::ISSUER,
        };
        let actual = extracted.get_str(issuer);
        if actual != Some(expected) {
            if parser_type == ParserType::SamlResponse
                && actual.is_none()
                && first_login_assertion_xml(saml_content, opts.xml_limits)?.is_none()
            {
                return Err(SamlError::AssertionMissing);
            }
            return Err(SamlError::issuer_mismatch(expected, actual));
        }
        if parser_type == ParserType::SamlResponse {
            response_issuer::validate_response_issuer(expected, saml_content, opts.xml_limits)?;
        }
    }
    let is_response = matches!(
        parser_type,
        ParserType::SamlResponse | ParserType::LogoutResponse | ParserType::ManageNameIdResponse
    );
    if is_response {
        validate_in_response_to(
            extracted.get_str(fields::response::IN_RESPONSE_TO),
            opts.expected_in_response_to,
        )?;
    }
    validate_message_destination(
        parser_type,
        extracted,
        expected_recipient,
        authentication,
        signed_destination,
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
            opts.clock_skew.not_on_or_after_millis(),
        )?;
    }
    match parser_type {
        ParserType::ManageNameIdResponse => {
            check_status(saml_content, parser_type, opts.xml_limits)
        }
        ParserType::SamlResponse
        | ParserType::SamlRequest
        | ParserType::LogoutResponse
        | ParserType::LogoutRequest
        | ParserType::ManageNameIdRequest => Ok(()),
    }
}

fn validate_in_response_to(actual: Option<&str>, expected: Option<&str>) -> Result<(), SamlError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if actual.map(collapse_whitespace).as_deref() != Some(expected) {
        return Err(SamlError::in_response_to_mismatch(Some(expected), actual));
    }
    Ok(())
}

fn signature_is_present(
    binding: Binding,
    request: &HttpRequest,
    root: &crate::xml::dom::Node,
) -> bool {
    let detached = match binding {
        Binding::Redirect => request.query.iter().any(|(name, _)| name == "Signature"),
        Binding::SimpleSign => request.body.iter().any(|(name, _)| name == "Signature"),
        Binding::Post | Binding::Artifact | Binding::Soap => false,
    };
    detached || !saml_signature_candidates(root).is_empty()
}

fn decrypt_assertion_elements(
    prepared: PreparedMessage,
    parser_type: ParserType,
    signature_verified: bool,
    opts: &FlowOptions<'_>,
) -> Result<PreparedMessage, SamlError> {
    let decrypt = parser_type == ParserType::SamlResponse
        && (opts.assertion_elements.is_selected()
            || (signature_verified
                && opts.decrypt_key.is_some()
                && crate::encrypted_elements::carries_encrypted_elements(&prepared.saml_content)?));
    if !decrypt {
        return Ok(prepared);
    }
    if !signature_verified {
        return Err(SamlError::SignatureMissing);
    }
    let key_pem = opts
        .decrypt_key
        .ok_or_else(|| SamlError::MissingKey("decryption_key".into()))?;
    crate::encrypted_elements::require_one_assertion_unless_message_authenticated(
        &prepared.saml_content,
        prepared.authentication,
        opts.xml_limits,
    )?;
    let (saml_content, assertion) = crate::encrypted_elements::decrypt_verified_assertion_elements(
        &prepared.saml_content,
        prepared.assertion.as_deref(),
        key_pem,
        opts,
    )?;
    Ok(PreparedMessage {
        saml_content,
        assertion,
        ..prepared
    })
}

fn flow_inner(
    opts: &FlowOptions<'_>,
    request: &HttpRequest,
    expected_recipient: Option<&str>,
    assertion_signature: AssertionSignatureRequirement,
    response_signature: ResponseSignatureRequirement,
    signed_destination: SignedMessageDestination,
) -> Result<FlowResultWithSignatureEvidence, SamlError> {
    let received = ReceivedMessage::decode(
        opts.binding,
        opts.parser_type,
        request,
        opts.redirect_inflate_max_bytes,
        opts.xml_limits,
    )?;
    validate_received_message(
        opts,
        received,
        expected_recipient,
        assertion_signature,
        response_signature,
        signed_destination,
    )
}

pub(crate) fn validate_received_message(
    opts: &FlowOptions<'_>,
    received: ReceivedMessage<'_>,
    expected_recipient: Option<&str>,
    assertion_signature: AssertionSignatureRequirement,
    response_signature: ResponseSignatureRequirement,
    signed_destination: SignedMessageDestination,
) -> Result<FlowResultWithSignatureEvidence, SamlError> {
    let ReceivedMessage {
        request,
        binding,
        xml,
    } = received;
    let parser_type = opts.parser_type;
    let document = crate::schema::document(&xml, opts.xml_limits, opts.schema_validator)?;
    validate_protocol_profile(&xml, parser_type, opts.xml_limits)?;
    if parser_type == ParserType::LogoutRequest
        && !opts.defer_logout_request_version
        && document.root.attr("Version") != Some("2.0")
    {
        return Err(SamlError::ProtocolProfile(
            "LogoutRequest Version must be 2.0".into(),
        ));
    }
    if parser_type == ParserType::SamlResponse {
        if let Err(status) = check_status(&xml, parser_type, opts.xml_limits) {
            let status_message = error_response::validate_error_response(
                opts,
                request,
                binding,
                &xml,
                &document.root,
                expected_recipient,
                signed_destination,
            )?;
            return Err(status.with_status_message(status_message));
        }
    }

    let verify_signature = match opts.signature_check {
        SignatureCheck::Skip => false,
        SignatureCheck::VerifyIfPresent => signature_is_present(binding, request, &document.root),
        SignatureCheck::Require => true,
    };
    let (prepared, sig_alg) = match (verify_signature, binding) {
        (false, _) => (
            PreparedMessage::received(xml, parser_type, opts.xml_limits)?,
            None,
        ),
        (true, Binding::Redirect | Binding::SimpleSign) => {
            let sig_alg = verify_detached(binding, parser_type, request, opts, &xml)?;
            let prepared = prepare_after_detached_signature(
                xml,
                &document.root,
                parser_type,
                opts,
                assertion_signature,
            )?;
            (
                PreparedMessage {
                    authentication: MessageAuthentication::Authenticated,
                    ..prepared
                },
                Some(sig_alg),
            )
        }
        (true, Binding::Post | Binding::Artifact | Binding::Soap) => (
            verify_and_prepare(
                xml,
                &document.root,
                parser_type,
                opts,
                assertion_signature,
                response_signature,
            )?,
            None,
        ),
    };
    if opts.require_encrypted_assertions && document.root.child_named("Assertion").is_some() {
        return Err(SamlError::EncryptionRequired {
            element: "Assertion",
        });
    }
    drop(document);
    let PreparedMessage {
        saml_content,
        assertion,
        authentication,
        verified_xml_signatures,
    } = decrypt_assertion_elements(prepared, parser_type, verify_signature, opts)?;

    let fields = default_fields(parser_type, assertion.as_deref())?;
    let extracted = extract_with_limits(&saml_content, &fields, opts.xml_limits)?;
    validate_context(
        parser_type,
        &saml_content,
        &extracted,
        opts,
        expected_recipient,
        authentication,
        signed_destination,
    )?;

    Ok(FlowResultWithSignatureEvidence {
        flow_result: FlowResult {
            saml_content,
            extract: extracted,
            sig_alg,
        },
        verified_xml_signatures,
        authentication,
    })
}

pub(crate) fn flow_with_authentication(
    opts: &FlowOptions<'_>,
    request: &HttpRequest,
) -> Result<FlowResultWithSignatureEvidence, SamlError> {
    flow_inner(
        opts,
        request,
        None,
        AssertionSignatureRequirement::Compatible,
        ResponseSignatureRequirement::Optional,
        SignedMessageDestination::Required,
    )
}

pub(crate) fn flow_with_expected_recipient_and_signature_evidence(
    opts: &FlowOptions<'_>,
    request: &HttpRequest,
    expected_recipient: &str,
    assertion_signature: AssertionSignatureRequirement,
    response_signature: ResponseSignatureRequirement,
    signed_destination: SignedMessageDestination,
) -> Result<FlowResultWithSignatureEvidence, SamlError> {
    flow_inner(
        opts,
        request,
        Some(expected_recipient),
        assertion_signature,
        response_signature,
        signed_destination,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correlated_status_message_reads_unqualified_response_attributes() {
        let destination = "https://sp.example.com/acs";
        let message = "MFA provider unavailable";
        for (in_response_to_attr, destination_attr, expected) in [
            ("InResponseTo", "Destination", Some(message)),
            ("other:InResponseTo", "Destination", None),
            ("InResponseTo", "other:Destination", None),
        ] {
            let xml = format!(
                r#"<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:other="urn:example:other"
                    {in_response_to_attr}="_login" {destination_attr}="{destination}">
                    <Status><StatusMessage>{message}</StatusMessage></Status>
                </Response>"#
            );
            let diagnostic = correlated_status_message(
                &xml,
                XmlLimits::default(),
                Some("_login"),
                Some(destination),
                SignedMessageDestination::Required,
            );
            assert_eq!(
                diagnostic.as_ref().map(StatusMessage::as_str),
                expected,
                "{in_response_to_attr}, {destination_attr}",
            );
        }
    }
}
