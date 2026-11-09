use crate::constants::{Binding, CertUse, ParserType};
use crate::entity::EntitySetting;
use crate::error::SamlError;
use crate::flow::{
    flow, flow_with_expected_recipient_and_signature_evidence, AssertionSignatureRequirement,
    FlowOptions, FlowResult, HttpRequest, ResponseSignatureRequirement, SignedMessageDestination,
};
use crate::metadata::Metadata;
use std::time::SystemTime;

#[derive(Debug, Clone, Copy)]
pub(crate) struct LogoutFlowValidation<'a> {
    expected_recipient: Option<&'a str>,
    now: Option<SystemTime>,
    clock_drifts: (i64, i64),
}

impl<'a> LogoutFlowValidation<'a> {
    pub(crate) fn typed(
        expected_recipient: &'a str,
        now: SystemTime,
        clock_drifts: (i64, i64),
    ) -> Self {
        Self {
            expected_recipient: Some(expected_recipient),
            now: Some(now),
            clock_drifts,
        }
    }

    fn raw(clock_drifts: (i64, i64)) -> Self {
        Self {
            expected_recipient: None,
            now: None,
            clock_drifts,
        }
    }
}

/// Parse a `<LogoutRequest>` from `from`.
///
/// `IssueInstant` is required and must use the SAML UTC `xs:dateTime` lexical
/// form. No maximum request age is inferred from `IssueInstant`. An optional
/// `NotOnOrAfter` uses the same UTC form; saml-rs rejects the request at or
/// after that instant, widened by the configured `NotOnOrAfter` clock drift.
/// This fail-closed expiration check is library policy: SAML permits, but does
/// not require, a recipient to discard an expired request.
///
/// # Errors
///
/// Returns an error if `binding` is unsupported, required binding parameters
/// are missing, the SAML payload cannot be base64/DEFLATE decoded, XML parsing
/// or extraction fails, `IssueInstant` or `NotOnOrAfter` is not conformant,
/// `NotOnOrAfter` has expired, the peer issuer does not match `from_meta`, or
/// logout request signature validation fails when `self_setting` requires
/// signed requests. Signature failures include missing signatures, untrusted
/// signing certificates, invalid detached signatures, RelayState/signed-octet
/// correlation failures, and XML signature validation errors.
///
/// This raw compatibility parser has no actual receiving endpoint and
/// therefore does not compare `Destination`. Callers that operate an endpoint
/// directly own that check. Prefer [`crate::Saml`] for a binding-aware typed
/// SLO receiver.
pub fn parse_logout_request(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    binding: Binding,
    request: &HttpRequest,
) -> Result<FlowResult, SamlError> {
    parse_logout_request_inner(
        self_setting,
        from_meta,
        binding,
        request,
        LogoutFlowValidation::raw(self_setting.clock_drifts),
    )
}

pub(crate) fn parse_logout_request_at(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    binding: Binding,
    request: &HttpRequest,
    validation: LogoutFlowValidation<'_>,
) -> Result<FlowResult, SamlError> {
    parse_logout_request_inner(self_setting, from_meta, binding, request, validation)
}

fn parse_logout_request_inner(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    binding: Binding,
    request: &HttpRequest,
    validation: LogoutFlowValidation<'_>,
) -> Result<FlowResult, SamlError> {
    let signing_certs = from_meta.x509_certificates(CertUse::Signing);
    run_logout_flow(
        &FlowOptions {
            binding: Some(binding),
            parser_type: Some(ParserType::LogoutRequest),
            check_signature: self_setting.want_logout_request_signed,
            verify_signature_if_present: false,
            require_audience_restriction: true,
            strict_xml_signature_profile: self_setting.strict_xml_signature_profile,
            from_issuer: from_meta.get_entity_id(),
            signing_certs: &signing_certs,
            decrypt_key: None,
            decrypt_key_pass: None,
            allow_insecure_software_rsa_key_transport_decryption: false,
            clock_drifts: validation.clock_drifts,
            now: validation.now,
            redirect_inflate_max_bytes: self_setting.redirect_inflate_max_bytes,
            xml_limits: self_setting.xml_limits,
            expected_audience: None,
            expected_in_response_to: None,
        },
        request,
        validation.expected_recipient,
    )
}

fn parse_logout_response_inner(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    binding: Binding,
    request: &HttpRequest,
    expected_in_response_to: Option<&str>,
    validation: LogoutFlowValidation<'_>,
) -> Result<FlowResult, SamlError> {
    let signing_certs = from_meta.x509_certificates(CertUse::Signing);
    run_logout_flow(
        &FlowOptions {
            binding: Some(binding),
            parser_type: Some(ParserType::LogoutResponse),
            check_signature: self_setting.want_logout_response_signed,
            verify_signature_if_present: false,
            require_audience_restriction: true,
            strict_xml_signature_profile: self_setting.strict_xml_signature_profile,
            from_issuer: from_meta.get_entity_id(),
            signing_certs: &signing_certs,
            decrypt_key: None,
            decrypt_key_pass: None,
            allow_insecure_software_rsa_key_transport_decryption: false,
            clock_drifts: validation.clock_drifts,
            now: validation.now,
            redirect_inflate_max_bytes: self_setting.redirect_inflate_max_bytes,
            xml_limits: self_setting.xml_limits,
            expected_audience: None,
            expected_in_response_to,
        },
        request,
        validation.expected_recipient,
    )
}

/// Parse a `<LogoutResponse>` from `from` and require it to answer `request_id`.
///
/// Single Logout responses are state-machine messages. The caller must pass the
/// ID of the `LogoutRequest` it issued so stale or unrelated responses cannot be
/// accepted as completion for the current logout transaction.
///
/// An empty caller-provided `request_id` is rejected as
/// [`SamlError::InvalidInResponseTo`]. A non-empty `request_id` that does not
/// match the SAML response returns [`SamlError::InResponseToMismatch`].
///
/// `IssueInstant` validation establishes only that the required attribute is
/// present and uses the SAML UTC lexical form. This parser applies no maximum
/// message age; callers own any additional freshness policy.
///
/// # Errors
///
/// Returns an error if `request_id` is empty, `binding` is unsupported,
/// required binding parameters are missing, the SAML payload cannot be
/// base64/DEFLATE decoded, XML parsing or extraction fails, `IssueInstant` is
/// missing or is not a UTC SAML timestamp, the peer issuer does not match
/// `from_meta`, `InResponseTo` does not match `request_id`, or logout response
/// signature validation fails when `self_setting` requires signed responses.
/// Signature failures include missing signatures, untrusted signing
/// certificates, invalid detached signatures, RelayState/signed-octet
/// correlation failures, and XML signature validation errors.
///
/// This raw compatibility parser has no actual receiving endpoint and
/// therefore does not compare `Destination`. Callers that operate an endpoint
/// directly own that check. Prefer [`crate::Saml`] for a binding-aware typed
/// SLO receiver.
pub fn parse_logout_response(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    binding: Binding,
    request: &HttpRequest,
    request_id: &str,
) -> Result<FlowResult, SamlError> {
    if request_id.is_empty() {
        return Err(SamlError::InvalidInResponseTo);
    }
    parse_logout_response_inner(
        self_setting,
        from_meta,
        binding,
        request,
        Some(request_id),
        LogoutFlowValidation::raw(self_setting.clock_drifts),
    )
}

pub(crate) fn parse_logout_response_at(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    binding: Binding,
    request: &HttpRequest,
    request_id: &str,
    validation: LogoutFlowValidation<'_>,
) -> Result<FlowResult, SamlError> {
    if request_id.is_empty() {
        return Err(SamlError::InvalidInResponseTo);
    }
    parse_logout_response_inner(
        self_setting,
        from_meta,
        binding,
        request,
        Some(request_id),
        validation,
    )
}

/// Parse a `<LogoutResponse>` without binding it to a `LogoutRequest` ID.
///
/// Prefer [`parse_logout_response`] for normal SLO handling. This exists for
/// legacy interop and custom state machines that perform request correlation
/// outside this crate.
///
/// Callers using this raw function own request correlation, replay protection,
/// comparison of `Destination` with the actual receiving endpoint, and any
/// optional message-freshness policy.
///
/// # Errors
///
/// Returns an error if `binding` is unsupported, required binding parameters
/// are missing, the SAML payload cannot be base64/DEFLATE decoded, XML parsing
/// or extraction fails, `IssueInstant` is missing or is not a UTC SAML
/// timestamp, the peer issuer does not match `from_meta`, or logout response
/// signature validation fails when `self_setting` requires signed responses.
/// Signature failures include missing signatures, untrusted signing
/// certificates, invalid detached signatures, RelayState/signed-octet
/// correlation failures, and XML signature validation errors. This function
/// deliberately does not enforce `InResponseTo` correlation.
pub fn parse_logout_response_without_request_id(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    binding: Binding,
    request: &HttpRequest,
) -> Result<FlowResult, SamlError> {
    parse_logout_response_inner(
        self_setting,
        from_meta,
        binding,
        request,
        None,
        LogoutFlowValidation::raw(self_setting.clock_drifts),
    )
}

fn run_logout_flow(
    options: &FlowOptions<'_>,
    request: &HttpRequest,
    expected_recipient: Option<&str>,
) -> Result<FlowResult, SamlError> {
    match expected_recipient {
        Some(expected_recipient) => Ok(flow_with_expected_recipient_and_signature_evidence(
            options,
            request,
            expected_recipient,
            AssertionSignatureRequirement::Compatible,
            ResponseSignatureRequirement::Optional,
            SignedMessageDestination::Required,
        )?
        .into_parts()
        .0),
        None => flow(options, request),
    }
}
