use super::{missing_binding_parameter, single_param, FlowOptions, HttpRequest};
use crate::constants::{Binding, ParserType};
use crate::error::{SamlError, SignatureVerificationReason};
use crate::model::RelayStateParam;

fn decoded_octet_params(octet: &str) -> Vec<(String, String)> {
    url::form_urlencoded::parse(octet.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

fn detached_signature_verification() -> SamlError {
    SamlError::SignatureVerification {
        reason: SignatureVerificationReason::DetachedMessageSignature,
    }
}

fn relay_state_param(value: Option<&str>) -> Option<RelayStateParam> {
    RelayStateParam::try_from_option(value.map(str::to_string)).ok()
}

fn detached_relay_state_mismatch(expected: Option<&str>, actual: Option<&str>) -> SamlError {
    match (relay_state_param(expected), relay_state_param(actual)) {
        (Some(expected), Some(actual)) => SamlError::RelayStateMismatch { expected, actual },
        _ => SamlError::SignatureVerification {
            reason: SignatureVerificationReason::RelayStateCorrelation,
        },
    }
}

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
        Binding::Post | Binding::Artifact | Binding::Soap => Ok(()),
    }
}

/// Verify a detached (redirect/SimpleSign) message signature, returning the
/// verified `SigAlg`. Requires a crypto provider.
pub(super) fn verify_detached(
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
    if !crate::crypto::signature_profile::allows_signature_method(opts.xml_signatures, sig_alg) {
        return Err(SamlError::AlgorithmUnsupported);
    }
    crate::crypto::initialize_crypto_provider()?;

    if let Some(secret) = opts
        .hmac_secret
        .filter(|_| bergshamra::crypto::sign::is_hmac_algorithm(sig_alg))
    {
        if crate::crypto::sign::verify_hmac_message_signature(octet, signature, secret, sig_alg)? {
            return Ok(sig_alg.to_string());
        }
        return Err(detached_signature_verification());
    }

    let mut provider_error = None;
    let mut tried_invalid = false;
    for cert in opts.signing_certs {
        match crate::crypto::sign::verify_message_signature_under_profile(
            octet,
            signature,
            cert,
            sig_alg,
            opts.xml_signatures,
        ) {
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
