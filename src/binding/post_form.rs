//! HTTP-POST binding auto-submit form.

use super::escape::html_escape;
use crate::error::SamlError;
use url::Url;

const UNSAFE_POST_BINDING_ACTION_URL: &str = "POST form action must be an absolute HTTP(S) URL";
const PARTIAL_POST_BINDING_SIGNATURE: &str =
    "POST form needs both SigAlg and Signature, or neither";

struct HiddenField<'a> {
    name: &'a str,
    value: &'a str,
}

fn render_post_form(action: &str, fields: &[HiddenField<'_>]) -> String {
    let action = html_escape(action);
    let fields = fields
        .iter()
        .map(|field| {
            let name = html_escape(field.name);
            let value = html_escape(field.value);
            format!("<input type=\"hidden\" name=\"{name}\" value=\"{value}\"/>")
        })
        .collect::<String>();
    format!(
        "<!DOCTYPE html><html><body onload=\"document.forms[0].submit()\">\
<form method=\"post\" action=\"{action}\">{fields}\
<noscript><input type=\"submit\" value=\"Continue\"/></noscript></form></body></html>"
    )
}

fn binding_fields<'a>(
    param_name: &'a str,
    b64_value: &'a str,
    relay_state: Option<&'a str>,
    sig_alg: Option<&'a str>,
    signature: Option<&'a str>,
) -> Vec<HiddenField<'a>> {
    let mut fields = vec![HiddenField {
        name: param_name,
        value: b64_value,
    }];
    if let Some(state) = relay_state {
        fields.push(HiddenField {
            name: "RelayState",
            value: state,
        });
    }
    if let (Some(sig_alg), Some(signature)) = (sig_alg, signature) {
        fields.push(HiddenField {
            name: "SigAlg",
            value: sig_alg,
        });
        fields.push(HiddenField {
            name: "Signature",
            value: signature,
        });
    }
    fields
}

fn validate_signature_fields(
    sig_alg: Option<&str>,
    signature: Option<&str>,
) -> Result<(), SamlError> {
    match (sig_alg, signature) {
        (Some(_), Some(_)) | (None, None) => Ok(()),
        (Some(_), None) | (None, Some(_)) => {
            Err(SamlError::Invalid(PARTIAL_POST_BINDING_SIGNATURE.into()))
        }
    }
}

pub(crate) fn build_simplesign_octet(
    param_name: &str,
    xml: &str,
    relay_state: Option<&str>,
    sig_alg: &str,
) -> String {
    match relay_state {
        Some(relay_state) => {
            format!("{param_name}={xml}&RelayState={relay_state}&SigAlg={sig_alg}")
        }
        None => format!("{param_name}={xml}&SigAlg={sig_alg}"),
    }
}

/// Build a self-submitting HTML form for the SAML HTTP-POST binding.
///
/// `param_name` is `SAMLRequest` or `SAMLResponse`; `b64_value` is the
/// base64-encoded message. An optional `relay_state` is added as a hidden
/// field. All values are HTML-escaped. The form `action` must be an absolute
/// `http` or `https` URL.
///
/// # Errors
///
/// Returns [`SamlError::Invalid`] when `action` is not an absolute HTTP(S)
/// URL.
#[cfg(test)]
pub(crate) fn saml_post_binding_form(
    action: &str,
    param_name: &str,
    b64_value: &str,
    relay_state: Option<&str>,
) -> Result<String, SamlError> {
    saml_post_binding_form_with_signature(action, param_name, b64_value, relay_state, None, None)
}

pub(crate) fn saml_post_binding_form_with_signature(
    action: &str,
    param_name: &str,
    b64_value: &str,
    relay_state: Option<&str>,
    sig_alg: Option<&str>,
    signature: Option<&str>,
) -> Result<String, SamlError> {
    validate_post_form_action(action)?;
    validate_signature_fields(sig_alg, signature)?;
    let fields = binding_fields(param_name, b64_value, relay_state, sig_alg, signature);
    Ok(render_post_form(action, &fields))
}

fn validate_post_form_action(action: &str) -> Result<(), SamlError> {
    let url = Url::parse(action)
        .map_err(|_| SamlError::Invalid(UNSAFE_POST_BINDING_ACTION_URL.into()))?;
    if matches!(url.scheme(), "http" | "https") && url.has_host() {
        Ok(())
    } else {
        Err(SamlError::Invalid(UNSAFE_POST_BINDING_ACTION_URL.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::build_simplesign_octet;

    #[test]
    fn simplesign_octet_omits_absent_relay_state() {
        assert_eq!(
            build_simplesign_octet("SAMLRequest", "<xml/>", None, "alg"),
            "SAMLRequest=<xml/>&SigAlg=alg"
        );
    }

    #[test]
    fn simplesign_octet_preserves_explicit_empty_relay_state() {
        assert_eq!(
            build_simplesign_octet("SAMLRequest", "<xml/>", Some(""), "alg"),
            "SAMLRequest=<xml/>&RelayState=&SigAlg=alg"
        );
    }

    #[test]
    fn simplesign_octet_includes_present_relay_state() {
        assert_eq!(
            build_simplesign_octet("SAMLResponse", "<xml/>", Some("state"), "alg"),
            "SAMLResponse=<xml/>&RelayState=state&SigAlg=alg"
        );
    }
}
