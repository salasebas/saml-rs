//! Inbound browser message conversion helpers.
//!
//! References: SAML Bindings 2.0 <https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf> and HTTP POST-SimpleSign <https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-binding-simplesign.html>.

use core::marker::PhantomData;

use super::artifact::DeliveredArtifact;
use super::forms::FormField;
use crate::artifact::ResolvedProtocolMessage;
use crate::binding::{base64_decode_with_limit, build_simplesign_octet};
use crate::constants::url_params;
use crate::error::SamlError;
use crate::model::{AuthnRequest, LogoutRequest, LogoutResponse, SsoResponse};
use crate::raw::HttpRequest;
use crate::xml::XmlLimits;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageField {
    Request,
    Response,
}

impl MessageField {
    fn param_name(self) -> &'static str {
        match self {
            Self::Request => url_params::SAML_REQUEST,
            Self::Response => url_params::SAML_RESPONSE,
        }
    }

    fn opposite_param_name(self) -> &'static str {
        match self {
            Self::Request => url_params::SAML_RESPONSE,
            Self::Response => url_params::SAML_REQUEST,
        }
    }
}

/// Typed browser input for inbound SAML messages.
///
/// # Examples
///
/// ```
/// use saml_rs::{AuthnRequest, BrowserInput, FormField, SsoResponse};
///
/// let redirect = BrowserInput::<AuthnRequest>::redirect("SAMLRequest=...");
/// let post = BrowserInput::<SsoResponse>::post(vec![
///     FormField::new("SAMLResponse", "..."),
/// ]);
///
/// # let _ = (redirect, post);
/// ```
///
/// SSO responses are received through POST-family bindings or as a resolved
/// artifact, not Redirect:
///
/// ```compile_fail
/// use saml_rs::{BrowserInput, SsoResponse};
///
/// let _ = BrowserInput::<SsoResponse>::redirect("SAMLResponse=...");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserInput<Message> {
    /// HTTP-Redirect input as a raw query string.
    Redirect {
        /// Raw URL query, with or without a leading `?`.
        raw_query: String,
        /// Message marker.
        _message: PhantomData<Message>,
    },
    /// HTTP-POST input as parsed form fields.
    Post {
        /// Parsed form fields.
        fields: Vec<FormField>,
        /// Message marker.
        _message: PhantomData<Message>,
    },
    /// HTTP-POST-SimpleSign input.
    SimpleSignPost {
        /// Raw form body.
        raw_body: String,
        /// Parsed form fields.
        fields: Vec<FormField>,
        /// Message marker.
        _message: PhantomData<Message>,
    },
    /// HTTP-Artifact input, after the artifact was resolved.
    Artifact {
        /// Artifact and RelayState the browser delivered.
        delivered: DeliveredArtifact,
        /// Message the artifact issuer returned for that artifact.
        resolved: ResolvedProtocolMessage,
        /// Message marker.
        _message: PhantomData<Message>,
    },
}

impl BrowserInput<AuthnRequest> {
    /// Create Redirect input from a raw query string.
    pub fn redirect(raw_query: impl Into<String>) -> Self {
        redirect_input(raw_query)
    }

    /// Create POST input from parsed fields.
    pub fn post(fields: Vec<FormField>) -> Self {
        post_input(fields)
    }

    /// Create SimpleSign input from parsed fields.
    pub fn simple_sign(fields: Vec<FormField>) -> Self {
        simple_sign_input(fields)
    }

    /// Parse a raw `application/x-www-form-urlencoded` SimpleSign body.
    pub fn simple_sign_body(raw_body: impl Into<String>) -> Self {
        simple_sign_body_input(raw_body)
    }
}

impl BrowserInput<SsoResponse> {
    /// Create POST input from parsed fields.
    pub fn post(fields: Vec<FormField>) -> Self {
        post_input(fields)
    }

    /// Create HTTP-Artifact input from the delivered artifact and the
    /// message it resolved to.
    ///
    /// `resolved` comes from
    /// [`ArtifactResolution::finish`](crate::ArtifactResolution::finish) on a
    /// [`ArtifactDereference::web_browser_sso`](crate::ArtifactDereference::web_browser_sso)
    /// resolution of [`DeliveredArtifact::artifact`].
    pub fn artifact(delivered: DeliveredArtifact, resolved: ResolvedProtocolMessage) -> Self {
        Self::Artifact {
            delivered,
            resolved,
            _message: PhantomData,
        }
    }

    /// Create SimpleSign input from parsed fields.
    pub fn simple_sign(fields: Vec<FormField>) -> Self {
        simple_sign_input(fields)
    }

    /// Parse a raw `application/x-www-form-urlencoded` SimpleSign body.
    pub fn simple_sign_body(raw_body: impl Into<String>) -> Self {
        simple_sign_body_input(raw_body)
    }
}

impl BrowserInput<LogoutRequest> {
    /// Create Redirect input from a raw query string.
    pub fn redirect(raw_query: impl Into<String>) -> Self {
        redirect_input(raw_query)
    }

    /// Create POST input from parsed fields.
    pub fn post(fields: Vec<FormField>) -> Self {
        post_input(fields)
    }

    /// Create SimpleSign input from parsed fields.
    pub fn simple_sign(fields: Vec<FormField>) -> Self {
        simple_sign_input(fields)
    }

    /// Parse a raw `application/x-www-form-urlencoded` SimpleSign body.
    pub fn simple_sign_body(raw_body: impl Into<String>) -> Self {
        simple_sign_body_input(raw_body)
    }
}

impl BrowserInput<LogoutResponse> {
    /// Create Redirect input from a raw query string.
    pub fn redirect(raw_query: impl Into<String>) -> Self {
        redirect_input(raw_query)
    }

    /// Create POST input from parsed fields.
    pub fn post(fields: Vec<FormField>) -> Self {
        post_input(fields)
    }

    /// Create SimpleSign input from parsed fields.
    pub fn simple_sign(fields: Vec<FormField>) -> Self {
        simple_sign_input(fields)
    }

    /// Parse a raw `application/x-www-form-urlencoded` SimpleSign body.
    pub fn simple_sign_body(raw_body: impl Into<String>) -> Self {
        simple_sign_body_input(raw_body)
    }
}

impl TryFrom<BrowserInput<AuthnRequest>> for HttpRequest {
    type Error = SamlError;

    fn try_from(value: BrowserInput<AuthnRequest>) -> Result<Self, Self::Error> {
        http_request_from_input(value, true, MessageField::Request)
    }
}

impl TryFrom<BrowserInput<SsoResponse>> for HttpRequest {
    type Error = SamlError;

    fn try_from(value: BrowserInput<SsoResponse>) -> Result<Self, Self::Error> {
        http_request_from_input(value, false, MessageField::Response)
    }
}

impl TryFrom<BrowserInput<LogoutRequest>> for HttpRequest {
    type Error = SamlError;

    fn try_from(value: BrowserInput<LogoutRequest>) -> Result<Self, Self::Error> {
        http_request_from_input(value, true, MessageField::Request)
    }
}

impl TryFrom<BrowserInput<LogoutResponse>> for HttpRequest {
    type Error = SamlError;

    fn try_from(value: BrowserInput<LogoutResponse>) -> Result<Self, Self::Error> {
        http_request_from_input(value, true, MessageField::Response)
    }
}

fn redirect_input<Message>(raw_query: impl Into<String>) -> BrowserInput<Message> {
    BrowserInput::Redirect {
        raw_query: raw_query.into(),
        _message: PhantomData,
    }
}

fn post_input<Message>(fields: Vec<FormField>) -> BrowserInput<Message> {
    BrowserInput::Post {
        fields,
        _message: PhantomData,
    }
}

fn simple_sign_input<Message>(fields: Vec<FormField>) -> BrowserInput<Message> {
    BrowserInput::SimpleSignPost {
        raw_body: String::new(),
        fields,
        _message: PhantomData,
    }
}

fn simple_sign_body_input<Message>(raw_body: impl Into<String>) -> BrowserInput<Message> {
    let raw_body = raw_body.into();
    let fields = parse_form_fields(&raw_body);
    BrowserInput::SimpleSignPost {
        raw_body,
        fields,
        _message: PhantomData,
    }
}

fn http_request_from_input<Message>(
    value: BrowserInput<Message>,
    allow_redirect: bool,
    expected_message: MessageField,
) -> Result<HttpRequest, SamlError> {
    match value {
        BrowserInput::Redirect { raw_query, .. } => {
            if !allow_redirect {
                return Err(SamlError::UndefinedBinding);
            }
            let raw_query = raw_query.trim_start_matches('?').to_string();
            let octet_string = redirect_octet_from_raw_query(&raw_query, expected_message)?;
            let query = parse_form_pairs(&raw_query);
            Ok(HttpRequest {
                query,
                octet_string,
                ..Default::default()
            })
        }
        BrowserInput::Post { fields, .. } => {
            validate_form_message_kind(&fields, expected_message)?;
            Ok(HttpRequest::post(fields_to_pairs(fields)))
        }
        BrowserInput::SimpleSignPost {
            raw_body,
            mut fields,
            ..
        } => {
            if fields.is_empty() {
                fields = parse_form_fields(&raw_body);
            }
            let octet_string = simplesign_octet_from_fields(&fields, expected_message)?;
            let mut request = HttpRequest::post(fields_to_pairs(fields));
            request.octet_string = Some(octet_string);
            Ok(request)
        }
        BrowserInput::Artifact { .. } => Err(SamlError::UndefinedBinding),
    }
}

struct RawQueryParam<'a> {
    name: &'a str,
    encoded_value: &'a str,
}

fn raw_query_params(raw_query: &str) -> impl Iterator<Item = RawQueryParam<'_>> {
    raw_query
        .split('&')
        .filter(|segment| !segment.is_empty())
        .map(|segment| match segment.split_once('=') {
            Some((name, encoded_value)) => RawQueryParam {
                name,
                encoded_value,
            },
            None => RawQueryParam {
                name: segment,
                encoded_value: "",
            },
        })
}

fn unique_encoded_query_value<'a>(
    params: &'a [RawQueryParam<'a>],
    name: &str,
) -> Result<Option<&'a str>, SamlError> {
    let mut values = params
        .iter()
        .filter(|param| param.name == name)
        .map(|param| param.encoded_value);
    let first = values.next();
    if values.next().is_some() {
        return Err(SamlError::Invalid(format!(
            "ambiguous Redirect field {name}"
        )));
    }
    Ok(first)
}

fn validate_query_message_kind<'a>(
    params: &'a [RawQueryParam<'a>],
    expected_message: MessageField,
) -> Result<&'a str, SamlError> {
    let expected_name = expected_message.param_name();
    let opposite_name = expected_message.opposite_param_name();
    let expected = unique_encoded_query_value(params, expected_name)?;
    let opposite = unique_encoded_query_value(params, opposite_name)?;
    match (expected, opposite) {
        (Some(value), None) => Ok(value),
        (None, None) => Err(SamlError::Invalid(format!(
            "missing Redirect field {expected_name}"
        ))),
        (None, Some(_)) | (Some(_), Some(_)) => Err(SamlError::Invalid(format!(
            "expected Redirect field {expected_name}, found {opposite_name}"
        ))),
    }
}

fn redirect_octet_from_raw_query(
    raw_query: &str,
    expected_message: MessageField,
) -> Result<Option<String>, SamlError> {
    let params: Vec<_> = raw_query_params(raw_query).collect();
    let message_name = expected_message.param_name();
    let message_value = validate_query_message_kind(&params, expected_message)?;
    let relay_state = unique_encoded_query_value(&params, url_params::RELAY_STATE)?;
    let sig_alg = unique_encoded_query_value(&params, url_params::SIG_ALG)?;
    let signature = unique_encoded_query_value(&params, url_params::SIGNATURE)?;

    let sig_alg = match (sig_alg, signature) {
        (Some(sig_alg), Some(_)) => sig_alg,
        (None, None) => return Ok(None),
        _ => {
            return Err(SamlError::Invalid(
                "incomplete Redirect signature parameters".into(),
            ))
        }
    };

    Ok(Some(match relay_state {
        Some(relay_state) => {
            format!("{message_name}={message_value}&RelayState={relay_state}&SigAlg={sig_alg}")
        }
        None => format!("{message_name}={message_value}&SigAlg={sig_alg}"),
    }))
}

fn parse_form_pairs(raw: &str) -> Vec<(String, String)> {
    url::form_urlencoded::parse(raw.as_bytes())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

fn parse_form_fields(raw: &str) -> Vec<FormField> {
    parse_form_pairs(raw)
        .into_iter()
        .map(|(name, value)| FormField::new(name, value))
        .collect()
}

fn fields_to_pairs(fields: Vec<FormField>) -> Vec<(String, String)> {
    fields.into_iter().map(FormField::into_pair).collect()
}

fn field_value<'a>(fields: &'a [FormField], name: &str) -> Result<Option<&'a str>, SamlError> {
    let mut values = fields
        .iter()
        .filter(|field| field.name() == name)
        .map(FormField::value);
    let first = values.next();
    if values.next().is_some() {
        return Err(SamlError::Invalid("ambiguous form field".into()));
    }
    Ok(first)
}

fn validate_form_message_kind(
    fields: &[FormField],
    expected_message: MessageField,
) -> Result<&str, SamlError> {
    let expected_name = expected_message.param_name();
    let opposite_name = expected_message.opposite_param_name();
    let expected = field_value(fields, expected_name)?;
    let opposite = field_value(fields, opposite_name)?;
    match (expected, opposite) {
        (Some(value), None) => Ok(value),
        (None, None) => Err(SamlError::Invalid(format!(
            "missing form field {expected_name}"
        ))),
        (None, Some(_)) | (Some(_), Some(_)) => Err(SamlError::Invalid(format!(
            "expected form field {expected_name}, found {opposite_name}"
        ))),
    }
}

fn simplesign_octet_from_fields(
    fields: &[FormField],
    expected_message: MessageField,
) -> Result<String, SamlError> {
    let message_name = expected_message.param_name();
    let encoded = validate_form_message_kind(fields, expected_message)?;
    let raw_xml = String::from_utf8(base64_decode_with_limit(
        encoded,
        XmlLimits::default().max_bytes,
    )?)
    .map_err(|err| SamlError::Xml(err.to_string()))?;
    let sig_alg = field_value(fields, url_params::SIG_ALG)?.ok_or(SamlError::MissingSigAlg)?;
    let relay_state = field_value(fields, url_params::RELAY_STATE)?;
    Ok(build_simplesign_octet(
        message_name,
        &raw_xml,
        relay_state,
        sig_alg,
    ))
}
