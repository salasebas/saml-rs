//! Inbound SAML messages, in the form their binding delivered them.
//!
//! References: SAML Bindings 2.0 <https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf> and HTTP POST-SimpleSign <https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-binding-simplesign.html>.

use core::marker::PhantomData;

use super::artifact::DeliveredArtifact;
use super::forms::FormField;
use super::MessageField;
use crate::artifact::ResolvedProtocolMessage;
use crate::binding::{
    base64_decode_with_limit, build_simplesign_octet, encode_base64, single_parameter,
};
use crate::constants::{url_params, Binding};
use crate::error::{utf8_err, SamlError};
use crate::flow::HttpRequest;
use crate::model::{AuthnRequest, LogoutRequest, LogoutResponse, SsoResponse};
use crate::name_id_management::{ManageNameIdRequest, ManageNameIdResponse};
use crate::soap::{read_soap_body, SoapChannel};
use crate::xml::XmlLimits;

mod sealed {
    pub trait Sealed {}
}

/// A protocol message saml-rs receives over HTTP-Redirect.
///
/// It bounds [`Inbound::redirect`]. The trait is sealed: saml-rs implements
/// it for the messages it reads from HTTP-Redirect, and other crates cannot.
#[diagnostic::on_unimplemented(
    message = "saml-rs does not receive `{Self}` over HTTP-Redirect",
    label = "no HTTP-Redirect input for `{Self}`"
)]
pub trait RedirectMessage: sealed::Sealed {}

/// A protocol message saml-rs receives over HTTP-POST or HTTP-POST-SimpleSign.
///
/// It bounds [`Inbound::post`] and [`Inbound::simple_sign`]. The trait is
/// sealed: saml-rs implements it for the messages it reads from both POST
/// bindings, and other crates cannot.
#[diagnostic::on_unimplemented(
    message = "saml-rs does not receive `{Self}` over HTTP-POST",
    label = "no HTTP-POST input for `{Self}`"
)]
pub trait PostMessage: sealed::Sealed {}

/// A Single Logout message that [`Inbound::soap`] reads from a SOAP exchange.
///
/// It bounds [`Inbound::soap`]. The trait is sealed: saml-rs implements it for
/// `LogoutRequest` and `LogoutResponse`, and other crates cannot. A PAOS
/// message and a SOAP `ManageNameIDRequest` have their own operations, which
/// take the envelope.
#[diagnostic::on_unimplemented(
    message = "`Inbound::soap` does not read `{Self}`",
    label = "no `Inbound::soap` input for `{Self}`",
    note = "`Inbound::soap` reads SOAP Single Logout messages; PAOS and SOAP name identifier management have their own operations"
)]
pub trait SoapMessage: sealed::Sealed {}

impl sealed::Sealed for AuthnRequest {}
impl sealed::Sealed for SsoResponse {}
impl sealed::Sealed for LogoutRequest {}
impl sealed::Sealed for LogoutResponse {}
impl sealed::Sealed for ManageNameIdRequest {}
impl sealed::Sealed for ManageNameIdResponse {}

impl RedirectMessage for AuthnRequest {}
impl RedirectMessage for LogoutRequest {}
impl RedirectMessage for LogoutResponse {}
impl RedirectMessage for ManageNameIdRequest {}
impl RedirectMessage for ManageNameIdResponse {}

impl PostMessage for AuthnRequest {}
impl PostMessage for SsoResponse {}
impl PostMessage for LogoutRequest {}
impl PostMessage for LogoutResponse {}

impl SoapMessage for LogoutRequest {}
impl SoapMessage for LogoutResponse {}

/// A SAML message the deployment received, in the form its binding delivered
/// it.
///
/// Build it with the constructor for the binding the message arrived on and
/// pass it to the operation that reads `Message`. The operation's parameter
/// fixes `Message`, so the call needs no type annotation. A constructor exists
/// only for the bindings saml-rs receives `Message` over: see
/// [`RedirectMessage`], [`PostMessage`], and [`SoapMessage`]. Only an
/// [`SsoResponse`] arrives as a resolved artifact.
///
/// # Examples
///
/// ```
/// use saml_rs::{
///     FormField, IdpDescriptor, Inbound, PendingAuthnRequest, ReplayPolicy, Saml, SamlError,
///     SamlValidationContext, Sp, SsoSession,
/// };
/// use std::time::SystemTime;
///
/// fn finish(
///     sp: &Saml<Sp>,
///     idp: &IdpDescriptor,
///     pending: &PendingAuthnRequest,
///     fields: Vec<FormField>,
/// ) -> Result<SsoSession, SamlError> {
///     let validation = SamlValidationContext::new(SystemTime::now(), ReplayPolicy::Disabled);
///     sp.finish_sso(idp, pending, Inbound::post(fields), validation)
/// }
/// # let _ = finish;
/// ```
///
/// An SSO response does not arrive over HTTP-Redirect:
///
/// ```compile_fail,E0277
/// use saml_rs::{Inbound, SsoResponse};
///
/// let _: Inbound<SsoResponse> = Inbound::redirect("SAMLResponse=...");
/// ```
#[derive(Debug, Clone)]
pub struct Inbound<Message> {
    pub(crate) transport: Transport,
    _message: PhantomData<Message>,
}

impl<Message> PartialEq for Inbound<Message> {
    fn eq(&self, other: &Self) -> bool {
        self.transport == other.transport
    }
}

impl<Message> Eq for Inbound<Message> {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Transport {
    Redirect {
        raw_query: String,
    },
    Post {
        fields: Vec<FormField>,
    },
    SimpleSign {
        fields: Vec<FormField>,
    },
    Artifact {
        delivered: DeliveredArtifact,
        resolved: ResolvedProtocolMessage,
    },
    Soap {
        envelope: String,
        channel: SoapChannel,
    },
}

impl<Message> Inbound<Message> {
    /// Create HTTP-Redirect input from the raw URL query, with or without a
    /// leading `?`.
    ///
    /// Pass the query as received, still URL-encoded: a Redirect signature
    /// covers the encoded parameters.
    pub fn redirect(raw_query: impl Into<String>) -> Self
    where
        Message: RedirectMessage,
    {
        Self::from_transport(Transport::Redirect {
            raw_query: raw_query.into(),
        })
    }

    /// Create HTTP-POST input from the parsed form fields.
    ///
    /// `Inbound::post` requires a message type that implements [`PostMessage`]:
    ///
    /// ```compile_fail,E0277
    /// use saml_rs::{Inbound, ManageNameIdRequest};
    ///
    /// let _: Inbound<ManageNameIdRequest> = Inbound::post(Vec::new());
    /// ```
    pub fn post(fields: Vec<FormField>) -> Self
    where
        Message: PostMessage,
    {
        Self::from_transport(Transport::Post { fields })
    }

    /// Create HTTP-POST-SimpleSign input from the parsed form fields.
    ///
    /// `Inbound::simple_sign` requires a message type that implements
    /// [`PostMessage`]:
    ///
    /// ```compile_fail,E0277
    /// use saml_rs::{Inbound, ManageNameIdRequest};
    ///
    /// let _: Inbound<ManageNameIdRequest> = Inbound::simple_sign(Vec::new());
    /// ```
    pub fn simple_sign(fields: Vec<FormField>) -> Self
    where
        Message: PostMessage,
    {
        Self::from_transport(Transport::SimpleSign { fields })
    }

    /// Create SOAP input from the envelope of a synchronous exchange.
    ///
    /// `channel` records the protection the deployment established for the
    /// exchange. With [`SoapChannel::unattested`], the message must carry an
    /// XML signature. When `channel` attests mutual authentication and
    /// integrity, an unsigned message is accepted, and a present signature is
    /// still verified. Attest that only when the credential that
    /// authenticated the peer belongs to the peer descriptor of the receiving
    /// operation: the TLS or HTTP client credential for a `LogoutRequest`
    /// passed to `receive_slo`, or the TLS server certificate for a
    /// `LogoutResponse` passed to `finish_slo`.
    ///
    /// `Inbound::soap` requires a message type that implements [`SoapMessage`]:
    ///
    /// ```compile_fail,E0277
    /// use saml_rs::{AuthnRequest, Inbound, SoapChannel};
    ///
    /// let _: Inbound<AuthnRequest> = Inbound::soap("<soap:Envelope/>", SoapChannel::unattested());
    /// ```
    pub fn soap(envelope: impl Into<String>, channel: SoapChannel) -> Self
    where
        Message: SoapMessage,
    {
        Self::from_transport(Transport::Soap {
            envelope: envelope.into(),
            channel,
        })
    }

    /// Binding the message arrived on.
    pub fn binding(&self) -> Binding {
        match self.transport {
            Transport::Redirect { .. } => Binding::Redirect,
            Transport::Post { .. } => Binding::Post,
            Transport::SimpleSign { .. } => Binding::SimpleSign,
            Transport::Artifact { .. } => Binding::Artifact,
            Transport::Soap { .. } => Binding::Soap,
        }
    }

    fn from_transport(transport: Transport) -> Self {
        Self {
            transport,
            _message: PhantomData,
        }
    }
}

impl Inbound<SsoResponse> {
    /// Create HTTP-Artifact input from the delivered artifact and the
    /// message it resolved to.
    ///
    /// `resolved` comes from
    /// [`ArtifactResolution::finish`](crate::ArtifactResolution::finish) on the
    /// resolution of [`DeliveredArtifact::artifact`].
    pub fn artifact(delivered: DeliveredArtifact, resolved: ResolvedProtocolMessage) -> Self {
        Self::from_transport(Transport::Artifact {
            delivered,
            resolved,
        })
    }

    pub(crate) fn into_http_request(self, limits: XmlLimits) -> Result<HttpRequest, SamlError> {
        http_request_from_transport(self.transport, false, MessageField::Response, limits)
    }
}

impl Inbound<AuthnRequest> {
    pub(crate) fn into_http_request(self, limits: XmlLimits) -> Result<HttpRequest, SamlError> {
        http_request_from_transport(self.transport, true, MessageField::Request, limits)
    }
}

impl Inbound<LogoutRequest> {
    pub(crate) fn into_http_request(
        self,
        limits: XmlLimits,
        schema_validator: Option<crate::SchemaValidator>,
    ) -> Result<HttpRequest, SamlError> {
        logout_http_request(
            self.transport,
            MessageField::Request,
            limits,
            schema_validator,
        )
    }
}

impl Inbound<LogoutResponse> {
    pub(crate) fn into_http_request(
        self,
        limits: XmlLimits,
        schema_validator: Option<crate::SchemaValidator>,
    ) -> Result<HttpRequest, SamlError> {
        logout_http_request(
            self.transport,
            MessageField::Response,
            limits,
            schema_validator,
        )
    }
}

impl TryFrom<Inbound<AuthnRequest>> for HttpRequest {
    type Error = SamlError;

    fn try_from(value: Inbound<AuthnRequest>) -> Result<Self, Self::Error> {
        value.into_http_request(XmlLimits::default())
    }
}

impl TryFrom<Inbound<SsoResponse>> for HttpRequest {
    type Error = SamlError;

    fn try_from(value: Inbound<SsoResponse>) -> Result<Self, Self::Error> {
        value.into_http_request(XmlLimits::default())
    }
}

impl TryFrom<Inbound<LogoutRequest>> for HttpRequest {
    type Error = SamlError;

    fn try_from(value: Inbound<LogoutRequest>) -> Result<Self, Self::Error> {
        value.into_http_request(XmlLimits::default(), None)
    }
}

impl TryFrom<Inbound<LogoutResponse>> for HttpRequest {
    type Error = SamlError;

    fn try_from(value: Inbound<LogoutResponse>) -> Result<Self, Self::Error> {
        value.into_http_request(XmlLimits::default(), None)
    }
}

impl TryFrom<Inbound<ManageNameIdRequest>> for HttpRequest {
    type Error = SamlError;

    fn try_from(value: Inbound<ManageNameIdRequest>) -> Result<Self, Self::Error> {
        http_request_from_transport(
            value.transport,
            true,
            MessageField::Request,
            XmlLimits::default(),
        )
    }
}

impl TryFrom<Inbound<ManageNameIdResponse>> for HttpRequest {
    type Error = SamlError;

    fn try_from(value: Inbound<ManageNameIdResponse>) -> Result<Self, Self::Error> {
        http_request_from_transport(
            value.transport,
            true,
            MessageField::Response,
            XmlLimits::default(),
        )
    }
}

fn logout_http_request(
    transport: Transport,
    expected_message: MessageField,
    limits: XmlLimits,
    schema_validator: Option<crate::SchemaValidator>,
) -> Result<HttpRequest, SamlError> {
    match transport {
        Transport::Soap { envelope, .. } => {
            soap_request(&envelope, expected_message, limits, schema_validator)
        }
        other => http_request_from_transport(other, true, expected_message, limits),
    }
}

/// The protocol element of a SOAP body, carried as an HTTP-POST message.
fn soap_request(
    envelope: &str,
    expected_message: MessageField,
    limits: XmlLimits,
    schema_validator: Option<crate::SchemaValidator>,
) -> Result<HttpRequest, SamlError> {
    let body = read_soap_body(envelope, limits, &[])?;
    crate::schema::validate(envelope, schema_validator)?;
    Ok(HttpRequest::post(vec![(
        expected_message.param_name().to_string(),
        encode_base64(body.xml.as_bytes()),
    )]))
}

fn http_request_from_transport(
    transport: Transport,
    allow_redirect: bool,
    expected_message: MessageField,
    limits: XmlLimits,
) -> Result<HttpRequest, SamlError> {
    match transport {
        Transport::Redirect { raw_query } => {
            if !allow_redirect {
                return Err(SamlError::UnsupportedBinding {
                    binding: Binding::Redirect,
                });
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
        Transport::Post { fields } => {
            validate_form_message_kind(&fields, expected_message)?;
            Ok(HttpRequest::post(fields_to_pairs(fields)))
        }
        Transport::SimpleSign { fields } => {
            let octet_string = simplesign_octet_from_fields(&fields, expected_message, limits)?;
            let mut request = HttpRequest::post(fields_to_pairs(fields));
            request.octet_string = Some(octet_string);
            Ok(request)
        }
        Transport::Artifact { .. } => Err(SamlError::UnsupportedBinding {
            binding: Binding::Artifact,
        }),
        Transport::Soap { .. } => Err(SamlError::UnsupportedBinding {
            binding: Binding::Soap,
        }),
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
    name: &'static str,
) -> Result<Option<&'a str>, SamlError> {
    single_parameter(
        params.iter().map(|param| (param.name, param.encoded_value)),
        name,
    )
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
        (None, None) => Err(SamlError::MissingBindingParameter {
            name: expected_name,
        }),
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

pub(crate) fn parse_form_fields(raw: &str) -> Vec<FormField> {
    parse_form_pairs(raw)
        .into_iter()
        .map(|(name, value)| FormField::new(name, value))
        .collect()
}

fn fields_to_pairs(fields: Vec<FormField>) -> Vec<(String, String)> {
    fields.into_iter().map(FormField::into_pair).collect()
}

pub(crate) fn field_value<'a>(
    fields: &'a [FormField],
    name: &'static str,
) -> Result<Option<&'a str>, SamlError> {
    single_parameter(
        fields.iter().map(|field| (field.name(), field.value())),
        name,
    )
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
        (None, None) => Err(SamlError::MissingBindingParameter {
            name: expected_name,
        }),
        (None, Some(_)) | (Some(_), Some(_)) => Err(SamlError::Invalid(format!(
            "expected form field {expected_name}, found {opposite_name}"
        ))),
    }
}

fn simplesign_octet_from_fields(
    fields: &[FormField],
    expected_message: MessageField,
    limits: XmlLimits,
) -> Result<String, SamlError> {
    let message_name = expected_message.param_name();
    let encoded = validate_form_message_kind(fields, expected_message)?;
    let raw_xml = String::from_utf8(base64_decode_with_limit(encoded, limits.max_bytes)?)
        .map_err(utf8_err)?;
    let sig_alg =
        field_value(fields, url_params::SIG_ALG)?.ok_or(SamlError::MissingBindingParameter {
            name: url_params::SIG_ALG,
        })?;
    let relay_state = field_value(fields, url_params::RELAY_STATE)?;
    Ok(build_simplesign_octet(
        message_name,
        &raw_xml,
        relay_state,
        sig_alg,
    ))
}
