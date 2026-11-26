use super::authn_context::{requested_authn_context_from_extract, RequestedAuthnContext};
use super::extract::{
    name_id_policy_from_extract, optional_endpoint, optional_u16, required_saml_utc_instant,
    required_str, subject_confirmations_at,
};
use super::identifiers::{MessageId, SamlInstant};
use super::status::{RequestVersionMismatch, Status, SubordinateStatusCode};
use super::subject::{NameId, NameIdPolicy, RequestedSubject, RequestedSubjectIdentifier};
use super::EndpointUrl;
use crate::browser::SsoResponseBinding;
use crate::config::{EntityId, NameIdFormat};
use crate::constants::Binding;
use crate::error::SamlError;
use crate::flow::FlowResult;
use crate::util::Value;
use crate::xml::any_uri::collapse_whitespace;
use crate::xml::fields::{authn_request, request, ISSUER};
use crate::xml::xs_boolean;
use std::sync::Arc;

/// Whether the request has more than one `NameIDPolicy`.
pub(crate) fn repeats_name_id_policy(raw_flow: &FlowResult) -> bool {
    matches!(
        raw_flow.extract.get(authn_request::NAME_ID_POLICY),
        Some(Value::Array(policies)) if policies.len() > 1
    )
}

/// How the request's `Version` differs from `2.0`, or `None` for `2.0`.
///
/// A declared major version below 2 and a `Version` that is not `major.minor`
/// return an error, because no SAML 2.0 response can answer them.
pub(crate) fn later_request_version(
    raw_flow: &FlowResult,
) -> Result<Option<RequestVersionMismatch>, SamlError> {
    RequestVersionMismatch::for_request(required_str(&raw_flow.extract, authn_request::VERSION)?)
}

/// `ForceAuthn` on an `<AuthnRequest>` (Core §3.4.1).
///
/// [`Self::Required`] is `true`. [`Self::NotRequired`] is `false`. Omission
/// leaves [`AuthnRequest::force_authn`] as `None`. When this and [`IsPassive`]
/// are both required, do not freshly authenticate the presenter unless
/// `IsPassive` can be met.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForceAuthn {
    /// `ForceAuthn="true"`.
    Required,
    /// `ForceAuthn="false"`.
    NotRequired,
}

impl ForceAuthn {
    pub(crate) fn from_bool(value: bool) -> Self {
        if value {
            Self::Required
        } else {
            Self::NotRequired
        }
    }

    pub(crate) fn as_bool(self) -> bool {
        match self {
            Self::Required => true,
            Self::NotRequired => false,
        }
    }
}

/// `IsPassive` on an `<AuthnRequest>` (Core §3.4.1).
///
/// [`Self::Required`] is `true`: do not take visible control of the user
/// interface. [`Self::NotRequired`] is `false`. Omission leaves
/// [`AuthnRequest::passive`] as `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsPassive {
    /// `IsPassive="true"`.
    Required,
    /// `IsPassive="false"`.
    NotRequired,
}

impl IsPassive {
    pub(crate) fn from_bool(value: bool) -> Self {
        if value {
            Self::Required
        } else {
            Self::NotRequired
        }
    }

    pub(crate) fn as_bool(self) -> bool {
        match self {
            Self::Required => true,
            Self::NotRequired => false,
        }
    }
}

/// Parsed AuthnRequest result.
#[derive(Debug, Clone)]
pub struct AuthnRequest {
    id: MessageId,
    issue_instant: SamlInstant,
    issuer: EntityId,
    destination: Option<EndpointUrl>,
    acs_url: Option<EndpointUrl>,
    protocol_binding: Option<SsoResponseBinding>,
    acs_index: Option<u16>,
    name_id_policy: Option<NameIdPolicy>,
    force_authn: Option<ForceAuthn>,
    passive: Option<IsPassive>,
    provider_name: Option<String>,
    requested_subject: Option<RequestedSubject>,
    requested_authn_context: Option<RequestedAuthnContext>,
}

/// An authentication request the identity provider will not fulfil.
///
/// Pass it to
/// [`IdentityProvider::respond_sso_refusal`](crate::IdentityProvider::respond_sso_refusal)
/// or
/// [`IdentityProvider::respond_sso_refusal_artifact`](crate::IdentityProvider::respond_sso_refusal_artifact)
/// to send a correlated SAML error response.
#[derive(Clone)]
pub struct RefusedAuthnRequest {
    pub(crate) request: AuthnRequest,
    pub(crate) relay_state: Option<super::RelayState>,
    pub(crate) reason: AuthnRequestRefusalReason,
    pub(crate) status: Status,
    pub(crate) content_error: Option<Arc<SamlError>>,
}

impl RefusedAuthnRequest {
    pub(crate) fn new(
        request: AuthnRequest,
        relay_state: Option<super::RelayState>,
        refusal: Refusal,
    ) -> Self {
        let (reason, status, content_error) = match refusal {
            Refusal::Unsigned => (
                AuthnRequestRefusalReason::Unsigned,
                Status::requester(),
                None,
            ),
            Refusal::Version(mismatch) => (
                AuthnRequestRefusalReason::VersionMismatch,
                mismatch.status(),
                None,
            ),
            Refusal::Content(ContentFault::UnsupportedProtocolBinding(error)) => (
                AuthnRequestRefusalReason::UnsupportedProtocolBinding,
                Status::requester().with_subordinate(SubordinateStatusCode::unsupported_binding()),
                Some(Arc::new(error)),
            ),
            Refusal::Content(ContentFault::Malformed(error)) => (
                AuthnRequestRefusalReason::MalformedRequest,
                Status::requester(),
                Some(Arc::new(error)),
            ),
            Refusal::RepeatedNameIdPolicy => (
                AuthnRequestRefusalReason::RepeatedNameIdPolicy,
                Status::requester(),
                None,
            ),
            Refusal::OutsideAgeWindow => (
                AuthnRequestRefusalReason::OutsideAgeWindow,
                Status::requester(),
                None,
            ),
        };
        Self {
            request,
            relay_state,
            reason,
            status,
            content_error,
        }
    }

    /// Why the identity provider refuses the request.
    pub fn reason(&self) -> AuthnRequestRefusalReason {
        self.reason
    }

    /// Why the request content was refused, for
    /// [`AuthnRequestRefusalReason::MalformedRequest`] and
    /// [`AuthnRequestRefusalReason::UnsupportedProtocolBinding`].
    ///
    /// The error stays local: the response carries only the SAML status.
    pub fn content_error(&self) -> Option<&SamlError> {
        self.content_error.as_deref()
    }
}

impl std::fmt::Debug for RefusedAuthnRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefusedAuthnRequest")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

/// Why [`IdentityProvider::receive_sso`](crate::IdentityProvider::receive_sso)
/// refuses an authentication request it could otherwise answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthnRequestRefusalReason {
    /// No verified signature covers the request, and the service provider's
    /// metadata sets `AuthnRequestsSigned` or this identity provider requires
    /// signed requests.
    Unsigned,
    /// The request `IssueInstant` is outside the age window that
    /// [`SamlValidationContext::with_authn_request_age`](crate::SamlValidationContext::with_authn_request_age)
    /// sets.
    OutsideAgeWindow,
    /// The request has more than one `NameIDPolicy`, which `AuthnRequestType`
    /// allows once.
    RepeatedNameIdPolicy,
    /// The request's `ProtocolBinding` names a binding that the `Response`
    /// cannot use: HTTP-Redirect, SOAP, or a URI that is not HTTP-POST,
    /// HTTP-POST-SimpleSign, or HTTP-Artifact. The status is `Requester` with
    /// `UnsupportedBinding`, and the response goes to the service provider's
    /// default assertion consumer service.
    UnsupportedProtocolBinding,
    /// The request has content that the identity provider cannot read: a
    /// second `Subject` or `RequestedAuthnContext`, a `Subject` with more than
    /// one identifier, a `RequestedAuthnContext` without references or with
    /// both kinds, a `Comparison`, `ForceAuthn`, `IsPassive`, `AllowCreate`, or
    /// `AssertionConsumerServiceIndex` outside its schema type, an
    /// `AssertionConsumerServiceURL` that is not an absolute HTTP(S) URL, both
    /// an `AssertionConsumerServiceURL` and an `AssertionConsumerServiceIndex`,
    /// or a decrypted requested `NameID` that breaks the protocol profile. The
    /// status is `Requester`.
    /// [`RefusedAuthnRequest::content_error`] says what was wrong.
    ///
    /// When the fault is in `AssertionConsumerServiceURL` or
    /// `AssertionConsumerServiceIndex`, or the request carries both, the
    /// response goes to the service provider's default assertion consumer
    /// service.
    MalformedRequest,
    /// The request's `Version` is later than `2.0`, such as `2.1` or `3.0`.
    /// The status is `VersionMismatch`, with `RequestVersionTooHigh` for a
    /// later major version, and the response goes to the service provider's
    /// default assertion consumer service, as every response to a request of
    /// a later version does.
    VersionMismatch,
}

impl std::fmt::Display for AuthnRequestRefusalReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsigned => f.write_str("the request is unsigned"),
            Self::OutsideAgeWindow => {
                f.write_str("the request IssueInstant is outside the age window")
            }
            Self::RepeatedNameIdPolicy => f.write_str("the request has more than one NameIDPolicy"),
            Self::UnsupportedProtocolBinding => {
                f.write_str("the request ProtocolBinding cannot carry the response")
            }
            Self::MalformedRequest => f.write_str("the request content is malformed"),
            Self::VersionMismatch => f.write_str("the request Version is later than 2.0"),
        }
    }
}

/// Why `receive_sso` refuses a request, with what its answer needs.
pub(crate) enum Refusal {
    Unsigned,
    Version(RequestVersionMismatch),
    Content(ContentFault),
    RepeatedNameIdPolicy,
    OutsideAgeWindow,
}

/// Request content that the identity provider cannot read or answer.
pub(crate) enum ContentFault {
    UnsupportedProtocolBinding(SamlError),
    Malformed(SamlError),
}

pub(crate) struct ReadAuthnRequest {
    pub(crate) request: AuthnRequest,
    pub(crate) fault: Option<ContentFault>,
}

impl AuthnRequest {
    /// Request ID, with XML whitespace collapsed as for an `xs:ID`.
    pub fn id(&self) -> &MessageId {
        &self.id
    }

    /// Request `IssueInstant`, normalized according to XML Schema whitespace rules.
    pub fn issue_instant(&self) -> &SamlInstant {
        &self.issue_instant
    }

    /// Request issuer.
    pub fn issuer(&self) -> &EntityId {
        &self.issuer
    }

    /// `Destination`, when present, with its XML Schema `anyURI` whitespace
    /// collapsed.
    pub fn destination(&self) -> Option<&EndpointUrl> {
        self.destination.as_ref()
    }

    /// `AssertionConsumerServiceURL`, when present, with its XML Schema
    /// `anyURI` whitespace collapsed.
    pub fn acs_url(&self) -> Option<&EndpointUrl> {
        self.acs_url.as_ref()
    }

    /// Requested response `ProtocolBinding`, when present.
    pub fn protocol_binding(&self) -> Option<SsoResponseBinding> {
        self.protocol_binding
    }

    /// Requested `AssertionConsumerServiceIndex`, when present.
    pub fn acs_index(&self) -> Option<u16> {
        self.acs_index
    }

    /// NameIDPolicy, when present.
    pub fn name_id_policy(&self) -> Option<&NameIdPolicy> {
        self.name_id_policy.as_ref()
    }

    /// `ForceAuthn`, when set. See [`ForceAuthn`].
    pub fn force_authn(&self) -> Option<ForceAuthn> {
        self.force_authn
    }

    /// `IsPassive`, when set. See [`IsPassive`].
    pub fn passive(&self) -> Option<IsPassive> {
        self.passive
    }

    /// The requester's human-readable `ProviderName`, when present.
    pub fn provider_name(&self) -> Option<&str> {
        self.provider_name.as_deref()
    }

    /// Requested `<Subject>`, when present. See [`RequestedSubject`].
    pub fn requested_subject(&self) -> Option<&RequestedSubject> {
        self.requested_subject.as_ref()
    }

    /// `<RequestedAuthnContext>`, when present. See [`RequestedAuthnContext`].
    pub fn requested_authn_context(&self) -> Option<&RequestedAuthnContext> {
        self.requested_authn_context.as_ref()
    }
}

impl AuthnRequest {
    /// The request with only its `ID`, `IssueInstant`, `Issuer`, and
    /// `Destination` read, for a request whose other content is not relied on.
    pub(crate) fn from_flow_without_content(raw_flow: &FlowResult) -> Result<Self, SamlError> {
        let extract = &raw_flow.extract;
        Ok(Self {
            id: MessageId::try_new(collapse_whitespace(required_str(extract, request::ID)?))?,
            issue_instant: required_saml_utc_instant(
                extract.get_str(request::ISSUE_INSTANT),
                "AuthnRequest",
                "IssueInstant",
            )?,
            issuer: EntityId::try_new(required_str(extract, ISSUER)?)?,
            destination: optional_endpoint(extract, request::DESTINATION)?,
            acs_url: None,
            protocol_binding: None,
            acs_index: None,
            name_id_policy: None,
            force_authn: None,
            passive: None,
            provider_name: None,
            requested_subject: None,
            requested_authn_context: None,
        })
    }

    pub(crate) fn from_flow(raw_flow: &FlowResult) -> Result<ReadAuthnRequest, SamlError> {
        let addressed = Self::from_flow_without_content(raw_flow)?;
        let extract = &raw_flow.extract;
        let (endpoint, mut fault) = match RequestedEndpoint::read(extract) {
            Ok(endpoint) => (endpoint, None),
            Err(endpoint_fault) => (RequestedEndpoint::default(), Some(endpoint_fault)),
        };
        let name_id_policy = readable(&mut fault, name_id_policy_from_extract(extract));
        let force_authn = readable(
            &mut fault,
            optional_flag(extract, request::FORCE_AUTHN, "ForceAuthn"),
        )
        .map(ForceAuthn::from_bool);
        let passive = readable(
            &mut fault,
            optional_flag(extract, request::IS_PASSIVE, "IsPassive"),
        )
        .map(IsPassive::from_bool);
        let requested_subject = readable(&mut fault, requested_subject_from_extract(extract));
        let requested_authn_context =
            readable(&mut fault, requested_authn_context_from_extract(extract));
        Ok(ReadAuthnRequest {
            request: Self {
                acs_url: endpoint.acs_url,
                protocol_binding: endpoint.protocol_binding,
                acs_index: endpoint.acs_index,
                name_id_policy,
                force_authn,
                passive,
                provider_name: extract.get_str(request::PROVIDER_NAME).map(str::to_string),
                requested_subject,
                requested_authn_context,
                ..addressed
            },
            fault,
        })
    }
}

#[derive(Default)]
struct RequestedEndpoint {
    acs_url: Option<EndpointUrl>,
    protocol_binding: Option<SsoResponseBinding>,
    acs_index: Option<u16>,
}

impl RequestedEndpoint {
    fn read(extract: &crate::util::Value) -> Result<Self, ContentFault> {
        let acs_url = optional_endpoint(extract, request::ASSERTION_CONSUMER_SERVICE_URL)
            .map_err(ContentFault::Malformed)?;
        let protocol_binding =
            optional_response_binding(extract).map_err(ContentFault::UnsupportedProtocolBinding)?;
        let acs_index = optional_u16(extract, request::ASSERTION_CONSUMER_SERVICE_INDEX)
            .map_err(ContentFault::Malformed)?;
        if acs_url.is_some() && acs_index.is_some() {
            return Err(ContentFault::Malformed(SamlError::Invalid(
                "AuthnRequest must not carry both AssertionConsumerServiceURL and AssertionConsumerServiceIndex".into(),
            )));
        }
        Ok(Self {
            acs_url,
            protocol_binding,
            acs_index,
        })
    }
}

fn readable<T>(fault: &mut Option<ContentFault>, read: Result<Option<T>, SamlError>) -> Option<T> {
    read.unwrap_or_else(|error| {
        fault.get_or_insert(ContentFault::Malformed(error));
        None
    })
}

fn optional_flag(
    extract: &crate::util::Value,
    path: &str,
    label: &str,
) -> Result<Option<bool>, SamlError> {
    extract
        .get_str(path)
        .map(|value| {
            xs_boolean(Some(value)).ok_or_else(|| {
                SamlError::Invalid(format!(
                    "AuthnRequest {label} must be an XML Schema boolean (true, false, 1, or 0)"
                ))
            })
        })
        .transpose()
}

fn requested_subject_from_extract(
    extract: &crate::util::Value,
) -> Result<Option<RequestedSubject>, SamlError> {
    if single_text(
        extract,
        authn_request::REQUESTED_SUBJECT,
        "AuthnRequest Subject",
    )?
    .is_none()
    {
        return Ok(None);
    }
    let identifier = requested_identifier(extract)?;
    let confirmations =
        subject_confirmations_at(extract, authn_request::REQUESTED_SUBJECT_CONFIRMATION);
    Ok(Some(RequestedSubject::new(identifier, confirmations)))
}

fn requested_identifier(
    extract: &crate::util::Value,
) -> Result<RequestedSubjectIdentifier, SamlError> {
    let name_id = single_text(
        extract,
        authn_request::REQUESTED_NAME_ID,
        "AuthnRequest NameID",
    )?;
    let base_id = single_text(
        extract,
        authn_request::REQUESTED_BASE_ID,
        "AuthnRequest BaseID",
    )?;
    let encrypted_id = single_text(
        extract,
        authn_request::REQUESTED_ENCRYPTED_ID,
        "AuthnRequest EncryptedID",
    )?;
    let identifiers = [name_id, base_id, encrypted_id]
        .into_iter()
        .filter(Option::is_some)
        .count();
    if identifiers > 1 {
        return Err(SamlError::Invalid(
            "AuthnRequest Subject must contain one identifier element".into(),
        ));
    }
    if let Some(value) = name_id {
        return Ok(RequestedSubjectIdentifier::NameId(name_id_from_extract(
            extract, value,
        )?));
    }
    if base_id.is_some() {
        return Ok(RequestedSubjectIdentifier::BaseId);
    }
    if encrypted_id.is_some() {
        return Ok(RequestedSubjectIdentifier::EncryptedId);
    }
    Ok(RequestedSubjectIdentifier::NoIdentifier)
}

fn name_id_from_extract(extract: &crate::util::Value, value: &str) -> Result<NameId, SamlError> {
    let format = single_text(
        extract,
        authn_request::REQUESTED_NAME_ID_FORMAT,
        "AuthnRequest NameID Format",
    )?
    .map(|format| NameIdFormat::from_uri(&collapse_whitespace(format)));
    Ok(NameId::received(
        value.to_string(),
        format,
        optional_attribute(
            extract,
            authn_request::REQUESTED_NAME_QUALIFIER,
            "NameQualifier",
        )?,
        optional_attribute(
            extract,
            authn_request::REQUESTED_SP_NAME_QUALIFIER,
            "SPNameQualifier",
        )?,
        optional_attribute(
            extract,
            authn_request::REQUESTED_SP_PROVIDED_ID,
            "SPProvidedID",
        )?,
    ))
}

fn optional_attribute(
    extract: &crate::util::Value,
    path: &str,
    label: &str,
) -> Result<Option<String>, SamlError> {
    Ok(single_text(extract, path, label)?.map(str::to_string))
}

fn single_text<'a>(
    extract: &'a crate::util::Value,
    path: &str,
    label: &str,
) -> Result<Option<&'a str>, SamlError> {
    match extract.get(path) {
        None | Some(crate::util::Value::Null) => Ok(None),
        Some(crate::util::Value::Str(value)) => Ok(Some(value.as_str())),
        Some(crate::util::Value::Array(_) | crate::util::Value::Object(_)) => {
            Err(SamlError::Invalid(format!("{label} must occur once")))
        }
    }
}

fn optional_response_binding(
    extract: &crate::util::Value,
) -> Result<Option<SsoResponseBinding>, SamlError> {
    let Some(protocol_binding) = extract.get_str(request::PROTOCOL_BINDING) else {
        return Ok(None);
    };
    let binding = Binding::from_urn(&collapse_whitespace(protocol_binding)).ok_or_else(|| {
        SamlError::Invalid(format!(
            "unsupported AuthnRequest ProtocolBinding {protocol_binding}"
        ))
    })?;
    SsoResponseBinding::try_from(binding).map(Some)
}
