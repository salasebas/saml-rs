use super::authn_context::{requested_authn_context_from_extract, RequestedAuthnContext};
use super::extract::{
    name_id_policy_from_extract, optional_endpoint, optional_u16, required_str,
    subject_confirmations_at,
};
use super::identifiers::{MessageId, SamlInstant};
use super::subject::{NameId, NameIdPolicy, RequestedSubject, RequestedSubjectIdentifier};
use super::EndpointUrl;
use crate::browser::SsoResponseBinding;
use crate::config::{EntityId, NameIdFormat};
use crate::constants::Binding;
use crate::error::SamlError;
use crate::flow::FlowResult;
use crate::xml::fields::{authn_request, request, ISSUER};
use crate::xml::{parse_saml_utc_date_time, xs_boolean};

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

impl AuthnRequest {
    /// Request ID.
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

    /// Destination endpoint, when present.
    pub fn destination(&self) -> Option<&EndpointUrl> {
        self.destination.as_ref()
    }

    /// AssertionConsumerServiceURL, when present.
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
    pub(crate) fn from_flow(raw_flow: FlowResult) -> Result<Self, SamlError> {
        Self::from_flow_with(raw_flow, optional_response_binding)
    }
}

impl AuthnRequest {
    /// Typed request from the SOAP leg of Enhanced Client/Proxy SSO.
    ///
    /// A `ProtocolBinding` that names the PAOS binding is reported as none.
    /// One that names HTTP-Artifact is rejected.
    pub(crate) fn try_from_paos_flow(raw_flow: FlowResult) -> Result<Self, SamlError> {
        Self::from_flow_with(raw_flow, |extract| {
            if extract.get_str(request::PROTOCOL_BINDING) == Some(PAOS_BINDING) {
                return Ok(None);
            }
            match optional_response_binding(extract)? {
                Some(SsoResponseBinding::Artifact) => Err(SamlError::UnsupportedBinding {
                    binding: Binding::Artifact,
                }),
                binding @ (Some(SsoResponseBinding::Post | SsoResponseBinding::SimpleSign)
                | None) => Ok(binding),
            }
        })
    }

    fn from_flow_with(
        raw_flow: FlowResult,
        response_binding: fn(&crate::util::Value) -> Result<Option<SsoResponseBinding>, SamlError>,
    ) -> Result<Self, SamlError> {
        let id = MessageId::try_new(required_str(&raw_flow.extract, request::ID)?)?;
        let issue_instant = issue_instant_from_extract(&raw_flow.extract)?;
        let issuer = EntityId::try_new(required_str(&raw_flow.extract, ISSUER)?)?;
        let destination = optional_endpoint(&raw_flow.extract, request::DESTINATION)?;
        let acs_url =
            optional_endpoint(&raw_flow.extract, request::ASSERTION_CONSUMER_SERVICE_URL)?;
        let protocol_binding = response_binding(&raw_flow.extract)?;
        let acs_index = optional_u16(&raw_flow.extract, request::ASSERTION_CONSUMER_SERVICE_INDEX)?;
        let name_id_policy = name_id_policy_from_extract(&raw_flow.extract)?;
        let force_authn = optional_flag(&raw_flow.extract, request::FORCE_AUTHN, "ForceAuthn")?
            .map(ForceAuthn::from_bool);
        let passive = optional_flag(&raw_flow.extract, request::IS_PASSIVE, "IsPassive")?
            .map(IsPassive::from_bool);
        let requested_subject = requested_subject_from_extract(&raw_flow.extract)?;
        let requested_authn_context = requested_authn_context_from_extract(&raw_flow.extract)?;
        Ok(Self {
            id,
            issue_instant,
            issuer,
            destination,
            acs_url,
            protocol_binding,
            acs_index,
            name_id_policy,
            force_authn,
            passive,
            provider_name: raw_flow
                .extract
                .get_str(request::PROVIDER_NAME)
                .map(str::to_string),
            requested_subject,
            requested_authn_context,
        })
    }
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
    .map(NameIdFormat::from_uri);
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

fn issue_instant_from_extract(extract: &crate::util::Value) -> Result<SamlInstant, SamlError> {
    let issue_instant = extract.get_str(request::ISSUE_INSTANT).ok_or_else(|| {
        SamlError::ProtocolProfile(
            "AuthnRequest is missing required unqualified attribute IssueInstant".into(),
        )
    })?;
    let issue_instant = parse_saml_utc_date_time(issue_instant).ok_or_else(|| {
        SamlError::ProtocolProfile(
            "AuthnRequest IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z"
                .into(),
        )
    })?;
    SamlInstant::try_new(issue_instant)
}

const PAOS_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:PAOS";

fn optional_response_binding(
    extract: &crate::util::Value,
) -> Result<Option<SsoResponseBinding>, SamlError> {
    let Some(protocol_binding) = extract.get_str(request::PROTOCOL_BINDING) else {
        return Ok(None);
    };
    let binding = Binding::from_urn(protocol_binding).ok_or_else(|| {
        SamlError::Invalid(format!(
            "unsupported AuthnRequest ProtocolBinding {protocol_binding}"
        ))
    })?;
    SsoResponseBinding::try_from(binding).map(Some)
}
