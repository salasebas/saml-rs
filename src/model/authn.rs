use super::extract::{
    name_id_format_from_uri, name_id_policy_from_extract, optional_endpoint, optional_u16,
    required_str, subject_confirmations_at,
};
use super::identifiers::{MessageId, SamlInstant};
use super::subject::{NameId, NameIdPolicy, RequestedSubject, RequestedSubjectIdentifier};
use super::{EndpointUrl, ReplayKey, SamlValidationContext};
use crate::browser::SsoResponseBinding;
use crate::config::EntityId;
use crate::constants::Binding;
use crate::error::SamlError;
use crate::raw::FlowResult;
use crate::xml::parse_saml_utc_date_time;

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
/// [`AuthnRequest::is_passive`] as `None`.
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
    is_passive: Option<IsPassive>,
    requested_subject: Option<RequestedSubject>,
    raw_flow: FlowResult,
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
    pub fn is_passive(&self) -> Option<IsPassive> {
        self.is_passive
    }

    /// Requested `<Subject>`, when present. See [`RequestedSubject`].
    pub fn requested_subject(&self) -> Option<&RequestedSubject> {
        self.requested_subject.as_ref()
    }

    /// Check and store this AuthnRequest's replay key using caller cache state.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::ReplayDetected`] when the request ID has already
    /// been seen. Cache implementations may also return storage-specific
    /// failures mapped to [`SamlError`].
    pub fn check_and_store_replay(
        &self,
        validation: &mut SamlValidationContext<'_>,
    ) -> Result<(), SamlError> {
        validation.check_and_store_message_replay(ReplayKey::AuthnRequestId(self.id.clone()))
    }

    /// Raw validated flow result.
    pub fn raw_flow(&self) -> &FlowResult {
        &self.raw_flow
    }
}

impl TryFrom<FlowResult> for AuthnRequest {
    type Error = SamlError;

    fn try_from(raw_flow: FlowResult) -> Result<Self, Self::Error> {
        Self::from_flow(raw_flow, optional_response_binding)
    }
}

impl AuthnRequest {
    /// Typed request from the SOAP leg of Enhanced Client/Proxy SSO.
    ///
    /// A `ProtocolBinding` that names the PAOS binding is reported as none.
    /// The raw flow keeps the attribute. One that names HTTP-Artifact is
    /// rejected.
    pub(crate) fn try_from_paos_flow(raw_flow: FlowResult) -> Result<Self, SamlError> {
        Self::from_flow(raw_flow, |extract| {
            if extract.get_str("request.protocolBinding") == Some(PAOS_BINDING) {
                return Ok(None);
            }
            match optional_response_binding(extract)? {
                Some(SsoResponseBinding::Artifact) => Err(SamlError::UndefinedBinding),
                binding @ (Some(SsoResponseBinding::Post | SsoResponseBinding::SimpleSign)
                | None) => Ok(binding),
            }
        })
    }

    fn from_flow(
        raw_flow: FlowResult,
        response_binding: fn(&crate::util::Value) -> Result<Option<SsoResponseBinding>, SamlError>,
    ) -> Result<Self, SamlError> {
        let id = MessageId::try_new(required_str(&raw_flow.extract, "request.id")?)?;
        let issue_instant = issue_instant_from_extract(&raw_flow.extract)?;
        let issuer = EntityId::try_new(required_str(&raw_flow.extract, "issuer")?)?;
        let destination = optional_endpoint(&raw_flow.extract, "request.destination")?;
        let acs_url = optional_endpoint(&raw_flow.extract, "request.assertionConsumerServiceUrl")?;
        let protocol_binding = response_binding(&raw_flow.extract)?;
        let acs_index = optional_u16(&raw_flow.extract, "request.assertionConsumerServiceIndex")?;
        let name_id_policy = name_id_policy_from_extract(&raw_flow.extract)?;
        let force_authn = optional_flag(&raw_flow.extract, "request.forceAuthn", "ForceAuthn")?
            .map(ForceAuthn::from_bool);
        let is_passive = optional_flag(&raw_flow.extract, "request.isPassive", "IsPassive")?
            .map(IsPassive::from_bool);
        let requested_subject = requested_subject_from_extract(&raw_flow.extract)?;
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
            is_passive,
            requested_subject,
            raw_flow,
        })
    }
}

fn optional_flag(
    extract: &crate::util::Value,
    path: &str,
    label: &str,
) -> Result<Option<bool>, SamlError> {
    let Some(value) = extract.get_str(path) else {
        return Ok(None);
    };
    match value {
        "true" | "1" => Ok(Some(true)),
        "false" | "0" => Ok(Some(false)),
        _ => Err(SamlError::Invalid(format!(
            "AuthnRequest {label} must be an XML Schema boolean (true, false, 1, or 0)"
        ))),
    }
}

fn requested_subject_from_extract(
    extract: &crate::util::Value,
) -> Result<Option<RequestedSubject>, SamlError> {
    if single_text(extract, "requestedSubject", "AuthnRequest Subject")?.is_none() {
        return Ok(None);
    }
    let identifier = requested_identifier(extract)?;
    let confirmations = subject_confirmations_at(extract, "requestedSubjectConfirmation");
    Ok(Some(RequestedSubject::new(identifier, confirmations)))
}

fn requested_identifier(
    extract: &crate::util::Value,
) -> Result<RequestedSubjectIdentifier, SamlError> {
    let name_id = single_text(extract, "requestedNameId", "AuthnRequest NameID")?;
    let base_id = single_text(extract, "requestedBaseId", "AuthnRequest BaseID")?;
    let encrypted_id = single_text(extract, "requestedEncryptedId", "AuthnRequest EncryptedID")?;
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
        "requestedNameIdFormat",
        "AuthnRequest NameID Format",
    )?
    .map(name_id_format_from_uri);
    Ok(NameId::with_qualifiers(
        value.to_string(),
        format,
        optional_attribute(extract, "requestedNameQualifier", "NameQualifier")?,
        optional_attribute(extract, "requestedSpNameQualifier", "SPNameQualifier")?,
        optional_attribute(extract, "requestedSpProvidedId", "SPProvidedID")?,
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
    let issue_instant = extract.get_str("request.issueInstant").ok_or_else(|| {
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
    let Some(protocol_binding) = extract.get_str("request.protocolBinding") else {
        return Ok(None);
    };
    let binding = Binding::from_urn(protocol_binding).ok_or_else(|| {
        SamlError::Invalid(format!(
            "unsupported AuthnRequest ProtocolBinding {protocol_binding}"
        ))
    })?;
    SsoResponseBinding::try_from(binding).map(Some)
}
