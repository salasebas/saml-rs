//! Name identifier management over the SOAP binding.
//!
//! The identity provider sends `ManageNameIDRequest` to a service provider and
//! reads its `ManageNameIDResponse`, or answers a service provider's request.

use crate::config::{EntityId, SpDescriptor};
use crate::constants::{name_id_format, namespace, status_code};
use crate::entity::{generate_id, now_iso8601};
use crate::error::SamlError;
use crate::metadata::Metadata;
use crate::model::{
    name_id_format_from_uri, validate_issued_name_id_length, EndpointUrl, MessageId, NameId,
    Received, ReplayKey, SamlValidationContext, Status, SubordinateStatusCode,
};
use crate::soap::{read_soap_body, SoapChannel, SoapProtocolMessage, SoapRequest, SoapResponse};
use crate::xml::parse_saml_utc_date_time;
use crate::xml::protocol_element::{
    issuer, issuer_format_is_entity, parse_saml, status_codes, SamlElement,
};
use crate::xml::write::XmlWriter;

/// The change a `ManageNameIDRequest` makes to an established identifier.
///
/// The identifier's format and qualifiers stay as established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameIdChange {
    /// `<NewID>`: the requester's new value for the identifier.
    ///
    /// From the identity provider, it replaces the `NameID` value. From the
    /// service provider, it is the `SPProvidedID` the identity provider sends
    /// with that identifier from now on.
    NewId(String),
    /// `<Terminate>`: the requester no longer issues or accepts assertions
    /// that use the identifier.
    Terminate,
}

/// `ManageNameIDRequest` received from a service provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManageNameIdRequest {
    id: MessageId,
    issuer: EntityId,
    name_id: NameId,
    change: NameIdChange,
}

impl ManageNameIdRequest {
    /// Request `ID`, which the response's `InResponseTo` carries.
    pub fn id(&self) -> &MessageId {
        &self.id
    }

    /// Service provider that sent the request.
    pub fn issuer(&self) -> &EntityId {
        &self.issuer
    }

    /// The identifier as both providers currently know it.
    pub fn name_id(&self) -> &NameId {
        &self.name_id
    }

    /// The requested change.
    pub fn change(&self) -> &NameIdChange {
        &self.change
    }
}

/// Result of reading a service provider's `ManageNameIDRequest`.
#[derive(Debug, Clone)]
pub enum ReceivedNameIdManagement {
    /// Apply the change, then answer with
    /// [`Saml::respond_name_id_management`](crate::Saml::respond_name_id_management).
    Request(Received<ManageNameIdRequest>),
    /// The identity provider answered the request without processing it.
    Refused(RefusedNameIdManagement),
}

/// Why the identity provider answered a `ManageNameIDRequest` without
/// processing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameIdManagementRefusal {
    /// The request `Version` is not `2.0`. The status is `VersionMismatch`.
    VersionMismatch,
    /// The request carries `EncryptedID` or `NewEncryptedID`, which this
    /// identity provider does not decrypt. The status is `Responder` with
    /// `RequestUnsupported`.
    EncryptedIdentifier,
}

/// `ManageNameIDResponse` returned for a request that was not processed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedNameIdManagement {
    response: SoapResponse,
    reason: NameIdManagementRefusal,
}

impl RefusedNameIdManagement {
    /// SOAP response to return to the service provider.
    pub fn response(&self) -> &SoapResponse {
        &self.response
    }

    /// Why the request was not processed.
    pub fn reason(&self) -> NameIdManagementRefusal {
        self.reason
    }
}

/// In-progress name identifier management started by the identity provider.
///
/// Send [`Self::request`] to the service provider, then pass its SOAP response
/// to [`Self::finish`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedNameIdManagement {
    request: SoapRequest,
    request_id: String,
    service_provider: String,
}

impl StartedNameIdManagement {
    /// SOAP `ManageNameIDRequest` addressed to the service provider's
    /// `ManageNameIDService`.
    pub fn request(&self) -> &SoapRequest {
        &self.request
    }

    /// Read the service provider's SOAP `ManageNameIDResponse`.
    ///
    /// `Ok` means the service provider applied the change.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::StatusNotSuccess`] with the service provider's
    /// status codes when it did not apply the change, for example
    /// `UnknownPrincipal`. Returns another [`SamlError`] when the envelope is
    /// not a `ManageNameIDResponse` from that service provider for this
    /// request.
    pub fn finish(&self, response_envelope: &str) -> Result<(), SamlError> {
        let body = read_soap_body(response_envelope)?;
        if body.local_name != "ManageNameIDResponse" || body.namespace != namespace::PROTOCOL {
            return Err(SamlError::ProtocolProfile(
                "SOAP body must be a ManageNameIDResponse".into(),
            ));
        }
        let response = parse_saml(&body.xml)?;
        if response.required_attr("Version")? != "2.0" {
            return Err(SamlError::ProtocolProfile(
                "ManageNameIDResponse Version must be 2.0".into(),
            ));
        }
        response.required_attr("ID")?;
        require_utc_instant(&response)?;
        let in_response_to = response.attr("InResponseTo");
        if in_response_to != Some(self.request_id.as_str()) {
            return Err(SamlError::in_response_to_mismatch(
                Some(&self.request_id),
                in_response_to,
            ));
        }
        require_peer_issuer(&response, &self.service_provider)?;
        let (top, second) = status_codes(&response)?;
        if top != status_code::SUCCESS {
            return Err(SamlError::StatusNotSuccess { top, second });
        }
        Ok(())
    }
}

/// The identity provider's side of name identifier management.
pub(crate) struct LocalIdentityProvider<'a> {
    pub(crate) entity_id: &'a str,
    pub(crate) metadata: &'a Metadata,
    pub(crate) default_name_id_format: Option<&'a str>,
}

pub(crate) fn start(
    idp: &LocalIdentityProvider<'_>,
    service_provider: &SpDescriptor,
    name_id: &NameId,
    change: &NameIdChange,
    channel: SoapChannel,
) -> Result<StartedNameIdManagement, SamlError> {
    local_services(idp.metadata)?;
    require_channel(channel)?;
    let sp_entity_id = service_provider.entity_id().as_str();
    let destination = service_provider
        .metadata()
        .soap_manage_name_id_service_locations()
        .into_iter()
        .next()
        .ok_or_else(|| SamlError::MissingMetadata("ManageNameIDService".into()))?;
    let format = name_id
        .format()
        .map(|format| format.as_uri())
        .or(idp.default_name_id_format);
    validate_issued_name_id_length(format, name_id.value())?;
    if let NameIdChange::NewId(value) = change {
        validate_issued_name_id_length(format, value)?;
    }
    let persistent = format == Some(name_id_format::PERSISTENT);
    let name_qualifier = name_id
        .name_qualifier()
        .or(persistent.then_some(idp.entity_id));
    let sp_name_qualifier = name_id
        .sp_name_qualifier()
        .or(persistent.then_some(sp_entity_id));

    let request_id = generate_id();
    let issue_instant = now_iso8601();
    let mut writer = XmlWriter::new();
    writer.start(
        "samlp:ManageNameIDRequest",
        &[
            ("xmlns:samlp", namespace::PROTOCOL),
            ("xmlns:saml", namespace::ASSERTION),
            ("ID", request_id.as_str()),
            ("Version", "2.0"),
            ("IssueInstant", issue_instant.as_str()),
            ("Destination", destination.as_str()),
        ],
    );
    writer.text_element("saml:Issuer", &[], idp.entity_id);
    let name_id_attrs: Vec<(&str, &str)> = [
        ("Format", format),
        ("NameQualifier", name_qualifier),
        ("SPNameQualifier", sp_name_qualifier),
        ("SPProvidedID", name_id.sp_provided_id()),
    ]
    .into_iter()
    .filter_map(|(name, value)| value.map(|value| (name, value)))
    .collect();
    writer.text_element("saml:NameID", &name_id_attrs, name_id.value());
    match change {
        NameIdChange::NewId(value) => writer.text_element("samlp:NewID", &[], value),
        NameIdChange::Terminate => writer.empty("samlp:Terminate", &[]),
    }
    writer.end("samlp:ManageNameIDRequest");
    let request =
        SoapProtocolMessage::request(EndpointUrl::try_new(destination)?, &writer.finish())?;
    Ok(StartedNameIdManagement {
        request,
        request_id,
        service_provider: sp_entity_id.to_string(),
    })
}

pub(crate) fn receive(
    idp: &LocalIdentityProvider<'_>,
    service_provider: &SpDescriptor,
    request_envelope: &str,
    channel: SoapChannel,
    mut validation: SamlValidationContext<'_>,
) -> Result<ReceivedNameIdManagement, SamlError> {
    let locations = local_services(idp.metadata)?;
    require_channel(channel)?;
    let body = read_soap_body(request_envelope)?;
    if body.local_name != "ManageNameIDRequest" || body.namespace != namespace::PROTOCOL {
        return Err(SamlError::ProtocolProfile(
            "SOAP body must be a ManageNameIDRequest".into(),
        ));
    }
    let request = parse_saml(&body.xml)?;
    let id = MessageId::try_new(request.required_attr("ID")?)?;
    let version = request.required_attr("Version")?;
    require_utc_instant(&request)?;
    if version != "2.0" {
        return refused(
            idp.entity_id,
            &id,
            Status::version_mismatch(),
            NameIdManagementRefusal::VersionMismatch,
        );
    }
    let sp_entity_id = service_provider.entity_id();
    if request
        .children
        .iter()
        .filter(|child| child.is(namespace::ASSERTION, "Issuer"))
        .count()
        > 1
    {
        return Err(SamlError::ProtocolProfile(
            "ManageNameIDRequest requires at most one Issuer".into(),
        ));
    }
    require_peer_issuer(&request, sp_entity_id.as_str())?;
    let recipient = validation.resolve_recipient_endpoint(&locations)?;
    if let Some(destination) = request.attr("Destination") {
        if destination != recipient {
            return Err(SamlError::destination_mismatch(
                &recipient,
                Some(destination),
            ));
        }
    }
    let (identifier, change) = identifier_and_change(&request)?;
    validation.check_and_store_message_replay(ReplayKey::ManageNameIdRequestId(id.clone()))?;
    let (Identifier::Plain(name_id), Change::Plain(change)) = (identifier, change) else {
        return refused(
            idp.entity_id,
            &id,
            Status::responder().with_subordinate(SubordinateStatusCode::request_unsupported()),
            NameIdManagementRefusal::EncryptedIdentifier,
        );
    };
    Ok(ReceivedNameIdManagement::Request(Received::new(
        ManageNameIdRequest {
            id,
            issuer: sp_entity_id.clone(),
            name_id,
            change,
        },
    )))
}

pub(crate) fn respond(
    idp: &LocalIdentityProvider<'_>,
    service_provider: &SpDescriptor,
    request: &Received<ManageNameIdRequest>,
    status: &Status,
) -> Result<SoapResponse, SamlError> {
    let sp_entity_id = service_provider.entity_id();
    let issuer = request.message().issuer();
    if issuer != sp_entity_id {
        return Err(SamlError::issuer_mismatch(
            sp_entity_id.as_str(),
            Some(issuer.as_str()),
        ));
    }
    response(idp.entity_id, request.message().id(), status)
}

fn refused(
    idp_entity_id: &str,
    in_response_to: &MessageId,
    status: Status,
    reason: NameIdManagementRefusal,
) -> Result<ReceivedNameIdManagement, SamlError> {
    Ok(ReceivedNameIdManagement::Refused(RefusedNameIdManagement {
        response: response(idp_entity_id, in_response_to, &status)?,
        reason,
    }))
}

fn response(
    idp_entity_id: &str,
    in_response_to: &MessageId,
    status: &Status,
) -> Result<SoapResponse, SamlError> {
    let mut writer = XmlWriter::new();
    writer.start(
        "samlp:ManageNameIDResponse",
        &[
            ("xmlns:samlp", namespace::PROTOCOL),
            ("xmlns:saml", namespace::ASSERTION),
            ("ID", generate_id().as_str()),
            ("Version", "2.0"),
            ("IssueInstant", now_iso8601().as_str()),
            ("InResponseTo", in_response_to.as_str()),
        ],
    );
    writer.text_element("saml:Issuer", &[], idp_entity_id);
    writer.start("samlp:Status", &[]);
    let top = status.top_level().as_uri();
    match status.subordinate() {
        Some(subordinate) => {
            writer.start("samlp:StatusCode", &[("Value", top)]);
            writer.empty("samlp:StatusCode", &[("Value", subordinate.as_uri())]);
            writer.end("samlp:StatusCode");
        }
        None => writer.empty("samlp:StatusCode", &[("Value", top)]),
    }
    writer.end("samlp:Status");
    writer.end("samlp:ManageNameIDResponse");
    SoapResponse::new(&writer.finish())
}

enum Identifier {
    Plain(NameId),
    Encrypted,
}

enum Change {
    Plain(NameIdChange),
    Encrypted,
}

fn identifier_and_change(request: &SamlElement) -> Result<(Identifier, Change), SamlError> {
    let mut content = request.children.iter().filter(|child| {
        !(child.is(namespace::ASSERTION, "Issuer")
            || child.is(namespace::DSIG, "Signature")
            || child.is(namespace::PROTOCOL, "Extensions"))
    });
    let malformed = || {
        SamlError::ProtocolProfile(
            "ManageNameIDRequest requires one NameID or EncryptedID and one NewID, NewEncryptedID, or Terminate"
                .into(),
        )
    };
    let (Some(identifier), Some(change), None) = (content.next(), content.next(), content.next())
    else {
        return Err(malformed());
    };
    let identifier = if identifier.is(namespace::ASSERTION, "NameID") {
        Identifier::Plain(name_id(simple_content(identifier)?))
    } else if identifier.is(namespace::ASSERTION, "EncryptedID") {
        Identifier::Encrypted
    } else {
        return Err(malformed());
    };
    let change = if change.is(namespace::PROTOCOL, "NewID") {
        Change::Plain(NameIdChange::NewId(simple_content(change)?.text.clone()))
    } else if change.is(namespace::PROTOCOL, "Terminate") {
        if !simple_content(change)?.text.trim().is_empty() {
            return Err(SamlError::ProtocolProfile(
                "ManageNameIDRequest Terminate must be empty".into(),
            ));
        }
        Change::Plain(NameIdChange::Terminate)
    } else if change.is(namespace::PROTOCOL, "NewEncryptedID") {
        Change::Encrypted
    } else {
        return Err(malformed());
    };
    Ok((identifier, change))
}

fn simple_content(element: &SamlElement) -> Result<&SamlElement, SamlError> {
    if element.children.is_empty() {
        return Ok(element);
    }
    Err(SamlError::ProtocolProfile(format!(
        "ManageNameIDRequest {} must not contain elements",
        element.local_name
    )))
}

fn name_id(element: &SamlElement) -> NameId {
    let attr = |name| element.attr(name).map(str::to_string);
    NameId::with_qualifiers(
        element.text.clone(),
        element.attr("Format").map(name_id_format_from_uri),
        attr("NameQualifier"),
        attr("SPNameQualifier"),
        attr("SPProvidedID"),
    )
}

fn require_utc_instant(element: &SamlElement) -> Result<(), SamlError> {
    let instant = element.required_attr("IssueInstant")?;
    if parse_saml_utc_date_time(&instant).is_none() {
        return Err(SamlError::ProtocolProfile(format!(
            "{} IssueInstant must be a UTC xs:dateTime",
            element.local_name
        )));
    }
    Ok(())
}

fn require_peer_issuer(element: &SamlElement, expected: &str) -> Result<(), SamlError> {
    let issuer = issuer(element).ok_or_else(|| SamlError::issuer_mismatch(expected, None))?;
    if issuer.value != expected {
        return Err(SamlError::issuer_mismatch(expected, Some(&issuer.value)));
    }
    if !issuer_format_is_entity(issuer.format.as_deref()) {
        return Err(SamlError::ProtocolProfile(format!(
            "{} Issuer Format must be omitted or entity",
            element.local_name
        )));
    }
    Ok(())
}

fn local_services(metadata: &Metadata) -> Result<Vec<String>, SamlError> {
    let locations = metadata.soap_manage_name_id_service_locations();
    if locations.is_empty() {
        return Err(SamlError::MissingMetadata("ManageNameIDService".into()));
    }
    Ok(locations)
}

fn require_channel(channel: SoapChannel) -> Result<(), SamlError> {
    if channel.authenticates_peer() {
        Ok(())
    } else {
        Err(SamlError::SoapChannelProtection)
    }
}
