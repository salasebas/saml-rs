//! Name identifier management over the SOAP binding.
//!
//! The identity provider sends `ManageNameIDRequest` to a service provider and
//! reads its `ManageNameIDResponse`, or answers a service provider's request.

use std::sync::Arc;

use crate::config::{EntityId, IdentifierEncryptionPolicy, SpDescriptor};
use crate::constants::{namespace, status_code};
use crate::entity::{generate_id, EntitySetting};
use crate::error::SamlError;
use crate::metadata::Metadata;
use crate::model::{
    name_id_format_from_uri, EndpointUrl, MessageId, NameId, Received, ReplayKey, SamlInstant,
    SamlValidationContext, Status, SubordinateStatusCode,
};
use crate::soap::{read_soap_body, SoapChannel, SoapProtocolMessage, SoapRequest, SoapResponse};
use crate::xml::parse_saml_utc_date_time;
use crate::xml::protocol_element::{
    issuer, issuer_format_is_entity, parse_saml_with_limits, status_codes, SamlElement,
};
use crate::xml::XmlLimits;

mod encryption;
pub(crate) mod redirect;
pub(crate) mod xml;

pub(crate) use encryption::protect_request;
use encryption::{decrypt_name_id, decrypt_new_id};
use xml::{render_request, render_response, Prefixes, RequestXml, Requester, ResponseXml};

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

/// `ManageNameIDRequest` received from a peer provider.
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

    /// Provider that sent the request.
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

/// Marker for a `ManageNameIDResponse` in browser input and outbound actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManageNameIdResponse {}

/// Result of reading a peer's `ManageNameIDRequest`.
///
/// `Response` is the answer for the binding: [`SoapResponse`] over SOAP, and
/// [`Outbound<ManageNameIdResponse>`](crate::Outbound) over HTTP-Redirect.
#[derive(Debug, Clone)]
pub enum ReceivedNameIdManagement<Response = SoapResponse> {
    /// Apply the change, then answer with
    /// [`Saml::respond_name_id_management`](crate::Saml::respond_name_id_management),
    /// or its `_redirect` counterpart for HTTP-Redirect.
    Request(Box<Received<ManageNameIdRequest>>),
    /// The provider answered the request without processing it.
    Refused(RefusedNameIdManagement<Response>),
}

/// Why a provider answered a `ManageNameIDRequest` without processing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameIdManagementRefusal {
    /// The request `Version` is not `2.0`. The status is `VersionMismatch`.
    VersionMismatch,
    /// The request's `EncryptedID` does not decrypt, with this provider's
    /// decryption key, to one `NameID`. The status is `Requester` with
    /// `UnknownPrincipal`.
    UndecryptableIdentifier,
    /// The request's `NewEncryptedID` does not decrypt, with this provider's
    /// decryption key, to one `NewID`. The status is `Requester`.
    UndecryptableNewIdentifier,
}

impl NameIdManagementRefusal {
    pub(crate) fn status(self) -> Status {
        match self {
            Self::VersionMismatch => Status::version_mismatch(),
            Self::UndecryptableIdentifier => {
                Status::requester().with_subordinate(SubordinateStatusCode::unknown_principal())
            }
            Self::UndecryptableNewIdentifier => Status::requester(),
        }
    }
}

/// `ManageNameIDResponse` returned for a request that was not processed.
#[derive(Debug, Clone)]
pub struct RefusedNameIdManagement<Response = SoapResponse> {
    response: Response,
    reason: NameIdManagementRefusal,
    decryption_error: Option<Arc<SamlError>>,
}

impl<Response> RefusedNameIdManagement<Response> {
    pub(crate) fn new(
        response: Response,
        reason: NameIdManagementRefusal,
        decryption_error: Option<SamlError>,
    ) -> Self {
        Self {
            response,
            reason,
            decryption_error: decryption_error.map(Arc::new),
        }
    }

    /// Response to return to the requester.
    pub fn response(&self) -> &Response {
        &self.response
    }

    /// Why the request was not processed.
    pub fn reason(&self) -> NameIdManagementRefusal {
        self.reason
    }

    /// Why an `EncryptedID` or `NewEncryptedID` did not decrypt, for
    /// [`NameIdManagementRefusal::UndecryptableIdentifier`] and
    /// [`NameIdManagementRefusal::UndecryptableNewIdentifier`].
    ///
    /// The error stays local: the response carries only the SAML status. A
    /// missing decryption key or an unreadable key is reported here.
    pub fn decryption_error(&self) -> Option<&SamlError> {
        self.decryption_error.as_deref()
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
    xml_limits: XmlLimits,
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
        let body = read_soap_body(response_envelope, self.xml_limits)?;
        if body.local_name != "ManageNameIDResponse" || body.namespace != namespace::PROTOCOL {
            return Err(SamlError::ProtocolProfile(
                "SOAP body must be a ManageNameIDResponse".into(),
            ));
        }
        let response = parse_saml_with_limits(&body.xml, self.xml_limits)?;
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
        require_one_status_code(&response)?;
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
    pub(crate) setting: &'a EntitySetting,
}

pub(crate) fn start(
    idp: &LocalIdentityProvider<'_>,
    service_provider: &SpDescriptor,
    name_id: &NameId,
    change: &NameIdChange,
    identifier_encryption: IdentifierEncryptionPolicy,
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
    let request_id = generate_id();
    let xml = render_request(
        &Prefixes::SOAP,
        &RequestXml {
            id: &request_id,
            issuer: idp.entity_id,
            destination: &destination,
            name_id,
            change,
            requester: Requester::IdentityProvider,
            default_format: idp.setting.default_name_id_format(),
            idp_entity_id: idp.entity_id,
            sp_entity_id,
        },
    )?;
    let xml = protect_request(
        xml,
        identifier_encryption,
        idp.setting,
        service_provider.metadata(),
    )?;
    let request = SoapProtocolMessage::request(EndpointUrl::try_new(destination)?, &xml)?;
    Ok(StartedNameIdManagement {
        request,
        request_id,
        service_provider: sp_entity_id.to_string(),
        xml_limits: idp.setting.xml_limits,
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
    let body = read_soap_body(request_envelope, idp.setting.xml_limits)?;
    if body.local_name != "ManageNameIDRequest" || body.namespace != namespace::PROTOCOL {
        return Err(SamlError::ProtocolProfile(
            "SOAP body must be a ManageNameIDRequest".into(),
        ));
    }
    let request = parse_saml_with_limits(&body.xml, idp.setting.xml_limits)?;
    let id = MessageId::try_new(request.required_attr("ID")?)?;
    let version = request.required_attr("Version")?;
    let issue_instant = require_utc_instant(&request)?;
    if version != "2.0" {
        return refused(
            idp.entity_id,
            &id,
            NameIdManagementRefusal::VersionMismatch,
            None,
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
    validation.check_manage_name_id_request_issue_instant(&issue_instant)?;
    validation.check_and_store_message_replay(ReplayKey::ManageNameIdRequestId(id.clone()))?;
    match plaintext_content(&body.xml, identifier, change, idp.setting) {
        Ok((name_id, change)) => Ok(ReceivedNameIdManagement::Request(Box::new(Received::new(
            ManageNameIdRequest {
                id,
                issuer: sp_entity_id.clone(),
                name_id,
                change,
            },
        )))),
        Err(undecryptable) => refused(
            idp.entity_id,
            &id,
            undecryptable.reason,
            Some(undecryptable.error),
        ),
    }
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
    reason: NameIdManagementRefusal,
    decryption_error: Option<SamlError>,
) -> Result<ReceivedNameIdManagement, SamlError> {
    Ok(ReceivedNameIdManagement::Refused(
        RefusedNameIdManagement::new(
            response(idp_entity_id, in_response_to, &reason.status())?,
            reason,
            decryption_error,
        ),
    ))
}

fn response(
    idp_entity_id: &str,
    in_response_to: &MessageId,
    status: &Status,
) -> Result<SoapResponse, SamlError> {
    SoapResponse::new(&render_response(
        &Prefixes::SOAP,
        &ResponseXml {
            id: &generate_id(),
            issuer: idp_entity_id,
            destination: None,
            in_response_to: in_response_to.as_str(),
            status,
        },
    ))
}

pub(crate) enum Identifier {
    Plain(NameId),
    Encrypted,
}

pub(crate) enum Change {
    Plain(NameIdChange),
    Encrypted,
}

pub(crate) fn identifier_and_change(
    request: &SamlElement,
) -> Result<(Identifier, Change), SamlError> {
    let mut content = request.children.iter().peekable();
    for (element_namespace, local_name) in [
        (namespace::ASSERTION, "Issuer"),
        (namespace::DSIG, "Signature"),
        (namespace::PROTOCOL, "Extensions"),
    ] {
        content.next_if(|child| child.is(element_namespace, local_name));
    }
    let malformed = || {
        SamlError::ProtocolProfile(
            "ManageNameIDRequest requires one NameID or EncryptedID and one NewID, NewEncryptedID, or Terminate, after at most one Issuer, Signature, and Extensions in that order"
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

/// An `EncryptedID` or `NewEncryptedID` that did not decrypt.
pub(crate) struct Undecryptable {
    pub(crate) reason: NameIdManagementRefusal,
    pub(crate) error: SamlError,
}

/// The identifier and change of the request `xml`, with `EncryptedID` and
/// `NewEncryptedID` decrypted by the receiver's decryption key.
pub(crate) fn plaintext_content(
    xml: &str,
    identifier: Identifier,
    change: Change,
    setting: &EntitySetting,
) -> Result<(NameId, NameIdChange), Undecryptable> {
    let name_id = match identifier {
        Identifier::Plain(name_id) => name_id,
        Identifier::Encrypted => decrypt_name_id(xml, setting).map_err(|error| Undecryptable {
            reason: NameIdManagementRefusal::UndecryptableIdentifier,
            error,
        })?,
    };
    let change = match change {
        Change::Plain(change) => change,
        Change::Encrypted => {
            NameIdChange::NewId(decrypt_new_id(xml, setting).map_err(|error| Undecryptable {
                reason: NameIdManagementRefusal::UndecryptableNewIdentifier,
                error,
            })?)
        }
    };
    Ok((name_id, change))
}

pub(crate) fn require_one_status_code(response: &SamlElement) -> Result<(), SamlError> {
    let statuses: Vec<&SamlElement> = response
        .children
        .iter()
        .filter(|child| child.is(namespace::PROTOCOL, "Status"))
        .collect();
    let codes = match statuses.as_slice() {
        [status] => status
            .children
            .iter()
            .filter(|child| child.is(namespace::PROTOCOL, "StatusCode"))
            .count(),
        _ => 0,
    };
    if codes == 1 {
        return Ok(());
    }
    Err(SamlError::ProtocolProfile(
        "ManageNameIDResponse requires one Status with one StatusCode".into(),
    ))
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

fn require_utc_instant(element: &SamlElement) -> Result<SamlInstant, SamlError> {
    let instant = element.required_attr("IssueInstant")?;
    let instant = parse_saml_utc_date_time(&instant).ok_or_else(|| {
        SamlError::ProtocolProfile(format!(
            "{} IssueInstant must be a UTC xs:dateTime",
            element.local_name
        ))
    })?;
    SamlInstant::try_new(instant)
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
