//! `ManageNameIDRequest` and `ManageNameIDResponse` XML for every binding.

use crate::constants::{name_id_format, namespace};
use crate::entity::{now_iso8601, EntitySetting};
use crate::error::SamlError;
use crate::model::{
    is_name_id_format, validate_issued_name_id_length, validate_name_id_format, NameId, Status,
};
use crate::template::validate_tag_prefix;
use crate::xml::write::XmlWriter;

use super::NameIdChange;

/// The provider that sends a `ManageNameIDRequest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Requester {
    IdentityProvider,
    ServiceProvider,
}

/// Namespace prefixes for the protocol and assertion elements.
pub(crate) struct Prefixes<'a> {
    protocol: &'a str,
    assertion: &'a str,
}

impl Prefixes<'static> {
    pub(crate) const SOAP: Self = Self {
        protocol: "samlp",
        assertion: "saml",
    };
}

impl<'a> Prefixes<'a> {
    pub(crate) fn of(setting: &'a EntitySetting) -> Result<Self, SamlError> {
        validate_tag_prefix("protocol", &setting.tag_prefix_protocol)?;
        validate_tag_prefix("assertion", &setting.tag_prefix_assertion)?;
        Ok(Self {
            protocol: &setting.tag_prefix_protocol,
            assertion: &setting.tag_prefix_assertion,
        })
    }

    fn protocol(&self, local: &str) -> String {
        format!("{}:{local}", self.protocol)
    }

    fn assertion(&self, local: &str) -> String {
        format!("{}:{local}", self.assertion)
    }
}

/// A `ManageNameIDRequest` to render.
pub(crate) struct RequestXml<'a> {
    pub(crate) id: &'a str,
    pub(crate) issuer: &'a str,
    pub(crate) destination: &'a str,
    pub(crate) name_id: &'a NameId,
    pub(crate) change: &'a NameIdChange,
    pub(crate) requester: Requester,
    pub(crate) default_format: Option<&'a str>,
    pub(crate) idp_entity_id: &'a str,
    pub(crate) sp_entity_id: &'a str,
}

/// A `ManageNameIDResponse` to render.
pub(crate) struct ResponseXml<'a> {
    pub(crate) id: &'a str,
    pub(crate) issuer: &'a str,
    pub(crate) destination: Option<&'a str>,
    pub(crate) in_response_to: &'a str,
    pub(crate) status: &'a Status,
}

pub(crate) fn render_request(
    prefixes: &Prefixes<'_>,
    request: &RequestXml<'_>,
) -> Result<String, SamlError> {
    let name_id = request.name_id;
    let format = name_id
        .format()
        .map(|format| format.as_uri())
        .or(match request.requester {
            Requester::IdentityProvider => request.default_format,
            Requester::ServiceProvider => None,
        });
    if is_name_id_format(format, name_id_format::TRANSIENT) {
        return Err(SamlError::ProtocolProfile(
            "name identifier management is not used with a transient NameID".into(),
        ));
    }
    validate_name_id_format(format)?;
    validate_issued_name_id_length(format, name_id.value())?;
    if let (Requester::IdentityProvider, NameIdChange::NewId(value)) =
        (request.requester, request.change)
    {
        validate_issued_name_id_length(format, value)?;
    }
    let persistent = is_name_id_format(format, name_id_format::PERSISTENT);
    let name_qualifier = name_id
        .name_qualifier()
        .or(persistent.then_some(request.idp_entity_id));
    let sp_name_qualifier = name_id
        .sp_name_qualifier()
        .or(persistent.then_some(request.sp_entity_id));

    let root = prefixes.protocol("ManageNameIDRequest");
    let xmlns_protocol = format!("xmlns:{}", prefixes.protocol);
    let xmlns_assertion = format!("xmlns:{}", prefixes.assertion);
    let issue_instant = now_iso8601();
    let mut writer = XmlWriter::new();
    writer.start(
        &root,
        &[
            (xmlns_protocol.as_str(), namespace::PROTOCOL),
            (xmlns_assertion.as_str(), namespace::ASSERTION),
            ("ID", request.id),
            ("Version", "2.0"),
            ("IssueInstant", issue_instant.as_str()),
            ("Destination", request.destination),
        ],
    );
    writer.text_element(&prefixes.assertion("Issuer"), &[], request.issuer);
    let name_id_attrs: Vec<(&str, &str)> = [
        ("Format", format),
        ("NameQualifier", name_qualifier),
        ("SPNameQualifier", sp_name_qualifier),
        ("SPProvidedID", name_id.sp_provided_id()),
    ]
    .into_iter()
    .filter_map(|(name, value)| value.map(|value| (name, value)))
    .collect();
    writer.text_element(
        &prefixes.assertion("NameID"),
        &name_id_attrs,
        name_id.value(),
    );
    match request.change {
        NameIdChange::NewId(value) => {
            writer.text_element(&prefixes.protocol("NewID"), &[], value);
        }
        NameIdChange::Terminate => writer.empty(&prefixes.protocol("Terminate"), &[]),
    }
    writer.end(&root);
    Ok(writer.finish())
}

pub(crate) fn render_response(prefixes: &Prefixes<'_>, response: &ResponseXml<'_>) -> String {
    let root = prefixes.protocol("ManageNameIDResponse");
    let status_name = prefixes.protocol("Status");
    let status_code_name = prefixes.protocol("StatusCode");
    let xmlns_protocol = format!("xmlns:{}", prefixes.protocol);
    let xmlns_assertion = format!("xmlns:{}", prefixes.assertion);
    let issue_instant = now_iso8601();
    let mut attributes = vec![
        (xmlns_protocol.as_str(), namespace::PROTOCOL),
        (xmlns_assertion.as_str(), namespace::ASSERTION),
        ("ID", response.id),
        ("Version", "2.0"),
        ("IssueInstant", issue_instant.as_str()),
    ];
    if let Some(destination) = response.destination {
        attributes.push(("Destination", destination));
    }
    attributes.push(("InResponseTo", response.in_response_to));
    let mut writer = XmlWriter::new();
    writer.start(&root, &attributes);
    writer.text_element(&prefixes.assertion("Issuer"), &[], response.issuer);
    writer.start(&status_name, &[]);
    let top_level = [("Value", response.status.top_level().as_uri())];
    match response.status.subordinate() {
        Some(subordinate) => {
            writer.start(&status_code_name, &top_level);
            writer.empty(&status_code_name, &[("Value", subordinate.as_uri())]);
            writer.end(&status_code_name);
        }
        None => writer.empty(&status_code_name, &top_level),
    }
    writer.end(&status_name);
    writer.end(&root);
    writer.finish()
}
