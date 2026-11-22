//! SAML protocol elements read with their namespaces, for SOAP exchanges.

use crate::constants::{name_id_format, namespace};
use crate::error::SamlError;
use crate::model::Status;
use crate::xml::dom::XmlLimits;
pub(crate) use crate::xml::dom::{
    parse_qualified_document as parse_saml_with_limits, QualifiedElement as SamlElement,
};

impl SamlElement {
    pub(crate) fn attr_ns(&self, namespace: &str, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(ns, key, _)| ns.as_deref() == Some(namespace) && key == name)
            .map(|(_, _, value)| value.as_str())
    }

    pub(crate) fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(ns, key, _)| ns.is_none() && key == name)
            .map(|(_, _, value)| value.as_str())
    }

    pub(crate) fn required_attr(&self, name: &str) -> Result<String, SamlError> {
        self.attr(name)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                SamlError::ProtocolProfile(format!(
                    "{} is missing required attribute {name}",
                    self.local_name
                ))
            })
    }

    pub(crate) fn is(&self, namespace: &str, local_name: &str) -> bool {
        self.namespace == namespace && self.local_name == local_name
    }
}

pub(crate) struct PartyName {
    pub(crate) value: String,
    pub(crate) format: Option<String>,
}

pub(crate) fn parse_saml(xml: &str) -> Result<SamlElement, SamlError> {
    parse_saml_with_limits(xml, XmlLimits::default())
}

/// The first non-empty `saml:Issuer` child.
pub(crate) fn issuer(element: &SamlElement) -> Option<PartyName> {
    let issuer = element
        .children
        .iter()
        .find(|child| child.is(namespace::ASSERTION, "Issuer"))?;
    let value = issuer.text.trim();
    if value.is_empty() {
        return None;
    }
    Some(PartyName {
        value: value.to_string(),
        format: issuer.attr("Format").map(str::to_string),
    })
}

pub(crate) fn issuer_format_is_entity(format: Option<&str>) -> bool {
    match format {
        None => true,
        Some(format) => format == name_id_format::ENTITY,
    }
}

/// `Status` of a status response.
pub(crate) fn read_status(response: &SamlElement) -> Result<Status, SamlError> {
    let mut statuses = response
        .children
        .iter()
        .filter(|child| child.is(namespace::PROTOCOL, "Status"));
    let status = statuses.next().ok_or(SamlError::StatusMissing)?;
    if statuses.next().is_some() {
        return Err(SamlError::ProtocolProfile(format!(
            "{} requires one Status",
            response.local_name
        )));
    }
    let code = status
        .children
        .iter()
        .find(|child| child.is(namespace::PROTOCOL, "StatusCode"))
        .ok_or(SamlError::StatusMissing)?;
    let top = code
        .attr("Value")
        .filter(|value| !value.is_empty())
        .ok_or(SamlError::StatusMissing)?;
    let second = code
        .children
        .iter()
        .find(|child| child.is(namespace::PROTOCOL, "StatusCode"))
        .and_then(|child| child.attr("Value"));
    Status::received(top, second)
}
