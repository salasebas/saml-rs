use crate::constants::{name_id_format, namespace};
use crate::error::SamlError;
use crate::model::{SamlInstant, Status, StatusMessage};
use crate::xml::any_uri::collapse_whitespace;
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

    pub(crate) fn required_issue_instant(&self) -> Result<SamlInstant, SamlError> {
        let instant = self.required_attr("IssueInstant")?;
        SamlInstant::parse_utc(&instant).ok_or_else(|| {
            SamlError::ProtocolProfile(format!(
                "{} IssueInstant must be a UTC xs:dateTime",
                self.local_name
            ))
        })
    }
}

pub(crate) struct PartyName {
    pub(crate) value: String,
    pub(crate) format: Option<String>,
}

pub(crate) fn parse_saml(xml: &str) -> Result<SamlElement, SamlError> {
    parse_saml_with_limits(xml, XmlLimits::default())
}

pub(crate) fn issuer(element: &SamlElement) -> Option<PartyName> {
    let issuer = element
        .children
        .iter()
        .find(|child| child.is(namespace::ASSERTION, "Issuer"))?;
    if issuer.text.is_empty() {
        return None;
    }
    Some(PartyName {
        value: issuer.text.clone(),
        format: issuer.attr("Format").map(collapse_whitespace),
    })
}

pub(crate) fn issuer_format_is_entity(format: Option<&str>) -> bool {
    match format {
        None => true,
        Some(format) => format == name_id_format::ENTITY,
    }
}

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
    let top = code.attr("Value").ok_or(SamlError::StatusMissing)?;
    let second = code
        .children
        .iter()
        .find(|child| child.is(namespace::PROTOCOL, "StatusCode"))
        .and_then(|child| child.attr("Value"));
    Status::received(top, second)
}

pub(crate) fn read_status_message(response: SamlElement) -> Option<StatusMessage> {
    let status = sole_protocol_child(response, "Status")?;
    let message = sole_protocol_child(status, "StatusMessage")?;
    if !message.children.is_empty() || !message.attrs.is_empty() || message.text.is_empty() {
        return None;
    }
    Some(StatusMessage(message.text))
}

fn sole_protocol_child(parent: SamlElement, name: &str) -> Option<SamlElement> {
    let mut matches = parent
        .children
        .into_iter()
        .filter(|child| child.is(namespace::PROTOCOL, name));
    let child = matches.next()?;
    matches.next().is_none().then_some(child)
}
