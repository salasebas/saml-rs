use crate::constants::{name_id_format, namespace};
use crate::error::SamlError;
use crate::model::{SamlInstant, StatusMessage};
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

pub(crate) fn issuer(element: &SamlElement) -> Result<Option<PartyName>, SamlError> {
    let Some(issuer) = at_most_one_child(element, namespace::ASSERTION, "Issuer")? else {
        return Ok(None);
    };
    if issuer.text.is_empty() {
        return Ok(None);
    }
    Ok(Some(PartyName {
        value: issuer.text.clone(),
        format: issuer.attr("Format").map(collapse_whitespace),
    }))
}

pub(crate) fn issuer_format_is_entity(format: Option<&str>) -> bool {
    match format {
        None => true,
        Some(format) => format == name_id_format::ENTITY,
    }
}

fn at_most_one_child<'a>(
    parent: &'a SamlElement,
    namespace: &str,
    local_name: &str,
) -> Result<Option<&'a SamlElement>, SamlError> {
    let mut matches = parent
        .children
        .iter()
        .filter(|child| child.is(namespace, local_name));
    let child = matches.next();
    if matches.next().is_some() {
        return Err(SamlError::ProtocolProfile(format!(
            "{} allows at most one {local_name}",
            parent.local_name
        )));
    }
    Ok(child)
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
