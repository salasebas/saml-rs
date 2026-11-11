//! SAML protocol elements read with their namespaces, for SOAP exchanges.

use std::ops::Range;

use quick_xml::escape::unescape;
use quick_xml::events::Event;
use quick_xml::name::{Namespace, ResolveResult};
use quick_xml::reader::NsReader;

use crate::constants::{name_id_format, namespace};
use crate::error::SamlError;
use crate::xml::dom::{self, Node, XmlLimits};

pub(crate) struct SamlElement {
    pub(crate) local_name: String,
    pub(crate) namespace: String,
    attributes: Vec<(String, String)>,
    pub(crate) text: String,
    pub(crate) children: Vec<SamlElement>,
    /// Byte range of the element in the parsed XML.
    pub(crate) span: Range<usize>,
}

impl SamlElement {
    pub(crate) fn attr(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
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

pub(crate) fn parse_saml_with_limits(
    xml: &str,
    limits: XmlLimits,
) -> Result<SamlElement, SamlError> {
    let document = dom::parse_with_limits(xml, limits)?;
    let mut elements = resolved_elements(xml, limits)?;
    annotate(&document.root, xml.len(), &mut elements)
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

/// Top-level and second-level `StatusCode` values of a status response.
pub(crate) fn status_codes(response: &SamlElement) -> Result<(String, Option<String>), SamlError> {
    let mut statuses = response
        .children
        .iter()
        .filter(|child| child.is(namespace::PROTOCOL, "Status"));
    let status = statuses.next().ok_or(SamlError::UndefinedStatus)?;
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
        .ok_or(SamlError::UndefinedStatus)?;
    let top = code
        .attr("Value")
        .filter(|value| !value.is_empty())
        .ok_or(SamlError::UndefinedStatus)?
        .to_string();
    let second = code
        .children
        .iter()
        .find(|child| child.is(namespace::PROTOCOL, "StatusCode"))
        .and_then(|child| child.attr("Value"))
        .map(str::to_string);
    Ok((top, second))
}

struct ResolvedElement {
    local_name: String,
    namespace: String,
    unqualified_attributes: Vec<(String, String)>,
}

fn annotate(
    node: &Node,
    xml_len: usize,
    elements: &mut std::vec::IntoIter<ResolvedElement>,
) -> Result<SamlElement, SamlError> {
    let ResolvedElement {
        local_name,
        namespace,
        unqualified_attributes,
    } = elements
        .next()
        .ok_or_else(|| SamlError::Xml("protocol element is missing a namespace".into()))?;
    if local_name != node.local_name {
        return Err(SamlError::Xml(
            "protocol element namespace does not match the element".into(),
        ));
    }
    let mut children = Vec::new();
    for child in &node.children {
        children.push(annotate(child, xml_len, elements)?);
    }
    if node.end < node.start || node.end > xml_len {
        return Err(SamlError::Xml("protocol element is incomplete".into()));
    }
    Ok(SamlElement {
        local_name,
        namespace,
        attributes: unqualified_attributes,
        text: node.text.clone(),
        children,
        span: node.start..node.end,
    })
}

fn resolved_elements(
    xml: &str,
    limits: XmlLimits,
) -> Result<std::vec::IntoIter<ResolvedElement>, SamlError> {
    let mut reader = NsReader::from_str(xml);
    reader
        .resolver_mut()
        .set_max_namespace_bindings(limits.max_attributes_per_element);
    let mut buf = Vec::new();
    let mut names = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(element) | Event::Empty(element)) => {
                let (namespace, local_name) = reader.resolver().resolve_element(element.name());
                let local_name = local_name.as_ref().to_string();
                let namespace = match namespace {
                    ResolveResult::Bound(Namespace(uri)) => unescape(uri)
                        .map_err(|err| SamlError::Xml(err.to_string()))?
                        .into_owned(),
                    ResolveResult::Unbound | ResolveResult::Unknown(_) => String::new(),
                };
                let mut unqualified_attributes = Vec::new();
                for attribute in element.attributes() {
                    let attribute = attribute.map_err(|err| SamlError::Xml(err.to_string()))?;
                    if attribute.key.prefix().is_some() || attribute.key.as_ref() == "xmlns" {
                        continue;
                    }
                    let value = attribute
                        .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                        .map_err(|err| SamlError::Xml(err.to_string()))?
                        .into_owned();
                    unqualified_attributes.push((attribute.key.as_ref().to_string(), value));
                }
                names.push(ResolvedElement {
                    local_name,
                    namespace,
                    unqualified_attributes,
                });
            }
            Ok(Event::DocType(_)) => {
                return Err(SamlError::Xml("DOCTYPE is not allowed".into()));
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(err) => return Err(SamlError::Xml(err.to_string())),
        }
        buf.clear();
    }
    Ok(names.into_iter())
}
