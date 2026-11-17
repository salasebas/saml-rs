use crate::error::{xml_err, SamlError};
use crate::util::{camel_case, Value};
use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};

/// Replaces the endpoint XML fragments under `key` with their `attributes`,
/// whitespace collapsed as for `xs:anyURI`.
pub(super) fn read_endpoints(
    meta: &mut Value,
    key: &str,
    attributes: &[&str],
) -> Result<(), SamlError> {
    if let Some(fragments) = meta.get(key) {
        let endpoints = parse_endpoint_fragments(fragments, attributes)?;
        meta.insert(key, endpoints);
    }
    Ok(())
}

pub(super) fn parse_endpoint_fragments(
    value: &Value,
    attributes: &[&str],
) -> Result<Value, SamlError> {
    match value {
        Value::Null => Ok(Value::Null),
        Value::Str(xml) => parse_endpoint_fragment(xml, attributes),
        Value::Array(items) => items
            .iter()
            .map(|item| parse_endpoint_fragments(item, attributes))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(_) => Err(SamlError::xml("expected endpoint XML fragment")),
    }
}

fn parse_endpoint_fragment(xml: &str, attributes: &[&str]) -> Result<Value, SamlError> {
    let mut reader = Reader::from_str(xml);
    let element = match reader.read_event().map_err(xml_err)? {
        Event::Start(element) | Event::Empty(element) => element,
        _ => return Err(SamlError::xml("expected endpoint element")),
    };
    let mut values: Vec<_> = attributes
        .iter()
        .map(|name| (camel_case(name), None))
        .collect();
    for attribute in element.attributes() {
        let attribute = attribute.map_err(xml_err)?;
        let Some(index) = attributes
            .iter()
            .position(|name| *name == attribute.key.as_ref())
        else {
            continue;
        };
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(xml_err)?;
        values[index].1 = Some(Value::Str(
            value
                .split([' ', '\t', '\r', '\n'])
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(" "),
        ));
    }
    Ok(Value::Object(
        values
            .into_iter()
            .filter_map(|(key, value)| value.map(|value| (key, value)))
            .collect(),
    ))
}
