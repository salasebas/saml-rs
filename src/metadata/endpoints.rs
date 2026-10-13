use crate::error::SamlError;
use crate::util::{camel_case, Value};
use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};

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
        Value::Object(_) => Err(SamlError::Xml("expected endpoint XML fragment".into())),
    }
}

fn parse_endpoint_fragment(xml: &str, attributes: &[&str]) -> Result<Value, SamlError> {
    let mut reader = Reader::from_str(xml);
    let element = match reader
        .read_event()
        .map_err(|error| SamlError::Xml(error.to_string()))?
    {
        Event::Start(element) | Event::Empty(element) => element,
        _ => return Err(SamlError::Xml("expected endpoint element".into())),
    };
    let mut values: Vec<_> = attributes
        .iter()
        .map(|name| (camel_case(name), None))
        .collect();
    for attribute in element.attributes() {
        let attribute = attribute.map_err(|error| SamlError::Xml(error.to_string()))?;
        let Some(index) = attributes
            .iter()
            .position(|name| *name == attribute.key.as_ref())
        else {
            continue;
        };
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|error| SamlError::Xml(error.to_string()))?;
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
