use crate::constants::namespace;
use crate::util::{camel_case, Value};
use crate::xml::any_uri::collapse_whitespace;
use crate::xml::protocol_element::SamlElement;

pub(super) fn role_endpoints(role: &SamlElement, name: &str, attributes: &[&str]) -> Value {
    Value::Array(endpoint_values(role, name, attributes).collect())
}

pub(super) fn roles_endpoints(roles: &[SamlElement], name: &str, attributes: &[&str]) -> Value {
    Value::Array(
        roles
            .iter()
            .flat_map(|role| endpoint_values(role, name, attributes))
            .collect(),
    )
}

fn endpoint_values<'a>(
    role: &'a SamlElement,
    name: &'a str,
    attributes: &'a [&str],
) -> impl Iterator<Item = Value> + 'a {
    role.children
        .iter()
        .filter(move |child| child.is(namespace::METADATA, name))
        .map(move |endpoint| endpoint_value(endpoint, attributes))
}

fn endpoint_value(endpoint: &SamlElement, attributes: &[&str]) -> Value {
    Value::Object(
        attributes
            .iter()
            .filter_map(|attribute| {
                let value = endpoint.attr(attribute)?;
                Some((
                    camel_case(attribute),
                    Value::Str(collapse_whitespace(value)),
                ))
            })
            .collect(),
    )
}
