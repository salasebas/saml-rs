use crate::constants::namespace;
use crate::error::SamlError;
use crate::util::{camel_case, Value};
use crate::xml::any_uri::collapse_whitespace;
use crate::xml::protocol_element::SamlElement;
use crate::xml::{is_xs_integer, xs_boolean};

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

pub(super) fn check_indexed_endpoints(role: &SamlElement, name: &str) -> Result<(), SamlError> {
    for endpoint in endpoint_elements(role, name) {
        let fault = if endpoint.attr("Binding").is_none() {
            "has no Binding"
        } else if endpoint.attr("Location").is_none_or(str::is_empty) {
            "has no Location"
        } else if !endpoint.attr("index").is_some_and(is_xs_integer) {
            "has no integer index"
        } else if endpoint
            .attr("isDefault")
            .is_some_and(|is_default| xs_boolean(Some(is_default)).is_none())
        {
            "has an isDefault that is not an xs:boolean"
        } else {
            continue;
        };
        return Err(SamlError::Invalid(format!("{name} {fault}")));
    }
    Ok(())
}

fn endpoint_elements<'a>(
    role: &'a SamlElement,
    name: &'a str,
) -> impl Iterator<Item = &'a SamlElement> + 'a {
    role.children
        .iter()
        .filter(move |child| child.is(namespace::METADATA, name))
}

fn endpoint_values<'a>(
    role: &'a SamlElement,
    name: &'a str,
    attributes: &'a [&str],
) -> impl Iterator<Item = Value> + 'a {
    endpoint_elements(role, name).map(move |endpoint| endpoint_value(endpoint, attributes))
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
