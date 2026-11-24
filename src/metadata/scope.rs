use super::write::MetadataWriter;
use crate::constants::namespace;
use crate::error::SamlError;
use crate::xml::protocol_element::SamlElement;
use crate::xml::{is_xml_char, xs_boolean};

const NAMESPACE: &str = "urn:mace:shibboleth:metadata:1.0";

/// A `shibmd:Scope` declaration in identity provider metadata.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MetadataScope {
    /// Literal scope or regular expression, as published.
    pub value: String,
    /// Whether the publisher marked the value as a regular expression.
    pub regexp: bool,
}

pub(super) fn scope_elements(parent: &SamlElement) -> impl Iterator<Item = &SamlElement> {
    parent
        .children
        .iter()
        .filter(|child| child.is(namespace::METADATA, "Extensions"))
        .flat_map(|extensions| &extensions.children)
        .filter(|extension| extension.is(NAMESPACE, "Scope"))
}

pub(super) fn read_scopes(elements: &[SamlElement]) -> Result<Vec<MetadataScope>, SamlError> {
    elements
        .iter()
        .map(|element| {
            if !element.children.is_empty() {
                return Err(SamlError::Invalid(
                    "shibmd:Scope must contain only text".into(),
                ));
            }
            if element
                .attrs
                .iter()
                .any(|(ns, name, _)| ns.is_some() && name == "regexp")
            {
                return Err(SamlError::Invalid(
                    "shibmd:Scope regexp must be unqualified".into(),
                ));
            }
            let regexp =
                xs_boolean(Some(element.attr("regexp").unwrap_or("false"))).ok_or_else(|| {
                    SamlError::Invalid("shibmd:Scope regexp must be an xs:boolean".into())
                })?;
            Ok(MetadataScope {
                value: element.text.clone(),
                regexp,
            })
        })
        .collect()
}

pub(super) fn write_scopes(
    w: &mut MetadataWriter,
    scopes: &[MetadataScope],
) -> Result<(), SamlError> {
    if scopes.is_empty() {
        return Ok(());
    }
    w.start("Extensions", &[("xmlns:shibmd", NAMESPACE)]);
    for scope in scopes {
        if !scope.value.chars().all(is_xml_char) {
            return Err(SamlError::Invalid(
                "shibmd:Scope contains invalid XML text".into(),
            ));
        }
        let regexp = if scope.regexp { "true" } else { "false" };
        w.text_element_with_attrs("shibmd:Scope", &[("regexp", regexp)], &scope.value);
    }
    w.end("Extensions");
    Ok(())
}
