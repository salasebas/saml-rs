use std::ops::Range;

use quick_xml::events::{BytesDecl, BytesStart};
use quick_xml::name::{
    Namespace, NamespaceError, NamespaceResolver, PrefixDeclaration, QName, ResolveResult,
};
use quick_xml::XmlVersion;

use super::{check_xml_chars, is_xml_whitespace_char, namespace_error, ParseMode, XmlLimits};
use crate::error::{xml_err, ResourceLimit, SamlError};
use crate::xml::name::is_ncname;

const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";
pub(super) const XMLNS_NAMESPACE: &str = "http://www.w3.org/2000/xmlns/";

#[derive(Debug, Clone)]
pub(crate) struct Element<N, A> {
    pub(crate) namespace: N,
    pub(crate) local_name: String,
    pub(crate) attrs: Vec<A>,
    pub(crate) children: Vec<Self>,
    pub(crate) text: String,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

pub(crate) type Node = Element<(), LocalAttribute>;
pub(crate) type QualifiedElement = Element<String, (Option<String>, String, String)>;

#[derive(Debug, Clone)]
pub(crate) struct LocalAttribute {
    pub(crate) name: String,
    pub(crate) value: String,
    pub(super) qualified: bool,
}

impl Node {
    pub(crate) fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Self> {
        self.children
            .iter()
            .filter(move |child| child.local_name == name)
    }

    pub(crate) fn child_named(&self, name: &str) -> Option<&Self> {
        self.children.iter().find(|child| child.local_name == name)
    }

    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|attribute| attribute.name == name)
            .map(|attribute| attribute.value.as_str())
    }

    pub(crate) fn unqualified_attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|attribute| !attribute.qualified && attribute.name == name)
            .map(|attribute| attribute.value.as_str())
    }
}

pub(super) fn read_element<N, A>(
    e: &BytesStart,
    resolver: &mut NamespaceResolver,
    limits: XmlLimits,
    mode: ParseMode,
    span: Range<usize>,
    element_namespace: impl FnOnce(Option<&str>, &str) -> N,
    attribute: impl Fn(QName<'_>, Option<&str>, String) -> Option<A>,
) -> Result<Element<N, A>, SamlError> {
    begin_scope(resolver)?;
    check_qname(e.name().into_inner())?;
    check_attribute_separation(e.attributes_raw())?;
    let attrs = read_attrs(e, resolver, limits)?;

    let (namespace, local_name) = resolver.resolve_element(e.name());
    check_prefix_declared(&namespace, mode)?;
    let namespace = namespace_uri(&namespace);
    if matches!(mode, ParseMode::StandaloneElement) && namespace == Some(XMLNS_NAMESPACE) {
        return Err(SamlError::xml("element names cannot use the xmlns prefix"));
    }
    let namespace = element_namespace(namespace, local_name.into_inner());
    let mut expanded_names = Vec::with_capacity(attrs.len());
    let mut attributes = Vec::with_capacity(attrs.len());
    for (name, value) in attrs {
        if name.as_namespace_binding().is_some() {
            attributes.extend(attribute(name, Some(XMLNS_NAMESPACE), value));
            continue;
        }
        let (namespace, local_name) = resolver.resolve_attribute(name);
        check_prefix_declared(&namespace, mode)?;
        let expanded_name = (local_name, namespace);
        if expanded_names.contains(&expanded_name) {
            return Err(SamlError::xml(format!(
                "duplicate attribute `{}`",
                name.into_inner()
            )));
        }
        attributes.extend(attribute(name, namespace_uri(&expanded_name.1), value));
        expanded_names.push(expanded_name);
    }

    Ok(Element {
        local_name: local_name.into_inner().to_owned(),
        namespace,
        attrs: attributes,
        children: Vec::new(),
        text: String::new(),
        start: span.start,
        end: span.end,
    })
}

fn begin_scope(resolver: &mut NamespaceResolver) -> Result<(), SamlError> {
    let level = resolver
        .level()
        .checked_add(1)
        .ok_or_else(|| namespace_error(NamespaceError::TooDeeplyNested(usize::from(u16::MAX))))?;
    resolver.set_level(level);
    Ok(())
}

pub(crate) fn push_normalized_namespaces(
    resolver: &mut NamespaceResolver,
    element: &BytesStart<'_>,
) -> Result<(), SamlError> {
    begin_scope(resolver)?;
    for attribute in element.attributes() {
        let attribute = attribute.map_err(xml_err)?;
        if let Some(declaration) = attribute.key.as_namespace_binding() {
            let value = attribute
                .normalized_value(XmlVersion::Implicit1_0)
                .map_err(xml_err)?;
            bind_namespace(resolver, declaration, &value)?;
        }
    }
    Ok(())
}

fn read_attrs<'a>(
    e: &'a BytesStart,
    resolver: &mut NamespaceResolver,
    limits: XmlLimits,
) -> Result<Vec<(QName<'a>, String)>, SamlError> {
    let mut out = Vec::new();
    for attr in e.attributes() {
        if out.len() >= limits.max_attributes_per_element {
            return Err(SamlError::LimitExceeded {
                limit: ResourceLimit::XmlAttributesPerElement,
                maximum: limits.max_attributes_per_element,
            });
        }
        let attr = attr.map_err(xml_err)?;
        check_qname(attr.key.into_inner())?;
        if attr.value.contains('<') {
            return Err(SamlError::xml("`<` is not allowed in an attribute value"));
        }
        let value = attr
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(xml_err)?
            .into_owned();
        if value.len() > limits.max_attribute_value_bytes {
            return Err(SamlError::LimitExceeded {
                limit: ResourceLimit::XmlAttributeValueBytes,
                maximum: limits.max_attribute_value_bytes,
            });
        }
        check_xml_chars(&value)?;
        if let Some(declaration) = attr.key.as_namespace_binding() {
            bind_namespace(resolver, declaration, &value)?;
        }
        out.push((attr.key, value));
    }
    Ok(out)
}

fn namespace_uri<'a>(namespace: &ResolveResult<'a>) -> Option<&'a str> {
    match namespace {
        ResolveResult::Bound(Namespace(uri)) => Some(uri),
        ResolveResult::Unbound | ResolveResult::Unknown(_) => None,
    }
}

fn check_qname(name: &str) -> Result<(), SamlError> {
    if name.splitn(2, ':').all(is_ncname) {
        Ok(())
    } else {
        Err(SamlError::xml(format!(
            "`{name}` is not a qualified XML name"
        )))
    }
}

pub(super) fn validate_declaration(declaration: &BytesDecl<'_>) -> Result<(), SamlError> {
    let error = || SamlError::xml("malformed XML declaration");
    let declaration = BytesStart::from_content(declaration.as_ref(), "xml".len());
    check_attribute_separation(declaration.attributes_raw())?;
    let mut previous = 0;
    for attribute in declaration.attributes() {
        let attribute = attribute.map_err(xml_err)?;
        let order = match (attribute.key.into_inner(), attribute.value.as_ref()) {
            ("version", version)
                if version.strip_prefix("1.").is_some_and(|minor| {
                    !minor.is_empty() && minor.bytes().all(|byte| byte.is_ascii_digit())
                }) =>
            {
                1
            }
            ("encoding", encoding) => {
                let mut bytes = encoding.bytes();
                if !bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
                    || !bytes.all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
                {
                    return Err(error());
                }
                2
            }
            ("standalone", "yes" | "no") => 3,
            _ => return Err(error()),
        };
        if order <= previous || (previous == 0 && order != 1) {
            return Err(error());
        }
        previous = order;
    }
    if previous == 0 {
        return Err(error());
    }
    Ok(())
}

fn check_attribute_separation(attributes: &str) -> Result<(), SamlError> {
    let mut open_quote = None;
    let mut after_value = false;
    for ch in attributes.chars() {
        if after_value && !is_xml_whitespace_char(ch) {
            return Err(SamlError::xml("attributes must be separated by whitespace"));
        }
        after_value = false;
        match open_quote {
            Some(quote) if ch == quote => {
                open_quote = None;
                after_value = true;
            }
            Some(_) => {}
            None if matches!(ch, '"' | '\'') => open_quote = Some(ch),
            None => {}
        }
    }
    Ok(())
}

fn check_prefix_declared(resolved: &ResolveResult<'_>, mode: ParseMode) -> Result<(), SamlError> {
    match (resolved, mode) {
        (
            ResolveResult::Unknown(prefix),
            ParseMode::Document | ParseMode::StandaloneElement | ParseMode::Roots,
        ) => Err(SamlError::xml(format!(
            "namespace prefix `{prefix}` is not declared"
        ))),
        (ResolveResult::Unknown(_), ParseMode::Fragment)
        | (ResolveResult::Unbound | ResolveResult::Bound(_), _) => Ok(()),
    }
}

fn bind_namespace(
    resolver: &mut NamespaceResolver,
    declaration: PrefixDeclaration,
    namespace: &str,
) -> Result<(), SamlError> {
    if declaration == PrefixDeclaration::Default
        && matches!(namespace, XML_NAMESPACE | XMLNS_NAMESPACE)
    {
        return Err(SamlError::xml(format!(
            "namespace `{namespace}` cannot be the default namespace"
        )));
    }
    if let (PrefixDeclaration::Named(prefix), "") = (declaration, namespace) {
        return Err(SamlError::xml(format!(
            "namespace prefix `{prefix}` cannot be undeclared"
        )));
    }
    resolver
        .add(declaration, Namespace(namespace))
        .map_err(namespace_error)
}
