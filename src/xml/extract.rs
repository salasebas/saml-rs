//! XML field extraction over the local DOM.
//!
//! Operates directly on the [`super::dom`] tree, implementing the `local-name()`
//! path subset used by the SAML field definitions: absolute element paths, `~`
//! wildcard (substring match on local-name), attribute selection (0/1/N),
//! whole-node context capture, `index`+`attributePath` aggregation, and
//! multi-path union.

use super::dom::{self, Node, XmlLimits};
use crate::error::SamlError;
use crate::util::{camel_case, uniq, zip_object, Value};

/// Element path: a single chain, or several chains whose text is unioned.
#[derive(Debug, Clone)]
pub enum LocalPath {
    /// One element chain.
    Single(Vec<String>),
    /// Several chains (text values unioned and de-duplicated).
    Multi(Vec<Vec<String>>),
}

/// A single extraction directive.
#[derive(Debug, Clone)]
pub struct ExtractorField {
    /// Result key.
    pub key: String,
    /// Element path.
    pub local_path: LocalPath,
    /// Attribute names to read (0 → text, 1 → value, N → camelCased object).
    pub attributes: Vec<String>,
    /// Key attribute(s) for aggregation.
    pub index: Option<Vec<String>>,
    /// Child element chain whose value is aggregated under the index key.
    pub attribute_path: Option<Vec<String>>,
    /// Capture the whole matched node's source instead of its value.
    pub context: bool,
    /// Parse this XML instead of the root document.
    pub shortcut: Option<String>,
}

fn to_vec(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

impl ExtractorField {
    /// New field with a single element path and no attributes.
    pub fn new(key: &str, path: &[&str]) -> Self {
        Self {
            key: key.to_string(),
            local_path: LocalPath::Single(to_vec(path)),
            attributes: Vec::new(),
            index: None,
            attribute_path: None,
            context: false,
            shortcut: None,
        }
    }

    /// Multi-path field (text union).
    pub fn multi(key: &str, paths: &[&[&str]]) -> Self {
        Self {
            key: key.to_string(),
            local_path: LocalPath::Multi(paths.iter().map(|p| to_vec(p)).collect()),
            attributes: Vec::new(),
            index: None,
            attribute_path: None,
            context: false,
            shortcut: None,
        }
    }

    /// Set the attributes to read.
    pub fn attrs(mut self, attributes: &[&str]) -> Self {
        self.attributes = to_vec(attributes);
        self
    }

    /// Capture the whole node source.
    pub fn with_context(mut self) -> Self {
        self.context = true;
        self
    }

    /// Configure `index` + `attributePath` aggregation.
    pub fn aggregate(mut self, index: &[&str], attribute_path: &[&str]) -> Self {
        self.index = Some(to_vec(index));
        self.attribute_path = Some(to_vec(attribute_path));
        self
    }

    /// Parse `xml` instead of the root document for this field.
    pub fn with_shortcut(mut self, xml: &str) -> Self {
        self.shortcut = Some(xml.to_string());
        self
    }
}

fn seg_matches(local: &str, seg: &str) -> bool {
    match seg.strip_prefix('~') {
        Some(sub) => local.contains(sub),
        None => local == seg,
    }
}

/// Apply an absolute path: the first segment matches the root element itself.
fn select_path<'a>(root: &'a Node, path: &[String]) -> Vec<&'a Node> {
    let Some((first, rest)) = path.split_first() else {
        return Vec::new();
    };
    if !seg_matches(&root.local_name, first) {
        return Vec::new();
    }
    let mut current = vec![root];
    for seg in rest {
        current = current
            .iter()
            .flat_map(|n| n.children.iter())
            .filter(|c| seg_matches(&c.local_name, seg))
            .collect();
    }
    current
}

/// Descend through child element names (used for `attributePath`).
fn descend<'a>(node: &'a Node, names: &[String]) -> Vec<&'a Node> {
    let mut current = vec![node];
    for name in names {
        current = current
            .iter()
            .flat_map(|n| n.children.iter())
            .filter(|c| seg_matches(&c.local_name, name))
            .collect();
    }
    current
}

/// Collapse a single-element vec to a scalar, otherwise to an array.
fn one_or_array(mut values: Vec<Value>) -> Value {
    if values.len() == 1 {
        values.pop().unwrap_or(Value::Null)
    } else {
        Value::Array(values)
    }
}

fn aggregate(
    nodes: &[&Node],
    index: &[String],
    attribute_path: &[String],
    attributes: &[String],
) -> Value {
    let key_attr = index.first().map(String::as_str).unwrap_or_default();
    let mut keys: Vec<String> = Vec::new();
    let mut values: Vec<Value> = Vec::new();
    for node in nodes {
        keys.push(node.attr(key_attr).unwrap_or_default().to_string());
        let targets = descend(node, attribute_path);
        let vals: Vec<Value> = if attributes.is_empty() {
            targets.iter().map(|t| Value::Str(t.text.clone())).collect()
        } else {
            let attr = &attributes[0];
            targets
                .iter()
                .filter_map(|t| t.attr(attr))
                .map(|v| Value::Str(v.to_string()))
                .collect()
        };
        values.push(one_or_array(vals));
    }
    zip_object(&keys, values, false)
}

fn extract_field(src: &str, root: &Node, field: &ExtractorField) -> Value {
    let path = match &field.local_path {
        LocalPath::Multi(paths) => {
            let mut texts = Vec::new();
            for p in paths {
                for n in select_path(root, p) {
                    texts.push(n.text.clone());
                }
            }
            return Value::Array(uniq(texts).into_iter().map(Value::Str).collect());
        }
        LocalPath::Single(p) => p,
    };

    let nodes = select_path(root, path);

    if let (Some(index), Some(attribute_path)) = (&field.index, &field.attribute_path) {
        return aggregate(&nodes, index, attribute_path, &field.attributes);
    }

    if field.context {
        return match nodes.len() {
            0 => Value::Null,
            1 => Value::Str(src[nodes[0].start..nodes[0].end].to_string()),
            _ => Value::Array(
                nodes
                    .iter()
                    .map(|n| Value::Str(src[n.start..n.end].to_string()))
                    .collect(),
            ),
        };
    }

    if field.attributes.len() > 1 {
        let objs: Vec<Value> = nodes
            .iter()
            .map(|n| {
                let entries = field
                    .attributes
                    .iter()
                    .filter_map(|a| {
                        n.attr(a)
                            .map(|v| (camel_case(a), Value::Str(v.to_string())))
                    })
                    .collect();
                Value::Object(entries)
            })
            .collect();
        return one_or_array(objs);
    }

    if field.attributes.len() == 1 {
        let attr = &field.attributes[0];
        return match nodes.iter().find_map(|n| n.attr(attr)) {
            Some(v) => Value::Str(v.to_string()),
            None => Value::Null,
        };
    }

    match nodes.len() {
        0 => Value::Null,
        1 => Value::Str(nodes[0].text.clone()),
        _ => Value::Array(nodes.iter().map(|n| Value::Str(n.text.clone())).collect()),
    }
}

/// Extract `fields` from `xml`, returning a [`Value::Object`] keyed by field key.
pub fn extract(xml: &str, fields: &[ExtractorField]) -> Result<Value, SamlError> {
    extract_with_limits(xml, fields, XmlLimits::default())
}

/// Extract `fields` from `xml` with explicit parser resource limits.
pub fn extract_with_limits(
    xml: &str,
    fields: &[ExtractorField],
    limits: XmlLimits,
) -> Result<Value, SamlError> {
    let root_doc = dom::parse_with_limits(xml, limits)?;
    let mut out: Vec<(String, Value)> = Vec::new();
    for field in fields {
        let value = match &field.shortcut {
            Some(sc) => {
                let doc = dom::parse_with_limits(sc, limits)?;
                extract_field(sc, &doc.root, field)
            }
            None => extract_field(xml, &root_doc.root, field),
        };
        out.push((field.key.clone(), value));
    }
    Ok(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::fields;

    const RESPONSE: &str = include_str!("../../tests/fixtures/response.xml");
    const SPMETA: &str = include_str!("../../tests/fixtures/spmeta.xml");

    fn assertion_of(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
        let field = ExtractorField::new("a", &["Response", "Assertion"]).with_context();
        let value = extract(xml, std::slice::from_ref(&field))?;
        Ok(value.get_str("a").ok_or("assertion present")?.to_string())
    }

    #[test]
    fn camel_case_matches_camelcase_lib() {
        assert_eq!(camel_case("ID"), "id");
        assert_eq!(camel_case("IssueInstant"), "issueInstant");
        assert_eq!(camel_case("SessionNotOnOrAfter"), "sessionNotOnOrAfter");
        assert_eq!(camel_case("WantAssertionsSigned"), "wantAssertionsSigned");
        assert_eq!(camel_case("isDefault"), "isDefault");
        assert_eq!(
            camel_case("AssertionConsumerServiceURL"),
            "assertionConsumerServiceUrl"
        );
    }

    #[test]
    fn multiple_and_single_attributes() -> Result<(), Box<dyn std::error::Error>> {
        let result = extract(
            RESPONSE,
            &[ExtractorField::new("response", &["Response"]).attrs(&["ID", "Destination"])],
        )?;
        assert_eq!(
            result.get_str("response.id"),
            Some("_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6")
        );
        assert_eq!(
            result.get_str("response.destination"),
            Some("http://sp.example.com/demo1/index.php?acs")
        );

        let status = extract(
            RESPONSE,
            &[
                ExtractorField::new("statusCode", &["Response", "Status", "StatusCode"])
                    .attrs(&["Value"]),
            ],
        )?;
        assert_eq!(
            status.get_str("statusCode"),
            Some("urn:oasis:names:tc:SAML:2.0:status:Success")
        );
        Ok(())
    }

    #[test]
    fn inner_text_and_context() -> Result<(), Box<dyn std::error::Error>> {
        let audience = extract(
            RESPONSE,
            &[ExtractorField::new(
                "audience",
                &[
                    "Response",
                    "Assertion",
                    "Conditions",
                    "AudienceRestriction",
                    "Audience",
                ],
            )],
        )?;
        assert_eq!(
            audience.get_str("audience"),
            Some("https://sp.example.com/metadata")
        );

        // context: existing node returns its source; missing node returns null
        let ctx = extract(
            RESPONSE,
            &[
                ExtractorField::new("status", &["Response", "Status"]).with_context(),
                ExtractorField::new("sig", &["Response", "Signature"]).with_context(),
            ],
        )?;
        assert!(ctx
            .get_str("status")
            .unwrap_or_default()
            .contains("StatusCode"));
        assert!(ctx.get("sig").map(Value::is_null).unwrap_or(false));
        Ok(())
    }

    #[test]
    fn context_span_preserves_source_around_non_element_events(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let xml = concat!(
            "<?xml version=\"1.0\"?>",
            "<!--before response-->",
            "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ",
            "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">",
            "<?target instruction?>",
            "<saml:Assertion ID=\"a1\"><![CDATA[text]]><!--inside-->",
            "<saml:Subject>subject</saml:Subject></saml:Assertion>",
            "</samlp:Response>",
        );
        let expected = concat!(
            "<saml:Assertion ID=\"a1\"><![CDATA[text]]><!--inside-->",
            "<saml:Subject>subject</saml:Subject></saml:Assertion>",
        );
        let result = extract(
            xml,
            &[ExtractorField::new("assertion", &["Response", "Assertion"]).with_context()],
        )?;

        assert_eq!(result.get_str("assertion"), Some(expected));
        Ok(())
    }

    #[test]
    fn multi_path_union_is_unique() -> Result<(), Box<dyn std::error::Error>> {
        let result = extract(
            RESPONSE,
            &[ExtractorField::multi(
                "issuer",
                &[
                    &["Response", "Issuer"],
                    &["Response", "Assertion", "Issuer"],
                ],
            )],
        )?;
        let arr = result
            .get("issuer")
            .and_then(Value::as_array)
            .unwrap_or(&[]);
        assert_eq!(arr.len(), 1);
        assert_eq!(
            arr[0],
            Value::Str("https://idp.example.com/metadata".into())
        );
        Ok(())
    }

    #[test]
    fn attribute_aggregation_and_wildcard() -> Result<(), Box<dyn std::error::Error>> {
        // non-wildcard: SAML attributes keyed by Name with AttributeValue text
        let attrs = extract(
            RESPONSE,
            &[ExtractorField::new(
                "attributes",
                &["Response", "Assertion", "AttributeStatement", "Attribute"],
            )
            .aggregate(&["Name"], &["AttributeValue"])],
        )?;
        assert_eq!(attrs.get_str("attributes.uid"), Some("test"));
        assert_eq!(attrs.get_str("attributes.mail"), Some("test@example.com"));
        assert_eq!(
            attrs
                .get("attributes.eduPersonAffiliation")
                .and_then(Value::as_array)
                .map(<[_]>::len),
            Some(2)
        );

        // wildcard ~SSODescriptor + certificate by `use`
        let cert = extract(
            SPMETA,
            &[ExtractorField::new(
                "certificate",
                &["EntityDescriptor", "~SSODescriptor", "KeyDescriptor"],
            )
            .aggregate(&["use"], &["KeyInfo", "X509Data", "X509Certificate"])],
        )?;
        assert!(cert.get_str("certificate.signing").is_some());
        assert!(cert.get_str("certificate.encryption").is_some());

        // index attr as key, another attr as value
        let sso = extract(
            SPMETA,
            &[ExtractorField::new(
                "singleSignOnService",
                &[
                    "EntityDescriptor",
                    "~SSODescriptor",
                    "AssertionConsumerService",
                ],
            )
            .aggregate(&["Binding"], &[])
            .attrs(&["Location"])],
        )?;
        assert_eq!(
            sso.get("singleSignOnService")
                .and_then(|m| m.get_key("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"))
                .and_then(Value::as_str),
            Some("https://sp.example.org/sp/sso")
        );
        Ok(())
    }

    #[test]
    fn login_response_field_set() -> Result<(), Box<dyn std::error::Error>> {
        let assertion = assertion_of(RESPONSE)?;
        let result = extract(RESPONSE, &fields::login_response_fields(&assertion))?;
        assert_eq!(
            result.get_str("nameID"),
            Some("_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7")
        );
        assert_eq!(
            result.get_str("issuer"),
            Some("https://idp.example.com/metadata")
        );
        assert_eq!(result.get_str("attributes.uid"), Some("test"));
        assert_eq!(
            result.get_str("response.inResponseTo"),
            Some("_41e758fee373d51639552c4b040b1090e97f6685")
        );
        Ok(())
    }

    #[test]
    fn login_response_fields_read_name_id_qualifiers() -> Result<(), Box<dyn std::error::Error>> {
        let response = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r"><saml:Assertion ID="_a"><saml:Subject><saml:NameID NameQualifier="https://idp.example.com" SPNameQualifier="https://sp.example.com" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" SPProvidedID="alias">pseudonym</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>"#;
        let assertion = assertion_of(response)?;
        let result = extract(response, &fields::login_response_fields(&assertion))?;
        assert_eq!(
            [
                result.get_str("nameIDQualifiers.nameQualifier"),
                result.get_str("nameIDQualifiers.spNameQualifier"),
                result.get_str("nameIDQualifiers.spProvidedId"),
            ],
            [
                Some("https://idp.example.com"),
                Some("https://sp.example.com"),
                Some("alias"),
            ]
        );

        let result = extract(
            RESPONSE,
            &fields::login_response_fields(&assertion_of(RESPONSE)?),
        )?;
        assert_eq!(result.get_str("nameIDQualifiers.nameQualifier"), None);
        Ok(())
    }
}
