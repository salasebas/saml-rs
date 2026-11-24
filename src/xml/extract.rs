use super::dom::{self, Node, XmlLimits};
use crate::error::SamlError;
use crate::util::{camel_case, zip_object, Value};

#[derive(Debug, Clone)]
pub struct ExtractorField {
    pub key: String,
    local_path: Vec<String>,
    pub attributes: Vec<String>,
    unqualified_attributes: bool,
    pub index: Option<Vec<String>>,
    pub attribute_path: Option<Vec<String>>,
    pub context: bool,
    pub shortcut: Option<String>,
}

fn to_vec(items: &[&str]) -> Vec<String> {
    items.iter().map(ToString::to_string).collect()
}

impl ExtractorField {
    pub fn new(key: &str, path: &[&str]) -> Self {
        Self {
            key: key.to_string(),
            local_path: to_vec(path),
            attributes: Vec::new(),
            unqualified_attributes: false,
            index: None,
            attribute_path: None,
            context: false,
            shortcut: None,
        }
    }

    pub fn attrs(mut self, attributes: &[&str]) -> Self {
        self.attributes = to_vec(attributes);
        self
    }

    pub(crate) fn unqualified_attributes(mut self) -> Self {
        self.unqualified_attributes = true;
        self
    }

    fn attribute<'a>(&self, node: &'a Node, name: &str) -> Option<&'a str> {
        if self.unqualified_attributes {
            node.unqualified_attr(name)
        } else {
            node.attr(name)
        }
    }

    pub fn capture_source(mut self) -> Self {
        self.context = true;
        self
    }

    pub fn aggregate(mut self, index: &[&str], attribute_path: &[&str]) -> Self {
        self.index = Some(to_vec(index));
        self.attribute_path = Some(to_vec(attribute_path));
        self
    }

    pub fn child_texts(mut self, path: &[&str]) -> Self {
        self.attribute_path = Some(to_vec(path));
        self
    }

    pub fn source_xml(mut self, xml: &str) -> Self {
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
    field: &ExtractorField,
) -> Value {
    let key_attr = index.first().map(String::as_str).unwrap_or_default();
    let mut keys: Vec<String> = Vec::new();
    let mut values: Vec<Value> = Vec::new();
    for node in nodes {
        keys.push(
            field
                .attribute(node, key_attr)
                .unwrap_or_default()
                .to_string(),
        );
        let targets = descend(node, attribute_path);
        let vals: Vec<Value> = if field.attributes.is_empty() {
            targets.iter().map(|t| Value::Str(t.text.clone())).collect()
        } else {
            let attr = &field.attributes[0];
            targets
                .iter()
                .filter_map(|target| field.attribute(target, attr))
                .map(|v| Value::Str(v.to_string()))
                .collect()
        };
        values.push(one_or_array(vals));
    }
    zip_object(&keys, values, false)
}

fn extract_field(src: &str, root: &Node, field: &ExtractorField) -> Value {
    let nodes = select_path(root, &field.local_path);

    if let (Some(index), Some(attribute_path)) = (&field.index, &field.attribute_path) {
        return aggregate(&nodes, index, attribute_path, field);
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
                let mut entries: Vec<(String, Value)> = field
                    .attributes
                    .iter()
                    .filter_map(|a| {
                        field
                            .attribute(n, a)
                            .map(|v| (camel_case(a), Value::Str(v.to_string())))
                    })
                    .collect();
                if let Some(path) = &field.attribute_path {
                    if let Some(last) = path.last() {
                        let texts = descend(n, path)
                            .iter()
                            .map(|t| Value::Str(t.text.clone()))
                            .collect();
                        entries.push((camel_case(last), Value::Array(texts)));
                    }
                }
                Value::Object(entries)
            })
            .collect();
        return one_or_array(objs);
    }

    if field.attributes.len() == 1 {
        let attr = &field.attributes[0];
        return match nodes.iter().find_map(|n| field.attribute(n, attr)) {
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

#[cfg(test)]
pub(crate) fn extract(xml: &str, fields: &[ExtractorField]) -> Result<Value, SamlError> {
    extract_with_limits(xml, fields, XmlLimits::default())
}

pub fn extract_with_limits(
    xml: &str,
    fields: &[ExtractorField],
    limits: XmlLimits,
) -> Result<Value, SamlError> {
    let root_doc = dom::parse_fragment_with_limits(xml, limits)?;
    let mut shortcut_docs: Vec<(&str, dom::Document)> = Vec::new();
    let mut out: Vec<(String, Value)> = Vec::with_capacity(fields.len());
    for field in fields {
        let value = match field.shortcut.as_deref() {
            Some(shortcut) if shortcut == xml => extract_field(xml, &root_doc.root, field),
            Some(shortcut) => {
                let doc = cached_shortcut(&mut shortcut_docs, shortcut, limits)?;
                extract_field(shortcut, &doc.root, field)
            }
            None => extract_field(xml, &root_doc.root, field),
        };
        out.push((field.key.clone(), value));
    }
    Ok(Value::Object(out))
}

fn cached_shortcut<'cache, 'src>(
    cache: &'cache mut Vec<(&'src str, dom::Document)>,
    shortcut: &'src str,
    limits: XmlLimits,
) -> Result<&'cache dom::Document, SamlError> {
    if let Some(index) = cache.iter().position(|(cached, _)| *cached == shortcut) {
        return Ok(&cache[index].1);
    }
    cache.push((shortcut, dom::parse_fragment_with_limits(shortcut, limits)?));
    let index = cache.len() - 1;
    Ok(&cache[index].1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::fields;

    const RESPONSE: &str = include_str!("../../tests/fixtures/misc/response.xml");
    const SPMETA: &str = include_str!("../../tests/fixtures/misc/spmeta.xml");

    fn assertion_of(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
        let field = ExtractorField::new("a", &["Response", "Assertion"]).capture_source();
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

        let ctx = extract(
            RESPONSE,
            &[
                ExtractorField::new("status", &["Response", "Status"]).capture_source(),
                ExtractorField::new("sig", &["Response", "Signature"]).capture_source(),
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
            &[ExtractorField::new("assertion", &["Response", "Assertion"]).capture_source()],
        )?;

        assert_eq!(result.get_str("assertion"), Some(expected));
        Ok(())
    }

    #[test]
    fn attribute_aggregation_and_wildcard() -> Result<(), Box<dyn std::error::Error>> {
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
        let name_formats: Vec<_> = result
            .get("attributeNameFormats")
            .and_then(Value::as_array)
            .unwrap_or(&[])
            .iter()
            .map(|attribute| {
                (
                    attribute.get_str("name"),
                    attribute.get_str("nameFormat"),
                    attribute.get("attributeValue"),
                )
            })
            .collect();
        let basic = Some("urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        let texts = |texts: &[&str]| {
            Value::Array(
                texts
                    .iter()
                    .map(|text| Value::Str(text.to_string()))
                    .collect(),
            )
        };
        assert_eq!(
            name_formats,
            [
                (Some("uid"), basic, Some(&texts(&["test"]))),
                (Some("mail"), basic, Some(&texts(&["test@example.com"]))),
                (
                    Some("eduPersonAffiliation"),
                    basic,
                    Some(&texts(&["users", "examplerole1"]))
                ),
            ]
        );
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

    #[test]
    fn identical_shortcut_strings_stay_distinct_from_other_documents(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let shared = "<Assertion ID=\"one\"><NameID>shared</NameID></Assertion>";
        let shared_again = shared.to_string();
        let other = "<Assertion ID=\"two\"><NameID>other</NameID></Assertion>";
        let root = "<Response><Issuer>root-issuer</Issuer></Response>";
        let result = extract(
            root,
            &[
                ExtractorField::new("sharedId", &["Assertion"])
                    .attrs(&["ID"])
                    .source_xml(shared),
                ExtractorField::new("sharedName", &["Assertion", "NameID"])
                    .source_xml(&shared_again),
                ExtractorField::new("otherName", &["Assertion", "NameID"]).source_xml(other),
                ExtractorField::new("issuer", &["Response", "Issuer"]),
                ExtractorField::new("sharedContext", &["Assertion"])
                    .capture_source()
                    .source_xml(shared),
            ],
        )?;

        assert_eq!(result.get_str("sharedId"), Some("one"));
        assert_eq!(result.get_str("sharedName"), Some("shared"));
        assert_eq!(result.get_str("otherName"), Some("other"));
        assert_eq!(result.get_str("issuer"), Some("root-issuer"));
        assert_eq!(result.get_str("sharedContext"), Some(shared));
        Ok(())
    }

    #[test]
    fn shortcut_equal_to_the_root_document_reads_that_document(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let xml = "<Assertion ID=\"a\"><NameID>n</NameID></Assertion>";
        let owned = xml.to_string();
        let result = extract(
            xml,
            &[
                ExtractorField::new("id", &["Assertion"])
                    .attrs(&["ID"])
                    .source_xml(&owned),
                ExtractorField::new("name", &["Assertion", "NameID"]),
                ExtractorField::new("context", &["Assertion"])
                    .capture_source()
                    .source_xml(&owned),
            ],
        )?;

        assert_eq!(result.get_str("id"), Some("a"));
        assert_eq!(result.get_str("name"), Some("n"));
        assert_eq!(result.get_str("context"), Some(xml));
        Ok(())
    }

    #[test]
    fn shortcut_parser_limits_still_apply() {
        let limits = XmlLimits {
            max_bytes: 4,
            ..XmlLimits::default()
        };
        let result = extract_with_limits(
            "<R/>",
            &[ExtractorField::new("name", &["Assertion", "NameID"]).source_xml("<Assertion/>")],
            limits,
        );

        assert!(
            matches!(
                result,
                Err(SamlError::LimitExceeded {
                    limit: crate::ResourceLimit::XmlBytes,
                    maximum: 4
                })
            ),
            "expected the shortcut to exceed max_bytes, got {result:?}"
        );
    }
}
