//! Minimal read-only XML DOM built on quick-xml.
//!
//! Nodes carry their source byte span so the extractor can return the exact
//! original substring for `context` fields (avoiding any re-serialisation /
//! canonicalisation concerns — verification is delegated to bergshamra).

use crate::error::SamlError;
use crate::xml::name::is_ncname;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::name::{
    Namespace, NamespaceError, NamespaceResolver, PrefixDeclaration, QName, ResolveResult,
};
use quick_xml::{Reader, XmlVersion};

/// Default maximum XML bytes accepted before DOM construction.
pub const DEFAULT_XML_MAX_BYTES: usize = 1024 * 1024;
/// Default maximum nested element depth accepted before DOM construction.
pub const DEFAULT_XML_MAX_DEPTH: usize = 1024;
/// Default maximum element nodes accepted before DOM construction.
pub const DEFAULT_XML_MAX_NODES: usize = 50_000;
/// Default maximum attributes accepted on one element.
pub const DEFAULT_XML_MAX_ATTRIBUTES_PER_ELEMENT: usize = 64;
/// Default maximum decoded bytes accepted for one attribute value.
pub const DEFAULT_XML_MAX_ATTRIBUTE_VALUE_BYTES: usize = 16 * 1024;
/// Default maximum decoded direct text bytes accepted for one element.
pub const DEFAULT_XML_MAX_TEXT_BYTES: usize = DEFAULT_XML_MAX_BYTES;

const XML_LIMIT_EXCEEDED: &str = "ERR_XML_LIMIT_EXCEEDED";
const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";
const XMLNS_NAMESPACE: &str = "http://www.w3.org/2000/xmlns/";

/// Resource limits enforced while parsing XML into the local DOM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XmlLimits {
    /// Maximum input bytes accepted before parsing.
    pub max_bytes: usize,
    /// Maximum nested element depth.
    pub max_depth: usize,
    /// Maximum element nodes in the document.
    pub max_nodes: usize,
    /// Maximum attributes on one element.
    ///
    /// The DOM parser and protocol-profile validation also use this number as
    /// the maximum namespace bindings allowed in scope at once.
    pub max_attributes_per_element: usize,
    /// Maximum decoded bytes for one attribute value.
    pub max_attribute_value_bytes: usize,
    /// Maximum decoded direct text bytes for one element.
    pub max_text_bytes: usize,
}

impl XmlLimits {
    /// Disable parser resource limits. Intended only for trusted local input.
    pub const fn unbounded() -> Self {
        Self {
            max_bytes: usize::MAX,
            max_depth: usize::MAX,
            max_nodes: usize::MAX,
            max_attributes_per_element: usize::MAX,
            max_attribute_value_bytes: usize::MAX,
            max_text_bytes: usize::MAX,
        }
    }

    pub(crate) fn check_input_bytes(self, len: usize) -> Result<(), SamlError> {
        if len > self.max_bytes {
            return Err(limit_exceeded("max XML bytes", self.max_bytes));
        }
        Ok(())
    }

    pub(crate) fn count_element(self, count: &mut usize) -> Result<(), SamlError> {
        *count = count
            .checked_add(1)
            .ok_or_else(|| limit_exceeded("max XML nodes", self.max_nodes))?;
        if *count > self.max_nodes {
            return Err(limit_exceeded("max XML nodes", self.max_nodes));
        }
        Ok(())
    }

    pub(crate) fn check_depth(self, depth: usize) -> Result<(), SamlError> {
        if depth > self.max_depth {
            return Err(limit_exceeded("max XML depth", self.max_depth));
        }
        Ok(())
    }

    pub(crate) fn checked_depth(self, depth: usize) -> Result<usize, SamlError> {
        let depth = depth
            .checked_add(1)
            .ok_or_else(|| limit_exceeded("max XML depth", self.max_depth))?;
        self.check_depth(depth)?;
        Ok(depth)
    }
}

impl Default for XmlLimits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_XML_MAX_BYTES,
            max_depth: DEFAULT_XML_MAX_DEPTH,
            max_nodes: DEFAULT_XML_MAX_NODES,
            max_attributes_per_element: DEFAULT_XML_MAX_ATTRIBUTES_PER_ELEMENT,
            max_attribute_value_bytes: DEFAULT_XML_MAX_ATTRIBUTE_VALUE_BYTES,
            max_text_bytes: DEFAULT_XML_MAX_TEXT_BYTES,
        }
    }
}

/// A parsed XML element.
#[derive(Debug, Clone)]
pub struct Node {
    /// Local element name (namespace prefix stripped).
    pub local_name: String,
    /// Attributes as `(local-name, unescaped-value)` pairs.
    pub attrs: Vec<(String, String)>,
    /// Child elements in document order.
    pub children: Vec<Node>,
    /// Concatenated direct text content (unescaped).
    pub text: String,
    /// Byte offset of the element's opening `<` in the source.
    pub start: usize,
    /// Byte offset just past the element's closing `>` in the source.
    pub end: usize,
}

impl Node {
    /// Direct children matching a local name, in document order.
    pub(crate) fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Self> {
        self.children
            .iter()
            .filter(move |child| child.local_name == name)
    }

    /// First direct child matching a local name.
    #[cfg(crypto)]
    pub(crate) fn child_named(&self, name: &str) -> Option<&Self> {
        self.children.iter().find(|child| child.local_name == name)
    }

    /// Look up an attribute by local name.
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A parsed document (its single root element).
#[derive(Debug, Clone)]
pub struct Document {
    /// Document (root) element.
    pub root: Node,
}

fn local_name_str(name: QName) -> String {
    name.local_name().into_inner().to_owned()
}

fn limit_exceeded(limit: &str, max: usize) -> SamlError {
    SamlError::Invalid(format!("{XML_LIMIT_EXCEEDED}: {limit} exceeded ({max})"))
}

fn checked_append_text(
    target: &mut String,
    text: &str,
    limits: XmlLimits,
) -> Result<(), SamlError> {
    let next_len = target
        .len()
        .checked_add(text.len())
        .ok_or_else(|| limit_exceeded("max XML text bytes", limits.max_text_bytes))?;
    if next_len > limits.max_text_bytes {
        return Err(limit_exceeded("max XML text bytes", limits.max_text_bytes));
    }
    target.push_str(text);
    Ok(())
}

fn is_xml_char(ch: char) -> bool {
    matches!(ch, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..)
}

fn check_xml_chars(text: &str) -> Result<(), SamlError> {
    match text.chars().find(|&ch| !is_xml_char(ch)) {
        Some(ch) => Err(SamlError::Xml(format!(
            "character U+{:04X} is not allowed in XML",
            u32::from(ch)
        ))),
        None => Ok(()),
    }
}

fn check_qname(name: &str) -> Result<(), SamlError> {
    if name.splitn(2, ':').all(is_ncname) {
        Ok(())
    } else {
        Err(SamlError::Xml(format!(
            "`{name}` is not a qualified XML name"
        )))
    }
}

fn check_attribute_separation(attributes: &str) -> Result<(), SamlError> {
    let mut open_quote = None;
    let mut after_value = false;
    for ch in attributes.chars() {
        if after_value && !is_xml_whitespace_char(ch) {
            return Err(SamlError::Xml(
                "attributes must be separated by whitespace".into(),
            ));
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
        (ResolveResult::Unknown(prefix), ParseMode::Document | ParseMode::Roots) => Err(
            SamlError::Xml(format!("namespace prefix `{prefix}` is not declared")),
        ),
        (ResolveResult::Unknown(_), ParseMode::Fragment)
        | (ResolveResult::Unbound | ResolveResult::Bound(_), _) => Ok(()),
    }
}

fn namespace_error(error: NamespaceError) -> SamlError {
    match error {
        NamespaceError::TooManyBindings(max) => {
            limit_exceeded("max XML namespace bindings in scope", max)
        }
        other => SamlError::Xml(other.to_string()),
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
        return Err(SamlError::Xml(format!(
            "namespace `{namespace}` cannot be the default namespace"
        )));
    }
    if let (PrefixDeclaration::Named(prefix), "") = (declaration, namespace) {
        return Err(SamlError::Xml(format!(
            "namespace prefix `{prefix}` cannot be undeclared"
        )));
    }
    resolver
        .add(declaration, Namespace(namespace))
        .map_err(namespace_error)
}

fn read_element(
    e: &BytesStart,
    resolver: &mut NamespaceResolver,
    limits: XmlLimits,
    mode: ParseMode,
) -> Result<(String, Vec<(String, String)>), SamlError> {
    let level = resolver
        .level()
        .checked_add(1)
        .ok_or_else(|| namespace_error(NamespaceError::TooDeeplyNested(usize::from(u16::MAX))))?;
    resolver.set_level(level);
    check_qname(e.name().into_inner())?;
    check_attribute_separation(e.attributes_raw())?;
    let attrs = read_attrs(e, resolver, limits)?;

    let (namespace, local_name) = resolver.resolve_element(e.name());
    check_prefix_declared(&namespace, mode)?;
    let mut expanded_names = Vec::with_capacity(attrs.len());
    for (name, _) in &attrs {
        if name.as_namespace_binding().is_some() {
            continue;
        }
        let (namespace, local_name) = resolver.resolve_attribute(*name);
        check_prefix_declared(&namespace, mode)?;
        let expanded_name = (local_name, namespace);
        if expanded_names.contains(&expanded_name) {
            return Err(SamlError::Xml(format!(
                "duplicate attribute `{}`",
                name.into_inner()
            )));
        }
        expanded_names.push(expanded_name);
    }

    Ok((
        local_name.into_inner().to_owned(),
        attrs
            .into_iter()
            .map(|(name, value)| (local_name_str(name), value))
            .collect(),
    ))
}

fn read_attrs<'a>(
    e: &'a BytesStart,
    resolver: &mut NamespaceResolver,
    limits: XmlLimits,
) -> Result<Vec<(QName<'a>, String)>, SamlError> {
    let mut out = Vec::new();
    for attr in e.attributes() {
        if out.len() >= limits.max_attributes_per_element {
            return Err(limit_exceeded(
                "max XML attributes per element",
                limits.max_attributes_per_element,
            ));
        }
        let attr = attr.map_err(|err| SamlError::Xml(err.to_string()))?;
        check_qname(attr.key.into_inner())?;
        if attr.value.contains('<') {
            return Err(SamlError::Xml(
                "`<` is not allowed in an attribute value".into(),
            ));
        }
        let value = attr
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|err| SamlError::Xml(err.to_string()))?
            .into_owned();
        if value.len() > limits.max_attribute_value_bytes {
            return Err(limit_exceeded(
                "max XML attribute value bytes",
                limits.max_attribute_value_bytes,
            ));
        }
        check_xml_chars(&value)?;
        if let Some(declaration) = attr.key.as_namespace_binding() {
            bind_namespace(resolver, declaration, &value)?;
        }
        out.push((attr.key, value));
    }
    Ok(out)
}

fn find_lt(bytes: &[u8], before: usize, after: usize) -> usize {
    bytes[before..after]
        .iter()
        .position(|&b| b == b'<')
        .map(|p| before + p)
        .unwrap_or(before)
}

fn push_child(stack: &mut [Node], roots: &mut Vec<Node>, node: Node) {
    match stack.last_mut() {
        Some(parent) => parent.children.push(node),
        None => roots.push(node),
    }
}

#[derive(Clone, Copy)]
enum ParseMode {
    Document,
    Roots,
    Fragment,
}

fn is_xml_whitespace_char(ch: char) -> bool {
    matches!(ch, ' ' | '\t' | '\r' | '\n')
}

fn is_xml_whitespace(text: &str) -> bool {
    text.chars().all(is_xml_whitespace_char)
}

fn reject_non_document_content(mode: ParseMode) -> Result<(), SamlError> {
    match mode {
        ParseMode::Document | ParseMode::Fragment => Err(SamlError::Xml(
            "content is not allowed outside the document element".into(),
        )),
        ParseMode::Roots => Ok(()),
    }
}

fn push_general_ref(node: &mut Node, e: BytesRef, limits: XmlLimits) -> Result<(), SamlError> {
    if let Some(ch) = e
        .resolve_char_ref()
        .map_err(|err| SamlError::Xml(err.to_string()))?
    {
        let mut buf = [0; 4];
        let text = ch.encode_utf8(&mut buf);
        check_xml_chars(text)?;
        checked_append_text(&mut node.text, text, limits)?;
        return Ok(());
    }

    let entity = e.as_ref();
    let resolved = resolve_predefined_entity(entity)
        .ok_or_else(|| SamlError::Xml(format!("unrecognized entity `{entity}`")))?;
    checked_append_text(&mut node.text, resolved, limits)?;
    Ok(())
}

/// Parse `xml` into a well-formed [`Document`] with one document element.
///
/// `xml` must also be namespace-well-formed: it declares every namespace
/// prefix it uses.
pub fn parse(xml: &str) -> Result<Document, SamlError> {
    parse_with_limits(xml, XmlLimits::default())
}

/// Parse `xml` into a well-formed [`Document`] with explicit resource limits.
pub fn parse_with_limits(xml: &str, limits: XmlLimits) -> Result<Document, SamlError> {
    parse_single_root(xml, limits, ParseMode::Document)
}

/// Parse one element cut out of a larger document, such as an extracted
/// `context` value. A namespace prefix it uses may be declared on an ancestor
/// that is not part of `xml`; every other [`parse_with_limits`] check applies.
pub(crate) fn parse_fragment_with_limits(
    xml: &str,
    limits: XmlLimits,
) -> Result<Document, SamlError> {
    parse_single_root(xml, limits, ParseMode::Fragment)
}

fn parse_single_root(xml: &str, limits: XmlLimits, mode: ParseMode) -> Result<Document, SamlError> {
    let mut roots = parse_roots_inner(xml, limits, mode)?;
    let root = match roots.len() {
        0 => return Err(SamlError::Xml("no document element".into())),
        1 => roots
            .pop()
            .ok_or_else(|| SamlError::Xml("no document element".into()))?,
        _ => return Err(SamlError::Xml("multiple document elements".into())),
    };
    Ok(Document { root })
}

/// Parse every top-level element (used to detect multiple root descriptors).
///
/// Each element must be well-formed and declare every namespace prefix it
/// uses.
pub fn parse_roots(xml: &str) -> Result<Vec<Node>, SamlError> {
    parse_roots_with_limits(xml, XmlLimits::default())
}

/// Parse every top-level element with explicit resource limits.
pub fn parse_roots_with_limits(xml: &str, limits: XmlLimits) -> Result<Vec<Node>, SamlError> {
    parse_roots_inner(xml, limits, ParseMode::Roots)
}

fn parse_roots_inner(
    xml: &str,
    limits: XmlLimits,
    mode: ParseMode,
) -> Result<Vec<Node>, SamlError> {
    limits.check_input_bytes(xml.len())?;
    check_xml_chars(xml)?;
    let mut reader = Reader::from_str(xml);
    reader.config_mut().check_comments = true;
    let mut resolver = NamespaceResolver::default();
    resolver.set_max_namespace_bindings(limits.max_attributes_per_element);
    let bytes = xml.as_bytes();
    let mut stack: Vec<Node> = Vec::new();
    let mut roots: Vec<Node> = Vec::new();
    let mut node_count = 0usize;

    loop {
        let before = reader.buffer_position() as usize;
        let event = reader
            .read_event()
            .map_err(|err| SamlError::Xml(err.to_string()))?;
        let after = reader.buffer_position() as usize;
        match event {
            Event::Start(e) => {
                limits.count_element(&mut node_count)?;
                limits.check_depth(stack.len().saturating_add(1))?;
                let start = find_lt(bytes, before, after);
                let (local_name, attrs) = read_element(&e, &mut resolver, limits, mode)?;
                stack.push(Node {
                    local_name,
                    attrs,
                    children: Vec::new(),
                    text: String::new(),
                    start,
                    end: 0,
                });
            }
            Event::Empty(e) => {
                limits.count_element(&mut node_count)?;
                limits.check_depth(stack.len().saturating_add(1))?;
                let start = find_lt(bytes, before, after);
                let (local_name, attrs) = read_element(&e, &mut resolver, limits, mode)?;
                let node = Node {
                    local_name,
                    attrs,
                    children: Vec::new(),
                    text: String::new(),
                    start,
                    end: after,
                };
                resolver.pop();
                push_child(&mut stack, &mut roots, node);
            }
            Event::End(_) => {
                resolver.pop();
                if let Some(mut node) = stack.pop() {
                    node.end = after;
                    push_child(&mut stack, &mut roots, node);
                }
            }
            Event::Text(e) => {
                if e.contains("]]>") {
                    return Err(SamlError::Xml("`]]>` is not allowed in text".into()));
                }
                if let Some(top) = stack.last_mut() {
                    checked_append_text(&mut top.text, &e.xml10_content(), limits)?;
                } else if !is_xml_whitespace(e.as_ref()) {
                    reject_non_document_content(mode)?;
                }
            }
            Event::CData(e) => {
                if let Some(top) = stack.last_mut() {
                    checked_append_text(&mut top.text, &e.xml10_content(), limits)?;
                } else {
                    reject_non_document_content(mode)?;
                }
            }
            Event::GeneralRef(e) => {
                if let Some(top) = stack.last_mut() {
                    push_general_ref(top, e, limits)?;
                } else {
                    reject_non_document_content(mode)?;
                }
            }
            // Hardening (adapted from openauth-saml): reject DTDs so the parser
            // can never be steered into entity-expansion / XXE territory.
            Event::DocType(_) => {
                return Err(SamlError::Xml("DOCTYPE is not allowed".into()));
            }
            Event::PI(instruction) if instruction.target() == "xml-stylesheet" => {
                return Err(SamlError::Xml(
                    "xml-stylesheet processing instructions are not allowed".into(),
                ));
            }
            Event::Decl(_) if before != 0 => {
                return Err(SamlError::Xml(
                    "an XML declaration is allowed only at the start of the input".into(),
                ));
            }
            Event::PI(instruction) if instruction.target().eq_ignore_ascii_case("xml") => {
                return Err(SamlError::Xml(format!(
                    "processing instruction target `{}` is reserved",
                    instruction.target()
                )));
            }
            Event::Eof => match stack.last() {
                Some(node) => {
                    return Err(SamlError::Xml(format!(
                        "element `{}` is not closed",
                        node.local_name
                    )));
                }
                None => break,
            },
            _ => {}
        }
    }

    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_doctype() {
        let xml = "<!DOCTYPE foo [<!ENTITY x \"y\">]><foo/>";
        assert!(parse(xml).is_err());
    }

    #[test]
    fn parses_root_and_attrs() -> Result<(), SamlError> {
        let doc = parse("<a:Root xmlns:a=\"urn:x\" id=\"1\"><b>hi</b></a:Root>")?;
        assert_eq!(doc.root.local_name, "Root");
        assert_eq!(doc.root.attr("id"), Some("1"));
        assert_eq!(doc.root.children.len(), 1);
        assert_eq!(doc.root.children[0].text, "hi");
        Ok(())
    }

    #[test]
    fn parses_escaped_attribute_and_text_values() -> Result<(), SamlError> {
        let doc = parse("<Root value=\"one &amp; two\"><Child>three &lt; four</Child></Root>")?;

        assert_eq!(doc.root.attr("value"), Some("one & two"));
        assert_eq!(doc.root.children[0].text, "three < four");
        Ok(())
    }

    #[test]
    fn parse_normalizes_literal_line_endings_in_text_and_cdata() -> Result<(), SamlError> {
        let cases = [
            ("<a>x\ny</a>", "x\ny"),
            ("<a>x\r\ny</a>", "x\ny"),
            ("<a>x\ry</a>", "x\ny"),
            ("<a>x\r\r\ny</a>", "x\n\ny"),
            ("<a><![CDATA[x\r\ny\rz]]></a>", "x\ny\nz"),
            ("<a>x\r<![CDATA[\ny]]></a>", "x\n\ny"),
            ("<a><![CDATA[x\r]]>\ny</a>", "x\n\ny"),
            ("<a>x\r<!---->\ny</a>", "x\n\ny"),
            ("<a>x\r&amp;\ny</a>", "x\n&\ny"),
            ("<a>x&#xD;y</a>", "x\ry"),
            ("<a>x&#xD;\ny</a>", "x\r\ny"),
            ("<a>x&#xD;\r\ny</a>", "x\r\ny"),
            ("<a>x\r&#xA;y</a>", "x\n\ny"),
        ];
        for (xml, text) in cases {
            assert_eq!(parse(xml)?.root.text, text, "{xml:?}");
        }
        Ok(())
    }

    #[test]
    fn line_ending_normalization_keeps_source_offsets() -> Result<(), SamlError> {
        let xml = "<a>\r\n<b>x\r\ny</b>\r\n</a>";

        let doc = parse(xml)?;

        let child = &doc.root.children[0];
        assert_eq!(&xml[child.start..child.end], "<b>x\r\ny</b>");
        assert_eq!(child.text, "x\ny");
        assert_eq!(&xml[doc.root.start..doc.root.end], xml);
        Ok(())
    }

    #[test]
    fn parse_rejects_multiple_document_elements() {
        let result = parse("<Root/><Second/>");

        assert!(matches!(result, Err(SamlError::Xml(_))));
    }

    #[test]
    fn parse_rejects_text_before_document_element() {
        let result = parse("outside<Root/>");

        assert!(matches!(result, Err(SamlError::Xml(_))));
    }

    #[test]
    fn parse_rejects_text_after_document_element() {
        let result = parse("<Root/>outside");

        assert!(matches!(result, Err(SamlError::Xml(_))));
    }

    #[test]
    fn parse_rejects_cdata_outside_document_element() {
        let result = parse("<Root/><![CDATA[outside]]>");

        assert!(matches!(result, Err(SamlError::Xml(_))));
    }

    #[test]
    fn parse_rejects_reference_outside_document_element() {
        let result = parse("<Root/>&amp;");

        assert!(matches!(result, Err(SamlError::Xml(_))));
    }

    #[test]
    fn parse_accepts_xml_misc_around_document_element() -> Result<(), SamlError> {
        let xml = concat!(
            "<?xml version=\"1.0\"?>\n",
            "<!-- before --><?before allowed?>\n",
            "<Root/>\n",
            "<?after allowed?><!-- after -->",
        );

        let document = parse(xml)?;

        assert_eq!(document.root.local_name, "Root");
        Ok(())
    }

    #[test]
    fn parse_rejects_stylesheet_processing_instruction() {
        let result = parse("<?xml-stylesheet href=\"external.xsl\"?><Root/>");

        assert!(matches!(result, Err(SamlError::Xml(_))));
    }

    #[test]
    fn parse_rejects_unclosed_element_after_document_element() {
        let result = parse("<Root/><Second>");

        assert!(matches!(result, Err(SamlError::Xml(_))));
    }

    #[test]
    fn parse_roots_rejects_unclosed_element() {
        let result = parse_roots("<Root/><Second>");

        assert!(matches!(result, Err(SamlError::Xml(_))));
    }

    #[test]
    fn parse_rejects_less_than_in_attribute_value() {
        let result = parse("<Root value=\"one<two\"/>");

        assert!(matches!(result, Err(SamlError::Xml(_))));
    }

    #[test]
    fn parse_rejects_characters_outside_the_xml_char_range() {
        for xml in [
            "<Root>\u{1}</Root>",
            "<Root value=\"\u{1F}\"/>",
            "<Root>\u{FFFE}</Root>",
            "<Root>&#1;</Root>",
            "<Root value=\"&#x1F;\"/>",
            "<Root>&#xFFFF;</Root>",
        ] {
            let result = parse(xml);

            assert!(matches!(result, Err(SamlError::Xml(_))), "{xml:?}");
        }
    }

    #[test]
    fn parse_rejects_double_hyphen_in_comment() {
        let result = parse("<Root><!-- one -- two --></Root>");

        assert!(matches!(result, Err(SamlError::Xml(_))));
    }

    #[test]
    fn parse_rejects_remaining_well_formedness_errors() {
        for xml in [
            "<a>]]></a>",
            "<a x=\"1\"y=\"2\"/>",
            "<1a/>",
            "<a 1x=\"v\"/>",
            "<a\u{A0}x=\"1\"/>",
            "<a><?xml version=\"1.0\"?></a>",
            "<?XML version=\"1.0\"?><a/>",
            "<a:b:c xmlns:a=\"u\"/>",
            "<a xmlns:p=\"\"/>",
        ] {
            let result = parse(xml);

            assert!(matches!(result, Err(SamlError::Xml(_))), "{xml:?}");
        }
    }

    #[test]
    fn parse_rejects_undeclared_namespace_prefix() {
        for xml in [
            "<p:Root/>",
            "<Root p:value=\"1\"/>",
            "<a:Root xmlns:a=\"urn:a\"><b:Child/></a:Root>",
            "<Root><a:Child xmlns:a=\"urn:a\"/><a:Child/></Root>",
            "<Root><Child xmlns:a=\"urn:a\"></Child><a:Child/></Root>",
        ] {
            let result = parse(xml);

            assert!(matches!(result, Err(SamlError::Xml(_))), "{xml:?}");
        }
    }

    #[test]
    fn parse_roots_rejects_undeclared_namespace_prefix() {
        for xml in [
            "<Root/><p:Second/>",
            "<a:Root xmlns:a=\"urn:a\"></a:Root><a:Second/>",
        ] {
            let result = parse_roots(xml);

            assert!(matches!(result, Err(SamlError::Xml(_))), "{xml:?}");
        }
    }

    #[test]
    fn parse_rejects_reserved_namespace_bindings() {
        for xml in [
            "<Root xmlns:xmlns=\"urn:a\"/>",
            "<Root xmlns:xml=\"urn:a\"/>",
            "<Root xmlns:p=\"http://www.w3.org/XML/1998/namespace\"/>",
            "<Root xmlns:p=\"http://www.w3.org/2000/xmlns/\"/>",
            "<Root xmlns:p=\"&#x68;ttp://www.w3.org/XML/1998/namespace\"/>",
            "<Root xmlns=\"http://www.w3.org/XML/1998/namespace\"/>",
            "<Root xmlns=\"http://www.w3.org/2000/xmlns/\"/>",
            "<Root xmlns=\"&#x68;ttp://www.w3.org/2000/xmlns/\"/>",
        ] {
            let result = parse(xml);

            assert!(matches!(result, Err(SamlError::Xml(_))), "{xml:?}");
        }
    }

    #[test]
    fn parse_rejects_attributes_with_the_same_expanded_name() {
        for xml in [
            "<Root xmlns:a=\"urn:a\" xmlns:b=\"urn:a\" a:value=\"1\" b:value=\"2\"/>",
            "<Root xmlns:a=\"urn:a\" xmlns:b=\"&#x75;rn:a\" a:value=\"1\" b:value=\"2\"/>",
            "<Root xmlns:a=\"urn:a\"><Child a:value=\"1\" xmlns:b=\"urn:a\" b:value=\"2\"/></Root>",
        ] {
            let result = parse(xml);

            assert!(matches!(result, Err(SamlError::Xml(_))), "{xml:?}");
        }
    }

    #[test]
    fn parse_accepts_prefixes_declared_on_an_ancestor_and_the_xml_prefix() -> Result<(), SamlError>
    {
        let document = parse(concat!(
            "<a:Root xmlns:a=\"urn:a\" xmlns:b=\"urn:b\" xml:lang=\"en\">",
            "<a:Child a:value=\"1\" b:value=\"2\" value=\"3\"/>",
            "</a:Root>",
        ))?;

        assert_eq!(document.root.attr("lang"), Some("en"));
        assert_eq!(document.root.children[0].attrs.len(), 3);
        Ok(())
    }

    #[test]
    fn parse_accepts_the_xml_namespace_written_with_a_character_reference() -> Result<(), SamlError>
    {
        let document = parse(concat!(
            "<Root xmlns:xml=\"&#x68;ttp://www.w3.org/XML/1998/namespace\" ",
            "xmlns:a=\"&#x75;rn:a\" xml:lang=\"en\" a:value=\"1\"/>",
        ))?;

        assert_eq!(document.root.attr("lang"), Some("en"));
        Ok(())
    }

    #[test]
    fn parse_fragment_accepts_prefixes_declared_outside_it() -> Result<(), SamlError> {
        let document = parse_fragment_with_limits(
            "<saml:Assertion ID=\"_1\"><saml:Issuer>idp</saml:Issuer></saml:Assertion>",
            XmlLimits::default(),
        )?;

        assert_eq!(document.root.children[0].text, "idp");
        Ok(())
    }

    #[test]
    fn parse_fragment_keeps_the_other_well_formedness_checks() {
        for xml in [
            "<saml:Assertion><saml:Issuer>",
            "<saml:Assertion ID=\"<\"/>",
            "<saml:Assertion>\u{1}</saml:Assertion>",
            "<saml:Assertion/><saml:Assertion/>",
            "<saml:Assertion a:ID=\"1\" a:ID=\"2\"/>",
            "<saml:Assertion>]]></saml:Assertion>",
            "<saml:Assertion:x/>",
            "<saml:Assertion ID=\"1\"Version=\"2.0\"/>",
            "<saml:Assertion xmlns:p=\"\"/>",
        ] {
            let result = parse_fragment_with_limits(xml, XmlLimits::default());

            assert!(matches!(result, Err(SamlError::Xml(_))), "{xml:?}");
        }
    }

    #[test]
    fn parse_roots_preserves_multiple_root_collection() -> Result<(), SamlError> {
        let roots = parse_roots("<Root/><Second/>")?;

        assert_eq!(roots.len(), 2);
        Ok(())
    }

    fn limit_hit<T>(result: Result<T, SamlError>) -> bool {
        matches!(result, Err(SamlError::Invalid(message)) if message.contains(XML_LIMIT_EXCEEDED))
    }

    #[test]
    fn rejects_xml_over_byte_limit() {
        let limits = XmlLimits {
            max_bytes: 4,
            ..Default::default()
        };

        assert!(limit_hit(parse_with_limits("<Root/>", limits)));
    }

    #[test]
    fn rejects_xml_over_depth_limit() {
        let limits = XmlLimits {
            max_depth: 2,
            ..Default::default()
        };

        assert!(limit_hit(parse_with_limits("<a><b><c/></b></a>", limits)));
    }

    #[test]
    fn rejects_xml_over_node_limit() {
        let limits = XmlLimits {
            max_nodes: 2,
            ..Default::default()
        };

        assert!(limit_hit(parse_with_limits("<a><b/><c/></a>", limits)));
    }

    #[test]
    fn rejects_xml_over_attribute_count_limit() {
        let limits = XmlLimits {
            max_attributes_per_element: 1,
            ..Default::default()
        };

        assert!(limit_hit(parse_with_limits("<a x=\"1\" y=\"2\"/>", limits)));
    }

    #[test]
    fn rejects_xml_over_default_attribute_count_limit() {
        let mut xml = String::from("<Response");
        for index in 0..=DEFAULT_XML_MAX_ATTRIBUTES_PER_ELEMENT {
            xml.push_str(&format!(" attr{index}=\"value{index}\""));
        }
        xml.push_str("/>");

        assert!(limit_hit(parse(&xml)));
    }

    #[test]
    fn rejects_xml_over_default_namespace_declaration_count_limit() {
        let mut xml = String::from("<Response");
        for index in 0..=DEFAULT_XML_MAX_ATTRIBUTES_PER_ELEMENT {
            xml.push_str(&format!(" xmlns:p{index}=\"urn:test:{index}\""));
        }
        xml.push_str("/>");

        assert!(limit_hit(parse(&xml)));
    }

    fn nested_namespace_bindings(levels: usize) -> String {
        let mut xml = String::new();
        for index in 0..levels {
            xml.push_str(&format!("<e{index} xmlns:p{index}=\"urn:test:{index}\">"));
        }
        for index in (0..levels).rev() {
            xml.push_str(&format!("</e{index}>"));
        }
        xml
    }

    #[test]
    fn rejects_xml_over_default_namespace_bindings_in_scope_limit() -> Result<(), SamlError> {
        parse(&nested_namespace_bindings(
            DEFAULT_XML_MAX_ATTRIBUTES_PER_ELEMENT,
        ))?;

        assert!(limit_hit(parse(&nested_namespace_bindings(
            DEFAULT_XML_MAX_ATTRIBUTES_PER_ELEMENT + 1
        ))));
        Ok(())
    }

    #[test]
    fn duplicate_attribute_returns_xml_error() {
        let result = parse("<Response ID=\"first\" ID=\"second\"/>");

        assert!(matches!(result, Err(SamlError::Xml(_))));
    }

    #[test]
    fn rejects_xml_over_attribute_value_limit() {
        let limits = XmlLimits {
            max_attribute_value_bytes: 3,
            ..Default::default()
        };

        assert!(limit_hit(parse_with_limits("<a x=\"1234\"/>", limits)));
    }

    #[test]
    fn rejects_xml_over_text_limit() {
        let limits = XmlLimits {
            max_text_bytes: 3,
            ..Default::default()
        };

        assert!(limit_hit(parse_with_limits("<a>1234</a>", limits)));
    }
}
