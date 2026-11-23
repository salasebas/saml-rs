//! Minimal read-only XML DOM built on quick-xml.
//!
//! Nodes carry their source byte span so the extractor can return the exact
//! original substring for `context` fields (avoiding any re-serialisation /
//! canonicalisation concerns — verification is delegated to bergshamra).

use crate::error::{xml_err, ResourceLimit, SamlError};
use crate::xml::name::is_ncname;
use crate::xml::{is_xml_char, utf8_bom_len};
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::{BytesRef, Event};
use quick_xml::name::{NamespaceError, NamespaceResolver};
use quick_xml::Reader;

const DEFAULT_XML_MAX_BYTES: usize = 1024 * 1024;
const DEFAULT_XML_MAX_DEPTH: usize = 1024;
const DEFAULT_XML_MAX_NODES: usize = 50_000;
const DEFAULT_XML_MAX_ATTRIBUTES_PER_ELEMENT: usize = 64;
const DEFAULT_XML_MAX_ATTRIBUTE_VALUE_BYTES: usize = 16 * 1024;
const DEFAULT_XML_MAX_TEXT_BYTES: usize = DEFAULT_XML_MAX_BYTES;

/// Resource limits enforced while parsing XML into the local DOM.
///
/// Start from [`Default`](Default::default) or [`Self::unbounded`] and assign
/// the limits you change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct XmlLimits {
    /// Maximum input bytes accepted before parsing.
    ///
    /// Defaults to 1 MiB (1,048,576 bytes).
    pub max_bytes: usize,
    /// Maximum nested element depth.
    ///
    /// Defaults to 1,024.
    pub max_depth: usize,
    /// Maximum element nodes in the document.
    ///
    /// Defaults to 50,000.
    pub max_nodes: usize,
    /// Maximum attributes on one element.
    ///
    /// The DOM parser and protocol-profile validation also use this number as
    /// the maximum namespace bindings allowed in scope at once.
    ///
    /// Defaults to 64.
    pub max_attributes_per_element: usize,
    /// Maximum decoded bytes for one attribute value.
    ///
    /// Defaults to 16 KiB (16,384 bytes).
    pub max_attribute_value_bytes: usize,
    /// Maximum decoded direct text bytes for one element.
    ///
    /// Defaults to 1 MiB (1,048,576 bytes).
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
            return Err(SamlError::LimitExceeded {
                limit: ResourceLimit::XmlBytes,
                maximum: self.max_bytes,
            });
        }
        Ok(())
    }

    pub(crate) fn count_element(self, count: &mut usize) -> Result<(), SamlError> {
        *count = count
            .checked_add(1)
            .ok_or_else(|| SamlError::LimitExceeded {
                limit: ResourceLimit::XmlNodes,
                maximum: self.max_nodes,
            })?;
        if *count > self.max_nodes {
            return Err(SamlError::LimitExceeded {
                limit: ResourceLimit::XmlNodes,
                maximum: self.max_nodes,
            });
        }
        Ok(())
    }

    pub(crate) fn check_depth(self, depth: usize) -> Result<(), SamlError> {
        if depth > self.max_depth {
            return Err(SamlError::LimitExceeded {
                limit: ResourceLimit::XmlDepth,
                maximum: self.max_depth,
            });
        }
        Ok(())
    }

    pub(crate) fn checked_depth(self, depth: usize) -> Result<usize, SamlError> {
        let depth = depth
            .checked_add(1)
            .ok_or_else(|| SamlError::LimitExceeded {
                limit: ResourceLimit::XmlDepth,
                maximum: self.max_depth,
            })?;
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

mod element;

use element::Element;
pub(crate) use element::{Node, QualifiedElement};

/// A parsed document (its single root element).
#[derive(Debug, Clone)]
pub struct Document {
    /// Document (root) element.
    pub root: Node,
}

fn local_attribute(name: &str, _: Option<&str>, value: String) -> Option<(String, String)> {
    Some((name.to_owned(), value))
}

fn checked_append_text(
    target: &mut String,
    text: &str,
    limits: XmlLimits,
) -> Result<(), SamlError> {
    let next_len =
        target
            .len()
            .checked_add(text.len())
            .ok_or_else(|| SamlError::LimitExceeded {
                limit: ResourceLimit::XmlTextBytes,
                maximum: limits.max_text_bytes,
            })?;
    if next_len > limits.max_text_bytes {
        return Err(SamlError::LimitExceeded {
            limit: ResourceLimit::XmlTextBytes,
            maximum: limits.max_text_bytes,
        });
    }
    target.push_str(text);
    Ok(())
}

fn check_xml_chars(text: &str) -> Result<(), SamlError> {
    match text.chars().find(|&ch| !is_xml_char(ch)) {
        Some(ch) => Err(SamlError::xml(format!(
            "character U+{:04X} is not allowed in XML",
            u32::from(ch)
        ))),
        None => Ok(()),
    }
}

/// Map a quick-xml reader error. The namespace-binding cap is a limit.
pub(crate) fn reader_err(error: quick_xml::Error) -> SamlError {
    match error {
        quick_xml::Error::Namespace(error) => namespace_error(error),
        other => xml_err(other),
    }
}

fn namespace_error(error: NamespaceError) -> SamlError {
    match error {
        NamespaceError::TooManyBindings(max) => SamlError::LimitExceeded {
            limit: ResourceLimit::XmlNamespaceBindings,
            maximum: max,
        },
        other => xml_err(other),
    }
}

fn push_child<N, A>(
    stack: &mut [Element<N, A>],
    roots: &mut Vec<Element<N, A>>,
    node: Element<N, A>,
) {
    match stack.last_mut() {
        Some(parent) => parent.children.push(node),
        None => roots.push(node),
    }
}

#[derive(Clone, Copy)]
enum ParseMode {
    Document,
    StandaloneElement,
    Roots,
    Fragment,
}

pub(crate) fn is_xml_whitespace_char(ch: char) -> bool {
    matches!(ch, ' ' | '\t' | '\r' | '\n')
}

fn is_xml_whitespace(text: &str) -> bool {
    text.chars().all(is_xml_whitespace_char)
}

fn reject_non_document_content(mode: ParseMode) -> Result<(), SamlError> {
    match mode {
        ParseMode::Document | ParseMode::StandaloneElement | ParseMode::Fragment => Err(
            SamlError::xml("content is not allowed outside the document element"),
        ),
        ParseMode::Roots => Ok(()),
    }
}

fn push_general_ref(
    text_content: &mut String,
    e: BytesRef,
    limits: XmlLimits,
) -> Result<(), SamlError> {
    if let Some(ch) = e.resolve_char_ref().map_err(xml_err)? {
        let mut buf = [0; 4];
        let text = ch.encode_utf8(&mut buf);
        check_xml_chars(text)?;
        checked_append_text(text_content, text, limits)?;
        return Ok(());
    }

    let entity = e.as_ref();
    let resolved = resolve_predefined_entity(entity)
        .ok_or_else(|| SamlError::xml(format!("unrecognized entity `{entity}`")))?;
    checked_append_text(text_content, resolved, limits)?;
    Ok(())
}

/// Parse `xml` into a well-formed, namespace-well-formed [`Document`] with one
/// document element, within `limits`.
pub(crate) fn parse_document(xml: &str, limits: XmlLimits) -> Result<Document, SamlError> {
    parse_single_root(xml, limits, ParseMode::Document)
}

pub(crate) fn parse_standalone_element(
    xml: &str,
    limits: XmlLimits,
) -> Result<(Node, String), SamlError> {
    let mut namespace = None;
    let roots = parse_roots_inner(
        xml,
        limits,
        ParseMode::StandaloneElement,
        |_, uri, _| {
            namespace.get_or_insert_with(|| uri.unwrap_or_default().to_owned());
        },
        local_attribute,
    )?;
    Ok((single_root(roots)?, namespace.unwrap_or_default()))
}

/// Parse one element cut out of a larger document, such as an extracted
/// `context` value. A namespace prefix it uses may be declared on an ancestor
/// that is not part of `xml`; every other [`parse_document`] check applies.
pub(crate) fn parse_fragment_with_limits(
    xml: &str,
    limits: XmlLimits,
) -> Result<Document, SamlError> {
    parse_single_root(xml, limits, ParseMode::Fragment)
}

fn parse_single_root(xml: &str, limits: XmlLimits, mode: ParseMode) -> Result<Document, SamlError> {
    let roots = parse_roots_inner(xml, limits, mode, |_, _, _| {}, local_attribute)?;
    Ok(Document {
        root: single_root(roots)?,
    })
}

fn single_root<T>(mut roots: Vec<T>) -> Result<T, SamlError> {
    if roots.len() > 1 {
        return Err(SamlError::xml("multiple document elements"));
    }
    roots
        .pop()
        .ok_or_else(|| SamlError::xml("no document element"))
}

/// Parse every top-level element within `limits`. Each element must be
/// well-formed and declare every namespace prefix it uses.
#[cfg(test)]
pub(crate) fn parse_all_roots(xml: &str, limits: XmlLimits) -> Result<Vec<Node>, SamlError> {
    parse_roots_with_element_names(xml, limits, |_, _, _| {})
}

pub(crate) fn parse_roots_with_element_names(
    xml: &str,
    limits: XmlLimits,
    on_name: impl FnMut(usize, Option<&str>, &str),
) -> Result<Vec<Node>, SamlError> {
    parse_roots_inner(xml, limits, ParseMode::Roots, on_name, local_attribute)
}

pub(crate) fn parse_qualified_document(
    xml: &str,
    limits: XmlLimits,
) -> Result<QualifiedElement, SamlError> {
    single_root(parse_roots_inner(
        xml,
        limits,
        ParseMode::Document,
        |_, ns, _| ns.unwrap_or_default().to_owned(),
        |name, ns, value| {
            (ns != Some(element::XMLNS_NAMESPACE))
                .then(|| (ns.map(str::to_owned), name.to_owned(), value))
        },
    )?)
}

fn parse_roots_inner<N, A>(
    xml: &str,
    limits: XmlLimits,
    mode: ParseMode,
    mut element_namespace: impl FnMut(usize, Option<&str>, &str) -> N,
    attribute: impl Fn(&str, Option<&str>, String) -> Option<A>,
) -> Result<Vec<Element<N, A>>, SamlError> {
    limits.check_input_bytes(xml.len())?;
    check_xml_chars(xml)?;
    let mut reader = Reader::from_str(xml);
    reader.config_mut().check_comments = true;
    let mut resolver = NamespaceResolver::default();
    resolver.set_max_namespace_bindings(limits.max_attributes_per_element);
    let bom_len = utf8_bom_len(xml);
    let mut stack: Vec<Element<N, A>> = Vec::new();
    let mut roots = Vec::new();
    let mut node_count = 0usize;

    loop {
        let before = bom_len + reader.buffer_position() as usize;
        let event = reader.read_event().map_err(xml_err)?;
        let after = bom_len + reader.buffer_position() as usize;
        match event {
            Event::Start(ref e) | Event::Empty(ref e) => {
                limits.count_element(&mut node_count)?;
                limits.check_depth(stack.len().saturating_add(1))?;
                let node = element::read_element(
                    e,
                    &mut resolver,
                    limits,
                    mode,
                    before..after,
                    |ns, name| element_namespace(before, ns, name),
                    &attribute,
                )?;
                if matches!(event, Event::Empty(_)) {
                    resolver.pop();
                    push_child(&mut stack, &mut roots, node);
                } else {
                    stack.push(node);
                }
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
                    return Err(SamlError::xml("`]]>` is not allowed in text"));
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
                    push_general_ref(&mut top.text, e, limits)?;
                } else {
                    reject_non_document_content(mode)?;
                }
            }
            // Hardening (adapted from openauth-saml): reject DTDs so the parser
            // can never be steered into entity-expansion / XXE territory.
            Event::DocType(_) => {
                return Err(SamlError::xml("DOCTYPE is not allowed"));
            }
            Event::PI(instruction) if instruction.target() == "xml-stylesheet" => {
                return Err(SamlError::xml(
                    "xml-stylesheet processing instructions are not allowed",
                ));
            }
            Event::Decl(_) if before != bom_len => {
                return Err(SamlError::xml(
                    "an XML declaration is allowed only at the start of the input",
                ));
            }
            Event::Decl(declaration) if matches!(mode, ParseMode::StandaloneElement) => {
                element::validate_declaration(&declaration)?;
            }
            Event::PI(instruction) if instruction.target().eq_ignore_ascii_case("xml") => {
                return Err(SamlError::xml(format!(
                    "processing instruction target `{}` is reserved",
                    instruction.target()
                )));
            }
            Event::PI(instruction)
                if matches!(mode, ParseMode::StandaloneElement)
                    && !is_ncname(instruction.target()) =>
            {
                return Err(SamlError::xml(
                    "processing instruction target must be an XML NCName",
                ));
            }
            Event::Eof => match stack.last() {
                Some(node) => {
                    return Err(SamlError::xml(format!(
                        "element `{}` is not closed",
                        node.local_name
                    )));
                }
                None => break,
            },
            Event::Comment(_) | Event::Decl(_) | Event::PI(_) => {}
        }
    }

    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_and_root_list_parsers_apply_their_limits() -> Result<(), Box<dyn std::error::Error>>
    {
        let shallow = XmlLimits {
            max_depth: 1,
            ..XmlLimits::default()
        };
        assert_eq!(
            parse_document("<a><b/></a>", XmlLimits::default())?
                .root
                .local_name,
            "a"
        );
        assert!(parse_document("<a/><b/>", XmlLimits::default()).is_err());
        assert!(parse_document("<a><b/></a>", shallow).is_err());
        assert_eq!(parse_all_roots("<a/><b/>", XmlLimits::default())?.len(), 2);
        assert!(parse_all_roots("<a><b/></a><c/>", shallow).is_err());
        Ok(())
    }

    #[test]
    fn rejects_doctype() {
        let xml = "<!DOCTYPE foo [<!ENTITY x \"y\">]><foo/>";
        assert!(parse_document(xml, XmlLimits::default()).is_err());
    }

    #[test]
    fn parses_root_and_attrs() -> Result<(), SamlError> {
        let doc = parse_document(
            "<a:Root xmlns:a=\"urn:x\" id=\"1\"><b>hi</b></a:Root>",
            XmlLimits::default(),
        )?;
        assert_eq!(doc.root.local_name, "Root");
        assert_eq!(doc.root.attr("id"), Some("1"));
        assert_eq!(doc.root.children.len(), 1);
        assert_eq!(doc.root.children[0].text, "hi");
        Ok(())
    }

    #[test]
    fn parses_escaped_attribute_and_text_values() -> Result<(), SamlError> {
        let doc = parse_document(
            "<Root value=\"one &amp; two\"><Child>three &lt; four</Child></Root>",
            XmlLimits::default(),
        )?;

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
            assert_eq!(
                parse_document(xml, XmlLimits::default())?.root.text,
                text,
                "{xml:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn line_ending_normalization_keeps_source_offsets() -> Result<(), SamlError> {
        let xml = "<a>\r\n<b>x\r\ny</b>\r\n</a>";

        let doc = parse_document(xml, XmlLimits::default())?;

        let child = &doc.root.children[0];
        assert_eq!(&xml[child.start..child.end], "<b>x\r\ny</b>");
        assert_eq!(child.text, "x\ny");
        assert_eq!(&xml[doc.root.start..doc.root.end], xml);
        Ok(())
    }

    #[test]
    fn a_byte_order_mark_keeps_source_offsets() -> Result<(), SamlError> {
        for xml in [
            "\u{feff}<a><b/>text</a>",
            "\u{feff}<?xml version=\"1.0\"?>\n<a><b/>text</a>",
        ] {
            let doc = parse_document(xml, XmlLimits::default())?;

            assert_eq!(
                &xml[doc.root.start..doc.root.end],
                "<a><b/>text</a>",
                "{xml:?}"
            );
            let child = &doc.root.children[0];
            assert_eq!(&xml[child.start..child.end], "<b/>", "{xml:?}");
        }
        Ok(())
    }

    #[test]
    fn parse_rejects_multiple_document_elements() {
        let result = parse_document("<Root/><Second/>", XmlLimits::default());

        assert!(matches!(result, Err(SamlError::Xml { .. })));
    }

    #[test]
    fn parse_rejects_text_before_document_element() {
        let result = parse_document("outside<Root/>", XmlLimits::default());

        assert!(matches!(result, Err(SamlError::Xml { .. })));
    }

    #[test]
    fn parse_rejects_text_after_document_element() {
        let result = parse_document("<Root/>outside", XmlLimits::default());

        assert!(matches!(result, Err(SamlError::Xml { .. })));
    }

    #[test]
    fn parse_rejects_cdata_outside_document_element() {
        let result = parse_document("<Root/><![CDATA[outside]]>", XmlLimits::default());

        assert!(matches!(result, Err(SamlError::Xml { .. })));
    }

    #[test]
    fn parse_rejects_reference_outside_document_element() {
        let result = parse_document("<Root/>&amp;", XmlLimits::default());

        assert!(matches!(result, Err(SamlError::Xml { .. })));
    }

    #[test]
    fn parse_accepts_xml_misc_around_document_element() -> Result<(), SamlError> {
        let xml = concat!(
            "<?xml version=\"1.0\"?>\n",
            "<!-- before --><?before allowed?>\n",
            "<Root/>\n",
            "<?after allowed?><!-- after -->",
        );

        let document = parse_document(xml, XmlLimits::default())?;

        assert_eq!(document.root.local_name, "Root");
        Ok(())
    }

    #[test]
    fn parse_rejects_stylesheet_processing_instruction() {
        let result = parse_document(
            "<?xml-stylesheet href=\"external.xsl\"?><Root/>",
            XmlLimits::default(),
        );

        assert!(matches!(result, Err(SamlError::Xml { .. })));
    }

    #[test]
    fn parse_rejects_unclosed_element_after_document_element() {
        let result = parse_document("<Root/><Second>", XmlLimits::default());

        assert!(matches!(result, Err(SamlError::Xml { .. })));
    }

    #[test]
    fn parse_roots_rejects_unclosed_element() {
        let result = parse_all_roots("<Root/><Second>", XmlLimits::default());

        assert!(matches!(result, Err(SamlError::Xml { .. })));
    }

    #[test]
    fn parse_rejects_less_than_in_attribute_value() {
        let result = parse_document("<Root value=\"one<two\"/>", XmlLimits::default());

        assert!(matches!(result, Err(SamlError::Xml { .. })));
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
            let result = parse_document(xml, XmlLimits::default());

            assert!(matches!(result, Err(SamlError::Xml { .. })), "{xml:?}");
        }
    }

    #[test]
    fn parse_rejects_double_hyphen_in_comment() {
        let result = parse_document("<Root><!-- one -- two --></Root>", XmlLimits::default());

        assert!(matches!(result, Err(SamlError::Xml { .. })));
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
            let result = parse_document(xml, XmlLimits::default());

            assert!(matches!(result, Err(SamlError::Xml { .. })), "{xml:?}");
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
            let result = parse_document(xml, XmlLimits::default());

            assert!(matches!(result, Err(SamlError::Xml { .. })), "{xml:?}");
        }
    }

    #[test]
    fn parse_roots_rejects_undeclared_namespace_prefix() {
        for xml in [
            "<Root/><p:Second/>",
            "<a:Root xmlns:a=\"urn:a\"></a:Root><a:Second/>",
        ] {
            let result = parse_all_roots(xml, XmlLimits::default());

            assert!(matches!(result, Err(SamlError::Xml { .. })), "{xml:?}");
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
            let result = parse_document(xml, XmlLimits::default());

            assert!(matches!(result, Err(SamlError::Xml { .. })), "{xml:?}");
        }
    }

    #[test]
    fn parse_rejects_attributes_with_the_same_expanded_name() {
        for xml in [
            "<Root xmlns:a=\"urn:a\" xmlns:b=\"urn:a\" a:value=\"1\" b:value=\"2\"/>",
            "<Root xmlns:a=\"urn:a\" xmlns:b=\"&#x75;rn:a\" a:value=\"1\" b:value=\"2\"/>",
            "<Root xmlns:a=\"urn:a\"><Child a:value=\"1\" xmlns:b=\"urn:a\" b:value=\"2\"/></Root>",
        ] {
            let result = parse_document(xml, XmlLimits::default());

            assert!(matches!(result, Err(SamlError::Xml { .. })), "{xml:?}");
        }
    }

    #[test]
    fn parse_accepts_prefixes_declared_on_an_ancestor_and_the_xml_prefix() -> Result<(), SamlError>
    {
        let document = parse_document(
            concat!(
                "<a:Root xmlns:a=\"urn:a\" xmlns:b=\"urn:b\" xml:lang=\"en\">",
                "<a:Child a:value=\"1\" b:value=\"2\" value=\"3\"/>",
                "</a:Root>",
            ),
            XmlLimits::default(),
        )?;

        assert_eq!(document.root.attr("lang"), Some("en"));
        assert_eq!(document.root.children[0].attrs.len(), 3);
        Ok(())
    }

    #[test]
    fn parse_accepts_the_xml_namespace_written_with_a_character_reference() -> Result<(), SamlError>
    {
        let document = parse_document(
            concat!(
                "<Root xmlns:xml=\"&#x68;ttp://www.w3.org/XML/1998/namespace\" ",
                "xmlns:a=\"&#x75;rn:a\" xml:lang=\"en\" a:value=\"1\"/>",
            ),
            XmlLimits::default(),
        )?;

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

            assert!(matches!(result, Err(SamlError::Xml { .. })), "{xml:?}");
        }
    }

    #[test]
    fn parse_roots_preserves_multiple_root_collection() -> Result<(), SamlError> {
        let roots = parse_all_roots("<Root/><Second/>", XmlLimits::default())?;

        assert_eq!(roots.len(), 2);
        Ok(())
    }

    fn limit_hit<T>(result: Result<T, SamlError>, expected: ResourceLimit) -> bool {
        matches!(result, Err(SamlError::LimitExceeded { limit, .. }) if limit == expected)
    }

    #[test]
    fn rejects_xml_over_byte_limit() {
        let limits = XmlLimits {
            max_bytes: 4,
            ..Default::default()
        };

        assert!(limit_hit(
            parse_document("<Root/>", limits),
            ResourceLimit::XmlBytes
        ));
    }

    #[test]
    fn rejects_xml_over_depth_limit() {
        let limits = XmlLimits {
            max_depth: 2,
            ..Default::default()
        };

        assert!(limit_hit(
            parse_document("<a><b><c/></b></a>", limits),
            ResourceLimit::XmlDepth
        ));
    }

    #[test]
    fn rejects_xml_over_node_limit() {
        let limits = XmlLimits {
            max_nodes: 2,
            ..Default::default()
        };

        assert!(limit_hit(
            parse_document("<a><b/><c/></a>", limits),
            ResourceLimit::XmlNodes
        ));
    }

    #[test]
    fn rejects_xml_over_attribute_count_limit() {
        let limits = XmlLimits {
            max_attributes_per_element: 1,
            ..Default::default()
        };

        assert!(limit_hit(
            parse_document("<a x=\"1\" y=\"2\"/>", limits),
            ResourceLimit::XmlAttributesPerElement
        ));
    }

    #[test]
    fn rejects_xml_over_default_attribute_count_limit() {
        let mut xml = String::from("<Response");
        for index in 0..=DEFAULT_XML_MAX_ATTRIBUTES_PER_ELEMENT {
            xml.push_str(&format!(" attr{index}=\"value{index}\""));
        }
        xml.push_str("/>");

        assert!(limit_hit(
            parse_document(&xml, XmlLimits::default()),
            ResourceLimit::XmlAttributesPerElement
        ));
    }

    #[test]
    fn rejects_xml_over_default_namespace_declaration_count_limit() {
        let mut xml = String::from("<Response");
        for index in 0..=DEFAULT_XML_MAX_ATTRIBUTES_PER_ELEMENT {
            xml.push_str(&format!(" xmlns:p{index}=\"urn:test:{index}\""));
        }
        xml.push_str("/>");

        assert!(limit_hit(
            parse_document(&xml, XmlLimits::default()),
            ResourceLimit::XmlAttributesPerElement
        ));
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
        parse_document(
            &nested_namespace_bindings(DEFAULT_XML_MAX_ATTRIBUTES_PER_ELEMENT),
            XmlLimits::default(),
        )?;

        assert!(limit_hit(
            parse_document(
                &nested_namespace_bindings(DEFAULT_XML_MAX_ATTRIBUTES_PER_ELEMENT + 1),
                XmlLimits::default()
            ),
            ResourceLimit::XmlNamespaceBindings
        ));
        Ok(())
    }

    #[test]
    fn duplicate_attribute_returns_xml_error() {
        let result = parse_document(
            "<Response ID=\"first\" ID=\"second\"/>",
            XmlLimits::default(),
        );

        assert!(matches!(result, Err(SamlError::Xml { .. })));
    }

    #[test]
    fn rejects_xml_over_attribute_value_limit() {
        let limits = XmlLimits {
            max_attribute_value_bytes: 3,
            ..Default::default()
        };

        assert!(limit_hit(
            parse_document("<a x=\"1234\"/>", limits),
            ResourceLimit::XmlAttributeValueBytes
        ));
    }

    #[test]
    fn rejects_xml_over_text_limit() {
        let limits = XmlLimits {
            max_text_bytes: 3,
            ..Default::default()
        };

        assert!(limit_hit(
            parse_document("<a>1234</a>", limits),
            ResourceLimit::XmlTextBytes
        ));
    }
}
