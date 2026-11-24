use quick_xml::events::{BytesStart, Event};
use quick_xml::name::PrefixDeclaration;
use quick_xml::Reader;

use crate::error::{xml_err, SamlError};
use crate::xml::utf8_bom_len;

struct Declaration {
    prefix: String,
    value: String,
}

/// Return the element at `start..end` of `xml` as standalone XML.
///
/// Each namespace an ancestor declares, that is in scope at the element and
/// that the element does not declare itself, is declared on the returned
/// element. That keeps a prefix used only in a QName value, such as
/// `xsi:type="xs:string"`, bound. An inherited default namespace is declared
/// unless an ancestor undeclares it with `xmlns=""`. An element with no
/// inherited namespace is returned unchanged.
///
/// # Errors
///
/// Returns [`SamlError::Xml`] when `xml` is malformed or `start..end` is not
/// one element of it.
pub(crate) fn standalone_element(xml: &str, start: usize, end: usize) -> Result<String, SamlError> {
    let element = xml
        .get(start..end)
        .ok_or_else(|| SamlError::xml("element is outside the document"))?;
    let inherited = inherited_declarations(xml, start)?;
    if inherited.is_empty() {
        return Ok(element.to_string());
    }
    let name_end = element
        .find(|ch: char| ch.is_ascii_whitespace() || ch == '/' || ch == '>')
        .ok_or_else(|| SamlError::xml("element start tag is incomplete"))?;
    let mut standalone = String::with_capacity(element.len());
    standalone.push_str(&element[..name_end]);
    for declaration in &inherited {
        standalone.push_str(" xmlns");
        if !declaration.prefix.is_empty() {
            standalone.push(':');
            standalone.push_str(&declaration.prefix);
        }
        standalone.push_str("=\"");
        standalone.push_str(&declaration.value);
        standalone.push('"');
    }
    standalone.push_str(&element[name_end..]);
    Ok(standalone)
}

fn inherited_declarations(xml: &str, start: usize) -> Result<Vec<Declaration>, SamlError> {
    let mut reader = Reader::from_str(xml);
    let bom_len = utf8_bom_len(xml);
    let mut ancestors: Vec<Vec<Declaration>> = Vec::new();
    loop {
        let before = bom_len + reader.buffer_position() as usize;
        let event = reader.read_event().map_err(xml_err)?;
        let after = bom_len + reader.buffer_position() as usize;
        match event {
            Event::Start(element) | Event::Empty(element) if (before..after).contains(&start) => {
                return Ok(in_scope(ancestors, &declarations(&element)?));
            }
            Event::Start(element) => ancestors.push(declarations(&element)?),
            Event::End(_) => {
                ancestors.pop();
            }
            Event::DocType(_) => {
                return Err(SamlError::xml("DOCTYPE is not allowed"));
            }
            Event::Eof => {
                return Err(SamlError::xml("element is outside the document"));
            }
            Event::Empty(_)
            | Event::Text(_)
            | Event::CData(_)
            | Event::Comment(_)
            | Event::Decl(_)
            | Event::PI(_)
            | Event::GeneralRef(_) => {}
        }
    }
}

fn declarations(element: &BytesStart<'_>) -> Result<Vec<Declaration>, SamlError> {
    let mut declared = Vec::new();
    for attribute in element.attributes() {
        let attribute = attribute.map_err(xml_err)?;
        let prefix = match attribute.key.as_namespace_binding() {
            Some(PrefixDeclaration::Default) => String::new(),
            Some(PrefixDeclaration::Named(prefix)) => prefix.to_string(),
            None => continue,
        };
        declared.push(Declaration {
            prefix,
            value: attribute.value.replace('"', "&quot;"),
        });
    }
    Ok(declared)
}

fn in_scope(ancestors: Vec<Vec<Declaration>>, own: &[Declaration]) -> Vec<Declaration> {
    let mut scope: Vec<Declaration> = Vec::new();
    for declaration in ancestors.into_iter().flatten() {
        scope.retain(|known| known.prefix != declaration.prefix);
        scope.push(declaration);
    }
    scope.retain(|declaration| {
        !declaration.value.is_empty() && !own.iter().any(|known| known.prefix == declaration.prefix)
    });
    scope
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::dom;

    fn first_grandchild(xml: &str) -> Result<String, SamlError> {
        let document = dom::parse_document(xml, crate::XmlLimits::default())?;
        let node = document
            .root
            .children
            .first()
            .and_then(|child| child.children.first())
            .ok_or_else(|| SamlError::xml("fixture has no grandchild"))?;
        standalone_element(xml, node.start, node.end)
    }

    #[test]
    fn an_element_that_redeclares_every_inherited_prefix_is_unchanged() -> Result<(), SamlError> {
        let xml = r#"<b:Root xmlns:b="urn:b"><b:Mid><b:Leaf xmlns:b="urn:inner" b:id="1"/></b:Mid></b:Root>"#;
        assert_eq!(
            first_grandchild(xml)?,
            r#"<b:Leaf xmlns:b="urn:inner" b:id="1"/>"#
        );
        Ok(())
    }

    #[test]
    fn every_namespace_in_scope_is_declared_on_the_element() -> Result<(), SamlError> {
        let xml = r#"<a:Root xmlns:a="urn:a" xmlns:b="urn:b" xmlns:unused="urn:unused"><a:Mid xmlns:c="urn:c"><b:Leaf c:id="1"><a:Inner/></b:Leaf></a:Mid></a:Root>"#;
        assert_eq!(
            first_grandchild(xml)?,
            r#"<b:Leaf xmlns:a="urn:a" xmlns:b="urn:b" xmlns:unused="urn:unused" xmlns:c="urn:c" c:id="1"><a:Inner/></b:Leaf>"#
        );
        Ok(())
    }

    #[test]
    fn a_prefix_used_only_in_a_qname_value_is_declared() -> Result<(), SamlError> {
        let xml = r#"<a:Root xmlns:a="urn:a" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema"><a:Mid><a:Value xsi:type="xs:string">v</a:Value></a:Mid></a:Root>"#;
        assert_eq!(
            first_grandchild(xml)?,
            r#"<a:Value xmlns:a="urn:a" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">v</a:Value>"#
        );
        Ok(())
    }

    #[test]
    fn an_undeclared_default_namespace_is_not_inherited() -> Result<(), SamlError> {
        let xml =
            r#"<a:Root xmlns="urn:default" xmlns:a="urn:a"><Mid xmlns=""><Leaf/></Mid></a:Root>"#;
        assert_eq!(first_grandchild(xml)?, r#"<Leaf xmlns:a="urn:a"/>"#);
        Ok(())
    }

    #[test]
    fn an_inherited_default_namespace_is_declared_on_the_element() -> Result<(), SamlError> {
        let xml = r#"<Root xmlns="urn:default"><Mid><Leaf id="1">text</Leaf></Mid></Root>"#;
        assert_eq!(
            first_grandchild(xml)?,
            r#"<Leaf xmlns="urn:default" id="1">text</Leaf>"#
        );
        Ok(())
    }

    #[test]
    fn the_innermost_ancestor_declaration_wins() -> Result<(), SamlError> {
        let xml = r#"<a:Root xmlns:a="urn:outer"><a:Mid xmlns:a='urn:"inner"'><a:Leaf/></a:Mid></a:Root>"#;
        assert_eq!(
            first_grandchild(xml)?,
            r#"<a:Leaf xmlns:a="urn:&quot;inner&quot;"/>"#
        );
        Ok(())
    }

    #[test]
    fn a_byte_order_mark_does_not_shift_the_element() -> Result<(), SamlError> {
        let xml = "\u{feff}<r xmlns:p=\"urn:outer\"><m><g><p:c xmlns:p=\"urn:inner\"/></g></m></r>";
        assert_eq!(
            first_grandchild(xml)?,
            r#"<g xmlns:p="urn:outer"><p:c xmlns:p="urn:inner"/></g>"#
        );
        Ok(())
    }

    #[test]
    fn a_span_that_is_not_an_element_is_rejected() {
        let xml = r#"<a:Root xmlns:a="urn:a">text</a:Root>"#;
        assert!(matches!(
            standalone_element(xml, xml.len(), xml.len()),
            Err(SamlError::Xml { .. })
        ));
    }
}
