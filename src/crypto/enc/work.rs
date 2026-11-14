use super::{parse_xml_document, ENC};
use crate::error::SamlError;
use bergshamra::xml::{Document as XmlDocument, NodeId};

pub(super) fn document_work(
    document: &XmlDocument<'_>,
    keys: usize,
    maximum: usize,
) -> Result<usize, SamlError> {
    add_revealed_work(0, element_count(document, document.root()), keys, maximum)
}

fn element_count(document: &XmlDocument<'_>, root: NodeId) -> usize {
    document
        .descendants(root)
        .into_iter()
        .filter(|node| {
            document.element(*node).is_some_and(|element| {
                element.matches_name_ns(ENC, "EncryptedData")
                    || element.matches_name_ns(ENC, "EncryptedKey")
                    || element.matches_name_ns("http://www.w3.org/2009/xmlenc11#", "DerivedKey")
            })
        })
        .count()
}

pub(super) fn revealed_elements(wrapper: &str) -> Result<usize, SamlError> {
    let document = parse_xml_document(wrapper)?;
    let root = document
        .document_element()
        .ok_or_else(|| SamlError::Xml("no document element".into()))?;
    let plaintext = document
        .children_iter(root)
        .find(|node| document.element(*node).is_some())
        .ok_or_else(|| SamlError::Xml("no decrypted element".into()))?;
    Ok(element_count(&document, plaintext))
}

pub(super) fn add_revealed_work(
    current: usize,
    elements: usize,
    keys: usize,
    maximum: usize,
) -> Result<usize, SamlError> {
    let work = elements
        .checked_mul(keys)
        .and_then(|work| current.checked_add(work))
        .ok_or_else(|| limit_exceeded(maximum))?;
    if work > maximum {
        return Err(limit_exceeded(maximum));
    }
    Ok(work)
}

fn limit_exceeded(maximum: usize) -> SamlError {
    SamlError::Invalid(format!(
        "ERR_DECRYPTION_LIMIT_EXCEEDED: max decryption work units exceeded ({maximum})"
    ))
}
