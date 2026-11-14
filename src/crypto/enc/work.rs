use super::{parse_xml_document, ENC};
use crate::error::SamlError;
use bergshamra::xml::{Document as XmlDocument, NodeId};

/// Maximum aggregate decryption work units accepted from one message.
///
/// Each XML Encryption `EncryptedData`, `EncryptedKey`, and `DerivedKey` costs
/// one unit per configured decryption key, including rollover keys. This conservatively
/// bounds key resolution and retries, even when a retrieval method names a
/// key elsewhere in the document. Encrypted content revealed by decryption
/// counts toward the same limit before further decryption is allowed.
///
/// This fixed resource policy applies to every inbound encrypted-element
/// entry point, independently of XML parser limits and signature policy.
/// Exceeding it returns [`SamlError::Invalid`] with
/// `ERR_DECRYPTION_LIMIT_EXCEEDED` before the excessive work is performed.
pub const MAX_DECRYPTION_WORK: usize = 32;

pub(super) fn document_work(document: &XmlDocument<'_>, keys: usize) -> Result<usize, SamlError> {
    add_revealed_work(0, element_count(document, document.root()), keys)
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
) -> Result<usize, SamlError> {
    let work = elements
        .checked_mul(keys)
        .and_then(|work| current.checked_add(work))
        .ok_or_else(limit_exceeded)?;
    if work > MAX_DECRYPTION_WORK {
        return Err(limit_exceeded());
    }
    Ok(work)
}

fn limit_exceeded() -> SamlError {
    SamlError::Invalid(format!(
        "ERR_DECRYPTION_LIMIT_EXCEEDED: max decryption work units exceeded ({MAX_DECRYPTION_WORK})"
    ))
}
