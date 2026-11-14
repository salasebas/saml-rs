use super::{parse_xml_document, root_children, ENC};
use crate::constants::{self, namespace};
use crate::error::SamlError;
use bergshamra::xml::{Document as XmlDocument, NodeId};

pub(crate) fn response_uses_cbc_encrypted_assertion(xml: &str) -> Result<bool, SamlError> {
    let document = parse_xml_document(xml)?;
    let mut uses_cbc = false;
    for assertion in root_children(&document, namespace::ASSERTION, "EncryptedAssertion")? {
        let algorithm = encrypted_data_algorithm(&document, assertion)?;
        if constants::is_xml_encryption_cbc_algorithm(&algorithm) {
            uses_cbc = true;
        } else if !constants::is_xml_encryption_gcm_algorithm(&algorithm) {
            return Err(SamlError::Unsupported(format!(
                "unsupported encrypted assertion data algorithm: {algorithm}"
            )));
        }
    }
    Ok(uses_cbc)
}

// Bergshamra reads the canonicalized wrapper, whose attributes may be reordered.
// It selects the first xenc method and reads Algorithm by local name.
pub(super) fn encrypted_data_algorithm(
    document: &XmlDocument<'_>,
    element: NodeId,
) -> Result<String, SamlError> {
    let wrapper = super::decrypt::encrypted_wrapper(document, element)?;
    let encrypted = parse_xml_document(&wrapper)?;
    let data = encrypted
        .descendants(encrypted.root())
        .into_iter()
        .find(|node| {
            encrypted
                .element(*node)
                .is_some_and(|element| element.matches_name_ns(ENC, "EncryptedData"))
        })
        .ok_or_else(|| SamlError::Crypto("missing EncryptedData".into()))?;
    encrypted
        .first_child_element_by_name_ns(data, ENC, "EncryptionMethod")
        .and_then(|method| encrypted.element(method))
        .and_then(|method| method.get_attribute("Algorithm"))
        .map(str::to_owned)
        .ok_or_else(|| SamlError::Crypto("missing EncryptionMethod Algorithm".into()))
}
