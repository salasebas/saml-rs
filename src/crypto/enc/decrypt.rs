use std::ops::Range;

use super::{
    assertion_children, assertion_elements, namespace_complete, node_range, parse_xml_document,
    root_children, selected_kinds, splice, EncryptedElementKind, ENC, ENCRYPTED_ASSERTION,
    ENCRYPTED_ATTRIBUTE, ENCRYPTED_ID, LOGOUT_REQUEST_ENCRYPTED_ID,
};
use super::{policy::encrypted_data_algorithm, work};
use crate::config::{AssertionElementEncryption, X509Credential};
use crate::constants::{key_encryption_algorithm, namespace};
use crate::entity::EntitySetting;
use crate::error::{crypto_err, xml_err, SamlError};
use crate::flow::{FlowOptions, MessageAuthentication};
use crate::xml::dom::{self, XmlLimits};
use bergshamra::keys::Key;
use bergshamra::xml::{uppsala, Document as XmlDocument, NodeId, NodeKind};
use bergshamra::{decrypt, EncContext, KeysManager};

const RSA15_DECRYPTION_DISABLED: &str = "XML-Enc RSA-v1.5 key transport (http://www.w3.org/2001/04/xmlenc#rsa-1_5) is refused before decryption unless allow_rsa15_key_transport_decryption is selected";

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub(crate) struct AssertionDecryptionOptions {
    /// Decrypt an `<EncryptedKey>` that uses RSA-v1.5 key transport.
    ///
    /// When this is `false`, an encrypted element whose XML names
    /// `http://www.w3.org/2001/04/xmlenc#rsa-1_5` in an `<EncryptionMethod>`
    /// is refused with [`SamlError::Unsupported`] before any key is
    /// decrypted. RSA-v1.5 is open to Bleichenbacher's chosen-ciphertext
    /// attack. Set it only for a peer that cannot send RSA-OAEP. It also
    /// needs `crypto-legacy-algorithms`.
    pub allow_rsa15_key_transport_decryption: bool,
    pub max_decryption_work: usize,
}

impl Default for AssertionDecryptionOptions {
    fn default() -> Self {
        Self {
            allow_rsa15_key_transport_decryption: false,
            max_decryption_work: crate::constants::DEFAULT_MAX_DECRYPTION_WORK,
        }
    }
}

impl From<&EntitySetting> for AssertionDecryptionOptions {
    fn from(setting: &EntitySetting) -> Self {
        Self {
            allow_rsa15_key_transport_decryption: setting.allow_rsa15_key_transport_decryption,
            max_decryption_work: setting.max_decryption_work,
        }
    }
}

impl From<&FlowOptions<'_>> for AssertionDecryptionOptions {
    fn from(options: &FlowOptions<'_>) -> Self {
        Self {
            allow_rsa15_key_transport_decryption: options.allow_rsa15_key_transport_decryption,
            max_decryption_work: options.max_decryption_work,
        }
    }
}

fn decrypt_with_keys(
    xml: &str,
    enc_keys: &[Key],
    options: AssertionDecryptionOptions,
) -> Result<String, SamlError> {
    if !options.allow_rsa15_key_transport_decryption && names_rsa15_key_transport(xml)? {
        return Err(SamlError::Unsupported(RSA15_DECRYPTION_DISABLED.into()));
    }
    let mut first_error = None;
    for enc_key in enc_keys {
        let mut manager = KeysManager::new();
        manager.add_key(enc_key.clone());
        match decrypt(&EncContext::new(manager), xml) {
            Ok(decrypted) => return Ok(decrypted),
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    Err(first_error.map_or_else(
        || SamlError::MissingKey("decryption_key".into()),
        crypto_err,
    ))
}

fn names_rsa15_key_transport(xml: &str) -> Result<bool, SamlError> {
    let document = uppsala::parse(xml).map_err(xml_err)?;
    Ok(document
        .descendants(document.root())
        .into_iter()
        .any(|node| {
            document.element(node).is_some_and(|element| {
                element.matches_name_ns(ENC, "EncryptionMethod")
                    && element.attributes.iter().any(|attribute| {
                        attribute.name.local_name == "Algorithm"
                            && attribute.value == key_encryption_algorithm::RSA_1_5
                    })
            })
        }))
}

#[cfg(all(test, not(feature = "crypto-fips")))]
pub(crate) fn decrypt_assertion_with_limits(
    xml: &str,
    enc_key: &Key,
    options: AssertionDecryptionOptions,
    limits: XmlLimits,
) -> Result<(String, String), SamlError> {
    let (response, assertions) =
        decrypt_assertions_with_limits(xml, std::slice::from_ref(enc_key), options, limits)?;
    let assertion = assertions
        .into_iter()
        .next()
        .ok_or(SamlError::AssertionMissing)?;
    Ok((response, assertion))
}

pub(crate) fn decrypt_assertions_with_limits(
    xml: &str,
    enc_keys: &[Key],
    options: AssertionDecryptionOptions,
    limits: XmlLimits,
) -> Result<(String, Vec<String>), SamlError> {
    let decrypted = decrypt_selected(xml, limits, enc_keys.len(), options, |document| {
        let encrypted = root_children(document, namespace::ASSERTION, "EncryptedAssertion")?;
        if encrypted.is_empty() {
            return Err(if super::assertions(document)?.is_empty() {
                SamlError::AssertionMissing
            } else {
                SamlError::EncryptionRequired {
                    element: "Assertion",
                }
            });
        }
        let replacements = encrypted
            .into_iter()
            .map(|element| {
                decrypted_element(
                    document,
                    element,
                    ENCRYPTED_ASSERTION,
                    enc_keys,
                    options,
                    limits,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(replacements))
    })?
    .ok_or(SamlError::AssertionMissing)?;
    Ok((decrypted.xml, decrypted.plaintexts))
}

pub(crate) fn decrypt_root_child(
    xml: &str,
    kind: EncryptedElementKind,
    enc_keys: &[Key],
    options: AssertionDecryptionOptions,
    limits: XmlLimits,
) -> Result<String, SamlError> {
    decrypt_selected(xml, limits, enc_keys.len(), options, |document| {
        let [element] = root_children(document, kind.namespace, kind.encrypted)?[..] else {
            return Ok(None);
        };
        let replacement = decrypted_element(document, element, kind, enc_keys, options, limits)?;
        Ok(Some(vec![replacement]))
    })?
    .map(|decrypted| decrypted.xml)
    .ok_or_else(|| {
        SamlError::ProtocolProfile(format!("{} requires one {}", kind.parent, kind.encrypted))
    })
}

pub(crate) fn decrypt_authn_request_encrypted_id(
    xml: &str,
    key_pem: &str,
    key_pass: Option<&str>,
    additional: &[X509Credential],
    options: AssertionDecryptionOptions,
    limits: XmlLimits,
    authentication: MessageAuthentication,
) -> Result<Option<String>, SamlError> {
    let decrypted = decrypt_selected(
        xml,
        limits,
        additional.len().saturating_add(1),
        options,
        |document| {
            let [subject] = root_children(document, namespace::ASSERTION, "Subject")?[..] else {
                return Ok(None);
            };
            let encrypted_ids: Vec<NodeId> =
                assertion_children(document, subject, "EncryptedID").collect();
            let [encrypted_id] = encrypted_ids[..] else {
                return Ok(None);
            };
            match authentication {
                MessageAuthentication::Authenticated => {}
                MessageAuthentication::Unauthenticated => {
                    if !uses_gcm(document, encrypted_id) {
                        return Ok(None);
                    }
                }
            }
            let enc_keys =
                crate::crypto::keys::load_decryption_keys(key_pem, key_pass, additional)?;
            let Ok(replacement) = decrypted_element(
                document,
                encrypted_id,
                ENCRYPTED_ID,
                &enc_keys,
                options,
                limits,
            ) else {
                return Ok(None);
            };
            Ok(Some(vec![replacement]))
        },
    )?;
    Ok(decrypted.map(|decrypted| decrypted.xml))
}

fn uses_gcm(document: &XmlDocument<'_>, encrypted: NodeId) -> bool {
    encrypted_data_algorithm(document, encrypted)
        .is_ok_and(|algorithm| crate::constants::is_xml_encryption_gcm_algorithm(&algorithm))
}

pub(crate) fn carries_encrypted_assertion_elements(xml: &str) -> Result<bool, SamlError> {
    let document = parse_xml_document(xml)?;
    for kind in [ENCRYPTED_ID, ENCRYPTED_ATTRIBUTE] {
        if !assertion_elements(&document, kind.parent, kind.encrypted)?.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn decrypt_assertion_elements(
    xml: &str,
    enc_keys: &[Key],
    options: AssertionDecryptionOptions,
    limits: XmlLimits,
    required: AssertionElementEncryption,
) -> Result<String, SamlError> {
    let decrypted = decrypt_selected(xml, limits, enc_keys.len(), options, |document| {
        for kind in selected_kinds(required) {
            if !assertion_elements(document, kind.parent, kind.plaintext)?.is_empty() {
                return Err(SamlError::EncryptionRequired {
                    element: kind.plaintext,
                });
            }
        }
        let mut replacements = Vec::new();
        for kind in [ENCRYPTED_ID, ENCRYPTED_ATTRIBUTE] {
            for element in assertion_elements(document, kind.parent, kind.encrypted)? {
                replacements.push(decrypted_element(
                    document, element, kind, enc_keys, options, limits,
                )?);
            }
        }
        Ok((!replacements.is_empty()).then_some(replacements))
    })?;
    Ok(decrypted.map_or_else(|| xml.to_owned(), |decrypted| decrypted.xml))
}

pub(crate) fn decrypt_logout_request_encrypted_id(
    xml: &str,
    enc_keys: &[Key],
    options: AssertionDecryptionOptions,
    limits: XmlLimits,
) -> Result<Option<String>, SamlError> {
    let decrypted = decrypt_selected(xml, limits, enc_keys.len(), options, |document| {
        let encrypted_ids = root_children(document, namespace::ASSERTION, "EncryptedID")?;
        let [encrypted_id] = encrypted_ids.as_slice() else {
            return Err(SamlError::ProtocolProfile(
                "LogoutRequest decryption requires one EncryptedID".into(),
            ));
        };
        let kind = LOGOUT_REQUEST_ENCRYPTED_ID;
        let peer_keys = require_encrypted_element_children(document, *encrypted_id, kind)?;
        let Ok(decrypted) = decrypt_with_keys(
            &encrypted_wrapper(document, *encrypted_id)?,
            enc_keys,
            options,
        ) else {
            return Ok(None);
        };
        let plaintext = decrypted_child(&decrypted, peer_keys, kind, limits)?;
        match plaintext.local_name.as_str() {
            "NameID" => {}
            "BaseID"
                if !root_children(&parse_xml_document(&decrypted)?, kind.namespace, "BaseID")?
                    .is_empty() => {}
            _ => return Err(must_carry(kind)),
        }
        Ok(Some(vec![DecryptedElement {
            range: node_range(document, *encrypted_id)?,
            plaintext: decrypted[plaintext.start..plaintext.end].to_string(),
            revealed_elements: work::revealed_elements(&decrypted)?,
        }]))
    })?;
    Ok(decrypted.map(|decrypted| decrypted.xml))
}

struct DecryptedElement {
    range: Range<usize>,
    plaintext: String,
    revealed_elements: usize,
}

struct DecryptedDocument {
    xml: String,
    plaintexts: Vec<String>,
}

fn decrypt_selected(
    xml: &str,
    limits: XmlLimits,
    keys: usize,
    options: AssertionDecryptionOptions,
    decrypt: impl FnOnce(&XmlDocument<'_>) -> Result<Option<Vec<DecryptedElement>>, SamlError>,
) -> Result<Option<DecryptedDocument>, SamlError> {
    crate::crypto::provider::ensure_crypto_provider_initialized()?;
    dom::parse_document(xml, limits)?;
    let document = parse_xml_document(xml)?;
    let mut work = work::document_work(&document, keys, options.max_decryption_work)?;
    let Some(replacements) = decrypt(&document)? else {
        return Ok(None);
    };
    for replacement in &replacements {
        work = work::add_revealed_work(
            work,
            replacement.revealed_elements,
            keys,
            options.max_decryption_work,
        )?;
    }
    let decrypted = splice(
        xml,
        replacements
            .iter()
            .map(|replacement| (replacement.range.clone(), replacement.plaintext.as_str()))
            .collect(),
    );
    limits.check_input_bytes(decrypted.len())?;
    Ok(Some(DecryptedDocument {
        xml: decrypted,
        plaintexts: replacements
            .into_iter()
            .map(|replacement| replacement.plaintext)
            .collect(),
    }))
}

fn decrypted_element(
    document: &XmlDocument<'_>,
    element: NodeId,
    kind: EncryptedElementKind,
    enc_keys: &[Key],
    options: AssertionDecryptionOptions,
    limits: XmlLimits,
) -> Result<DecryptedElement, SamlError> {
    let peer_keys = require_encrypted_element_children(document, element, kind)?;
    let decrypted = decrypt_with_keys(&encrypted_wrapper(document, element)?, enc_keys, options)?;
    let plaintext = decrypted_plaintext(&decrypted, peer_keys, kind, limits)?;
    Ok(DecryptedElement {
        range: node_range(document, element)?,
        plaintext: plaintext.to_string(),
        revealed_elements: work::revealed_elements(&decrypted)?,
    })
}

pub(super) fn encrypted_wrapper(
    document: &XmlDocument<'_>,
    element: NodeId,
) -> Result<String, SamlError> {
    // The whole wrapper is decrypted so that an `EncryptedKey` beside
    // `EncryptedData`, named by a `RetrievalMethod`, resolves (E43).
    crate::xml::decode_utf8(namespace_complete(document, element)?)
}

fn require_encrypted_element_children(
    document: &XmlDocument<'_>,
    element: NodeId,
    kind: EncryptedElementKind,
) -> Result<usize, SamlError> {
    let mut encrypted_data = 0;
    let mut peer_keys = 0;
    for child in document.children_iter(element) {
        match document.node_kind(child) {
            Some(NodeKind::Element(child))
                if child.matches_name_ns(ENC, "EncryptedData") && peer_keys == 0 =>
            {
                encrypted_data += 1;
            }
            Some(NodeKind::Element(child))
                if child.matches_name_ns(ENC, "EncryptedKey") && encrypted_data == 1 =>
            {
                peer_keys += 1;
            }
            Some(NodeKind::Text(text) | NodeKind::CData(text)) if is_xml_whitespace(text) => {}
            Some(NodeKind::Comment(_) | NodeKind::ProcessingInstruction(_)) => {}
            _ => return Err(encrypted_element_children_error(kind)),
        }
    }
    if encrypted_data != 1 {
        return Err(encrypted_element_children_error(kind));
    }
    Ok(peer_keys)
}

fn encrypted_element_children_error(kind: EncryptedElementKind) -> SamlError {
    SamlError::ProtocolProfile(format!(
        "{} must contain one EncryptedData and only EncryptedKey after it",
        kind.encrypted
    ))
}

fn is_xml_whitespace(text: &str) -> bool {
    text.bytes()
        .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
}

fn decrypted_plaintext(
    wrapper: &str,
    peer_keys: usize,
    kind: EncryptedElementKind,
    limits: XmlLimits,
) -> Result<&str, SamlError> {
    let plaintext = decrypted_child(wrapper, peer_keys, kind, limits)?;
    if plaintext.local_name == kind.plaintext {
        return Ok(&wrapper[plaintext.start..plaintext.end]);
    }
    if kind
        .unsupported_plaintext
        .contains(&plaintext.local_name.as_str())
    {
        return Err(SamlError::Unsupported(format!(
            "{} carrying {} is not supported",
            kind.encrypted, plaintext.local_name
        )));
    }
    Err(must_carry(kind))
}

fn decrypted_child(
    wrapper: &str,
    peer_keys: usize,
    kind: EncryptedElementKind,
    limits: XmlLimits,
) -> Result<dom::Node, SamlError> {
    let root = dom::parse_document(wrapper, limits)?.root;
    let mut keys = root.children.into_iter();
    let Some(plaintext) = keys.next() else {
        return Err(must_carry(kind));
    };
    if keys.len() != peer_keys
        || keys.any(|key| key.local_name != "EncryptedKey")
        || !is_xml_whitespace(&root.text)
    {
        return Err(must_carry(kind));
    }
    Ok(plaintext)
}

fn must_carry(kind: EncryptedElementKind) -> SamlError {
    SamlError::ProtocolProfile(format!(
        "{} must carry one {}",
        kind.encrypted, kind.plaintext
    ))
}
