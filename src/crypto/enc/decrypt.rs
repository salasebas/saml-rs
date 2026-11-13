//! Assertion, `<EncryptedID>`, `<EncryptedAttribute>`, and `<NewEncryptedID>`
//! decryption.

use std::ops::Range;

use super::{
    assertion_children, assertion_elements, crypto_err, namespace_complete, node_range,
    parse_xml_document, root_children, selected_kinds, splice, EncryptedElementKind, ENC,
    ENCRYPTED_ASSERTION, ENCRYPTED_ATTRIBUTE, ENCRYPTED_ID, LOGOUT_REQUEST_ENCRYPTED_ID,
};
use crate::config::{AssertionElementEncryption, DecryptionCredential, ReceivedEncryptedElements};
use crate::constants::{key_encryption_algorithm, namespace};
use crate::error::SamlError;
use crate::xml::dom::{self, XmlLimits};
use bergshamra::keys::Key;
use bergshamra::xml::{uppsala, Document as XmlDocument, NodeId, NodeKind};
use bergshamra::{decrypt, EncContext, KeysManager};

const RSA15_DECRYPTION_DISABLED: &str = "XML-Enc RSA-v1.5 key transport (http://www.w3.org/2001/04/xmlenc#rsa-1_5) is refused before decryption unless allow_rsa15_key_transport_decryption is selected";

/// Options for XML-Enc assertion decryption.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct AssertionDecryptionOptions {
    /// Decrypt an `<EncryptedKey>` that uses RSA-v1.5 key transport.
    ///
    /// When this is `false`, an encrypted element whose XML names
    /// `http://www.w3.org/2001/04/xmlenc#rsa-1_5` in an `<EncryptionMethod>`
    /// is refused with [`SamlError::Unsupported`] before any key is
    /// decrypted. RSA-v1.5 is open to Bleichenbacher's chosen-ciphertext
    /// attack. Set it only for a peer that cannot send RSA-OAEP. It also
    /// needs `crypto-legacy-algorithms`.
    pub allow_rsa15_key_transport_decryption: bool,
}

/// Decrypt the `<EncryptedData>` in `xml` with the first of `enc_keys` that
/// decrypts it, after refusing an unselected RSA-v1.5 `<EncryptionMethod>`
/// anywhere in `xml`. When none does, the error is the first key's.
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

/// Whether an `<xenc:EncryptionMethod>` of `xml` has an `Algorithm` attribute
/// naming RSA-v1.5. `bergshamra` parses the same text with `uppsala` and reads
/// `Algorithm` by local name, so every such attribute is checked.
fn names_rsa15_key_transport(xml: &str) -> Result<bool, SamlError> {
    let document = uppsala::parse(xml).map_err(crypto_err)?;
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

/// Decrypt each `<EncryptedAssertion>` child of the document element of `xml`
/// using `enc_key`, replacing each one with its plaintext `<Assertion>`.
///
/// The `<xenc:EncryptedKey>` is the one in the `ds:KeyInfo` of
/// `<xenc:EncryptedData>`, or one after `<xenc:EncryptedData>` that a
/// `ds:RetrievalMethod` of type `http://www.w3.org/2001/04/xmlenc#EncryptedKey`
/// names.
///
/// Returns `(response_with_decrypted_assertions, first_decrypted_assertion)`.
///
/// # Errors
///
/// Fails when any `<EncryptedAssertion>` does not decrypt. Returns
/// [`SamlError::ProtocolProfile`] when an `<EncryptedAssertion>` holds
/// anything other than one `<xenc:EncryptedData>` followed only by
/// `<xenc:EncryptedKey>` elements, or when its plaintext is not one
/// `<Assertion>`. Returns [`SamlError::Unsupported`] for a refused key
/// transport, and another [`SamlError`] when decryption fails.
pub fn decrypt_assertion(
    xml: &str,
    enc_key: &Key,
    options: AssertionDecryptionOptions,
) -> Result<(String, String), SamlError> {
    decrypt_assertion_with_limits(xml, enc_key, options, XmlLimits::default())
}

/// Decrypt each `<EncryptedAssertion>` with explicit XML parser resource limits.
///
/// # Errors
///
/// As [`decrypt_assertion`], and [`SamlError::Invalid`] when a limit is exceeded.
pub fn decrypt_assertion_with_limits(
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
        .ok_or_else(undefined_encrypted_assertion)?;
    Ok((response, assertion))
}

/// `xml` with each `<EncryptedAssertion>` child of its document element
/// decrypted, and each decrypted `<Assertion>` in document order.
pub(crate) fn decrypt_assertions_with_limits(
    xml: &str,
    enc_keys: &[Key],
    options: AssertionDecryptionOptions,
    limits: XmlLimits,
) -> Result<(String, Vec<String>), SamlError> {
    let mut assertions = Vec::new();
    let response = decrypt_selected(xml, limits, |document| {
        let encrypted = root_children(document, namespace::ASSERTION, "EncryptedAssertion")?;
        if encrypted.is_empty() {
            return Ok(None);
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
        assertions = replacements
            .iter()
            .map(|(_, assertion)| assertion.clone())
            .collect();
        Ok(Some(replacements))
    })?
    .ok_or_else(undefined_encrypted_assertion)?;
    Ok((response, assertions))
}

fn undefined_encrypted_assertion() -> SamlError {
    SamlError::Crypto("ERR_UNDEFINED_ENCRYPTED_ASSERTION".into())
}

/// Replace the one `kind.encrypted` child of the document element of `xml`
/// with the plaintext it carries, decrypted with one of `enc_keys`.
///
/// # Errors
///
/// Returns [`SamlError::ProtocolProfile`] when the document element has no
/// such child or several, or when the plaintext is not one element of the
/// expected name. Returns another [`SamlError`] when decryption fails.
pub(crate) fn decrypt_root_child(
    xml: &str,
    kind: EncryptedElementKind,
    enc_keys: &[Key],
    options: AssertionDecryptionOptions,
    limits: XmlLimits,
) -> Result<String, SamlError> {
    decrypt_selected(xml, limits, |document| {
        let [element] = root_children(document, kind.namespace, kind.encrypted)?[..] else {
            return Ok(None);
        };
        let replacement = decrypted_element(document, element, kind, enc_keys, options, limits)?;
        Ok(Some(vec![replacement]))
    })?
    .ok_or_else(|| {
        SamlError::ProtocolProfile(format!("{} requires one {}", kind.parent, kind.encrypted))
    })
}

/// Whether a verified signature covers a received request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestAuthentication {
    Authenticated,
    Unauthenticated,
}

/// `xml` with the `<EncryptedID>` of the `<Subject>` of its `<AuthnRequest>`
/// replaced by the `<NameID>` it carries, decrypted with the private key in
/// `key_pem` or one of `additional`.
///
/// Returns `None` when the `<Subject>` carries no `<EncryptedID>`, for an
/// unauthenticated request whose `EncryptedData` does not name AES-GCM (CBC
/// ciphertext is decrypted only under a verified signature), and when the
/// `<EncryptedID>` does not decrypt to one `<NameID>`.
///
/// # Errors
///
/// Returns a [`SamlError`] when the key does not load.
pub(crate) fn decrypt_authn_request_encrypted_id(
    xml: &str,
    key_pem: &str,
    key_pass: Option<&str>,
    additional: &[DecryptionCredential],
    options: AssertionDecryptionOptions,
    limits: XmlLimits,
    authentication: RequestAuthentication,
) -> Result<Option<String>, SamlError> {
    decrypt_selected(xml, limits, |document| {
        let [subject] = root_children(document, namespace::ASSERTION, "Subject")?[..] else {
            return Ok(None);
        };
        let encrypted_ids: Vec<NodeId> =
            assertion_children(document, subject, "EncryptedID").collect();
        let [encrypted_id] = encrypted_ids[..] else {
            return Ok(None);
        };
        match authentication {
            RequestAuthentication::Authenticated => {}
            RequestAuthentication::Unauthenticated => {
                if !uses_gcm(document, encrypted_id) {
                    return Ok(None);
                }
            }
        }
        let enc_keys = crate::crypto::keys::load_decryption_keys(key_pem, key_pass, additional)?;
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
    })
}

/// Whether the `EncryptedData` of `encrypted` names an AES-GCM
/// `EncryptionMethod`.
fn uses_gcm(document: &XmlDocument<'_>, encrypted: NodeId) -> bool {
    document
        .first_child_element_by_name_ns(encrypted, ENC, "EncryptedData")
        .and_then(|data| document.first_child_element_by_name_ns(data, ENC, "EncryptionMethod"))
        .and_then(|method| document.element(method))
        .and_then(|method| method.get_attribute("Algorithm"))
        .is_some_and(crate::constants::is_xml_encryption_gcm_algorithm)
}

/// Whether an assertion in `xml` carries an `<EncryptedID>` in its `<Subject>`
/// or an `<EncryptedAttribute>` in an `<AttributeStatement>`.
pub(crate) fn carries_encrypted_assertion_elements(xml: &str) -> Result<bool, SamlError> {
    let document = parse_xml_document(xml)?;
    for kind in [ENCRYPTED_ID, ENCRYPTED_ATTRIBUTE] {
        if !assertion_elements(&document, kind.parent, kind.encrypted)?.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Decrypt the children of each assertion in `xml` with `enc_keys`: the ones
/// `selection` selects, and every one when `received` is
/// [`ReceivedEncryptedElements::DecryptReceived`].
///
/// Each `<EncryptedID>` of an assertion `<Subject>` becomes the `<NameID>` it
/// carries, and each `<EncryptedAttribute>` of an `<AttributeStatement>`
/// becomes its `<Attribute>`. The plaintext is placed where the encrypted
/// element was, so it takes the namespace context of that position.
///
/// # Errors
///
/// Returns [`SamlError::EncryptionRequired`] when a selected `<NameID>` or
/// `<Attribute>` is in plaintext. An `<EncryptedID>` whose plaintext is a
/// `<BaseID>` or an `<Assertion>` returns [`SamlError::Unsupported`]. Any other
/// plaintext that is not one element of the expected name returns
/// [`SamlError::ProtocolProfile`].
pub(crate) fn decrypt_assertion_elements(
    xml: &str,
    enc_keys: &[Key],
    options: AssertionDecryptionOptions,
    limits: XmlLimits,
    selection: AssertionElementEncryption,
    received: ReceivedEncryptedElements,
) -> Result<String, SamlError> {
    let decrypted = decrypt_selected(xml, limits, |document| {
        let selected = selected_kinds(selection);
        let decrypted = match received {
            ReceivedEncryptedElements::DecryptReceived => vec![ENCRYPTED_ID, ENCRYPTED_ATTRIBUTE],
            ReceivedEncryptedElements::DecryptSelected => selected.clone(),
        };
        for kind in &selected {
            if !assertion_elements(document, kind.parent, kind.plaintext)?.is_empty() {
                return Err(SamlError::EncryptionRequired {
                    element: kind.plaintext,
                });
            }
        }
        let mut replacements = Vec::new();
        for kind in decrypted {
            for element in assertion_elements(document, kind.parent, kind.encrypted)? {
                replacements.push(decrypted_element(
                    document, element, kind, enc_keys, options, limits,
                )?);
            }
        }
        Ok((!replacements.is_empty()).then_some(replacements))
    })?;
    Ok(decrypted.unwrap_or_else(|| xml.to_owned()))
}

/// Replace the `<EncryptedID>` of the `<LogoutRequest>` in `xml` with the
/// `<NameID>` it carries, decrypted with one of `enc_keys`.
///
/// Returns `None` when no key in `enc_keys` decrypts the `<EncryptedID>`
/// under `options`.
///
/// # Errors
///
/// Returns [`SamlError::ProtocolProfile`] unless the request carries exactly
/// one `<BaseID>`, `<NameID>`, or `<EncryptedID>`, and that one is an
/// `<EncryptedID>`. Its plaintext follows [`decrypt_assertion_elements`].
pub(crate) fn decrypt_logout_request_encrypted_id(
    xml: &str,
    enc_keys: &[Key],
    options: AssertionDecryptionOptions,
    limits: XmlLimits,
) -> Result<Option<String>, SamlError> {
    decrypt_selected(xml, limits, |document| {
        let mut identifiers = Vec::new();
        for name in ["BaseID", "NameID", "EncryptedID"] {
            identifiers.extend(root_children(document, namespace::ASSERTION, name)?);
        }
        let encrypted_ids = root_children(document, namespace::ASSERTION, "EncryptedID")?;
        let ([_], [encrypted_id]) = (&identifiers[..], &encrypted_ids[..]) else {
            return Err(SamlError::ProtocolProfile(
                "LogoutRequest requires one BaseID, NameID, or EncryptedID".into(),
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
        let plaintext = decrypted_plaintext(&decrypted, peer_keys, kind, limits)?;
        Ok(Some(vec![(
            node_range(document, *encrypted_id)?,
            plaintext.to_string(),
        )]))
    })
}

/// `xml` with each `(range, plaintext)` that `decrypt` returns from its
/// document spliced in, or `None` when `decrypt` decrypts nothing. `xml` is
/// parsed under `limits` before `decrypt` reads it, and the result must stay
/// within `limits.max_bytes`.
fn decrypt_selected(
    xml: &str,
    limits: XmlLimits,
    decrypt: impl FnOnce(&XmlDocument<'_>) -> Result<Option<Vec<(Range<usize>, String)>>, SamlError>,
) -> Result<Option<String>, SamlError> {
    crate::crypto::provider::ensure_crypto_provider_initialized()?;
    dom::parse_with_limits(xml, limits)?;
    let document = parse_xml_document(xml)?;
    let Some(replacements) = decrypt(&document)? else {
        return Ok(None);
    };
    let decrypted = splice(xml, replacements);
    limits.check_input_bytes(decrypted.len())?;
    Ok(Some(decrypted))
}

/// The source range of the encrypted `element` and the plaintext it carries.
fn decrypted_element(
    document: &XmlDocument<'_>,
    element: NodeId,
    kind: EncryptedElementKind,
    enc_keys: &[Key],
    options: AssertionDecryptionOptions,
    limits: XmlLimits,
) -> Result<(Range<usize>, String), SamlError> {
    let peer_keys = require_encrypted_element_children(document, element, kind)?;
    let decrypted = decrypt_with_keys(&encrypted_wrapper(document, element)?, enc_keys, options)?;
    let plaintext = decrypted_plaintext(&decrypted, peer_keys, kind, limits)?;
    Ok((node_range(document, element)?, plaintext.to_string()))
}

/// The encrypted `element` with the namespace declarations it uses, for
/// decryption.
fn encrypted_wrapper(document: &XmlDocument<'_>, element: NodeId) -> Result<String, SamlError> {
    // The whole wrapper is decrypted so that an `EncryptedKey` beside
    // `EncryptedData`, named by a `RetrievalMethod`, resolves (E43).
    String::from_utf8(namespace_complete(document, element)?)
        .map_err(|error| SamlError::Xml(error.to_string()))
}

/// `EncryptedElementType`: one `EncryptedData`, then any `EncryptedKey`.
/// Returns the number of `EncryptedKey` elements.
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

/// The element that took the place of `EncryptedData` in the decrypted
/// `wrapper`: its first child, followed by the `peer_keys` `EncryptedKey`
/// elements that were already there.
fn decrypted_plaintext(
    wrapper: &str,
    peer_keys: usize,
    kind: EncryptedElementKind,
    limits: XmlLimits,
) -> Result<&str, SamlError> {
    let root = dom::parse_with_limits(wrapper, limits)?.root;
    let Some((plaintext, keys)) = root.children.split_first() else {
        return Err(must_carry(kind));
    };
    if keys.len() != peer_keys
        || keys.iter().any(|key| key.local_name != "EncryptedKey")
        || !is_xml_whitespace(&root.text)
    {
        return Err(must_carry(kind));
    }
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

fn must_carry(kind: EncryptedElementKind) -> SamlError {
    SamlError::ProtocolProfile(format!(
        "{} must carry one {}",
        kind.encrypted, kind.plaintext
    ))
}
