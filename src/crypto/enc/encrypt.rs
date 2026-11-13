//! Assertion, `<EncryptedID>`, `<EncryptedAttribute>`, and `<NewEncryptedID>`
//! encryption.

use std::ops::Range;

use super::{
    assertion_elements, crypto_err, namespace_complete, node_range, parse_xml_document,
    root_children, selected_kinds, splice, EncryptedElementKind, ENC, LOGOUT_REQUEST_ENCRYPTED_ID,
};
use crate::binding::xml_escape;
use crate::config::AssertionElementEncryption;
use crate::constants::namespace;
use crate::crypto::keys::load_certificate;
use crate::crypto::xml_syntax::validate_crypto_xml_prefix;
use crate::error::SamlError;
use crate::xml::dom;
use crate::xml::fragment::standalone_element;
use bergshamra::xml::{Document as XmlDocument, NodeId};
use bergshamra::{encrypt, EncContext, KeysManager};

/// `<xenc:EncryptedData>` of type `Element` that carries `plaintext` for the
/// holder of `encrypt_cert`.
pub(super) fn encrypted_data_xml(
    plaintext: &[u8],
    encrypt_cert: &str,
    data_alg: &str,
    key_alg: &str,
) -> Result<String, SamlError> {
    let data_alg = xml_escape(data_alg);
    let key_alg = xml_escape(key_alg);
    let template = format!(
        "<xenc:EncryptedData xmlns:xenc=\"{enc}\" Type=\"{enc}Element\"><xenc:EncryptionMethod Algorithm=\"{data_alg}\"/><ds:KeyInfo xmlns:ds=\"{dsig}\"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm=\"{key_alg}\"/><xenc:CipherData><xenc:CipherValue></xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue></xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>",
        enc = ENC,
        dsig = namespace::DSIG,
    );

    let mut manager = KeysManager::new();
    manager.add_key(load_certificate(encrypt_cert)?);
    let ctx = EncContext::new(manager);
    encrypt(&ctx, &template, plaintext).map_err(crypto_err)
}

/// Encrypt the `<Assertion>` in `xml`, replacing it with
/// `<{prefix}:EncryptedAssertion>`.
///
/// The plaintext is the `<Assertion>` as written, with each namespace in
/// scope from its ancestors declared on it, so it parses on its own.
///
/// `encrypt_cert` is the recipient's encryption certificate; `data_alg` /
/// `key_alg` are the data and key encryption algorithm URIs.
pub fn encrypt_assertion(
    xml: &str,
    encrypt_cert: &str,
    data_alg: &str,
    key_alg: &str,
    tag_prefix: &str,
) -> Result<String, SamlError> {
    crate::crypto::provider::ensure_crypto_provider_initialized()?;
    validate_crypto_xml_prefix("EncryptedAssertion", tag_prefix)?;
    let doc = dom::parse(xml)?;
    let assertion = doc
        .root
        .child_named("Assertion")
        .ok_or_else(|| SamlError::MissingMetadata("Assertion to encrypt".into()))?;
    let assertion_xml = standalone_element(xml, assertion.start, assertion.end)?;
    let encrypted_data =
        encrypted_data_xml(assertion_xml.as_bytes(), encrypt_cert, data_alg, key_alg)?;

    let encrypted_assertion = format!(
        "<{prefix}:EncryptedAssertion xmlns:{prefix}=\"{assertion_ns}\">{encrypted_data}</{prefix}:EncryptedAssertion>",
        prefix = tag_prefix,
        assertion_ns = namespace::ASSERTION,
    );
    Ok(format!(
        "{}{}{}",
        &xml[..assertion.start],
        encrypted_assertion,
        &xml[assertion.end..]
    ))
}

fn qualified_name(document: &XmlDocument<'_>, node: NodeId, local_name: &str) -> String {
    match document
        .element(node)
        .and_then(|element| element.name.prefix.as_deref())
    {
        Some(prefix) => format!("{prefix}:{local_name}"),
        None => local_name.to_string(),
    }
}

/// Replace the selected children of each assertion in `xml` with their
/// encrypted form for the holder of `encrypt_cert`.
///
/// Each `<NameID>` of an assertion `<Subject>` becomes an `<EncryptedID>`, and
/// each `<Attribute>` of an `<AttributeStatement>` becomes an
/// `<EncryptedAttribute>`. The wrapper takes the prefix of the element it
/// replaces. The encrypted element is its inclusive canonical form, so it
/// declares every namespace in scope.
pub(crate) fn encrypt_assertion_elements(
    xml: &str,
    encrypt_cert: &str,
    data_alg: &str,
    key_alg: &str,
    selection: AssertionElementEncryption,
) -> Result<String, SamlError> {
    encrypt_selected(xml, encrypt_cert, data_alg, key_alg, |document| {
        let mut selected = Vec::new();
        for kind in selected_kinds(selection) {
            for element in assertion_elements(document, kind.parent, kind.plaintext)? {
                selected.push((element, kind));
            }
        }
        Ok(selected)
    })
}

/// Replace the `<NameID>` of the `<LogoutRequest>` in `xml` with an
/// `<EncryptedID>` for the holder of `encrypt_cert`, as
/// [`encrypt_assertion_elements`] does for an assertion `<Subject>`.
pub(crate) fn encrypt_logout_request_name_id(
    xml: &str,
    encrypt_cert: &str,
    data_alg: &str,
    key_alg: &str,
) -> Result<String, SamlError> {
    encrypt_selected(xml, encrypt_cert, data_alg, key_alg, |document| {
        let [name_id] = root_children(document, namespace::ASSERTION, "NameID")?[..] else {
            return Err(SamlError::ProtocolProfile(
                "LogoutRequest must carry one NameID to encrypt".into(),
            ));
        };
        Ok(vec![(name_id, LOGOUT_REQUEST_ENCRYPTED_ID)])
    })
}

/// `xml` with each `(element, kind)` that `select` picks from its document
/// replaced by the `kind.encrypted` form of `element` for the holder of
/// `encrypt_cert`.
fn encrypt_selected(
    xml: &str,
    encrypt_cert: &str,
    data_alg: &str,
    key_alg: &str,
    select: impl FnOnce(&XmlDocument<'_>) -> Result<Vec<(NodeId, EncryptedElementKind)>, SamlError>,
) -> Result<String, SamlError> {
    crate::crypto::provider::ensure_crypto_provider_initialized()?;
    let document = parse_xml_document(xml)?;
    let replacements = select(&document)?
        .into_iter()
        .map(|(element, kind)| {
            encrypted_element(&document, element, kind, encrypt_cert, data_alg, key_alg)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(splice(xml, replacements))
}

/// The source range of `element` and the `kind.encrypted` wrapper that
/// replaces it. The wrapper takes the prefix of `element`, and keeps the
/// declaration of that prefix when `element` itself declares it. The encrypted
/// element is its inclusive canonical form.
fn encrypted_element(
    document: &XmlDocument<'_>,
    element: NodeId,
    kind: EncryptedElementKind,
    encrypt_cert: &str,
    data_alg: &str,
    key_alg: &str,
) -> Result<(Range<usize>, String), SamlError> {
    let plaintext = namespace_complete(document, element)?;
    let encrypted_data = encrypted_data_xml(&plaintext, encrypt_cert, data_alg, key_alg)?;
    let wrapper = qualified_name(document, element, kind.encrypted);
    let declaration = match own_prefix_declaration(document, element) {
        Some("") => format!(" xmlns=\"{}\"", kind.namespace),
        Some(prefix) => format!(" xmlns:{prefix}=\"{}\"", kind.namespace),
        None => String::new(),
    };
    Ok((
        node_range(document, element)?,
        format!("<{wrapper}{declaration}>{encrypted_data}</{wrapper}>"),
    ))
}

/// The prefix of `element` when `element` itself declares it. The empty prefix is the default namespace.
fn own_prefix_declaration<'d>(document: &'d XmlDocument<'_>, element: NodeId) -> Option<&'d str> {
    let element = document.element(element)?;
    let prefix = element.name.prefix.as_deref().unwrap_or("");
    element
        .namespace_declarations
        .iter()
        .any(|(declared, _)| declared == prefix)
        .then_some(prefix)
}

/// Replace each `kind.plaintext` child of the document element of `xml`, for
/// each of `kinds`, with its `kind.encrypted` form for the holder of
/// `encrypt_cert`.
pub(crate) fn encrypt_root_children(
    xml: &str,
    kinds: &[EncryptedElementKind],
    encrypt_cert: &str,
    data_alg: &str,
    key_alg: &str,
) -> Result<String, SamlError> {
    encrypt_selected(xml, encrypt_cert, data_alg, key_alg, |document| {
        let mut selected = Vec::new();
        for kind in kinds {
            for element in root_children(document, kind.namespace, kind.plaintext)? {
                selected.push((element, *kind));
            }
        }
        Ok(selected)
    })
}
