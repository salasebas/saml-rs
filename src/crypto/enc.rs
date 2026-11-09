//! Assertion, `<EncryptedID>`, `<EncryptedAttribute>`, and `<NewEncryptedID>`
//! encryption and decryption, delegating XML-Enc to the selected `bergshamra`
//! provider.

use std::ops::Range;

use super::keys::load_certificate;
use super::xml_syntax::validate_crypto_xml_prefix;
use crate::binding::xml_escape;
use crate::config::{
    AssertionElementEncryption, AttributeEncryptionPolicy, IdentifierEncryptionPolicy,
    ReceivedEncryptedElements,
};
use crate::constants::{key_encryption_algorithm, namespace};
use crate::error::SamlError;
use crate::xml::dom::{self, Node, XmlLimits};
use bergshamra::c14n::{canonicalize_doc, C14nMode};
use bergshamra::keys::Key;
use bergshamra::xml::{uppsala, Document as XmlDocument, NodeId, NodeKind, NodeSet};
use bergshamra::{decrypt, encrypt, EncContext, KeysManager};

const ENC: &str = "http://www.w3.org/2001/04/xmlenc#";
const SOFTWARE_RSA_DECRYPTION_DISABLED: &str = "XML-Enc RSA key-transport decryption with software private keys is disabled by default because the bundled RustCrypto rsa backend is affected by RUSTSEC-2023-0071. Enable allow_insecure_software_rsa_key_transport_decryption only as an explicit compatibility exception.";
const RSA15_DECRYPTION_DISABLED: &str = "XML-Enc RSA-v1.5 key transport (http://www.w3.org/2001/04/xmlenc#rsa-1_5) is refused before decryption unless allow_rsa15_key_transport_decryption is selected";

/// Options for XML-Enc assertion decryption.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct AssertionDecryptionOptions {
    /// Allow the bundled RustCrypto software RSA backend for XML-Enc key transport.
    ///
    /// This flag is enforced only when `crypto-rustcrypto` is selected. That
    /// backend reaches `RUSTSEC-2023-0071`-affected `rsa` code when an attacker
    /// can observe timing. Keep this `false` unless the caller has a
    /// deployment-specific reason to accept that risk.
    ///
    /// AWS-LC and FIPS builds use `aws-lc-rs` for RSA-OAEP and ignore this
    /// flag. FIPS still rejects algorithms outside its approved set, including
    /// the SHA-1 `RSA_OAEP_MGF1P` key transport.
    pub allow_insecure_software_rsa_key_transport_decryption: bool,
    /// Decrypt an `<EncryptedKey>` that uses RSA-v1.5 key transport.
    ///
    /// When this is `false`, an encrypted element whose XML names
    /// `http://www.w3.org/2001/04/xmlenc#rsa-1_5` in an `<EncryptionMethod>`
    /// is refused with [`SamlError::Unsupported`] before any key is
    /// decrypted. RSA-v1.5 is open to Bleichenbacher's chosen-ciphertext
    /// attack. Set it only for a peer that cannot send RSA-OAEP. It also
    /// needs `crypto-legacy-algorithms`, and on RustCrypto
    /// `allow_insecure_software_rsa_key_transport_decryption`.
    pub allow_rsa15_key_transport_decryption: bool,
}

fn crypto_err(err: impl std::fmt::Display) -> SamlError {
    SamlError::Crypto(err.to_string())
}

pub(crate) fn software_rsa_decryption_disabled() -> SamlError {
    SamlError::Unsupported(SOFTWARE_RSA_DECRYPTION_DISABLED.into())
}

/// Reject RustCrypto software RSA key-transport decryption unless the caller
/// opted in. AWS-LC and FIPS ignore the flag because they do not use the
/// `RUSTSEC-2023-0071`-affected `rsa` crate.
pub(crate) fn require_software_rsa_opt_in(
    options: AssertionDecryptionOptions,
) -> Result<(), SamlError> {
    if cfg!(feature = "crypto-rustcrypto")
        && !options.allow_insecure_software_rsa_key_transport_decryption
    {
        return Err(software_rsa_decryption_disabled());
    }
    Ok(())
}

/// Decrypt the `<EncryptedData>` in `xml` with `enc_key`, after refusing an
/// unselected RSA-v1.5 `<EncryptionMethod>` anywhere in `xml`.
fn decrypt_with_key(
    xml: &str,
    enc_key: &Key,
    options: AssertionDecryptionOptions,
) -> Result<String, SamlError> {
    if !options.allow_rsa15_key_transport_decryption && names_rsa15_key_transport(xml)? {
        return Err(SamlError::Unsupported(RSA15_DECRYPTION_DISABLED.into()));
    }
    let mut manager = KeysManager::new();
    manager.add_key(enc_key.clone());
    decrypt(&EncContext::new(manager), xml).map_err(crypto_err)
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

fn child<'a>(node: &'a Node, name: &str) -> Option<&'a Node> {
    node.children.iter().find(|c| c.local_name == name)
}

/// `<xenc:EncryptedData>` of type `Element` that carries `plaintext` for the
/// holder of `encrypt_cert`.
fn encrypted_data_xml(
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
/// `encrypt_cert` is the recipient's encryption certificate; `data_alg` /
/// `key_alg` are the data and key encryption algorithm URIs.
pub fn encrypt_assertion(
    xml: &str,
    encrypt_cert: &str,
    data_alg: &str,
    key_alg: &str,
    tag_prefix: &str,
) -> Result<String, SamlError> {
    super::provider::ensure_crypto_provider_initialized()?;
    validate_crypto_xml_prefix("EncryptedAssertion", tag_prefix)?;
    let doc = dom::parse(xml)?;
    let assertion = child(&doc.root, "Assertion")
        .ok_or_else(|| SamlError::MissingMetadata("Assertion to encrypt".into()))?;
    let assertion_xml = &xml[assertion.start..assertion.end];
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

/// Decrypt the `<EncryptedAssertion>` in `xml` using `enc_key`, replacing it
/// with the plaintext `<Assertion>`.
///
/// The `<xenc:EncryptedKey>` is the one in the `ds:KeyInfo` of
/// `<xenc:EncryptedData>`, or one after `<xenc:EncryptedData>` that a
/// `ds:RetrievalMethod` of type `http://www.w3.org/2001/04/xmlenc#EncryptedKey`
/// names.
///
/// Returns `(response_with_decrypted_assertion, decrypted_assertion)`.
///
/// # Errors
///
/// Returns [`SamlError::ProtocolProfile`] when the `<EncryptedAssertion>`
/// holds anything other than one `<xenc:EncryptedData>` followed only by
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

/// Decrypt the `<EncryptedAssertion>` with explicit XML parser resource limits.
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
    super::provider::ensure_crypto_provider_initialized()?;
    require_software_rsa_opt_in(options)?;
    dom::parse_with_limits(xml, limits)?;
    let document = parse_xml_document(xml)?;
    let encrypted = *root_children(&document, namespace::ASSERTION, "EncryptedAssertion")?
        .first()
        .ok_or_else(|| SamlError::Crypto("ERR_UNDEFINED_ENCRYPTED_ASSERTION".into()))?;
    let (range, assertion) = decrypted_element(
        &document,
        encrypted,
        ENCRYPTED_ASSERTION,
        enc_key,
        options,
        limits,
    )?;
    let response = splice(xml, vec![(range, assertion.clone())]);
    limits.check_input_bytes(response.len())?;
    limits.check_input_bytes(assertion.len())?;
    Ok((response, assertion))
}

/// Plaintext element, its encrypted wrapper, and the parent that holds it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EncryptedElementKind {
    /// Namespace of the plaintext element and of its wrapper.
    namespace: &'static str,
    parent: &'static str,
    plaintext: &'static str,
    encrypted: &'static str,
    /// Other plaintext elements that SAML allows here and this crate does not
    /// process.
    unsupported_plaintext: &'static [&'static str],
}

/// SAML Core §2.3.4.
const ENCRYPTED_ASSERTION: EncryptedElementKind = EncryptedElementKind {
    namespace: namespace::ASSERTION,
    parent: "Response",
    plaintext: "Assertion",
    encrypted: "EncryptedAssertion",
    unsupported_plaintext: &[],
};

/// SAML Core §2.2.4.
const ENCRYPTED_ID: EncryptedElementKind = EncryptedElementKind {
    namespace: namespace::ASSERTION,
    parent: "Subject",
    plaintext: "NameID",
    encrypted: "EncryptedID",
    unsupported_plaintext: &["BaseID", "Assertion"],
};

/// SAML Core §2.7.3.2.
const ENCRYPTED_ATTRIBUTE: EncryptedElementKind = EncryptedElementKind {
    namespace: namespace::ASSERTION,
    parent: "AttributeStatement",
    plaintext: "Attribute",
    encrypted: "EncryptedAttribute",
    unsupported_plaintext: &[],
};

/// SAML Core §3.7.1: the principal of a `<LogoutRequest>`.
const LOGOUT_REQUEST_ENCRYPTED_ID: EncryptedElementKind = EncryptedElementKind {
    namespace: namespace::ASSERTION,
    parent: "LogoutRequest",
    plaintext: "NameID",
    encrypted: "EncryptedID",
    unsupported_plaintext: &["BaseID"],
};

/// SAML Core §3.6.1: the identifier a `<ManageNameIDRequest>` names.
pub(crate) const MANAGED_NAME_ID: EncryptedElementKind = EncryptedElementKind {
    namespace: namespace::ASSERTION,
    parent: "ManageNameIDRequest",
    plaintext: "NameID",
    encrypted: "EncryptedID",
    unsupported_plaintext: &[],
};

/// SAML Core §3.6.1, as amended by Errata 05 E12: the new value a
/// `<ManageNameIDRequest>` carries.
pub(crate) const NEW_ID: EncryptedElementKind = EncryptedElementKind {
    namespace: namespace::PROTOCOL,
    parent: "ManageNameIDRequest",
    plaintext: "NewID",
    encrypted: "NewEncryptedID",
    unsupported_plaintext: &[],
};

fn selected_kinds(selection: AssertionElementEncryption) -> Vec<EncryptedElementKind> {
    let mut kinds = Vec::new();
    match selection.identifiers {
        IdentifierEncryptionPolicy::EncryptIdentifiers => kinds.push(ENCRYPTED_ID),
        IdentifierEncryptionPolicy::PlaintextIdentifiers => {}
    }
    match selection.attributes {
        AttributeEncryptionPolicy::EncryptAttributes => kinds.push(ENCRYPTED_ATTRIBUTE),
        AttributeEncryptionPolicy::PlaintextAttributes => {}
    }
    kinds
}

fn parse_xml_document(xml: &str) -> Result<XmlDocument<'_>, SamlError> {
    uppsala::parse(xml).map_err(|error| SamlError::Xml(error.to_string()))
}

fn assertion_children<'d>(
    document: &'d XmlDocument<'_>,
    parent: NodeId,
    local_name: &'d str,
) -> impl Iterator<Item = NodeId> + 'd {
    document.children_iter(parent).filter(move |child| {
        document
            .element(*child)
            .is_some_and(|element| element.matches_name_ns(namespace::ASSERTION, local_name))
    })
}

/// Each `local_name` child, in `namespace`, of the document element.
fn root_children(
    document: &XmlDocument<'_>,
    namespace: &'static str,
    local_name: &'static str,
) -> Result<Vec<NodeId>, SamlError> {
    let root = document
        .document_element()
        .ok_or_else(|| SamlError::Xml("no document element".into()))?;
    Ok(document
        .children_iter(root)
        .filter(|child| {
            document
                .element(*child)
                .is_some_and(|element| element.matches_name_ns(namespace, local_name))
        })
        .collect())
}

/// Each `<Assertion>` of `xml`: the document element itself, or each
/// `<Assertion>` child of a protocol `<Response>`.
fn assertions(document: &XmlDocument<'_>) -> Result<Vec<NodeId>, SamlError> {
    let root = document
        .document_element()
        .ok_or_else(|| SamlError::Xml("no document element".into()))?;
    let root_is_assertion = document
        .element(root)
        .is_some_and(|element| element.matches_name_ns(namespace::ASSERTION, "Assertion"));
    if root_is_assertion {
        return Ok(vec![root]);
    }
    Ok(assertion_children(document, root, "Assertion").collect())
}

/// Each `name` child of each `parent` child of each assertion, in document
/// order.
fn assertion_elements(
    document: &XmlDocument<'_>,
    parent: &'static str,
    name: &'static str,
) -> Result<Vec<NodeId>, SamlError> {
    let mut elements = Vec::new();
    for assertion in assertions(document)? {
        for parent in assertion_children(document, assertion, parent) {
            elements.extend(assertion_children(document, parent, name));
        }
    }
    Ok(elements)
}

fn node_range(document: &XmlDocument<'_>, node: NodeId) -> Result<Range<usize>, SamlError> {
    document
        .node_range(node)
        .ok_or_else(|| SamlError::Xml("element has no source range".into()))
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

/// Inclusive canonical form of `element`, which declares every namespace in
/// scope, so the element parses on its own.
fn namespace_complete(document: &XmlDocument<'_>, element: NodeId) -> Result<Vec<u8>, SamlError> {
    let node_set = NodeSet::tree_without_comments(element, document);
    canonicalize_doc(
        document,
        C14nMode::Inclusive,
        Some(&node_set),
        &[] as &[&str],
    )
    .map_err(crypto_err)
}

/// Replace each `(range, replacement)` of `xml`. Ranges are disjoint.
fn splice(xml: &str, mut replacements: Vec<(Range<usize>, String)>) -> String {
    replacements.sort_by_key(|(range, _)| range.start);
    let mut output = String::with_capacity(xml.len());
    let mut cursor = 0;
    for (range, replacement) in replacements {
        output.push_str(&xml[cursor..range.start]);
        output.push_str(&replacement);
        cursor = range.end;
    }
    output.push_str(&xml[cursor..]);
    output
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
    super::provider::ensure_crypto_provider_initialized()?;
    let document = parse_xml_document(xml)?;
    let mut replacements = Vec::new();
    for kind in selected_kinds(selection) {
        for element in assertion_elements(&document, kind.parent, kind.plaintext)? {
            replacements.push(encrypted_element(
                &document,
                element,
                kind,
                encrypt_cert,
                data_alg,
                key_alg,
            )?);
        }
    }
    Ok(splice(xml, replacements))
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
    super::provider::ensure_crypto_provider_initialized()?;
    let document = parse_xml_document(xml)?;
    let [name_id] = root_children(&document, namespace::ASSERTION, "NameID")?[..] else {
        return Err(SamlError::ProtocolProfile(
            "LogoutRequest must carry one NameID to encrypt".into(),
        ));
    };
    let replacement = encrypted_element(
        &document,
        name_id,
        LOGOUT_REQUEST_ENCRYPTED_ID,
        encrypt_cert,
        data_alg,
        key_alg,
    )?;
    Ok(splice(xml, vec![replacement]))
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
    super::provider::ensure_crypto_provider_initialized()?;
    let document = parse_xml_document(xml)?;
    let mut replacements = Vec::new();
    for kind in kinds {
        for element in root_children(&document, kind.namespace, kind.plaintext)? {
            replacements.push(encrypted_element(
                &document,
                element,
                *kind,
                encrypt_cert,
                data_alg,
                key_alg,
            )?);
        }
    }
    Ok(splice(xml, replacements))
}

/// Replace the one `kind.encrypted` child of the document element of `xml`
/// with the plaintext it carries, decrypted with `enc_key`.
///
/// # Errors
///
/// Returns [`SamlError::ProtocolProfile`] when the document element has no
/// such child or several, or when the plaintext is not one element of the
/// expected name. Returns another [`SamlError`] when decryption fails.
pub(crate) fn decrypt_root_child(
    xml: &str,
    kind: EncryptedElementKind,
    enc_key: &Key,
    options: AssertionDecryptionOptions,
    limits: XmlLimits,
) -> Result<String, SamlError> {
    super::provider::ensure_crypto_provider_initialized()?;
    require_software_rsa_opt_in(options)?;
    dom::parse_with_limits(xml, limits)?;
    let document = parse_xml_document(xml)?;
    let [element] = root_children(&document, kind.namespace, kind.encrypted)?[..] else {
        return Err(SamlError::ProtocolProfile(format!(
            "{} requires one {}",
            kind.parent, kind.encrypted
        )));
    };
    let replacement = decrypted_element(&document, element, kind, enc_key, options, limits)?;
    let decrypted = splice(xml, vec![replacement]);
    limits.check_input_bytes(decrypted.len())?;
    Ok(decrypted)
}

/// Whether a verified signature covers a received request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestAuthentication {
    Authenticated,
    Unauthenticated,
}

/// `xml` with the `<EncryptedID>` of the `<Subject>` of its `<AuthnRequest>`
/// replaced by the `<NameID>` it carries, decrypted with the private key in
/// `key_pem`.
///
/// Returns `None` when the `<Subject>` carries no `<EncryptedID>`, for an
/// unauthenticated request whose `EncryptedData` does not name AES-GCM (CBC
/// ciphertext is decrypted only under a verified signature), and when the
/// `<EncryptedID>` does not decrypt to one `<NameID>`.
///
/// # Errors
///
/// Returns [`SamlError::Unsupported`] when software RSA key-transport
/// decryption is not allowed, and another [`SamlError`] when the key does not
/// load.
pub(crate) fn decrypt_authn_request_encrypted_id(
    xml: &str,
    key_pem: &str,
    key_pass: Option<&str>,
    options: AssertionDecryptionOptions,
    limits: XmlLimits,
    authentication: RequestAuthentication,
) -> Result<Option<String>, SamlError> {
    super::provider::ensure_crypto_provider_initialized()?;
    dom::parse_with_limits(xml, limits)?;
    let document = parse_xml_document(xml)?;
    let [subject] = root_children(&document, namespace::ASSERTION, "Subject")?[..] else {
        return Ok(None);
    };
    let encrypted_ids: Vec<NodeId> =
        assertion_children(&document, subject, "EncryptedID").collect();
    let [encrypted_id] = encrypted_ids[..] else {
        return Ok(None);
    };
    match authentication {
        RequestAuthentication::Authenticated => {}
        RequestAuthentication::Unauthenticated => {
            if !uses_gcm(&document, encrypted_id) {
                return Ok(None);
            }
        }
    }
    require_software_rsa_opt_in(options)?;
    let enc_key = super::keys::load_private_key(key_pem, key_pass)?;
    let Ok(replacement) = decrypted_element(
        &document,
        encrypted_id,
        ENCRYPTED_ID,
        &enc_key,
        options,
        limits,
    ) else {
        return Ok(None);
    };
    let decrypted = splice(xml, vec![replacement]);
    limits.check_input_bytes(decrypted.len())?;
    Ok(Some(decrypted))
}

/// Whether the `EncryptedData` of `encrypted` names an AES-GCM
/// `EncryptionMethod`.
fn uses_gcm(document: &XmlDocument<'_>, encrypted: NodeId) -> bool {
    let child = |parent: NodeId, local_name: &'static str| {
        document.children_iter(parent).find(|child| {
            document
                .element(*child)
                .is_some_and(|element| element.matches_name_ns(ENC, local_name))
        })
    };
    child(encrypted, "EncryptedData")
        .and_then(|data| child(data, "EncryptionMethod"))
        .and_then(|method| document.element(method))
        .and_then(|method| method.get_attribute("Algorithm"))
        .is_some_and(crate::constants::is_xml_encryption_gcm_algorithm)
}

/// Whether an assertion in `xml` carries an `<EncryptedID>` in its `<Subject>`
/// or an `<EncryptedAttribute>` in an `<AttributeStatement>`.
pub(crate) fn carries_encrypted_assertion_elements(
    xml: &str,
    limits: XmlLimits,
) -> Result<bool, SamlError> {
    dom::parse_with_limits(xml, limits)?;
    let document = parse_xml_document(xml)?;
    for kind in [ENCRYPTED_ID, ENCRYPTED_ATTRIBUTE] {
        if !assertion_elements(&document, kind.parent, kind.encrypted)?.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Decrypt the children of each assertion in `xml` with `enc_key`: the ones
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
    enc_key: &Key,
    options: AssertionDecryptionOptions,
    limits: XmlLimits,
    selection: AssertionElementEncryption,
    received: ReceivedEncryptedElements,
) -> Result<String, SamlError> {
    super::provider::ensure_crypto_provider_initialized()?;
    require_software_rsa_opt_in(options)?;
    dom::parse_with_limits(xml, limits)?;
    let document = parse_xml_document(xml)?;
    let selected = selected_kinds(selection);
    let decrypted = match received {
        ReceivedEncryptedElements::DecryptReceived => vec![ENCRYPTED_ID, ENCRYPTED_ATTRIBUTE],
        ReceivedEncryptedElements::DecryptSelected => selected.clone(),
    };
    for kind in &selected {
        if !assertion_elements(&document, kind.parent, kind.plaintext)?.is_empty() {
            return Err(SamlError::EncryptionRequired {
                element: kind.plaintext,
            });
        }
    }
    let mut replacements = Vec::new();
    for kind in decrypted {
        for element in assertion_elements(&document, kind.parent, kind.encrypted)? {
            replacements.push(decrypted_element(
                &document, element, kind, enc_key, options, limits,
            )?);
        }
    }
    let decrypted = splice(xml, replacements);
    limits.check_input_bytes(decrypted.len())?;
    Ok(decrypted)
}

/// Replace the `<EncryptedID>` of the `<LogoutRequest>` in `xml` with the
/// `<NameID>` it carries, decrypted with `enc_key`.
///
/// # Errors
///
/// Returns [`SamlError::ProtocolProfile`] unless the request carries exactly
/// one `<BaseID>`, `<NameID>`, or `<EncryptedID>`, and that one is an
/// `<EncryptedID>`. Its plaintext follows [`decrypt_assertion_elements`].
pub(crate) fn decrypt_logout_request_encrypted_id(
    xml: &str,
    enc_key: &Key,
    options: AssertionDecryptionOptions,
    limits: XmlLimits,
) -> Result<String, SamlError> {
    super::provider::ensure_crypto_provider_initialized()?;
    require_software_rsa_opt_in(options)?;
    dom::parse_with_limits(xml, limits)?;
    let document = parse_xml_document(xml)?;
    let mut identifiers = Vec::new();
    for name in ["BaseID", "NameID", "EncryptedID"] {
        identifiers.extend(root_children(&document, namespace::ASSERTION, name)?);
    }
    let encrypted_ids = root_children(&document, namespace::ASSERTION, "EncryptedID")?;
    let ([_], [encrypted_id]) = (&identifiers[..], &encrypted_ids[..]) else {
        return Err(SamlError::ProtocolProfile(
            "LogoutRequest requires one BaseID, NameID, or EncryptedID".into(),
        ));
    };
    let replacement = decrypted_element(
        &document,
        *encrypted_id,
        LOGOUT_REQUEST_ENCRYPTED_ID,
        enc_key,
        options,
        limits,
    )?;
    let decrypted = splice(xml, vec![replacement]);
    limits.check_input_bytes(decrypted.len())?;
    Ok(decrypted)
}

/// The source range of the encrypted `element` and the plaintext it carries.
fn decrypted_element(
    document: &XmlDocument<'_>,
    element: NodeId,
    kind: EncryptedElementKind,
    enc_key: &Key,
    options: AssertionDecryptionOptions,
    limits: XmlLimits,
) -> Result<(Range<usize>, String), SamlError> {
    let peer_keys = require_encrypted_element_children(document, element, kind)?;
    // The whole wrapper is decrypted so that an `EncryptedKey` beside
    // `EncryptedData`, named by a `RetrievalMethod`, resolves (E43).
    let wrapper = String::from_utf8(namespace_complete(document, element)?)
        .map_err(|error| SamlError::Xml(error.to_string()))?;
    let decrypted = decrypt_with_key(&wrapper, enc_key, options)?;
    let plaintext = decrypted_plaintext(&decrypted, peer_keys, kind, limits)?;
    Ok((node_range(document, element)?, plaintext.to_string()))
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

#[cfg(all(test, not(feature = "crypto-fips")))]
mod tests {
    use super::*;
    use crate::constants::data_encryption_algorithm::AES_256;
    use crate::constants::key_encryption_algorithm::RSA_OAEP_MGF1P;
    use crate::crypto::keys::load_private_key;

    const SP_PRIVKEY: &str = include_str!("../../tests/fixtures/key/sp_privkey.pem");
    const SP_CERT: &str = include_str!("../../tests/fixtures/key/sp_signing_cert.cer");
    const RESPONSE: &str = include_str!("../../tests/fixtures/response.xml");

    #[test]
    fn encrypt_then_decrypt_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let encrypted = encrypt_assertion(RESPONSE, SP_CERT, AES_256, RSA_OAEP_MGF1P, "saml")?;
        assert!(encrypted.contains("EncryptedAssertion"));
        assert!(encrypted.contains("EncryptedData"));
        assert!(!encrypted.contains("<saml:Assertion"));

        let key = load_private_key(SP_PRIVKEY, None)?;
        let (response, assertion) =
            decrypt_assertion(&encrypted, &key, software_rsa_test_options())?;
        assert!(assertion.contains("Assertion"));
        assert!(assertion.contains("_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7"));
        assert!(response.contains("Assertion"));
        assert!(!response.contains("EncryptedAssertion"));
        Ok(())
    }

    fn encrypted_ids() -> AssertionElementEncryption {
        AssertionElementEncryption {
            identifiers: IdentifierEncryptionPolicy::EncryptIdentifiers,
            ..AssertionElementEncryption::default()
        }
    }

    fn only_encrypted_data(xml: &str) -> Result<&str, Box<dyn std::error::Error>> {
        let start = xml
            .find("<xenc:EncryptedData")
            .ok_or("missing EncryptedData")?;
        let end_tag = "</xenc:EncryptedData>";
        let end = xml.find(end_tag).ok_or("missing EncryptedData end")? + end_tag.len();
        Ok(&xml[start..end])
    }

    #[test]
    fn encrypted_id_plaintext_declares_the_namespaces_it_uses(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let encrypted = encrypt_assertion_elements(
            RESPONSE,
            SP_CERT,
            AES_256,
            RSA_OAEP_MGF1P,
            encrypted_ids(),
        )?;
        assert!(encrypted.contains("<saml:Subject><saml:EncryptedID><xenc:EncryptedData"));

        let mut manager = KeysManager::new();
        manager.add_key(load_private_key(SP_PRIVKEY, None)?);
        let plaintext = decrypt(&EncContext::new(manager), only_encrypted_data(&encrypted)?)?;
        let document = uppsala::parse(&plaintext)?;
        let root = document.document_element().ok_or("no plaintext element")?;
        let name_id = document
            .element(root)
            .ok_or("plaintext is not an element")?;
        assert!(name_id.matches_name_ns(namespace::ASSERTION, "NameID"));
        assert_eq!(
            document.element_text(root),
            Some("_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7")
        );
        Ok(())
    }

    fn response_with_encrypted_id_carrying(
        plaintext: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        response_with_encrypted_id_beside(plaintext, "")
    }

    /// An `EncryptedID` whose `EncryptedData` carries `plaintext`, followed by
    /// the unencrypted `beside`.
    fn response_with_encrypted_id_beside(
        plaintext: &str,
        beside: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let encrypted_data =
            encrypted_data_xml(plaintext.as_bytes(), SP_CERT, AES_256, RSA_OAEP_MGF1P)?;
        let start = RESPONSE.find("<saml:NameID").ok_or("missing NameID")?;
        let end_tag = "</saml:NameID>";
        let end = RESPONSE.find(end_tag).ok_or("missing NameID end")? + end_tag.len();
        Ok(format!(
            "{}<saml:EncryptedID>{encrypted_data}{beside}</saml:EncryptedID>{}",
            &RESPONSE[..start],
            &RESPONSE[end..]
        ))
    }

    #[test]
    fn encrypted_id_must_carry_a_name_id() -> Result<(), Box<dyn std::error::Error>> {
        let key = load_private_key(SP_PRIVKEY, None)?;
        let decrypt = |xml: &str| {
            decrypt_assertion_elements(
                xml,
                &key,
                software_rsa_test_options(),
                XmlLimits::default(),
                encrypted_ids(),
                ReceivedEncryptedElements::DecryptSelected,
            )
        };

        let attribute = response_with_encrypted_id_carrying(
            "<saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"mail\"/>",
        )?;
        assert!(matches!(
            decrypt(&attribute),
            Err(SamlError::ProtocolProfile(message)) if message == "EncryptedID must carry one NameID"
        ));

        let base_id = response_with_encrypted_id_carrying(
            "<saml:BaseID xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"/>",
        )?;
        assert!(matches!(decrypt(&base_id), Err(SamlError::Unsupported(_))));

        let two_elements = response_with_encrypted_id_carrying(
            "<saml:NameID>a</saml:NameID><saml:NameID>b</saml:NameID>",
        )?;
        assert!(matches!(
            decrypt(&two_elements),
            Err(SamlError::ProtocolProfile(message)) if message == "EncryptedID must carry one NameID"
        ));

        let name_id_and_key = response_with_encrypted_id_carrying(&format!(
            "<saml:NameID>a</saml:NameID><xenc:EncryptedKey xmlns:xenc=\"{ENC}\"/>"
        ))?;
        assert!(matches!(
            decrypt(&name_id_and_key),
            Err(SamlError::ProtocolProfile(message)) if message == "EncryptedID must carry one NameID"
        ));

        let key_only = response_with_encrypted_id_carrying(&format!(
            "<xenc:EncryptedKey xmlns:xenc=\"{ENC}\"/>"
        ))?;
        assert!(matches!(
            decrypt(&key_only),
            Err(SamlError::ProtocolProfile(message)) if message == "EncryptedID must carry one NameID"
        ));
        Ok(())
    }

    #[test]
    fn encrypted_id_holds_only_encrypted_data_and_encrypted_keys(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let plaintext_beside = response_with_encrypted_id_beside(
            &format!("<xenc:EncryptedKey xmlns:xenc=\"{ENC}\"/>"),
            "<saml:NameID>alice</saml:NameID>",
        )?;
        let result = decrypt_assertion_elements(
            &plaintext_beside,
            &load_private_key(SP_PRIVKEY, None)?,
            software_rsa_test_options(),
            XmlLimits::default(),
            encrypted_ids(),
            ReceivedEncryptedElements::DecryptSelected,
        );
        assert!(
            matches!(
                &result,
                Err(SamlError::ProtocolProfile(message))
                    if message == "EncryptedID must contain one EncryptedData and only EncryptedKey after it"
            ),
            "{result:?}"
        );
        Ok(())
    }

    /// Move the inline `EncryptedKey` of `encrypted_data` beside it, linked by a
    /// `RetrievalMethod`: the SAML Core Errata 05 E43 peer placement.
    fn with_peer_key(encrypted_data: &str) -> Result<String, Box<dyn std::error::Error>> {
        let start = encrypted_data
            .find("<xenc:EncryptedKey>")
            .ok_or("missing EncryptedKey")?;
        let end_tag = "</xenc:EncryptedKey>";
        let end = encrypted_data
            .find(end_tag)
            .ok_or("missing EncryptedKey end")?
            + end_tag.len();
        let key = encrypted_data[start..end].replacen(
            "<xenc:EncryptedKey>",
            &format!("<xenc:EncryptedKey xmlns:xenc=\"{ENC}\" Id=\"_peer_key\">"),
            1,
        );
        let retrieval =
            format!("<ds:RetrievalMethod URI=\"#_peer_key\" Type=\"{ENC}EncryptedKey\"/>");
        Ok(format!(
            "{}{retrieval}{}{key}",
            &encrypted_data[..start],
            &encrypted_data[end..]
        ))
    }

    #[test]
    fn encrypted_id_resolves_a_peer_key_named_by_retrieval_method(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let encrypted = encrypt_assertion_elements(
            RESPONSE,
            SP_CERT,
            AES_256,
            RSA_OAEP_MGF1P,
            encrypted_ids(),
        )?;
        let encrypted_data = only_encrypted_data(&encrypted)?;
        let peer = encrypted.replacen(encrypted_data, &with_peer_key(encrypted_data)?, 1);
        assert!(peer.contains("</xenc:EncryptedData><xenc:EncryptedKey"));

        let decrypted = decrypt_assertion_elements(
            &peer,
            &load_private_key(SP_PRIVKEY, None)?,
            software_rsa_test_options(),
            XmlLimits::default(),
            encrypted_ids(),
            ReceivedEncryptedElements::DecryptSelected,
        )?;
        assert!(!decrypted.contains("EncryptedID"));
        assert!(decrypted.contains(">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>"));
        Ok(())
    }

    #[test]
    fn encrypted_assertion_resolves_a_peer_key_named_by_retrieval_method(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let encrypted = encrypt_assertion(RESPONSE, SP_CERT, AES_256, RSA_OAEP_MGF1P, "saml")?;
        let encrypted_data = only_encrypted_data(&encrypted)?;
        let peer = encrypted.replacen(
            encrypted_data,
            &with_peer_key(encrypted_data)?.replacen(
                "<xenc:EncryptedKey",
                "<?pi?><xenc:EncryptedKey",
                1,
            ),
            1,
        );
        assert!(peer.contains("</xenc:EncryptedData><?pi?><xenc:EncryptedKey"));

        let (response, assertion) = decrypt_assertion(
            &peer,
            &load_private_key(SP_PRIVKEY, None)?,
            software_rsa_test_options(),
        )?;
        assert!(assertion.starts_with("<saml:Assertion"));
        assert!(assertion.contains("_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7"));
        assert!(response.contains(&assertion));
        assert!(!response.contains("EncryptedAssertion"));
        assert!(!response.contains("EncryptedKey"));
        Ok(())
    }

    fn software_rsa_test_options() -> AssertionDecryptionOptions {
        AssertionDecryptionOptions {
            allow_insecure_software_rsa_key_transport_decryption: cfg!(
                feature = "crypto-rustcrypto"
            ),
            ..AssertionDecryptionOptions::default()
        }
    }

    #[test]
    fn encrypted_id_declares_the_namespace_of_its_prefix() -> Result<(), Box<dyn std::error::Error>>
    {
        let request = concat!(
            r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" "#,
            r#"ID="_r" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">"#,
            r#"<n:Issuer xmlns:n="urn:oasis:names:tc:SAML:2.0:assertion">idp</n:Issuer>"#,
            r#"<n:NameID xmlns:n="urn:oasis:names:tc:SAML:2.0:assertion">alice</n:NameID>"#,
            r#"</samlp:LogoutRequest>"#,
        );
        let encrypted = encrypt_logout_request_name_id(request, SP_CERT, AES_256, RSA_OAEP_MGF1P)?;
        let document = uppsala::parse(&encrypted)?;
        if root_children(&document, namespace::ASSERTION, "EncryptedID")?.len() != 1 {
            return Err(format!("no assertion-namespace EncryptedID: {encrypted}").into());
        }
        let key = load_private_key(SP_PRIVKEY, None)?;
        let decrypted = decrypt_logout_request_encrypted_id(
            &encrypted,
            &key,
            software_rsa_test_options(),
            XmlLimits::default(),
        )?;
        assert!(decrypted.contains(">alice</n:NameID>"), "{decrypted}");
        Ok(())
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn decrypt_rejects_software_rsa_by_default() -> Result<(), Box<dyn std::error::Error>> {
        let encrypted = encrypt_assertion(RESPONSE, SP_CERT, AES_256, RSA_OAEP_MGF1P, "saml")?;
        let key = load_private_key(SP_PRIVKEY, None)?;
        assert!(matches!(
            decrypt_assertion(&encrypted, &key, AssertionDecryptionOptions::default()),
            Err(SamlError::Unsupported(message))
                if message.contains("RUSTSEC-2023-0071")
        ));
        Ok(())
    }

    #[cfg(feature = "crypto-legacy-algorithms")]
    #[test]
    fn decrypt_refuses_rsa15_key_transport_unless_selected(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::constants::key_encryption_algorithm::RSA_1_5;

        let embedded = encrypt_assertion(RESPONSE, SP_CERT, AES_256, RSA_1_5, "saml")?;
        let encrypted_data = only_encrypted_data(&embedded)?;
        let peer = embedded.replacen(encrypted_data, &with_peer_key(encrypted_data)?, 1);
        let key = load_private_key(SP_PRIVKEY, None)?;
        for encrypted in [embedded.as_str(), peer.as_str()] {
            let refused = decrypt_assertion(encrypted, &key, software_rsa_test_options());
            assert!(
                matches!(&refused, Err(SamlError::Unsupported(message)) if message.contains("rsa-1_5")),
                "{refused:?}"
            );

            let selected = AssertionDecryptionOptions {
                allow_rsa15_key_transport_decryption: true,
                ..software_rsa_test_options()
            };
            let (_, assertion) = decrypt_assertion(encrypted, &key, selected)?;
            assert!(assertion.contains("_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7"));
        }
        Ok(())
    }

    #[cfg(feature = "crypto-aws-lc")]
    #[test]
    fn aws_lc_decrypts_rsa_oaep_with_default_options() -> Result<(), Box<dyn std::error::Error>> {
        let encrypted = encrypt_assertion(RESPONSE, SP_CERT, AES_256, RSA_OAEP_MGF1P, "saml")?;
        let key = load_private_key(SP_PRIVKEY, None)?;
        let (response, assertion) =
            decrypt_assertion(&encrypted, &key, AssertionDecryptionOptions::default())?;
        assert!(assertion.contains("Assertion"));
        assert!(assertion.contains("_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7"));
        assert!(response.contains("Assertion"));
        assert!(!response.contains("EncryptedAssertion"));
        Ok(())
    }
}
