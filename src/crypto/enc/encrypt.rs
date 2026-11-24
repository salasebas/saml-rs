use std::ops::Range;

use super::{
    assertion_elements, namespace_complete, node_range, parse_xml_document, root_children,
    selected_kinds, splice, EncryptedElementKind, ENC, LOGOUT_REQUEST_ENCRYPTED_ID,
};
use crate::binding::xml_escape;
use crate::config::AssertionElementEncryption;
use crate::constants::namespace;
use crate::crypto::keys::load_certificate;
use crate::entity::EntitySetting;
use crate::error::{crypto_err, SamlError};
use crate::xml::dom;
use crate::xml::fragment::standalone_element;
use crate::xml::name::validate_namespace_prefix;
use bergshamra::xml::{Document as XmlDocument, NodeId};
use bergshamra::{encrypt, EncContext, Key, KeysManager};

#[derive(Clone, Copy)]
pub(crate) struct KeyTransport<'a> {
    uri: &'a str,
    parameters: Option<(&'a str, &'a str)>,
}

impl<'a> KeyTransport<'a> {
    pub(crate) fn from_setting(setting: &'a EntitySetting) -> Self {
        Self {
            uri: &setting.key_encryption_algorithm,
            parameters: setting
                .rsa_oaep_parameters
                .as_ref()
                .filter(|_| {
                    setting.key_encryption_algorithm
                        == crate::constants::key_encryption_algorithm::RSA_OAEP
                })
                .map(|(digest, mgf)| (digest.as_uri(), mgf.as_uri())),
        }
    }
}

impl<'a> From<&'a str> for KeyTransport<'a> {
    fn from(uri: &'a str) -> Self {
        Self {
            uri,
            parameters: None,
        }
    }
}

/// The certificates a peer publishes for encryption, with the data
/// encryption algorithm and the key transport to encrypt for it.
pub(crate) struct EncryptionRecipient<'a> {
    certificates: Vec<&'a str>,
    data_algorithm: &'a str,
    key_transport: KeyTransport<'a>,
}

impl<'a> EncryptionRecipient<'a> {
    pub(crate) fn new(
        certificates: impl IntoIterator<Item = &'a str>,
        data_algorithm: &'a str,
        key_transport: KeyTransport<'a>,
    ) -> Self {
        Self {
            certificates: certificates.into_iter().collect(),
            data_algorithm,
            key_transport,
        }
    }

    /// Encrypt with the algorithms of `setting` for a peer that publishes
    /// `certificates`.
    pub(crate) fn from_setting(certificates: &'a [String], setting: &'a EntitySetting) -> Self {
        Self::new(
            certificates.iter().map(String::as_str),
            &setting.data_encryption_algorithm,
            KeyTransport::from_setting(setting),
        )
    }

    /// Encrypt `plaintext` for the first certificate that the data
    /// encryption algorithm and the key transport can encrypt for, and
    /// return that key with the `EncryptedData`.
    ///
    /// A certificate is skipped when it does not load, or when the crypto
    /// provider cannot wrap a data key with its key, such as an EC key or an
    /// RSA key too small for the key transport.
    pub(super) fn encrypt_first(
        &self,
        plaintext: &[u8],
    ) -> Result<(EncryptionKey<'a>, String), SamlError> {
        let mut first_error = None;
        for certificate in &self.certificates {
            let attempt = load_certificate(certificate).and_then(|key| {
                let key = EncryptionKey {
                    key,
                    data_algorithm: self.data_algorithm,
                    key_transport: self.key_transport,
                };
                encrypted_data_xml(plaintext, &key).map(|encrypted_data| (key, encrypted_data))
            });
            match attempt {
                Ok(encrypted) => return Ok(encrypted),
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        Err(first_error
            .unwrap_or_else(|| SamlError::MissingMetadata("encryption certificate".into())))
    }
}

/// A peer key with the algorithms that encrypt for it.
pub(super) struct EncryptionKey<'a> {
    key: Key,
    data_algorithm: &'a str,
    key_transport: KeyTransport<'a>,
}

fn encrypted_data_xml(
    plaintext: &[u8],
    recipient: &EncryptionKey<'_>,
) -> Result<String, SamlError> {
    let key_alg = recipient.key_transport;
    let data_alg = xml_escape(recipient.data_algorithm);
    let parameters = match key_alg.parameters {
        Some((digest, mgf)) => format!(
            "<ds:DigestMethod Algorithm=\"{}\"/><xenc11:MGF xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\" Algorithm=\"{}\"/>",
            xml_escape(digest), xml_escape(mgf),
        ),
        None => String::new(),
    };
    let key_alg = xml_escape(key_alg.uri);
    let template = format!(
        "<xenc:EncryptedData xmlns:xenc=\"{enc}\" Type=\"{enc}Element\"><xenc:EncryptionMethod Algorithm=\"{data_alg}\"/><ds:KeyInfo xmlns:ds=\"{dsig}\"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm=\"{key_alg}\">{parameters}</xenc:EncryptionMethod><xenc:CipherData><xenc:CipherValue></xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue></xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>",
        enc = ENC,
        dsig = namespace::DSIG,
    );

    let mut manager = KeysManager::new();
    manager.add_key(recipient.key.clone());
    let ctx = EncContext::new(manager);
    encrypt(&ctx, &template, plaintext).map_err(crypto_err)
}

#[cfg(test)]
pub(crate) fn encrypt_assertion(
    xml: &str,
    encrypt_cert: &str,
    data_alg: &str,
    key_alg: &str,
    tag_prefix: &str,
) -> Result<String, SamlError> {
    encrypt_assertion_with_key_transport(
        xml,
        &EncryptionRecipient::new([encrypt_cert], data_alg, key_alg.into()),
        tag_prefix,
    )
}

pub(crate) fn encrypt_assertion_with_key_transport(
    xml: &str,
    recipient: &EncryptionRecipient<'_>,
    tag_prefix: &str,
) -> Result<String, SamlError> {
    crate::crypto::provider::ensure_crypto_provider_initialized()?;
    validate_namespace_prefix("EncryptedAssertion XML prefix", tag_prefix)?;
    let doc = dom::parse_document(xml, crate::XmlLimits::default())?;
    let assertion = doc
        .root
        .child_named("Assertion")
        .ok_or_else(|| SamlError::MissingMetadata("Assertion to encrypt".into()))?;
    let assertion_xml = standalone_element(xml, assertion.start, assertion.end)?;
    let (_, encrypted_data) = recipient.encrypt_first(assertion_xml.as_bytes())?;

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

pub(crate) fn encrypt_assertion_elements(
    xml: &str,
    recipient: &EncryptionRecipient<'_>,
    selection: AssertionElementEncryption,
) -> Result<String, SamlError> {
    encrypt_selected(xml, recipient, |document| {
        let mut selected = Vec::new();
        for kind in selected_kinds(selection) {
            for element in assertion_elements(document, kind.parent, kind.plaintext)? {
                selected.push((element, kind));
            }
        }
        Ok(selected)
    })
}

pub(crate) fn encrypt_logout_request_name_id(
    xml: &str,
    encrypt_cert: &str,
    data_alg: &str,
    key_alg: KeyTransport<'_>,
) -> Result<String, SamlError> {
    let recipient = EncryptionRecipient::new([encrypt_cert], data_alg, key_alg);
    encrypt_selected(xml, &recipient, |document| {
        let [name_id] = root_children(document, namespace::ASSERTION, "NameID")?[..] else {
            return Err(SamlError::ProtocolProfile(
                "LogoutRequest must carry one NameID to encrypt".into(),
            ));
        };
        Ok(vec![(name_id, LOGOUT_REQUEST_ENCRYPTED_ID)])
    })
}

fn encrypt_selected(
    xml: &str,
    recipient: &EncryptionRecipient<'_>,
    select: impl FnOnce(&XmlDocument<'_>) -> Result<Vec<(NodeId, EncryptedElementKind)>, SamlError>,
) -> Result<String, SamlError> {
    crate::crypto::provider::ensure_crypto_provider_initialized()?;
    let document = parse_xml_document(xml)?;
    let mut key = None;
    let mut replacements = Vec::new();
    for (element, kind) in select(&document)? {
        let plaintext = namespace_complete(&document, element)?;
        let encrypted_data = match &key {
            Some(key) => encrypted_data_xml(&plaintext, key)?,
            None => {
                let (selected, encrypted_data) = recipient.encrypt_first(&plaintext)?;
                key = Some(selected);
                encrypted_data
            }
        };
        replacements.push(encrypted_element(
            &document,
            element,
            kind,
            &encrypted_data,
        )?);
    }
    Ok(splice(xml, replacements))
}

fn encrypted_element(
    document: &XmlDocument<'_>,
    element: NodeId,
    kind: EncryptedElementKind,
    encrypted_data: &str,
) -> Result<(Range<usize>, String), SamlError> {
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

fn own_prefix_declaration<'d>(document: &'d XmlDocument<'_>, element: NodeId) -> Option<&'d str> {
    let element = document.element(element)?;
    let prefix = element.name.prefix.as_deref().unwrap_or("");
    element
        .namespace_declarations
        .iter()
        .any(|(declared, _)| declared == prefix)
        .then_some(prefix)
}

pub(crate) fn encrypt_root_children(
    xml: &str,
    kinds: &[EncryptedElementKind],
    encrypt_cert: &str,
    data_alg: &str,
    key_alg: KeyTransport<'_>,
) -> Result<String, SamlError> {
    let recipient = EncryptionRecipient::new([encrypt_cert], data_alg, key_alg);
    encrypt_selected(xml, &recipient, |document| {
        let mut selected = Vec::new();
        for kind in kinds {
            for element in root_children(document, kind.namespace, kind.plaintext)? {
                selected.push((element, *kind));
            }
        }
        Ok(selected)
    })
}
