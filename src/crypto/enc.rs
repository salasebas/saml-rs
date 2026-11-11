//! Assertion, `<EncryptedID>`, `<EncryptedAttribute>`, and `<NewEncryptedID>`
//! encryption and decryption, delegating XML-Enc to the selected `bergshamra`
//! provider.

mod decrypt;
mod encrypt;

use std::ops::Range;

use crate::config::{
    AssertionElementEncryption, AttributeEncryptionPolicy, IdentifierEncryptionPolicy,
};
use crate::constants::namespace;
use crate::error::SamlError;
use bergshamra::c14n::{canonicalize_doc, C14nMode};
use bergshamra::xml::{uppsala, Document as XmlDocument, NodeId, NodeSet};

pub(crate) use decrypt::{
    carries_encrypted_assertion_elements, decrypt_assertion_elements,
    decrypt_assertions_with_limits, decrypt_authn_request_encrypted_id,
    decrypt_logout_request_encrypted_id, decrypt_root_child, RequestAuthentication,
};
pub use decrypt::{decrypt_assertion, decrypt_assertion_with_limits, AssertionDecryptionOptions};
pub use encrypt::encrypt_assertion;
pub(crate) use encrypt::{
    encrypt_assertion_elements, encrypt_logout_request_name_id, encrypt_root_children,
};

const ENC: &str = "http://www.w3.org/2001/04/xmlenc#";

fn crypto_err(err: impl std::fmt::Display) -> SamlError {
    SamlError::Crypto(err.to_string())
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

#[cfg(all(test, not(feature = "crypto-fips")))]
mod tests {
    use super::encrypt::encrypted_data_xml;
    use super::*;
    use crate::config::ReceivedEncryptedElements;
    use crate::constants::data_encryption_algorithm::AES_256;
    use crate::constants::key_encryption_algorithm::RSA_OAEP_MGF1P;
    use crate::crypto::keys::load_private_key;
    use crate::xml::dom::XmlLimits;
    use bergshamra::{decrypt, EncContext, KeysManager};

    const SP_PRIVKEY: &str =
        include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
    const SP_CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");
    const RESPONSE: &str = include_str!("../../tests/fixtures/misc/response.xml");

    #[test]
    fn encrypt_then_decrypt_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let start = RESPONSE
            .find("<saml:Assertion ")
            .ok_or("missing assertion")?;
        let end_tag = "</saml:Assertion>";
        let end = RESPONSE.find(end_tag).ok_or("missing assertion end")? + end_tag.len();
        let standalone = RESPONSE[start..end].replacen(
            "<saml:Assertion ",
            r#"<saml:Assertion xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" "#,
            1,
        );

        let encrypted = encrypt_assertion(RESPONSE, SP_CERT, AES_256, RSA_OAEP_MGF1P, "saml")?;
        let encrypted_data = only_encrypted_data(&encrypted)?;
        assert_eq!(
            encrypted.replacen(encrypted_data, "", 1),
            format!(
                r#"{}<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"></saml:EncryptedAssertion>{}"#,
                &RESPONSE[..start],
                &RESPONSE[end..]
            )
        );

        let key = load_private_key(SP_PRIVKEY, None)?;
        let (response, assertion) =
            decrypt_assertion(&encrypted, &key, AssertionDecryptionOptions::default())?;
        assert_eq!(assertion, standalone);
        assert_eq!(
            response,
            format!("{}{standalone}{}", &RESPONSE[..start], &RESPONSE[end..])
        );
        Ok(())
    }

    #[test]
    fn decrypt_assertion_decrypts_every_encrypted_assertion(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let start = RESPONSE
            .find("<saml:Assertion ")
            .ok_or("missing assertion")?;
        let end_tag = "</saml:Assertion>";
        let end = RESPONSE.find(end_tag).ok_or("missing assertion end")? + end_tag.len();
        let assertion = &RESPONSE[start..end];
        let two = format!("{}{assertion}{}", &RESPONSE[..end], &RESPONSE[end..]);
        let first = encrypt_assertion(&two, SP_CERT, AES_256, RSA_OAEP_MGF1P, "saml")?;
        let encrypted = encrypt_assertion(&first, SP_CERT, AES_256, RSA_OAEP_MGF1P, "saml")?;
        assert_eq!(encrypted.matches("<saml:EncryptedAssertion").count(), 2);

        let key = load_private_key(SP_PRIVKEY, None)?;
        let (response, decrypted) =
            decrypt_assertion(&encrypted, &key, AssertionDecryptionOptions::default())?;
        assert!(!response.contains("EncryptedAssertion"));
        let standalone = assertion.replacen(
            "<saml:Assertion ",
            r#"<saml:Assertion xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" "#,
            1,
        );
        assert_eq!(response.matches(&standalone).count(), 2);
        assert_eq!(decrypted, standalone);
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
                std::slice::from_ref(&key),
                AssertionDecryptionOptions::default(),
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
            &[load_private_key(SP_PRIVKEY, None)?],
            AssertionDecryptionOptions::default(),
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
            &[load_private_key(SP_PRIVKEY, None)?],
            AssertionDecryptionOptions::default(),
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
            AssertionDecryptionOptions::default(),
        )?;
        assert!(assertion.starts_with("<saml:Assertion"));
        assert!(assertion.contains("_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7"));
        assert!(response.contains(&assertion));
        assert!(!response.contains("EncryptedAssertion"));
        assert!(!response.contains("EncryptedKey"));
        Ok(())
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
            &[key],
            AssertionDecryptionOptions::default(),
            XmlLimits::default(),
        );
        assert!(
            matches!(&decrypted, Ok(Some(xml)) if xml.contains(">alice</n:NameID>")),
            "{decrypted:?}"
        );
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
            let refused = decrypt_assertion(encrypted, &key, AssertionDecryptionOptions::default());
            assert!(
                matches!(&refused, Err(SamlError::Unsupported(message)) if message.contains("rsa-1_5")),
                "{refused:?}"
            );

            let selected = AssertionDecryptionOptions {
                allow_rsa15_key_transport_decryption: true,
                ..AssertionDecryptionOptions::default()
            };
            let (_, assertion) = decrypt_assertion(encrypted, &key, selected)?;
            assert!(assertion.contains("_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7"));
        }
        Ok(())
    }
}
