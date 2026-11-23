//! Signing a SAML metadata document.

use std::borrow::Cow;

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::config::{Passphrase, SignatureAlgorithm, X509Credential};
use crate::crypto::keys::read_private_key;
use crate::crypto::sign::sign_root_as_first_child;
use crate::entity::generate_id;
use crate::error::{xml_err, SamlError};
use crate::xml::dom::{self, Node, XmlLimits};
use crate::xml::name::is_ncname;

/// Sign a metadata document with an enveloped XML signature over its root.
///
/// `xml` holds one unsigned `EntityDescriptor` or `EntitiesDescriptor` root,
/// such as the output of [`generate_sp_metadata`](super::generate_sp_metadata)
/// or an aggregate the application assembled. The signature is the root's
/// first child. Its one reference is `#` and the root's `ID`, with the
/// enveloped-signature and exclusive canonicalization transforms, and its
/// `KeyInfo` carries the credential's certificate. A root without an `ID`
/// gets a generated one. The digest algorithm matches `algorithm`, such as
/// SHA-256 for [`SignatureAlgorithm::RsaSha256`].
///
/// [`MetadataTrustPolicy::RequireSignature`](crate::MetadataTrustPolicy::RequireSignature)
/// pinned to the credential's certificate verifies the result when the
/// document carries no other signature and the key passes that policy's
/// algorithm and key-size checks.
///
/// # Errors
///
/// Returns [`SamlError::Invalid`] when the root is not an `EntityDescriptor`
/// or `EntitiesDescriptor`, when the root already has a signature or an `ID`
/// that is not an XML NCName, or when `algorithm` is
/// [`SignatureAlgorithm::HmacSha1`]. Returns [`SamlError::Xml`]
/// or [`SamlError::LimitExceeded`] when `xml` is not well-formed or exceeds the
/// default [`XmlLimits`](crate::XmlLimits). Returns [`SamlError::Crypto`] when
/// the key cannot be read or the crypto provider cannot sign with `algorithm`.
pub fn sign_metadata(
    xml: &str,
    credential: &X509Credential,
    algorithm: &SignatureAlgorithm,
) -> Result<String, SamlError> {
    if matches!(algorithm, SignatureAlgorithm::HmacSha1) {
        return Err(SamlError::Invalid(
            "metadata is signed with a private key, not an HMAC secret".into(),
        ));
    }
    let root = dom::parse_document(xml, XmlLimits::default())?.root;
    if !matches!(
        root.local_name.as_str(),
        "EntityDescriptor" | "EntitiesDescriptor"
    ) {
        return Err(SamlError::Invalid(format!(
            "`{}` is not a metadata root",
            root.local_name
        )));
    }
    if root.child_named("Signature").is_some() {
        return Err(SamlError::Invalid("metadata root is already signed".into()));
    }
    let xml = match root.attr("ID") {
        Some(id) if !is_ncname(id) => {
            return Err(SamlError::Invalid(format!(
                "metadata root ID `{id}` is not an XML NCName"
            )))
        }
        Some(_) => Cow::Borrowed(xml),
        None => Cow::Owned(with_generated_root_id(xml, &root)?),
    };
    let key = read_private_key(
        credential.key().as_str(),
        credential.passphrase().map(Passphrase::as_str),
    )?;
    sign_root_as_first_child(
        &xml,
        &root.local_name,
        &key,
        credential.certificate().as_str(),
        algorithm.as_uri(),
    )
}

fn with_generated_root_id(xml: &str, root: &Node) -> Result<String, SamlError> {
    let mut reader = Reader::from_str(&xml[root.start..root.end]);
    let name_len = match reader.read_event().map_err(xml_err)? {
        Event::Start(tag) | Event::Empty(tag) => tag.name().into_inner().len(),
        other => {
            return Err(SamlError::xml(format!(
                "metadata root does not start with an element tag: {other:?}"
            )))
        }
    };
    let at = root.start + "<".len() + name_len;
    Ok(format!(
        "{} ID=\"{}\"{}",
        &xml[..at],
        generate_id(),
        &xml[at..]
    ))
}
