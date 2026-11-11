//! The signature and digest algorithms, and the verification keys, each
//! [`XmlSignatureProfile`] accepts on a signature that authenticates an
//! accepted message or a signed metadata import.

use crate::binding::base64_decode;
use crate::config::XmlSignatureProfile;
use crate::constants::{digest_algorithm, signature_algorithm};
use crate::error::SamlError;
use crate::xml::dom;
use bergshamra::core::algorithm as weak;
use bergshamra::keys::Key;

const MIN_RSA_KEY_BITS: usize = 2048;

/// Whether `profile` accepts the XML-DSig `SignatureMethod` or detached
/// `SigAlg` URI.
pub(crate) fn allows_signature_method(profile: XmlSignatureProfile, uri: &str) -> bool {
    match profile {
        XmlSignatureProfile::StrictRsaSha2 => matches!(
            uri,
            signature_algorithm::RSA_SHA256
                | signature_algorithm::RSA_SHA384
                | signature_algorithm::RSA_SHA512
        ),
        XmlSignatureProfile::ExcludeWeakAlgorithms => !matches!(
            uri,
            weak::RSA_MD5
                | weak::RSA_RIPEMD160
                | weak::ECDSA_RIPEMD160
                | weak::HMAC_MD5
                | weak::HMAC_RIPEMD160
        ),
        XmlSignatureProfile::AllowProviderSupportedForCompatibility => true,
    }
}

/// Whether `profile` rejects a `Response` or `Assertion` that carries a
/// signature in a SAML signature position that does not verify.
pub(crate) fn rejects_present_signature_that_does_not_verify(profile: XmlSignatureProfile) -> bool {
    match profile {
        XmlSignatureProfile::StrictRsaSha2 | XmlSignatureProfile::ExcludeWeakAlgorithms => true,
        XmlSignatureProfile::AllowProviderSupportedForCompatibility => false,
    }
}

/// Whether `profile` accepts the XML-DSig `DigestMethod` URI of a reference.
pub(crate) fn allows_digest_method(profile: XmlSignatureProfile, uri: &str) -> bool {
    match profile {
        XmlSignatureProfile::StrictRsaSha2 => matches!(
            uri,
            digest_algorithm::SHA256 | digest_algorithm::SHA384 | digest_algorithm::SHA512
        ),
        XmlSignatureProfile::ExcludeWeakAlgorithms => !matches!(uri, weak::MD5 | weak::RIPEMD160),
        XmlSignatureProfile::AllowProviderSupportedForCompatibility => true,
    }
}

/// Reject a peer or pinned metadata verification key that `profile` does not
/// accept.
///
/// [`XmlSignatureProfile::StrictRsaSha2`] and
/// [`XmlSignatureProfile::ExcludeWeakAlgorithms`] reject an RSA key shorter
/// than 2048 bits with the [`SamlError::Crypto`] error a provider reports for a
/// key it cannot use.
pub(crate) fn check_verification_key(
    profile: XmlSignatureProfile,
    key: &Key,
) -> Result<(), SamlError> {
    match profile {
        XmlSignatureProfile::StrictRsaSha2 | XmlSignatureProfile::ExcludeWeakAlgorithms => {
            match rsa_modulus_bits(key)? {
                Some(bits) if bits < MIN_RSA_KEY_BITS => Err(SamlError::Crypto(format!(
                    "{bits}-bit RSA key is shorter than the {MIN_RSA_KEY_BITS} bits the XML signature profile requires"
                ))),
                Some(_) | None => Ok(()),
            }
        }
        XmlSignatureProfile::AllowProviderSupportedForCompatibility => Ok(()),
    }
}

fn rsa_modulus_bits(key: &Key) -> Result<Option<usize>, SamlError> {
    if key.algorithm_name() != "RSA" {
        return Ok(None);
    }
    let unreadable = || SamlError::Crypto("RSA key modulus could not be read".into());
    let key_value = key.to_key_value_xml("").ok_or_else(unreadable)?;
    let document = dom::parse(&key_value)?;
    let modulus = document
        .root
        .children
        .iter()
        .find(|child| child.local_name == bergshamra::core::ns::node::RSA_MODULUS)
        .ok_or_else(unreadable)?;
    let modulus = base64_decode(&modulus.text)?;
    let Some(first) = modulus.iter().position(|byte| *byte != 0) else {
        return Ok(Some(0));
    };
    let leading_zero_bits =
        usize::try_from(modulus[first].leading_zeros()).map_err(|_| unreadable())?;
    Ok(Some((modulus.len() - first) * 8 - leading_zero_bits))
}
