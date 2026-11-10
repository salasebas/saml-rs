//! Key, certificate and KeyInfo helpers backed by the selected `bergshamra`
//! provider.

use crate::config::HmacSecret;
use crate::error::SamlError;
use crate::util::normalize_cert_string;
use bergshamra::keys::keyinfo::build_x509_key_info;
use bergshamra::keys::loader::{load_hmac_key, load_pem_auto, load_x509_cert_pem};
use bergshamra::keys::Key;

fn crypto_err(err: impl std::fmt::Display) -> SamlError {
    SamlError::Crypto(err.to_string())
}

/// Load a private key from PEM using the formats supported by the selected
/// crypto provider.
pub fn load_private_key(pem: &str, password: Option<&str>) -> Result<Key, SamlError> {
    super::provider::ensure_crypto_provider_initialized()?;
    load_pem_auto(pem.as_bytes(), password).map_err(crypto_err)
}

pub(crate) fn load_hmac_secret(secret: &HmacSecret) -> Result<Key, SamlError> {
    super::provider::ensure_crypto_provider_initialized()?;
    load_hmac_key(secret.as_bytes()).map_err(crypto_err)
}

/// Wrap a bare base64 certificate (as found in metadata) into a PEM block.
fn to_cert_pem(cert: &str) -> Result<String, SamlError> {
    if cert.contains("BEGIN CERTIFICATE") {
        return Ok(cert.to_string());
    }
    let b64 = normalize_cert_string(cert);
    if !b64.is_ascii() {
        return Err(SamlError::Crypto(
            "certificate is not base64 text".to_string(),
        ));
    }
    let mut body = String::new();
    let mut i = 0;
    while i < b64.len() {
        let end = (i + 64).min(b64.len());
        body.push_str(&b64[i..end]);
        body.push('\n');
        i = end;
    }
    Ok(format!(
        "-----BEGIN CERTIFICATE-----\n{body}-----END CERTIFICATE-----\n"
    ))
}

/// Load an X.509 certificate (PEM or bare base64) as a verification key.
pub fn load_certificate(cert: &str) -> Result<Key, SamlError> {
    super::provider::ensure_crypto_provider_initialized()?;
    load_x509_cert_pem(to_cert_pem(cert)?.as_bytes()).map_err(crypto_err)
}

/// Build a `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>` block from a
/// certificate.
pub fn build_key_info(cert: &str) -> String {
    let b64 = normalize_cert_string(cert);
    build_x509_key_info(&[b64.as_str()])
}

#[cfg(test)]
mod tests {
    use super::*;

    const SP_PRIVKEY: &str =
        include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
    // RustCrypto decrypts this PEM. AWS-LC and FIPS reject it.
    #[cfg(any(
        feature = "crypto-rustcrypto",
        feature = "crypto-aws-lc",
        feature = "crypto-fips"
    ))]
    const SP_PRIVKEY_ENC: &str =
        include_str!("../../tests/fixtures/key/sp/privkey.encrypted.pkcs8.pem");
    const SP_CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.cer");
    const IDP_CERT: &str = include_str!("../../tests/fixtures/key/idp/cert.cer");
    // SP signing passphrase from upstream test/key/keypass.txt.
    #[cfg(feature = "crypto-rustcrypto")]
    const SP_PASS: &str = "VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px";

    #[test]
    fn loads_unencrypted_private_key() -> Result<(), Box<dyn std::error::Error>> {
        let key = load_private_key(SP_PRIVKEY, None)?;
        assert!(key.has_private_key());
        assert_eq!(key.algorithm_name(), "RSA");
        Ok(())
    }

    #[test]
    #[cfg(feature = "crypto-rustcrypto")]
    fn loads_encrypted_private_key_with_passphrase() -> Result<(), Box<dyn std::error::Error>> {
        let key = load_private_key(SP_PRIVKEY_ENC, Some(SP_PASS))?;
        assert!(key.has_private_key());
        Ok(())
    }

    #[test]
    #[cfg(all(
        any(feature = "crypto-aws-lc", feature = "crypto-fips"),
        not(feature = "crypto-rustcrypto")
    ))]
    fn rejects_encrypted_private_key_when_provider_does_not_support_it() {
        assert!(load_private_key(SP_PRIVKEY_ENC, Some("unused")).is_err());
    }

    #[test]
    fn loads_certificate_and_builds_key_info() -> Result<(), Box<dyn std::error::Error>> {
        let key = load_certificate(IDP_CERT)?;
        assert_eq!(key.algorithm_name(), "RSA");
        assert!(key.to_spki_der().is_some());

        let key_info = build_key_info(SP_CERT);
        assert!(key_info.contains("<ds:X509Certificate>"));
        assert!(key_info.contains("xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\""));
        Ok(())
    }

    #[test]
    fn rejects_non_ascii_bare_certificate_across_pem_line_boundary(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cert = format!("{}\u{a0}AAAA", "A".repeat(63));
        assert!(matches!(
            load_certificate(&cert),
            Err(SamlError::Crypto(message)) if message == "certificate is not base64 text"
        ));
        Ok(())
    }
}
