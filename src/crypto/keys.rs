//! Key, certificate and KeyInfo helpers backed by the selected `bergshamra`
//! provider.

use crate::config::{CertificatePem, Credentials, HmacSecret, Passphrase, X509Credential};
use crate::error::{crypto_err, SamlError};
use crate::util::normalize_cert_string;
#[cfg(test)]
use bergshamra::keys::keyinfo::build_x509_key_info;
use bergshamra::keys::loader::{load_hmac_key, load_pem_auto, load_x509_cert_pem};
use bergshamra::keys::Key;

pub(crate) fn read_private_key(pem: &str, password: Option<&str>) -> Result<Key, SamlError> {
    super::provider::ensure_crypto_provider_initialized()?;
    load_pem_auto(pem.as_bytes(), password).map_err(crypto_err)
}

/// Check that every key and certificate in `credentials` loads, and that the
/// key of each signing and decryption credential is the private key of its
/// certificate.
pub(crate) fn check_credentials(credentials: &Credentials) -> Result<(), SamlError> {
    if let Some(credential) = credentials.signing_credential() {
        check_credential(credential, "signing credential")?;
    }
    for (index, certificate) in credentials
        .additional_signing_certificates()
        .iter()
        .enumerate()
    {
        load_published_certificate(
            certificate,
            &format!("additional signing certificate at index {index}"),
        )?;
    }
    for (index, credential) in credentials.decryption_credentials().iter().enumerate() {
        check_credential(
            credential,
            &format!("decryption credential at index {index}"),
        )?;
    }
    Ok(())
}

fn check_credential(credential: &X509Credential, name: &str) -> Result<(), SamlError> {
    super::provider::ensure_crypto_provider_initialized()?;
    let key = load_pem_auto(
        credential.key().as_str().as_bytes(),
        credential.passphrase().map(Passphrase::as_str),
    )
    .map_err(|error| credential_error(name, "the private key does not load", error))?;
    if !key.has_private_key() {
        return Err(SamlError::crypto(format!(
            "{name}: the private key PEM holds only a public key"
        )));
    }
    let certificate = load_published_certificate(credential.certificate(), name)?;
    if public_key(&key, name)? != public_key(&certificate, name)? {
        return Err(SamlError::crypto(format!(
            "{name}: the private key does not match the certificate"
        )));
    }
    Ok(())
}

fn load_published_certificate(certificate: &CertificatePem, name: &str) -> Result<Key, SamlError> {
    super::provider::ensure_crypto_provider_initialized()?;
    let published = normalize_cert_string(certificate.as_str());
    let pem = to_cert_pem(&published)
        .ok_or_else(|| SamlError::crypto(format!("{name}: the certificate does not load")))?;
    load_x509_cert_pem(pem.as_bytes())
        .map_err(|error| credential_error(name, "the certificate does not load", error))
}

/// The SubjectPublicKeyInfo of `key`, encoded by the selected provider.
fn public_key(key: &Key, name: &str) -> Result<Vec<u8>, SamlError> {
    key.data
        .export_public()
        .map_err(|error| credential_error(name, "the public key does not export", error))
}

fn credential_error(
    name: &str,
    problem: &str,
    source: impl std::error::Error + Send + Sync + 'static,
) -> SamlError {
    SamlError::Crypto {
        message: format!("{name}: {problem}"),
        source: Some(Box::new(source)),
    }
}

/// The decryption key `pem`, then each of `additional`, in the order they are
/// tried.
pub(crate) fn load_decryption_keys(
    pem: &str,
    password: Option<&str>,
    additional: &[X509Credential],
) -> Result<Vec<Key>, SamlError> {
    std::iter::once(read_private_key(pem, password))
        .chain(additional.iter().map(|credential| {
            read_private_key(
                credential.key().as_str(),
                credential
                    .passphrase()
                    .map(|passphrase| passphrase.as_str()),
            )
        }))
        .collect()
}

pub(crate) fn load_hmac_secret(secret: &HmacSecret) -> Result<Key, SamlError> {
    super::provider::ensure_crypto_provider_initialized()?;
    load_hmac_key(secret.as_bytes()).map_err(crypto_err)
}

/// Wrap a bare base64 certificate (as found in metadata) into a PEM block.
/// Returns `None` when the bare certificate is not ASCII text.
fn to_cert_pem(cert: &str) -> Option<String> {
    if cert.contains("BEGIN CERTIFICATE") {
        return Some(cert.to_string());
    }
    let b64 = normalize_cert_string(cert);
    if !b64.is_ascii() {
        return None;
    }
    let mut body = String::new();
    let mut i = 0;
    while i < b64.len() {
        let end = (i + 64).min(b64.len());
        body.push_str(&b64[i..end]);
        body.push('\n');
        i = end;
    }
    Some(format!(
        "-----BEGIN CERTIFICATE-----\n{body}-----END CERTIFICATE-----\n"
    ))
}

/// Load an X.509 certificate (PEM or bare base64) as a verification key.
pub(crate) fn load_certificate(cert: &str) -> Result<Key, SamlError> {
    super::provider::ensure_crypto_provider_initialized()?;
    let pem =
        to_cert_pem(cert).ok_or_else(|| SamlError::crypto("certificate is not base64 text"))?;
    load_x509_cert_pem(pem.as_bytes()).map_err(crypto_err)
}

/// Build a `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>` block from a
/// certificate.
#[cfg(test)]
fn build_key_info(cert: &str) -> String {
    let b64 = normalize_cert_string(cert);
    build_x509_key_info(&[b64.as_str()])
}

#[cfg(test)]
mod tests {
    use super::*;

    const SP_PRIVKEY: &str =
        include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
    // RustCrypto decrypts this PEM. AWS-LC and FIPS reject it.
    #[cfg(crypto)]
    const SP_PRIVKEY_ENC: &str =
        include_str!("../../tests/fixtures/key/sp/privkey.encrypted.pkcs8.pem");
    const SP_CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.cer");
    const IDP_CERT: &str = include_str!("../../tests/fixtures/key/idp/cert.cer");
    // SP signing passphrase from upstream test/key/keypass.txt.
    #[cfg(feature = "crypto-rustcrypto")]
    const SP_PASS: &str = "VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px";

    #[test]
    fn loads_unencrypted_private_key() -> Result<(), Box<dyn std::error::Error>> {
        let key = read_private_key(SP_PRIVKEY, None)?;
        assert!(key.has_private_key());
        assert_eq!(key.algorithm_name(), "RSA");
        Ok(())
    }

    #[test]
    #[cfg(feature = "crypto-rustcrypto")]
    fn loads_each_additional_decryption_key_with_its_own_passphrase(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::config::{CertificatePem, Passphrase, PrivateKeyPem};

        let keys = load_decryption_keys(
            SP_PRIVKEY,
            None,
            &[X509Credential::new(
                CertificatePem::new(SP_CERT),
                PrivateKeyPem::new(SP_PRIVKEY_ENC),
            )
            .with_passphrase(Passphrase::new(SP_PASS))],
        )?;
        assert_eq!(keys.len(), 2);
        assert!(keys.iter().all(Key::has_private_key));
        Ok(())
    }

    #[test]
    #[cfg(feature = "crypto-rustcrypto")]
    fn loads_encrypted_private_key_with_passphrase() -> Result<(), Box<dyn std::error::Error>> {
        let key = read_private_key(SP_PRIVKEY_ENC, Some(SP_PASS))?;
        assert!(key.has_private_key());
        Ok(())
    }

    #[test]
    #[cfg(all(
        any(feature = "crypto-aws-lc", feature = "crypto-fips"),
        not(feature = "crypto-rustcrypto")
    ))]
    fn rejects_encrypted_private_key_when_provider_does_not_support_it() {
        assert!(read_private_key(SP_PRIVKEY_ENC, Some("unused")).is_err());
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
            Err(SamlError::Crypto { message, .. }) if message == "certificate is not base64 text"
        ));
        Ok(())
    }
}
