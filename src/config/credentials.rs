use core::fmt;

use crate::error::SamlError;

/// PEM-encoded private key material.
///
/// `Debug` is intentionally redacted so key material is not dumped through
/// public config structs.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateKeyPem(String);

impl PrivateKeyPem {
    /// Wrap PEM-encoded private key material.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the PEM text.
    ///
    /// The value is secret-bearing key material. Prefer passing typed
    /// credentials through config APIs when possible; this accessor exists for
    /// migration code and raw compatibility escape hatches.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PrivateKeyPem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKeyPem(<redacted>)")
    }
}

/// PEM-encoded X.509 certificate material.
///
/// `Debug` avoids printing the certificate body by default because certificate
/// fields often travel beside private key configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct CertificatePem(String);

impl CertificatePem {
    /// Wrap PEM-encoded certificate material.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the PEM text for internal compatibility mapping.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CertificatePem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CertificatePem(<redacted>)")
    }
}

/// Passphrase used to decrypt private key material.
///
/// `Debug` is intentionally redacted so passphrases are not exposed through
/// logs or failing assertions.
#[derive(Clone, PartialEq, Eq)]
pub struct Passphrase(String);

impl Passphrase {
    /// Wrap passphrase text.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the passphrase text.
    ///
    /// The value is secret-bearing credential material. Prefer passing typed
    /// credentials through config APIs when possible; this accessor exists for
    /// migration code and raw compatibility escape hatches.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Passphrase(<redacted>)")
    }
}
/// Shared secret for an HMAC XML signature or detached signature.
///
/// The signer puts it in [`Credentials::hmac_secret`], and the verifier puts
/// the same secret on the signer's peer descriptor. `Debug` is redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct HmacSecret(Vec<u8>);

impl HmacSecret {
    /// Smallest accepted secret, in bytes: the SHA-1 output length.
    pub const MIN_LEN: usize = 20;

    /// Wrap secret bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the secret is shorter than
    /// [`Self::MIN_LEN`] bytes.
    pub fn try_new(value: impl Into<Vec<u8>>) -> Result<Self, SamlError> {
        let value = value.into();
        if value.len() < Self::MIN_LEN {
            return Err(SamlError::Invalid(format!(
                "HMAC secret must be at least {} bytes",
                Self::MIN_LEN
            )));
        }
        Ok(Self(value))
    }

    /// Borrow the secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for HmacSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HmacSecret(<redacted>)")
    }
}

/// Secret-bearing and certificate material for local SAML operations.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Credentials {
    /// Signing private key.
    pub signing_key: Option<PrivateKeyPem>,
    /// Passphrase for [`Self::signing_key`].
    pub signing_key_passphrase: Option<Passphrase>,
    /// Signing certificate.
    pub signing_certificate: Option<CertificatePem>,
    /// Secret for [`crate::SignatureAlgorithm::HmacSha1`].
    ///
    /// Messages are signed with it instead of [`Self::signing_key`] when that
    /// algorithm is selected.
    pub hmac_secret: Option<HmacSecret>,
    /// Encryption certificate advertised for peers.
    pub encryption_certificate: Option<CertificatePem>,
    /// Decryption private key for encrypted assertions.
    pub decryption_key: Option<PrivateKeyPem>,
    /// Passphrase for [`Self::decryption_key`].
    pub decryption_key_passphrase: Option<Passphrase>,
    /// More decryption keys, tried in order after [`Self::decryption_key`].
    ///
    /// Each certificate is published in metadata after
    /// [`Self::encryption_certificate`], so a peer may encrypt for any of
    /// them. Use it to roll over the encryption key: add the next key here,
    /// publish both, then make it the [`Self::decryption_key`] and drop the
    /// old one once every peer encrypts for the new certificate. Requires
    /// [`Self::decryption_key`].
    pub additional_decryption_keys: Vec<DecryptionCredential>,
}

/// A decryption private key and the encryption certificate peers use for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptionCredential {
    /// Encryption certificate published for [`Self::key`].
    pub certificate: CertificatePem,
    /// Decryption private key.
    pub key: PrivateKeyPem,
    /// Passphrase for [`Self::key`].
    pub passphrase: Option<Passphrase>,
}
