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

    pub(crate) fn as_str(&self) -> &str {
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

    pub(crate) fn as_str(&self) -> &str {
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

    pub(crate) fn as_str(&self) -> &str {
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
/// The signer puts it in [`Credentials::with_hmac_secret`], and the verifier puts
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

    #[cfg(crypto)]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for HmacSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HmacSecret(<redacted>)")
    }
}

/// Secret-bearing and certificate material for local SAML operations.
///
/// Start from [`Credentials::default`] and add material with the `with_*`
/// methods. A passphrase is only accepted together with the key it unlocks.
///
/// # Examples
///
/// ```
/// use saml_rs::{CertificatePem, Credentials, DecryptionCredential, PrivateKeyPem};
///
/// let credentials = Credentials::default()
///     .with_signing_key(PrivateKeyPem::new("signing key PEM"))
///     .with_signing_certificate(CertificatePem::new("signing certificate PEM"))
///     .with_decryption(DecryptionCredential {
///         certificate: CertificatePem::new("encryption certificate PEM"),
///         key: PrivateKeyPem::new("decryption key PEM"),
///         passphrase: None,
///     });
/// # let _ = credentials;
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Credentials {
    signing_key: Option<SigningKey>,
    signing_certificate: Option<CertificatePem>,
    additional_signing_certificates: Vec<CertificatePem>,
    hmac_secret: Option<HmacSecret>,
    decryption: Option<DecryptionCredential>,
    additional_decryption_keys: Vec<DecryptionCredential>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SigningKey {
    key: PrivateKeyPem,
    passphrase: Option<Passphrase>,
}

impl Credentials {
    /// Sign with an unencrypted private key.
    ///
    /// Replaces any signing key set before.
    pub fn with_signing_key(mut self, key: PrivateKeyPem) -> Self {
        self.signing_key = Some(SigningKey {
            key,
            passphrase: None,
        });
        self
    }

    /// Sign with a private key that `passphrase` unlocks.
    ///
    /// Replaces any signing key set before.
    pub fn with_encrypted_signing_key(
        mut self,
        key: PrivateKeyPem,
        passphrase: Passphrase,
    ) -> Self {
        self.signing_key = Some(SigningKey {
            key,
            passphrase: Some(passphrase),
        });
        self
    }

    /// Set the signing certificate, published in metadata and in signatures.
    pub fn with_signing_certificate(mut self, certificate: CertificatePem) -> Self {
        self.signing_certificate = Some(certificate);
        self
    }

    /// Publish one more signing certificate in metadata, after the signing
    /// certificate and any added before.
    ///
    /// Each certificate gets its own signing `KeyDescriptor`, in the order
    /// added. Signing still uses only the signing key and signing certificate.
    /// To roll over the signing key, publish the next certificate here and wait
    /// until every peer has refreshed this entity's metadata. Then switch the
    /// signing key and certificate to the new pair and keep the old
    /// certificate here during the overlap. Drop the old certificate when peers
    /// no longer need to verify messages signed with it.
    pub fn with_additional_signing_certificate(mut self, certificate: CertificatePem) -> Self {
        self.additional_signing_certificates.push(certificate);
        self
    }

    /// Set the secret for [`crate::SignatureAlgorithm::HmacSha1`].
    ///
    /// Messages are signed with it instead of the signing key when that
    /// algorithm is selected.
    pub fn with_hmac_secret(mut self, secret: HmacSecret) -> Self {
        self.hmac_secret = Some(secret);
        self
    }

    /// Set the primary decryption key and the encryption certificate peers
    /// use for it.
    ///
    /// Decryption tries this key first. Metadata publishes its certificate as
    /// the first encryption `KeyDescriptor`.
    pub fn with_decryption(mut self, credential: DecryptionCredential) -> Self {
        self.decryption = Some(credential);
        self
    }

    /// Add a decryption key, tried in the order added after the primary one.
    ///
    /// Each certificate is published in metadata after the primary encryption
    /// certificate, so a peer may encrypt for any of them. To roll over the
    /// encryption key, add the next key here. Then make it the primary
    /// decryption credential and add the old key here. Drop the old key once
    /// every peer has refreshed this entity's metadata. A config with an
    /// additional key and no primary one fails to build.
    pub fn with_additional_decryption_key(mut self, credential: DecryptionCredential) -> Self {
        self.additional_decryption_keys.push(credential);
        self
    }

    pub(crate) fn signing_key(&self) -> Option<&PrivateKeyPem> {
        self.signing_key.as_ref().map(|signing| &signing.key)
    }

    pub(crate) fn signing_key_passphrase(&self) -> Option<&Passphrase> {
        self.signing_key
            .as_ref()
            .and_then(|signing| signing.passphrase.as_ref())
    }

    pub(crate) fn signing_certificate(&self) -> Option<&CertificatePem> {
        self.signing_certificate.as_ref()
    }

    pub(crate) fn additional_signing_certificates(&self) -> &[CertificatePem] {
        &self.additional_signing_certificates
    }

    pub(crate) fn hmac_secret(&self) -> Option<&HmacSecret> {
        self.hmac_secret.as_ref()
    }

    pub(crate) fn decryption(&self) -> Option<&DecryptionCredential> {
        self.decryption.as_ref()
    }

    pub(crate) fn additional_decryption_keys(&self) -> &[DecryptionCredential] {
        &self.additional_decryption_keys
    }
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
