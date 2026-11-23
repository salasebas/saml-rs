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
/// methods.
///
/// # Examples
///
/// ```
/// use saml_rs::{CertificatePem, Credentials, PrivateKeyPem, X509Credential};
///
/// let credentials = Credentials::default()
///     .with_signing_credential(X509Credential::new(
///         CertificatePem::new("signing certificate PEM"),
///         PrivateKeyPem::new("signing key PEM"),
///     ))
///     .with_decryption_credential(X509Credential::new(
///         CertificatePem::new("encryption certificate PEM"),
///         PrivateKeyPem::new("decryption key PEM"),
///     ));
/// # let _ = credentials;
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Credentials {
    signing: Option<X509Credential>,
    additional_signing_certificates: Vec<CertificatePem>,
    hmac_secret: Option<HmacSecret>,
    decryption: Vec<X509Credential>,
}

impl Credentials {
    /// Replace the signing key and the signing certificate published for it
    /// in metadata and in signatures.
    pub fn with_signing_credential(mut self, credential: X509Credential) -> Self {
        self.signing = Some(credential);
        self
    }

    /// Append a signing certificate published in metadata after the signing
    /// credential's certificate and any added before.
    ///
    /// Each certificate gets its own signing `KeyDescriptor`, in the order
    /// added. Signing still uses only the signing credential. To roll over
    /// the signing key, publish the next certificate here and wait until
    /// every peer has refreshed this entity's metadata. Then switch the
    /// signing credential to the new pair and keep the old certificate here
    /// during the overlap. Drop the old certificate when peers no longer need
    /// to verify messages signed with it.
    pub fn with_additional_signing_certificate(mut self, certificate: CertificatePem) -> Self {
        self.additional_signing_certificates.push(certificate);
        self
    }

    /// Replace the secret used to sign messages with an HMAC algorithm.
    pub fn with_hmac_secret(mut self, secret: HmacSecret) -> Self {
        self.hmac_secret = Some(secret);
        self
    }

    /// Append a decryption key and the encryption certificate peers use for
    /// it.
    ///
    /// Decryption tries the keys in the order added and keeps the first that
    /// decrypts. When none decrypts, the error comes from the first key.
    /// Metadata publishes each certificate in its own encryption
    /// `KeyDescriptor`, in the same order, so a peer may encrypt for any of
    /// them. To roll over the encryption key, append the next credential and
    /// wait until every peer has refreshed this entity's metadata. Then list
    /// the next credential first, and drop the old one once every peer has
    /// refreshed again.
    pub fn with_decryption_credential(mut self, credential: X509Credential) -> Self {
        self.decryption.push(credential);
        self
    }

    /// Append decryption credentials, in iteration order, as
    /// [`Self::with_decryption_credential`] appends one.
    pub fn with_decryption_credentials(
        mut self,
        credentials: impl IntoIterator<Item = X509Credential>,
    ) -> Self {
        self.decryption.extend(credentials);
        self
    }

    /// The signing key, its certificate, and its passphrase.
    pub fn signing_credential(&self) -> Option<&X509Credential> {
        self.signing.as_ref()
    }

    /// The additional signing certificates, in publication order.
    pub fn additional_signing_certificates(&self) -> &[CertificatePem] {
        &self.additional_signing_certificates
    }

    /// The secret used to sign messages with an HMAC algorithm.
    pub fn hmac_secret(&self) -> Option<&HmacSecret> {
        self.hmac_secret.as_ref()
    }

    /// The decryption credentials, in decryption and publication order.
    pub fn decryption_credentials(&self) -> &[X509Credential] {
        &self.decryption
    }
}

/// A private key and the X.509 certificate of its public key.
///
/// [`Credentials::with_signing_credential`] signs with it and
/// [`Credentials::with_decryption_credential`] decrypts with it. Metadata
/// publishes the certificate for that use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509Credential {
    certificate: CertificatePem,
    key: PrivateKeyPem,
    passphrase: Option<Passphrase>,
}

impl X509Credential {
    /// Pair `key` with `certificate`, the certificate of its public key.
    pub fn new(certificate: CertificatePem, key: PrivateKeyPem) -> Self {
        Self {
            certificate,
            key,
            passphrase: None,
        }
    }

    /// Set the passphrase that unlocks the key, when the key is encrypted.
    pub fn with_passphrase(mut self, passphrase: Passphrase) -> Self {
        self.passphrase = Some(passphrase);
        self
    }

    /// The certificate of the key's public key.
    pub fn certificate(&self) -> &CertificatePem {
        &self.certificate
    }

    /// The private key.
    pub fn key(&self) -> &PrivateKeyPem {
        &self.key
    }

    /// The passphrase that unlocks the key, when it is encrypted.
    pub fn passphrase(&self) -> Option<&Passphrase> {
        self.passphrase.as_ref()
    }
}
