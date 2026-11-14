use crate::constants::{
    data_encryption_algorithm, digest_algorithm, key_encryption_algorithm, name_id_format,
    signature_algorithm, transform_algorithm,
};

/// XML signature algorithm used for outgoing signed messages.
///
/// [`Self::RsaSha256`] is the default. [`Self::RsaSha1`], [`Self::DsaSha1`],
/// and [`Self::HmacSha1`] use a SHA-1 digest and are used only when selected.
///
/// Custom URI values are forwarded to the configured crypto backend and can
/// still fail at runtime when unsupported by that backend.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// RSA with SHA-256.
    #[default]
    RsaSha256,
    /// RSA with SHA-384.
    RsaSha384,
    /// RSA with SHA-512.
    RsaSha512,
    /// RSA with SHA-1, signed with an RSA signing key.
    ///
    /// AWS-LC and FIPS do not sign with it.
    RsaSha1,
    /// DSA with SHA-1, signed with a DSA signing key.
    ///
    /// Needs the RustCrypto provider and `crypto-legacy-algorithms`.
    DsaSha1,
    /// HMAC-SHA1, signed with [`crate::Credentials::hmac_secret`].
    ///
    /// The verifier sets the same secret with `IdpDescriptor::with_hmac_secret`
    /// or `SpDescriptor::with_hmac_secret`.
    HmacSha1,
    /// Backend-specific signature algorithm URI.
    Custom(String),
}

impl SignatureAlgorithm {
    /// Return the XML-DSig algorithm URI.
    pub fn as_uri(&self) -> &str {
        match self {
            Self::RsaSha256 => signature_algorithm::RSA_SHA256,
            Self::RsaSha384 => signature_algorithm::RSA_SHA384,
            Self::RsaSha512 => signature_algorithm::RSA_SHA512,
            Self::RsaSha1 => signature_algorithm::RSA_SHA1,
            Self::DsaSha1 => signature_algorithm::DSA_SHA1,
            Self::HmacSha1 => signature_algorithm::HMAC_SHA1,
            Self::Custom(uri) => uri.as_str(),
        }
    }
}

/// XML digest algorithm URI used by XML-DSig profiles.
///
/// Custom URI values are forwarded to the configured crypto backend and can
/// still fail at runtime when unsupported by that backend.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DigestAlgorithm {
    /// SHA-1 digest preserved from the samlify port.
    Sha1ForCompatibility,
    /// Deprecated alias for [`Self::Sha1ForCompatibility`].
    #[deprecated(note = "use DigestAlgorithm::Sha1ForCompatibility")]
    Sha1,
    /// SHA-256 digest.
    Sha256,
    /// SHA-384 digest.
    Sha384,
    /// SHA-512 digest.
    Sha512,
    /// Backend-specific digest algorithm URI.
    Custom(String),
}

impl DigestAlgorithm {
    /// Return the XML digest algorithm URI.
    #[expect(
        deprecated,
        reason = "deprecated algorithm aliases remain mapped for the samlify port"
    )]
    pub fn as_uri(&self) -> &str {
        match self {
            Self::Sha1ForCompatibility | Self::Sha1 => digest_algorithm::SHA1,
            Self::Sha256 => digest_algorithm::SHA256,
            Self::Sha384 => digest_algorithm::SHA384,
            Self::Sha512 => digest_algorithm::SHA512,
            Self::Custom(uri) => uri.as_str(),
        }
    }
}

/// XML-Enc content encryption algorithm.
///
/// Custom URI values are forwarded to the configured crypto backend and can
/// still fail at runtime when unsupported by that backend.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum DataEncryptionAlgorithm {
    /// AES-128-CBC.
    Aes128,
    /// AES-256-CBC.
    #[default]
    Aes256,
    /// Triple DES CBC preserved from the samlify port.
    TripleDesForCompatibility,
    /// Deprecated alias for [`Self::TripleDesForCompatibility`].
    #[deprecated(note = "use DataEncryptionAlgorithm::TripleDesForCompatibility")]
    TripleDes,
    /// AES-128-GCM.
    Aes128Gcm,
    /// AES-256-GCM.
    Aes256Gcm,
    /// Backend-specific content encryption algorithm URI.
    Custom(String),
}

impl DataEncryptionAlgorithm {
    /// Return the XML-Enc algorithm URI.
    #[expect(
        deprecated,
        reason = "deprecated algorithm aliases remain mapped for the samlify port"
    )]
    pub fn as_uri(&self) -> &str {
        match self {
            Self::Aes128 => data_encryption_algorithm::AES_128,
            Self::Aes256 => data_encryption_algorithm::AES_256,
            Self::TripleDesForCompatibility | Self::TripleDes => {
                data_encryption_algorithm::TRIPLE_DES
            }
            Self::Aes128Gcm => data_encryption_algorithm::AES_128_GCM,
            Self::Aes256Gcm => data_encryption_algorithm::AES_256_GCM,
            Self::Custom(uri) => uri.as_str(),
        }
    }
}

/// XML-Enc key transport algorithm.
///
/// Custom URI values are forwarded to the configured crypto backend and can
/// still fail at runtime when unsupported by that backend.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyEncryptionAlgorithm {
    /// RSA-OAEP-MGF1P.
    #[default]
    RsaOaepMgf1p,
    /// XML Encryption 1.1 RSA-OAEP with explicit digest and mask generation.
    ///
    /// Config builders reject parameters the selected provider does not support.
    RsaOaep {
        /// Digest used by OAEP.
        digest: DigestAlgorithm,
        /// Mask generation function used by OAEP.
        mgf: MaskGenerationFunction,
    },
    /// RSAES-PKCS1-v1_5 preserved from the samlify port.
    Rsa15ForCompatibility,
    /// Deprecated alias for [`Self::Rsa15ForCompatibility`].
    #[deprecated(note = "use KeyEncryptionAlgorithm::Rsa15ForCompatibility")]
    Rsa15,
    /// Backend-specific key transport algorithm URI.
    Custom(String),
}

impl KeyEncryptionAlgorithm {
    /// Return the XML-Enc key transport algorithm URI.
    #[expect(
        deprecated,
        reason = "deprecated algorithm aliases remain mapped for the samlify port"
    )]
    pub fn as_uri(&self) -> &str {
        match self {
            Self::RsaOaepMgf1p => key_encryption_algorithm::RSA_OAEP_MGF1P,
            Self::RsaOaep { .. } => key_encryption_algorithm::RSA_OAEP,
            Self::Rsa15ForCompatibility | Self::Rsa15 => key_encryption_algorithm::RSA_1_5,
            Self::Custom(uri) => uri.as_str(),
        }
    }
}

/// Mask generation function for XML Encryption 1.1 RSA-OAEP.
///
/// More functions may be added. Use [`Self::as_uri`] to obtain the URI, or
/// include a wildcard when matching outside this crate:
///
/// ```compile_fail,E0004
/// use saml_rs::MaskGenerationFunction;
///
/// fn digest_name(mgf: MaskGenerationFunction) -> &'static str {
///     match mgf {
///         MaskGenerationFunction::Mgf1Sha256 => "SHA-256",
///         MaskGenerationFunction::Mgf1Sha384 => "SHA-384",
///         MaskGenerationFunction::Mgf1Sha512 => "SHA-512",
///     }
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MaskGenerationFunction {
    /// MGF1 with SHA-256.
    Mgf1Sha256,
    /// MGF1 with SHA-384.
    Mgf1Sha384,
    /// MGF1 with SHA-512.
    Mgf1Sha512,
}

impl MaskGenerationFunction {
    /// Return the XML Encryption 1.1 MGF algorithm URI.
    pub fn as_uri(&self) -> &str {
        match self {
            Self::Mgf1Sha256 => "http://www.w3.org/2009/xmlenc11#mgf1sha256",
            Self::Mgf1Sha384 => "http://www.w3.org/2009/xmlenc11#mgf1sha384",
            Self::Mgf1Sha512 => "http://www.w3.org/2009/xmlenc11#mgf1sha512",
        }
    }

    #[cfg(crypto)]
    pub(crate) fn digest_uri(&self) -> &str {
        match self {
            Self::Mgf1Sha256 => digest_algorithm::SHA256,
            Self::Mgf1Sha384 => digest_algorithm::SHA384,
            Self::Mgf1Sha512 => digest_algorithm::SHA512,
        }
    }
}

/// XML-DSig transform or canonicalization algorithm.
///
/// Custom URI values are forwarded to the configured crypto backend and can
/// still fail at runtime when unsupported by that backend.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransformAlgorithm {
    /// Enveloped-signature transform.
    EnvelopedSignature,
    /// Exclusive XML canonicalization.
    ExclusiveCanonicalization,
    /// Canonical XML 1.0 without comments.
    CanonicalXml,
    /// Backend-specific transform algorithm URI.
    Custom(String),
}

impl TransformAlgorithm {
    /// Return the XML-DSig transform URI.
    pub fn as_uri(&self) -> &str {
        match self {
            Self::EnvelopedSignature => transform_algorithm::ENVELOPED_SIGNATURE,
            Self::ExclusiveCanonicalization => transform_algorithm::EXC_C14N,
            Self::CanonicalXml => transform_algorithm::C14N,
            Self::Custom(uri) => uri.as_str(),
        }
    }
}

/// SAML NameID format URI.
///
/// A message or metadata that writes the format rejects a value that is not a
/// non-blank absolute URI reference with [`crate::SamlError::Invalid`]. A
/// received format is reported as sent.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NameIdFormat {
    /// Email address format.
    EmailAddress,
    /// Persistent identifier format.
    Persistent,
    /// Transient identifier format.
    Transient,
    /// Entity identifier format.
    Entity,
    /// Unspecified format.
    Unspecified,
    /// Kerberos principal name format.
    Kerberos,
    /// Windows domain qualified name format.
    WindowsDomainQualifiedName,
    /// X.509 subject name format.
    X509SubjectName,
    /// Deployment-specific NameID format URI.
    Custom(String),
}

impl NameIdFormat {
    /// Return the SAML NameID format URI.
    pub fn as_uri(&self) -> &str {
        match self {
            Self::EmailAddress => name_id_format::EMAIL_ADDRESS,
            Self::Persistent => name_id_format::PERSISTENT,
            Self::Transient => name_id_format::TRANSIENT,
            Self::Entity => name_id_format::ENTITY,
            Self::Unspecified => name_id_format::UNSPECIFIED,
            Self::Kerberos => name_id_format::KERBEROS,
            Self::WindowsDomainQualifiedName => name_id_format::WINDOWS_DOMAIN_QUALIFIED_NAME,
            Self::X509SubjectName => name_id_format::X509_SUBJECT_NAME,
            Self::Custom(uri) => uri.as_str(),
        }
    }
}

pub(crate) fn name_id_format_uris(formats: &[NameIdFormat]) -> Vec<String> {
    formats
        .iter()
        .map(|format| format.as_uri().to_string())
        .collect()
}

pub(super) fn transform_algorithm_uris(algorithms: &[TransformAlgorithm]) -> Vec<String> {
    algorithms
        .iter()
        .map(|algorithm| algorithm.as_uri().to_string())
        .collect()
}
