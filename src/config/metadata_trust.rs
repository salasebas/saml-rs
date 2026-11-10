use core::ops::Deref;

use crate::error::SamlError;
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
use crate::error::SignatureVerificationReason;
use crate::metadata::Metadata;
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
use crate::xml::XmlLimits;

use super::credentials::CertificatePem;
use super::descriptors::EntityId;
use super::metadata_signature_shape::{ensure_import_signature_shape, MetadataSignatureTransforms};
use super::policies::XmlSignatureProfile;

/// Explicit trust policy for imported SAML metadata.
///
/// This is a caller argument on descriptor import, not a field of
/// [`crate::SpValidationPolicy`] or [`crate::IdpValidationPolicy`]. There is
/// no `recommended()` constructor. The classification is
/// `docs/conformance/metadata-and-replay.md`.
///
/// SAML metadata trust is caller-pinned or federation-driven; this type does
/// not use a public web PKI CA store by default.
/// [`UnsignedForCompatibility`](Self::UnsignedForCompatibility) preserves an
/// unsigned samlify-port or raw metadata import. It is not the preferred
/// production trust model.
///
/// # Examples
///
/// ```no_run
/// use saml_rs::{CertificatePem, EntityId, IdpDescriptor, MetadataTrustPolicy};
///
/// # fn load_metadata() -> String { unimplemented!() }
/// # fn load_metadata_signing_cert() -> String { unimplemented!() }
/// # fn run() -> Result<(), saml_rs::SamlError> {
/// let cert = CertificatePem::new(load_metadata_signing_cert());
/// let certificates = [cert];
/// let idp = IdpDescriptor::from_metadata_xml_for(
///     EntityId::try_new("https://idp.example.com/metadata")?,
///     &load_metadata(),
///     MetadataTrustPolicy::RequireSignature {
///         trusted_certificates: &certificates,
///     },
/// )?;
/// assert!(idp.was_verified_with_pinned_certificates());
/// # Ok(()) }
/// ```
#[derive(Debug, Clone, Copy)]
pub enum MetadataTrustPolicy<'a> {
    /// Accept unsigned metadata to preserve a samlify-port or raw import.
    ///
    /// A signature on the document is not treated as verified.
    UnsignedForCompatibility,
    /// Require a valid metadata signature from one of the pinned certificates.
    ///
    /// The signature must be an enveloped `#id` signature over the metadata
    /// root. A signature that uses an MD5 or RIPEMD-160 signature or digest
    /// algorithm is rejected with [`SamlError::AlgorithmUnsupported`], and a
    /// pinned RSA certificate shorter than 2048 bits is not used to verify.
    /// See `docs/conformance/metadata-and-replay.md`.
    RequireSignature {
        /// Caller-pinned certificates trusted to sign the metadata.
        trusted_certificates: &'a [CertificatePem],
    },
    /// Require a pinned metadata signature, and also accept inclusive
    /// canonicalization.
    ///
    /// The identifier, single `#id` reference, algorithm, and key-size checks
    /// of [`Self::RequireSignature`] stay on. See
    /// `docs/conformance/metadata-and-replay.md`.
    RequireSignatureAllowingOtherCanonicalization {
        /// Caller-pinned certificates trusted to sign the metadata.
        trusted_certificates: &'a [CertificatePem],
    },
    /// Require a pinned metadata signature, and also accept MD5 and RIPEMD-160
    /// signature and digest algorithms and RSA certificates shorter than 2048
    /// bits where the crypto provider verifies them.
    ///
    /// The signature shape and transform checks of [`Self::RequireSignature`]
    /// stay on. See `docs/conformance/metadata-and-replay.md`.
    RequireSignatureAllowingWeakAlgorithmsForCompatibility {
        /// Caller-pinned certificates trusted to sign the metadata.
        trusted_certificates: &'a [CertificatePem],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    not(any(
        feature = "crypto-rustcrypto",
        feature = "crypto-aws-lc",
        feature = "crypto-fips"
    )),
    allow(dead_code)
)]
pub(super) enum AppliedMetadataTrust {
    UnsignedForCompatibility,
    SignedByPinnedCertificates {
        signed_entity_descriptor_xml: String,
    },
}
pub(super) fn metadata_entity_id<M>(metadata: &M) -> Result<&str, SamlError>
where
    M: Deref<Target = Metadata>,
{
    metadata
        .get_entity_id()
        .ok_or_else(|| SamlError::MissingMetadata("entityID".into()))
}

pub(super) fn ensure_expected_entity_id(
    expected: &EntityId,
    actual: &str,
) -> Result<(), SamlError> {
    if expected.as_str() == actual {
        return Ok(());
    }
    Err(SamlError::Invalid(format!(
        "metadata entityID `{actual}` did not match expected `{}`",
        expected.as_str()
    )))
}

pub(super) fn ensure_metadata_trust<M>(
    metadata: &M,
    trust: MetadataTrustPolicy<'_>,
) -> Result<AppliedMetadataTrust, SamlError>
where
    M: Deref<Target = Metadata>,
{
    match trust {
        MetadataTrustPolicy::UnsignedForCompatibility => {
            Ok(AppliedMetadataTrust::UnsignedForCompatibility)
        }
        MetadataTrustPolicy::RequireSignature {
            trusted_certificates,
        } => verify_pinned_metadata_signature(
            metadata,
            trusted_certificates,
            MetadataSignatureTransforms::Profile,
            XmlSignatureProfile::ExcludeWeakAlgorithms,
        ),
        MetadataTrustPolicy::RequireSignatureAllowingOtherCanonicalization {
            trusted_certificates,
        } => verify_pinned_metadata_signature(
            metadata,
            trusted_certificates,
            MetadataSignatureTransforms::AllowOtherCanonicalization,
            XmlSignatureProfile::ExcludeWeakAlgorithms,
        ),
        MetadataTrustPolicy::RequireSignatureAllowingWeakAlgorithmsForCompatibility {
            trusted_certificates,
        } => verify_pinned_metadata_signature(
            metadata,
            trusted_certificates,
            MetadataSignatureTransforms::Profile,
            XmlSignatureProfile::AllowProviderSupportedForCompatibility,
        ),
    }
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn verify_pinned_metadata_signature<M>(
    metadata: &M,
    trusted_certificates: &[CertificatePem],
    transforms: MetadataSignatureTransforms,
    algorithms: XmlSignatureProfile,
) -> Result<AppliedMetadataTrust, SamlError>
where
    M: Deref<Target = Metadata>,
{
    ensure_import_signature_shape(metadata.get_metadata(), transforms)?;
    let trusted_certificates: Vec<String> = trusted_certificates
        .iter()
        .map(|certificate| certificate.as_str().to_string())
        .collect();
    let verification = crate::crypto::verify::verify_metadata_signature_coverage_with_limits(
        metadata.get_metadata(),
        &trusted_certificates,
        XmlLimits::default(),
        algorithms,
    )?;
    if verification.verified() {
        let signed_entity_descriptor_xml = verification
            .into_signed_entity_descriptor_xml()
            .ok_or(SamlError::SignedReferenceMismatch)?;
        return Ok(AppliedMetadataTrust::SignedByPinnedCertificates {
            signed_entity_descriptor_xml,
        });
    }
    Err(SamlError::SignatureVerification {
        reason: SignatureVerificationReason::XmlSignature,
    })
}

#[cfg(not(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
)))]
fn verify_pinned_metadata_signature<M>(
    metadata: &M,
    _trusted_certificates: &[CertificatePem],
    transforms: MetadataSignatureTransforms,
    _algorithms: XmlSignatureProfile,
) -> Result<AppliedMetadataTrust, SamlError>
where
    M: Deref<Target = Metadata>,
{
    ensure_import_signature_shape(metadata.get_metadata(), transforms)?;
    Err(SamlError::Unsupported(
        "signed metadata verification requires a crypto provider feature".into(),
    ))
}
