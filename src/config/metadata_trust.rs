use crate::error::SamlError;
#[cfg(crypto)]
use crate::error::SignatureVerificationReason;
use crate::metadata::Metadata;
#[cfg(crypto)]
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
/// [`AllowUnsigned`](Self::AllowUnsigned) preserves an
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
/// let idp = IdpDescriptor::from_metadata_xml(
///     EntityId::try_new("https://idp.example.com/metadata")?,
///     &load_metadata(),
///     MetadataTrustPolicy::RequireSignature {
///         trusted_certificates: &certificates,
///     },
/// )?;
/// assert!(idp.signed_metadata_xml().is_some());
/// # Ok(()) }
/// ```
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum MetadataTrustPolicy<'a> {
    /// Accept unsigned metadata to preserve a samlify-port or raw import.
    ///
    /// A signature on the document is not treated as verified.
    AllowUnsigned,
    /// Require a valid metadata signature from one of the pinned certificates.
    ///
    /// The signature must be an enveloped `#id` signature over the metadata
    /// root. On a build that verifies MD5 or RIPEMD-160, a signature that uses
    /// one as its signature or digest algorithm is rejected with
    /// [`SamlError::AlgorithmUnsupported`]. A pinned RSA certificate shorter
    /// than 2048 bits is not used to verify.
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
    RequireSignatureAllowingWeakAlgorithms {
        /// Caller-pinned certificates trusted to sign the metadata.
        trusted_certificates: &'a [CertificatePem],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(crypto), allow(dead_code))]
pub(super) enum AppliedMetadataTrust {
    Unverified,
    SignedByPinnedCertificates { signed_metadata_xml: String },
}
pub(super) fn metadata_entity_id(metadata: &Metadata) -> Result<&str, SamlError> {
    metadata
        .entity_id()
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

pub(super) fn ensure_metadata_trust(
    metadata: &Metadata,
    trust: MetadataTrustPolicy<'_>,
) -> Result<AppliedMetadataTrust, SamlError> {
    match trust {
        MetadataTrustPolicy::AllowUnsigned => Ok(AppliedMetadataTrust::Unverified),
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
        MetadataTrustPolicy::RequireSignatureAllowingWeakAlgorithms {
            trusted_certificates,
        } => verify_pinned_metadata_signature(
            metadata,
            trusted_certificates,
            MetadataSignatureTransforms::Profile,
            XmlSignatureProfile::AllowWeakAlgorithms,
        ),
    }
}

#[cfg(crypto)]
fn verify_pinned_metadata_signature(
    metadata: &Metadata,
    trusted_certificates: &[CertificatePem],
    transforms: MetadataSignatureTransforms,
    algorithms: XmlSignatureProfile,
) -> Result<AppliedMetadataTrust, SamlError> {
    ensure_import_signature_shape(metadata.metadata_xml(), transforms)?;
    let trusted_certificates: Vec<String> = trusted_certificates
        .iter()
        .map(|certificate| certificate.as_str().to_string())
        .collect();
    let signed_metadata_xml =
        crate::crypto::verify::verify_metadata_signature_coverage_with_limits(
            metadata.metadata_xml(),
            &trusted_certificates,
            XmlLimits::default(),
            algorithms,
        )?
        .ok_or(SamlError::SignatureVerification {
            reason: SignatureVerificationReason::XmlSignature,
        })?;
    Ok(AppliedMetadataTrust::SignedByPinnedCertificates {
        signed_metadata_xml,
    })
}

#[cfg(not(crypto))]
fn verify_pinned_metadata_signature(
    metadata: &Metadata,
    _trusted_certificates: &[CertificatePem],
    transforms: MetadataSignatureTransforms,
    _algorithms: XmlSignatureProfile,
) -> Result<AppliedMetadataTrust, SamlError> {
    ensure_import_signature_shape(metadata.metadata_xml(), transforms)?;
    Err(SamlError::Unsupported(
        "signed metadata verification requires a crypto provider feature".into(),
    ))
}
