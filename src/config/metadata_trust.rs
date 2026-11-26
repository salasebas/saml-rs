use std::sync::Arc;

use crate::error::SamlError;
#[cfg(crypto)]
use crate::error::SignatureVerificationReason;
use crate::metadata::Metadata;
use crate::xml::XmlLimits;
use crate::xml::{dom, protocol_element};

use super::credentials::CertificatePem;
use super::descriptors::EntityId;
use super::metadata_signature_shape::{ensure_import_signature_shape, MetadataSignatureTransforms};
use super::policies::XmlSignatureProfile;

/// Explicit trust policy for imported SAML metadata.
///
/// This is a caller argument on descriptor import, not a field of
/// [`crate::SpValidationPolicy`] or [`crate::IdpValidationPolicy`]. The classification is
/// `docs/conformance/metadata-and-replay.md`.
///
/// For signed metadata, obtain the publisher's signing certificate independently
/// of the document and pin it as shown below. When the application authenticates
/// the metadata through another trusted channel, such as a file provisioned by
/// the operator, it can explicitly select [`Self::Unverified`].
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
    /// Import metadata without verifying a signature, even when one is present.
    ///
    /// The caller establishes the document's origin and integrity.
    Unverified,
    /// Require a valid metadata signature from one of the pinned certificates.
    ///
    /// The signature must be an enveloped `#id` signature over the metadata
    /// root, and the only `ds:Signature` in the document. An element named
    /// `Signature` or `Object` in another namespace, such as extension
    /// content, is not an XML signature element. On a build that verifies MD5
    /// or RIPEMD-160, a signature that uses one as its signature or digest
    /// algorithm is rejected with [`SamlError::AlgorithmUnsupported`]. A
    /// pinned RSA certificate shorter than 2048 bits is not used to verify.
    /// See `docs/conformance/metadata-and-replay.md`.
    RequireSignature {
        /// Caller-pinned certificates trusted to sign the metadata.
        trusted_certificates: &'a [CertificatePem],
    },
    /// Require a metadata signature from a trusted third-party registration
    /// authority that independently authorizes the scopes of the listed IdP.
    ///
    /// The signature requirements are the same as [`Self::RequireSignature`].
    /// Pin only certificates of authorities the SP trusts to authorize scope
    /// claims for this entity. A peer's own certificate cannot serve this role.
    RequireRegistrationAuthoritySignature {
        /// Independently obtained certificates of the registration authority.
        trusted_certificates: &'a [CertificatePem],
    },
    /// Require a pinned metadata signature and also accept inclusive
    /// Canonical XML 1.0 and 1.1 reference transforms, with or without comments.
    ///
    /// The identifier, single `#id` reference, algorithm, and key-size checks
    /// of [`Self::RequireSignature`] stay on. See
    /// `docs/conformance/metadata-and-replay.md`.
    RequireSignatureAllowingInclusiveCanonicalization {
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
    SignedByPinnedCertificates {
        signed_metadata_xml: Arc<str>,
        registration_authority: bool,
    },
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
    xml: &str,
    trust: MetadataTrustPolicy<'_>,
    limits: XmlLimits,
) -> Result<AppliedMetadataTrust, SamlError> {
    let (certificates, transforms, algorithms) = match trust {
        MetadataTrustPolicy::Unverified => return Ok(AppliedMetadataTrust::Unverified),
        MetadataTrustPolicy::RequireSignature {
            trusted_certificates,
        }
        | MetadataTrustPolicy::RequireRegistrationAuthoritySignature {
            trusted_certificates,
        } => (
            trusted_certificates,
            MetadataSignatureTransforms::Profile,
            XmlSignatureProfile::ExcludeWeakAlgorithms,
        ),
        MetadataTrustPolicy::RequireSignatureAllowingInclusiveCanonicalization {
            trusted_certificates,
        } => (
            trusted_certificates,
            MetadataSignatureTransforms::AllowInclusiveCanonicalization,
            XmlSignatureProfile::ExcludeWeakAlgorithms,
        ),
        MetadataTrustPolicy::RequireSignatureAllowingWeakAlgorithms {
            trusted_certificates,
        } => (
            trusted_certificates,
            MetadataSignatureTransforms::Profile,
            XmlSignatureProfile::AllowWeakAlgorithms,
        ),
    };
    let signed_metadata_xml =
        verify_pinned_metadata_signature(xml, certificates, transforms, algorithms, limits)?;
    Ok(AppliedMetadataTrust::SignedByPinnedCertificates {
        signed_metadata_xml: Arc::from(signed_metadata_xml),
        registration_authority: matches!(
            trust,
            MetadataTrustPolicy::RequireRegistrationAuthoritySignature { .. }
        ),
    })
}

#[cfg(crypto)]
fn verify_pinned_metadata_signature(
    xml: &str,
    trusted_certificates: &[CertificatePem],
    transforms: MetadataSignatureTransforms,
    algorithms: XmlSignatureProfile,
    limits: XmlLimits,
) -> Result<String, SamlError> {
    let document = dom::parse_document(xml, limits)?;
    let namespaced = protocol_element::parse_saml_with_limits(xml, limits)?;
    ensure_import_signature_shape(&document.root, &namespaced, transforms)?;
    let trusted_certificates: Vec<String> = trusted_certificates
        .iter()
        .map(|certificate| certificate.as_str().to_string())
        .collect();
    crate::crypto::verify::verify_metadata_signature_coverage(
        xml,
        document,
        &trusted_certificates,
        algorithms,
    )?
    .ok_or(SamlError::SignatureVerification {
        reason: SignatureVerificationReason::XmlSignature,
    })
}

#[cfg(not(crypto))]
fn verify_pinned_metadata_signature(
    xml: &str,
    _trusted_certificates: &[CertificatePem],
    transforms: MetadataSignatureTransforms,
    _algorithms: XmlSignatureProfile,
    limits: XmlLimits,
) -> Result<String, SamlError> {
    let document = dom::parse_document(xml, limits)?;
    let namespaced = protocol_element::parse_saml_with_limits(xml, limits)?;
    ensure_import_signature_shape(&document.root, &namespaced, transforms)?;
    Err(SamlError::Unsupported(
        "signed metadata verification requires a crypto provider feature".into(),
    ))
}
