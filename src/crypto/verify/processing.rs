//! Preflight restrictions and verified-signature profile checks.

use super::{
    allows_digest_method, allows_signature_method, bergshamra_ns, reference_resolution,
    transform_algorithm, verified_target_from_uri, BergshamraDocument, BergshamraNodeId,
    ReferenceResolutionReason, SamlError, XmlSignatureProfile,
};

fn exactly_one_dsig_child(
    document: &BergshamraDocument<'_>,
    parent: BergshamraNodeId,
    local_name: &str,
) -> Option<BergshamraNodeId> {
    let mut children = document
        .child_elements_by_name_ns(parent, bergshamra_ns::DSIG, local_name)
        .into_iter();
    let only = children.next()?;
    children.next().is_none().then_some(only)
}

fn dsig_algorithm<'a>(
    document: &'a BergshamraDocument<'_>,
    node: BergshamraNodeId,
) -> Option<&'a str> {
    document
        .element(node)
        .and_then(|element| element.get_attribute(bergshamra_ns::attr::ALGORITHM))
}

/// Check one verifier-accepted signature against `profile`.
///
/// Callers apply this only to a signature that authenticated the message or
/// metadata document being accepted. An invalid, untrusted, or unrelated
/// signature therefore cannot reject it.
pub(super) fn enforce_profile_on_verified_signature(
    document: &BergshamraDocument<'_>,
    signature_node: BergshamraNodeId,
    profile: XmlSignatureProfile,
) -> Result<(), SamlError> {
    match profile {
        XmlSignatureProfile::StrictRsaSha2 => {
            reject_signature_object(document, signature_node)?;
            enforce_strict_profile_on_verified_signature(document, signature_node)
        }
        XmlSignatureProfile::ExcludeWeakAlgorithms => {
            reject_signature_object(document, signature_node)?;
            enforce_algorithms_on_verified_signature(document, signature_node, profile)
        }
        XmlSignatureProfile::AllowProviderSupportedForCompatibility => Ok(()),
    }
}

fn reject_signature_object(
    document: &BergshamraDocument<'_>,
    signature_node: BergshamraNodeId,
) -> Result<(), SamlError> {
    if document
        .child_elements_by_name_ns(
            signature_node,
            bergshamra_ns::DSIG,
            bergshamra_ns::node::OBJECT,
        )
        .is_empty()
    {
        Ok(())
    } else {
        Err(SamlError::SignedReferenceMismatch)
    }
}

fn enforce_algorithms_on_verified_signature(
    document: &BergshamraDocument<'_>,
    signature_node: BergshamraNodeId,
    profile: XmlSignatureProfile,
) -> Result<(), SamlError> {
    for signed_info in document.child_elements_by_name_ns(
        signature_node,
        bergshamra_ns::DSIG,
        bergshamra_ns::node::SIGNED_INFO,
    ) {
        for method in document.child_elements_by_name_ns(
            signed_info,
            bergshamra_ns::DSIG,
            bergshamra_ns::node::SIGNATURE_METHOD,
        ) {
            if !dsig_algorithm(document, method)
                .is_some_and(|algorithm| allows_signature_method(profile, algorithm))
            {
                return Err(SamlError::AlgorithmUnsupported);
            }
        }
        for reference in document.child_elements_by_name_ns(
            signed_info,
            bergshamra_ns::DSIG,
            bergshamra_ns::node::REFERENCE,
        ) {
            for digest in document.child_elements_by_name_ns(
                reference,
                bergshamra_ns::DSIG,
                bergshamra_ns::node::DIGEST_METHOD,
            ) {
                if !dsig_algorithm(document, digest)
                    .is_some_and(|algorithm| allows_digest_method(profile, algorithm))
                {
                    return Err(SamlError::AlgorithmUnsupported);
                }
            }
        }
    }
    Ok(())
}

pub(super) fn enforce_strict_profile_on_verified_signature(
    document: &BergshamraDocument<'_>,
    signature_node: BergshamraNodeId,
) -> Result<(), SamlError> {
    let signed_info =
        exactly_one_dsig_child(document, signature_node, bergshamra_ns::node::SIGNED_INFO)
            .ok_or(SamlError::SignedReferenceMismatch)?;
    let canonicalization = exactly_one_dsig_child(
        document,
        signed_info,
        bergshamra_ns::node::CANONICALIZATION_METHOD,
    )
    .ok_or(SamlError::AlgorithmUnsupported)?;
    if dsig_algorithm(document, canonicalization) != Some(transform_algorithm::EXC_C14N) {
        return Err(SamlError::AlgorithmUnsupported);
    }
    let signature_method =
        exactly_one_dsig_child(document, signed_info, bergshamra_ns::node::SIGNATURE_METHOD)
            .ok_or(SamlError::AlgorithmUnsupported)?;
    if !dsig_algorithm(document, signature_method).is_some_and(|algorithm| {
        allows_signature_method(XmlSignatureProfile::StrictRsaSha2, algorithm)
    }) {
        return Err(SamlError::AlgorithmUnsupported);
    }
    let reference = exactly_one_dsig_child(document, signed_info, bergshamra_ns::node::REFERENCE)
        .ok_or(SamlError::SignedReferenceMismatch)?;
    let Some(uri) = document
        .element(reference)
        .and_then(|element| element.get_attribute(bergshamra_ns::attr::URI))
    else {
        return Err(reference_resolution(
            ReferenceResolutionReason::UnsupportedReferenceUri,
        ));
    };
    if !uri.starts_with('#') || uri.len() == 1 || uri.starts_with("#xpointer(") {
        return Err(reference_resolution(
            ReferenceResolutionReason::UnsupportedReferenceUri,
        ));
    }
    verified_target_from_uri(uri)?;

    let digest_method =
        exactly_one_dsig_child(document, reference, bergshamra_ns::node::DIGEST_METHOD)
            .ok_or(SamlError::AlgorithmUnsupported)?;
    if !dsig_algorithm(document, digest_method).is_some_and(|algorithm| {
        allows_digest_method(XmlSignatureProfile::StrictRsaSha2, algorithm)
    }) {
        return Err(SamlError::AlgorithmUnsupported);
    }
    enforce_reference_transforms(document, reference)
}

pub(super) fn enforce_reference_transforms(
    document: &BergshamraDocument<'_>,
    reference: BergshamraNodeId,
) -> Result<(), SamlError> {
    for transforms in document.child_elements_by_name_ns(
        reference,
        bergshamra_ns::DSIG,
        bergshamra_ns::node::TRANSFORMS,
    ) {
        // Bergshamra executes every direct child whose local name is
        // `Transform`, including elements outside the XML-DSig namespace.
        // Reject any element it would execute, and any other element child,
        // unless it is an allowed XML-DSig transform.
        for child in document.children_iter(transforms) {
            let Some(element) = document.element(child) else {
                continue;
            };
            if !element.matches_name_ns(bergshamra_ns::DSIG, bergshamra_ns::node::TRANSFORM)
                || !matches!(
                    element.get_attribute(bergshamra_ns::attr::ALGORITHM),
                    Some(transform_algorithm::ENVELOPED_SIGNATURE | transform_algorithm::EXC_C14N)
                )
            {
                return Err(SamlError::AlgorithmUnsupported);
            }
        }
    }
    Ok(())
}

pub(super) enum SignatureSelection {
    First,
    All,
}

pub(super) fn document_signatures<'a>(
    document: &'a BergshamraDocument<'_>,
) -> impl Iterator<Item = BergshamraNodeId> + 'a {
    document
        .descendants(document.root())
        .into_iter()
        .filter(|node| {
            document.element(*node).is_some_and(|element| {
                element.matches_name_ns(bergshamra_ns::DSIG, bergshamra_ns::node::SIGNATURE)
            })
        })
}

pub(super) fn preflight_signature_processing(
    document: &BergshamraDocument<'_>,
    selection: SignatureSelection,
    profile: XmlSignatureProfile,
) -> Result<(), SamlError> {
    let count = match selection {
        SignatureSelection::First => 1,
        SignatureSelection::All => usize::MAX,
    };
    for signature in document_signatures(document).take(count) {
        for signed_info in document.child_elements_by_name_ns(
            signature,
            bergshamra_ns::DSIG,
            bergshamra_ns::node::SIGNED_INFO,
        ) {
            for reference in document.child_elements_by_name_ns(
                signed_info,
                bergshamra_ns::DSIG,
                bergshamra_ns::node::REFERENCE,
            ) {
                let uri = document
                    .element(reference)
                    .and_then(|element| element.get_attribute(bergshamra_ns::attr::URI))
                    .unwrap_or_default();
                verified_target_from_uri(uri)?;
                if profile == XmlSignatureProfile::StrictRsaSha2 {
                    enforce_reference_transforms(document, reference)?;
                }
            }
        }
    }
    Ok(())
}
