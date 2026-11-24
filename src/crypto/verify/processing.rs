use super::{
    allows_digest_method, allows_signature_method, bergshamra_ns, crypto_err, reference_resolution,
    verified_target_from_uri, BergshamraDocument, BergshamraNodeId, DsigContext,
    ReferenceResolutionReason, SamlError, VerifyResult, XmlSignatureProfile,
};
use crate::constants::transform_algorithm;
use bergshamra::c14n::C14nMode;
use bergshamra::core::algorithm;
use bergshamra::dsig::verify::verify_all_document_with_source;

pub(super) fn exactly_one_dsig_child(
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

pub(super) fn verified_authn_request_signature<'a>(
    document: &BergshamraDocument<'_>,
    results: &'a [VerifyResult],
) -> Option<&'a VerifyResult> {
    let signature = exactly_one_dsig_child(
        document,
        document.document_element()?,
        bergshamra_ns::node::SIGNATURE,
    )?;
    results.iter().find(|result| match result {
        VerifyResult::Valid { signature_node, .. } => *signature_node == signature,
        VerifyResult::Invalid { .. } => false,
    })
}

fn dsig_algorithm<'a>(
    document: &'a BergshamraDocument<'_>,
    node: BergshamraNodeId,
) -> Option<&'a str> {
    document
        .element(node)
        .and_then(|element| element.get_attribute(bergshamra_ns::attr::ALGORITHM))
}

pub(super) fn verify_all_signatures(
    context: &DsigContext,
    document: &BergshamraDocument<'_>,
    xml: &str,
    profile: XmlSignatureProfile,
) -> Result<Vec<VerifyResult>, SamlError> {
    preflight_signature_processing(document, SignatureSelection::All, profile)?;
    let mut results =
        verify_all_document_with_source(context, document, Some(xml)).map_err(crypto_err)?;
    for result in &mut results {
        enforce_hmac_truncation_minimum(document, result);
    }
    Ok(results)
}

pub(super) fn enforce_hmac_truncation_minimum(
    document: &BergshamraDocument<'_>,
    result: &mut VerifyResult,
) {
    if let VerifyResult::Valid { signature_node, .. } = result {
        if let Some(reason) = invalid_hmac_truncation(document, *signature_node) {
            *result = VerifyResult::Invalid { reason };
        }
    }
}

fn invalid_hmac_truncation(
    document: &BergshamraDocument<'_>,
    signature: BergshamraNodeId,
) -> Option<String> {
    // Match the first namespaced children and first text or CDATA node read by Bergshamra.
    let signed_info = document.first_child_element_by_name_ns(
        signature,
        bergshamra_ns::DSIG,
        bergshamra_ns::node::SIGNED_INFO,
    )?;
    let method = document.first_child_element_by_name_ns(
        signed_info,
        bergshamra_ns::DSIG,
        bergshamra_ns::node::SIGNATURE_METHOD,
    )?;
    let minimum_bits = match dsig_algorithm(document, method)? {
        algorithm::HMAC_SHA384 => 192,
        algorithm::HMAC_SHA512 => 256,
        _ => return None, // Bergshamra's 160-bit floor covers the other supported HMAC algorithms.
    };
    let length = document.first_child_element_by_name_ns(
        method,
        bergshamra_ns::DSIG,
        bergshamra_ns::node::HMAC_OUTPUT_LENGTH,
    )?;
    match document
        .element_text(length)
        .and_then(|text| text.trim().parse::<usize>().ok())
    {
        Some(bits) if bits >= minimum_bits => None,
        Some(bits) => Some(format!(
            "HMACOutputLength {bits} bits is below minimum {minimum_bits} bits"
        )),
        None => Some("invalid HMACOutputLength value".to_owned()),
    }
}

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
        XmlSignatureProfile::AllowWeakAlgorithms => Ok(()),
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
    enforce_strict_reference_transforms(document, reference)
}

pub(super) fn enforce_message_signature_reference(
    document: &BergshamraDocument<'_>,
    signature: BergshamraNodeId,
    id: &str,
) -> Result<(), SamlError> {
    let signed_info = exactly_one_dsig_child(document, signature, bergshamra_ns::node::SIGNED_INFO)
        .ok_or(SamlError::SignedReferenceMismatch)?;
    let reference = exactly_one_dsig_child(document, signed_info, bergshamra_ns::node::REFERENCE)
        .ok_or(SamlError::SignedReferenceMismatch)?;
    let target = document
        .element(reference)
        .and_then(|element| element.get_attribute(bergshamra_ns::attr::URI))
        .and_then(|uri| uri.strip_prefix('#'));
    if target != Some(id) {
        return Err(SamlError::SignedReferenceMismatch);
    }
    enforce_reference_transforms(document, reference, |algorithm| {
        algorithm == transform_algorithm::ENVELOPED_SIGNATURE
            || C14nMode::from_uri(algorithm).is_some()
    })
}

fn enforce_strict_reference_transforms(
    document: &BergshamraDocument<'_>,
    reference: BergshamraNodeId,
) -> Result<(), SamlError> {
    enforce_reference_transforms(document, reference, |algorithm| {
        matches!(
            algorithm,
            transform_algorithm::ENVELOPED_SIGNATURE | transform_algorithm::EXC_C14N
        )
    })
}

fn enforce_reference_transforms(
    document: &BergshamraDocument<'_>,
    reference: BergshamraNodeId,
    allows_transform: impl Fn(&str) -> bool,
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
                || !element
                    .get_attribute(bergshamra_ns::attr::ALGORITHM)
                    .is_some_and(&allows_transform)
            {
                return Err(SamlError::AlgorithmUnsupported);
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
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
                    enforce_strict_reference_transforms(document, reference)?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bergshamra::core::algorithm::{HMAC_SHA384, HMAC_SHA512};
    use bergshamra::xml::uppsala;

    #[test]
    fn hmac_truncation_uses_the_minimum_for_each_signature_method(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for (method, bits, expected_valid) in [
            (HMAC_SHA384, Some(184), false),
            (HMAC_SHA384, Some(192), true),
            (HMAC_SHA512, Some(248), false),
            (HMAC_SHA512, Some(256), true),
            (HMAC_SHA512, None, true),
        ] {
            let length = bits.map_or_else(String::new, |bits| {
                format!("<ds:HMACOutputLength>{bits}</ds:HMACOutputLength>")
            });
            let xml = format!(
                r#"<ds:Signature xmlns:ds="{dsig}"><ds:SignedInfo><ds:SignatureMethod Algorithm="{method}">{length}</ds:SignatureMethod></ds:SignedInfo></ds:Signature>"#,
                dsig = bergshamra_ns::DSIG,
            );
            let document = uppsala::parse(&xml)?;
            let mut result = VerifyResult::Valid {
                signature_node: document.document_element().ok_or("missing Signature")?,
                references: Vec::new(),
                key_info: bergshamra::VerifiedKeyInfo {
                    algorithm: "HMAC".into(),
                    key_name: None,
                    x509_chain: Vec::new(),
                },
            };
            enforce_hmac_truncation_minimum(&document, &mut result);
            assert_eq!(
                matches!(result, VerifyResult::Valid { .. }),
                expected_valid,
                "{method}, {bits:?}: {result:?}"
            );
        }
        Ok(())
    }
}
