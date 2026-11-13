use crate::constants::transform_algorithm;
use crate::error::SamlError;
use crate::xml::dom::{self, Node};

/// Transform allowlist for a metadata import that requires a signature.
///
/// [`Self::Profile`] is enveloped signature and exclusive canonicalization.
/// [`Self::AllowOtherCanonicalization`] also accepts inclusive canonicalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MetadataSignatureTransforms {
    /// Enveloped signature and exclusive canonicalization only.
    Profile,
    /// Also accept inclusive canonicalization.
    AllowOtherCanonicalization,
}

/// Reject a signed metadata root whose shape `RequireSignature` does not import.
///
/// An unsigned root is left for the caller. A signed document must contain
/// exactly one signature, and that signature must be a direct child of the root.
///
/// # Errors
///
/// Returns [`SamlError::SignedReferenceMismatch`] when a signature is present
/// and does not have that shape.
pub(super) fn ensure_import_signature_shape(
    xml: &str,
    transforms: MetadataSignatureTransforms,
) -> Result<(), SamlError> {
    let document = dom::parse(xml)?;
    let root = &document.root;
    if !is_metadata_root(root) {
        return Ok(());
    }
    let mut signatures = Vec::new();
    collect_signatures(root, &mut signatures);
    if signatures.is_empty() {
        return Ok(());
    }
    if signatures.len() != 1 {
        return Err(SamlError::SignedReferenceMismatch);
    }
    let signature = signatures[0];
    let direct_signatures: Vec<_> = root.children_named("Signature").collect();
    if direct_signatures.len() != 1 || direct_signatures[0].start != signature.start {
        return Err(SamlError::SignedReferenceMismatch);
    }
    if contains_local_name(signature, "Object") {
        return Err(SamlError::SignedReferenceMismatch);
    }
    let Some(identifier) = root.attr("ID").filter(|identifier| !identifier.is_empty()) else {
        return Err(SamlError::SignedReferenceMismatch);
    };
    let references = signature_references(signature);
    let [reference] = references.as_slice() else {
        return Err(SamlError::SignedReferenceMismatch);
    };
    let expected_uri = format!("#{identifier}");
    if reference.attr("URI") != Some(expected_uri.as_str()) {
        return Err(SamlError::SignedReferenceMismatch);
    }
    let algorithms = transform_algorithms(reference)?;
    if !algorithms.contains(&transform_algorithm::ENVELOPED_SIGNATURE) {
        return Err(SamlError::SignedReferenceMismatch);
    }
    if algorithms
        .iter()
        .any(|algorithm| !allowed_transform(algorithm, transforms))
    {
        return Err(SamlError::SignedReferenceMismatch);
    }
    Ok(())
}

fn is_metadata_root(root: &Node) -> bool {
    matches!(
        root.local_name.as_str(),
        "EntityDescriptor" | "EntitiesDescriptor"
    )
}

fn profile_transform(algorithm: &str) -> bool {
    matches!(
        algorithm,
        transform_algorithm::ENVELOPED_SIGNATURE
            | transform_algorithm::EXC_C14N
            | transform_algorithm::EXC_C14N_WITH_COMMENTS
    )
}

fn allowed_transform(algorithm: &str, transforms: MetadataSignatureTransforms) -> bool {
    if profile_transform(algorithm) {
        return true;
    }
    transforms == MetadataSignatureTransforms::AllowOtherCanonicalization
        && matches!(
            algorithm,
            INCLUSIVE_C14N_10
                | INCLUSIVE_C14N_10_WITH_COMMENTS
                | INCLUSIVE_C14N_11
                | INCLUSIVE_C14N_11_WITH_COMMENTS
        )
}

const INCLUSIVE_C14N_10: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const INCLUSIVE_C14N_10_WITH_COMMENTS: &str =
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
const INCLUSIVE_C14N_11: &str = "http://www.w3.org/2006/12/xml-c14n11";
const INCLUSIVE_C14N_11_WITH_COMMENTS: &str = "http://www.w3.org/2006/12/xml-c14n11#WithComments";

fn collect_signatures<'a>(node: &'a Node, found: &mut Vec<&'a Node>) {
    for child in &node.children {
        if child.local_name == "Signature" {
            found.push(child);
        }
        collect_signatures(child, found);
    }
}

fn signature_references(signature: &Node) -> Vec<&Node> {
    signature
        .children_named("SignedInfo")
        .flat_map(|signed_info| signed_info.children_named("Reference"))
        .collect()
}

fn transform_algorithms(reference: &Node) -> Result<Vec<&str>, SamlError> {
    let mut algorithms = Vec::new();
    for transforms in reference.children_named("Transforms") {
        for transform in transforms.children_named("Transform") {
            match transform.attr("Algorithm") {
                Some(algorithm) if !algorithm.is_empty() => algorithms.push(algorithm),
                _ => return Err(SamlError::SignedReferenceMismatch),
            }
        }
    }
    Ok(algorithms)
}

fn contains_local_name(node: &Node, name: &str) -> bool {
    node.children
        .iter()
        .any(|child| child.local_name == name || contains_local_name(child, name))
}
