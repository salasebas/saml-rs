use crate::constants::{namespace, transform_algorithm};
use crate::error::SamlError;
use crate::xml::dom::Node;
use crate::xml::protocol_element::SamlElement;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MetadataSignatureTransforms {
    Profile,
    AllowInclusiveCanonicalization,
}

pub(super) fn ensure_import_signature_shape(
    root: &Node,
    namespaced_root: &SamlElement,
    transforms: MetadataSignatureTransforms,
) -> Result<(), SamlError> {
    if !is_metadata_root(root) {
        return Ok(());
    }
    let mut signatures = Vec::new();
    collect_signatures(root, namespaced_root, &mut signatures);
    let [(signature, namespaced_signature)] = signatures.as_slice() else {
        return if signatures.is_empty() {
            Ok(())
        } else {
            Err(SamlError::SignedReferenceMismatch)
        };
    };
    let is_root_child = root
        .children
        .iter()
        .any(|child| child.start == signature.start);
    if !is_root_child || contains_signature_object(namespaced_signature) {
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
    transforms == MetadataSignatureTransforms::AllowInclusiveCanonicalization
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

fn collect_signatures<'a, 'n>(
    node: &'a Node,
    namespaced: &'n SamlElement,
    found: &mut Vec<(&'a Node, &'n SamlElement)>,
) {
    for (child, namespaced_child) in node.children.iter().zip(&namespaced.children) {
        if namespaced_child.is(namespace::DSIG, "Signature") {
            found.push((child, namespaced_child));
        }
        collect_signatures(child, namespaced_child, found);
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

fn contains_signature_object(element: &SamlElement) -> bool {
    element
        .children
        .iter()
        .any(|child| child.is(namespace::DSIG, "Object") || contains_signature_object(child))
}
