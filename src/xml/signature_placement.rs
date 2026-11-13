//! Placement of embedded SAML signatures.

use super::dom::Node;

/// `Signature` children of `root`, then `Signature` children of each
/// `Assertion` child of `root`.
pub(crate) fn saml_signature_candidates(root: &Node) -> Vec<&Node> {
    let mut signatures: Vec<_> = root.children_named("Signature").collect();
    for assertion in root.children_named("Assertion") {
        signatures.extend(assertion.children_named("Signature"));
    }
    signatures
}
