//! Placement of embedded SAML signatures.

use super::dom::Node;

/// `Signature` children of `root`, then `Signature` children of each
/// `Assertion` child of `root`.
pub(crate) fn saml_signature_candidates(root: &Node) -> Vec<&Node> {
    let mut signatures = children_named(root, "Signature");
    for assertion in children_named(root, "Assertion") {
        signatures.extend(children_named(assertion, "Signature"));
    }
    signatures
}

fn children_named<'a>(node: &'a Node, name: &str) -> Vec<&'a Node> {
    node.children
        .iter()
        .filter(|child| child.local_name == name)
        .collect()
}
