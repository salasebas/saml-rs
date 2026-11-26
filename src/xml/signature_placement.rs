use super::dom::Node;

pub(crate) fn saml_signature_candidates(root: &Node) -> Vec<&Node> {
    let mut signatures: Vec<_> = root.children_named("Signature").collect();
    for assertion in root.children_named("Assertion") {
        signatures.extend(assertion.children_named("Signature"));
    }
    signatures
}
