use super::dom::Node;
use super::name::is_ncname;
use crate::error::SamlError;

pub(crate) fn signature_reference_path(reference: &str) -> Result<Vec<&str>, SamlError> {
    let invalid_reference = || {
        SamlError::Invalid(
            "SignatureConfig.reference must use /*[local-name(.)='NCName'] steps".into(),
        )
    };
    reference
        .strip_prefix('/')
        .ok_or_else(invalid_reference)?
        .split('/')
        .map(|step| {
            step.strip_prefix("*[local-name(.)='")
                .and_then(|name| name.strip_suffix("']"))
                .filter(|name| is_ncname(name))
                .ok_or_else(invalid_reference)
        })
        .collect()
}

pub(crate) fn saml_signature_candidates(root: &Node) -> Vec<&Node> {
    let mut signatures: Vec<_> = root.children_named("Signature").collect();
    for assertion in root.children_named("Assertion") {
        signatures.extend(assertion.children_named("Signature"));
    }
    signatures
}
