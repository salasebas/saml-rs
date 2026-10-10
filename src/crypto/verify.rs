//! XML-DSig verification and anti-wrapping checks, delegating cryptography to
//! the selected `bergshamra` provider.
//!
//! Security model:
//! - `trusted_keys_only`: the signature is verified against the certificate(s)
//!   declared in IdP metadata, never an attacker-supplied inline cert.
//! - `strict_verification`: bergshamra enforces that each signed reference
//!   targets the document element, an ancestor, or a sibling of the Signature.
//! - Explicit XSW guard: reject any `Assertion`/`Signature` nested under
//!   `SubjectConfirmationData`.
//! - Only content covered by a verified reference is returned for extraction.

use super::keys::load_certificate;
use crate::constants::{namespace, transform_algorithm};
use crate::error::{ReferenceResolutionReason, SamlError, SignatureVerificationReason};
use crate::util::normalize_cert_string;
use crate::xml::dom::{self, Node, XmlLimits};
use bergshamra::core::ns as bergshamra_ns;
use bergshamra::dsig::verify::verify_all_document_with_source;
use bergshamra::xml::{uppsala, Document as BergshamraDocument, NodeId as BergshamraNodeId};
use bergshamra::{verify, DsigContext, KeysManager, VerifiedReference, VerifyResult};
use quick_xml::events::Event;
use quick_xml::name::{Namespace, ResolveResult};
use quick_xml::reader::NsReader;
use std::collections::HashSet;

fn children_named<'a>(node: &'a Node, name: &str) -> Vec<&'a Node> {
    node.children
        .iter()
        .filter(|c| c.local_name == name)
        .collect()
}

fn has_child(node: &Node, name: &str) -> bool {
    node.children.iter().any(|c| c.local_name == name)
}

fn saml_signature_candidates(root: &Node) -> Vec<&Node> {
    let mut signatures = children_named(root, "Signature");
    for assertion in children_named(root, "Assertion") {
        signatures.extend(children_named(assertion, "Signature"));
    }
    signatures
}

fn has_descendant(node: &Node, names: &[&str]) -> bool {
    node.children
        .iter()
        .any(|c| names.contains(&c.local_name.as_str()) || has_descendant(c, names))
}

/// XSW guard: `Response/Assertion/Subject/SubjectConfirmation/SubjectConfirmationData//(Assertion|Signature)`.
fn wrapping_detected(root: &Node) -> bool {
    for assertion in children_named(root, "Assertion") {
        for subject in children_named(assertion, "Subject") {
            for sc in children_named(subject, "SubjectConfirmation") {
                for scd in children_named(sc, "SubjectConfirmationData") {
                    if has_descendant(scd, &["Assertion", "Signature"]) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn saml_id_attr(name: &str) -> bool {
    matches!(name, "ID" | "AssertionID")
}

fn duplicate_saml_id(node: &Node, seen: &mut HashSet<String>) -> Option<String> {
    for (name, value) in &node.attrs {
        if saml_id_attr(name) && !value.is_empty() && !seen.insert(value.clone()) {
            return Some(value.clone());
        }
    }
    node.children
        .iter()
        .find_map(|child| duplicate_saml_id(child, seen))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VerifiedTarget {
    WholeDocument,
    Id(String),
}

fn reference_resolution(reason: ReferenceResolutionReason) -> SamlError {
    SamlError::ReferenceResolution { reason }
}

fn verified_target_from_uri(uri: &str) -> Result<VerifiedTarget, SamlError> {
    if uri.is_empty() || uri == "#xpointer(/)" {
        return Ok(VerifiedTarget::WholeDocument);
    }

    let fragment = uri
        .strip_prefix('#')
        .ok_or_else(|| reference_resolution(ReferenceResolutionReason::ExternalReference))?;
    if fragment.is_empty() {
        return Err(reference_resolution(
            ReferenceResolutionReason::UnsupportedReferenceUri,
        ));
    }
    if let Some(id) = fragment
        .strip_prefix("xpointer(id('")
        .and_then(|rest| rest.strip_suffix("'))"))
    {
        if id.is_empty() {
            return Err(reference_resolution(
                ReferenceResolutionReason::UnsupportedReferenceUri,
            ));
        }
        return Ok(VerifiedTarget::Id(id.to_string()));
    }
    if fragment.starts_with("xpointer(") {
        return Err(reference_resolution(
            ReferenceResolutionReason::UnsupportedReferenceUri,
        ));
    }
    Ok(VerifiedTarget::Id(fragment.to_string()))
}

fn verified_targets(references: &[VerifiedReference]) -> Result<Vec<VerifiedTarget>, SamlError> {
    if references.is_empty() {
        return Err(reference_resolution(
            ReferenceResolutionReason::MissingSignatureReference,
        ));
    }

    let mut targets = Vec::with_capacity(references.len());
    for reference in references {
        if is_external_reference(&reference.uri) {
            return Err(reference_resolution(
                ReferenceResolutionReason::ExternalReference,
            ));
        }
        if !reference.digest_verified {
            return Err(SamlError::SignatureVerification {
                reason: SignatureVerificationReason::ReferenceDigest,
            });
        }
        let target = verified_target_from_uri(&reference.uri)?;
        if matches!(target, VerifiedTarget::Id(_)) && reference.resolved_node.is_none() {
            return Err(reference_resolution(
                ReferenceResolutionReason::UnresolvedReference,
            ));
        }
        targets.push(target);
    }
    Ok(targets)
}

fn node_saml_id(node: &Node) -> Option<&str> {
    node.attr("ID").or_else(|| node.attr("AssertionID"))
}

fn target_matches_node(targets: &[VerifiedTarget], node: &Node) -> bool {
    targets.iter().any(|target| match target {
        VerifiedTarget::WholeDocument => true,
        VerifiedTarget::Id(id) => node_saml_id(node).is_some_and(|node_id| node_id == id),
    })
}

fn id_target_matches_node(targets: &[VerifiedTarget], node: &Node) -> bool {
    targets.iter().any(|target| match target {
        VerifiedTarget::WholeDocument => false,
        VerifiedTarget::Id(id) => node_saml_id(node).is_some_and(|node_id| node_id == id),
    })
}

fn response_is_covered(targets: &[VerifiedTarget], root: &Node) -> bool {
    target_matches_node(targets, root)
}

fn verified_content_not_covered() -> SamlError {
    SamlError::SignedReferenceMismatch
}

const XML_C14N_10: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const XML_C14N_10_WITH_COMMENTS: &str =
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
const XML_C14N_11: &str = "http://www.w3.org/2006/12/xml-c14n11";
const XML_C14N_11_WITH_COMMENTS: &str = "http://www.w3.org/2006/12/xml-c14n11#WithComments";

fn metadata_signature_transform_allowed(algorithm: &str) -> bool {
    matches!(
        algorithm,
        transform_algorithm::ENVELOPED_SIGNATURE
            | transform_algorithm::EXC_C14N
            | transform_algorithm::EXC_C14N_WITH_COMMENTS
            | XML_C14N_10
            | XML_C14N_10_WITH_COMMENTS
            | XML_C14N_11
            | XML_C14N_11_WITH_COMMENTS
    )
}

fn ensure_metadata_reference_transforms_preserve_descriptor(
    reference: &Node,
) -> Result<(), SamlError> {
    for transforms in children_named(reference, "Transforms") {
        for transform in children_named(transforms, "Transform") {
            if transform
                .attr("Algorithm")
                .is_some_and(metadata_signature_transform_allowed)
            {
                continue;
            }
            return Err(verified_content_not_covered());
        }
    }
    Ok(())
}

fn ensure_metadata_signature_transforms_preserve_descriptor(root: &Node) -> Result<(), SamlError> {
    if !matches!(
        root.local_name.as_str(),
        "EntityDescriptor" | "EntitiesDescriptor"
    ) {
        return Ok(());
    }

    for signature in children_named(root, "Signature") {
        for signed_info in children_named(signature, "SignedInfo") {
            for reference in children_named(signed_info, "Reference") {
                ensure_metadata_reference_transforms_preserve_descriptor(reference)?;
            }
        }
    }
    Ok(())
}

fn verified_root_content(
    root: &Node,
    xml: &str,
    targets: &[VerifiedTarget],
) -> Result<String, SamlError> {
    if target_matches_node(targets, root) {
        return Ok(xml[root.start..root.end].to_string());
    }
    Err(verified_content_not_covered())
}

/// The response signature covers every assertion, or every assertion is signed.
/// An unsigned sibling is rejected.
fn assertion_has_bearer_confirmation(assertion: &Node) -> bool {
    const BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
    assertion
        .children
        .iter()
        .filter(|child| child.local_name == "Subject")
        .flat_map(|subject| subject.children.iter())
        .filter(|child| child.local_name == "SubjectConfirmation")
        .any(|confirmation| confirmation.attr("Method") == Some(BEARER))
}

fn response_assertions_covered(root: &Node, targets: &[VerifiedTarget]) -> bool {
    let assertions = children_named(root, "Assertion");
    !assertions.is_empty()
        && (response_is_covered(targets, root)
            || assertions
                .iter()
                .all(|assertion| id_target_matches_node(targets, assertion)))
}

/// Protocol-namespace local names that use response coverage and wrapping checks.
fn is_protocol_response_name(local_name: &str) -> bool {
    matches!(
        local_name,
        "Response"
            | "ArtifactResponse"
            | "LogoutResponse"
            | "ManageNameIDResponse"
            | "NameIDMappingResponse"
    )
}

fn document_element_name(xml: &str) -> Result<(String, String), SamlError> {
    let mut reader = NsReader::from_str(xml);
    let mut buffer = Vec::new();
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(element) | Event::Empty(element)) => {
                let (resolved, local_name) = reader.resolver().resolve_element(element.name());
                let local_name = local_name.as_ref().to_string();
                let resolved = match resolved {
                    ResolveResult::Bound(Namespace(uri)) => uri.to_string(),
                    ResolveResult::Unbound | ResolveResult::Unknown(_) => String::new(),
                };
                return Ok((resolved, local_name));
            }
            Ok(Event::Eof) => {
                return Err(SamlError::Xml("no document element".into()));
            }
            Ok(_) => {}
            Err(error) => return Err(SamlError::Xml(error.to_string())),
        }
        buffer.clear();
    }
}

fn root_uses_protocol_response_rules(xml: &str) -> Result<bool, SamlError> {
    let (element_namespace, local_name) = document_element_name(xml)?;
    Ok(element_namespace == namespace::PROTOCOL && is_protocol_response_name(&local_name))
}

/// Return the source of the content covered by a verified reference: the first
/// bearer `<Assertion>`, a consumed root element, or the whole protocol
/// response when assertions are encrypted.
fn verified_content(
    root: &Node,
    xml: &str,
    targets: &[VerifiedTarget],
    protocol_response: bool,
) -> Result<Option<String>, SamlError> {
    if root.local_name == "Assertion" {
        return verified_root_content(root, xml, targets).map(Some);
    }
    if protocol_response {
        let assertions = children_named(root, "Assertion");
        if !assertions.is_empty() {
            if !response_assertions_covered(root, targets) {
                if assertions.len() > 1 {
                    return Err(SamlError::PotentialWrappingAttack);
                }
                return Err(verified_content_not_covered());
            }
            let chosen = assertions
                .iter()
                .find(|assertion| assertion_has_bearer_confirmation(assertion))
                .copied()
                .unwrap_or(assertions[0]);
            return Ok(Some(xml[chosen.start..chosen.end].to_string()));
        }
        if has_child(root, "EncryptedAssertion") {
            if response_is_covered(targets, root) {
                return Ok(Some(xml[root.start..root.end].to_string()));
            }
            return Err(verified_content_not_covered());
        }
    }
    if matches!(
        root.local_name.as_str(),
        "EntityDescriptor" | "EntitiesDescriptor"
    ) {
        if target_matches_node(targets, root) {
            return Ok(Some(xml[root.start..root.end].to_string()));
        }
        return Err(verified_content_not_covered());
    }
    if matches!(
        root.local_name.as_str(),
        "AuthnRequest" | "LogoutRequest" | "LogoutResponse"
    ) {
        return verified_root_content(root, xml, targets).map(Some);
    }
    Ok(None)
}

/// Whether `targets` satisfy the same coverage [`verified_content`] accepts.
///
/// This is the strict-profile gate for signatures that authenticate a message
/// without becoming SSO evidence, including `LogoutRequest` and
/// `LogoutResponse`. Keep the branches aligned with [`verified_content`].
fn verified_targets_cover_accepted_content(
    root: &Node,
    targets: &[VerifiedTarget],
    protocol_response: bool,
) -> bool {
    if root.local_name == "Assertion" {
        return target_matches_node(targets, root);
    }
    if protocol_response {
        let assertions = children_named(root, "Assertion");
        if !assertions.is_empty() {
            return response_assertions_covered(root, targets);
        }
        if has_child(root, "EncryptedAssertion") {
            return response_is_covered(targets, root);
        }
    }
    if matches!(
        root.local_name.as_str(),
        "EntityDescriptor" | "EntitiesDescriptor"
    ) {
        return target_matches_node(targets, root);
    }
    if matches!(
        root.local_name.as_str(),
        "AuthnRequest" | "LogoutRequest" | "LogoutResponse"
    ) {
        return target_matches_node(targets, root);
    }
    false
}

fn assertion_is_directly_covered(
    root: &Node,
    targets: &[VerifiedTarget],
    protocol_response: bool,
) -> bool {
    if root.local_name == "Assertion" {
        return target_matches_node(targets, root);
    }
    if protocol_response {
        let assertions = children_named(root, "Assertion");
        return !assertions.is_empty()
            && assertions
                .iter()
                .all(|assertion| id_target_matches_node(targets, assertion));
    }
    false
}

fn references_cover_direct_assertion(
    document: &BergshamraDocument<'_>,
    references: &[VerifiedReference],
) -> bool {
    let Some(root) = document.document_element() else {
        return false;
    };
    let Some(root_element) = document.element(root) else {
        return false;
    };
    if root_element.matches_name_ns(crate::constants::namespace::ASSERTION, "Assertion") {
        return reference_covers_node(references, root);
    }
    root_element.matches_name_ns(crate::constants::namespace::PROTOCOL, "Response")
        && document.children_iter(root).any(|child| {
            document.element(child).is_some_and(|element| {
                element.matches_name_ns(crate::constants::namespace::ASSERTION, "Assertion")
                    && reference_covers_node(references, child)
            })
        })
}

fn bergshamra_child_element(
    document: &BergshamraDocument<'_>,
    parent: BergshamraNodeId,
    namespace: &str,
    local_name: &str,
) -> Option<BergshamraNodeId> {
    document.children_iter(parent).find(|child| {
        document
            .element(*child)
            .is_some_and(|element| element.matches_name_ns(namespace, local_name))
    })
}

fn verified_signature_algorithm(
    document: &BergshamraDocument<'_>,
    signature_node: BergshamraNodeId,
) -> Result<String, SamlError> {
    let signed_info = bergshamra_child_element(
        document,
        signature_node,
        bergshamra_ns::DSIG,
        bergshamra_ns::node::SIGNED_INFO,
    )
    .ok_or_else(|| SamlError::Crypto("verified signature is missing SignedInfo".into()))?;
    let signature_method = bergshamra_child_element(
        document,
        signed_info,
        bergshamra_ns::DSIG,
        bergshamra_ns::node::SIGNATURE_METHOD,
    )
    .ok_or_else(|| SamlError::Crypto("verified signature is missing SignatureMethod".into()))?;
    document
        .element(signature_method)
        .and_then(|element| element.get_attribute(bergshamra_ns::attr::ALGORITHM))
        .filter(|algorithm| !algorithm.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            SamlError::Crypto("verified signature is missing SignatureMethod Algorithm".into())
        })
}

fn reference_covers_node(references: &[VerifiedReference], node: BergshamraNodeId) -> bool {
    references
        .iter()
        .any(|reference| reference.resolved_node == Some(node))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedEmbeddedSignature {
    algorithm_uri: String,
    assertion_directly_covered: bool,
    response_covered: bool,
}

impl VerifiedEmbeddedSignature {
    pub(crate) fn algorithm_uri(&self) -> &str {
        &self.algorithm_uri
    }

    pub(crate) fn assertion_directly_covered(&self) -> bool {
        self.assertion_directly_covered
    }

    pub(crate) fn response_covered(&self) -> bool {
        self.response_covered
    }
}

fn verified_embedded_signature(
    document: &BergshamraDocument<'_>,
    signature_node: BergshamraNodeId,
    references: &[VerifiedReference],
    targets: &[VerifiedTarget],
) -> Result<Option<VerifiedEmbeddedSignature>, SamlError> {
    let Some(root) = document.document_element() else {
        return Ok(None);
    };
    let root_element = document
        .element(root)
        .ok_or_else(|| SamlError::Crypto("verified document root is not an element".into()))?;
    let whole_document_covered = targets
        .iter()
        .any(|target| matches!(target, VerifiedTarget::WholeDocument));

    let response_covered = root_element
        .matches_name_ns(crate::constants::namespace::PROTOCOL, "Response")
        && (whole_document_covered || reference_covers_node(references, root));
    let assertion_node =
        if root_element.matches_name_ns(crate::constants::namespace::ASSERTION, "Assertion") {
            Some(root)
        } else if root_element.matches_name_ns(crate::constants::namespace::PROTOCOL, "Response") {
            bergshamra_child_element(
                document,
                root,
                crate::constants::namespace::ASSERTION,
                "Assertion",
            )
        } else {
            None
        };
    let assertion_directly_covered = assertion_node.is_some_and(|assertion| {
        reference_covers_node(references, assertion)
            || (assertion == root && whole_document_covered)
    });

    if !response_covered && !assertion_directly_covered {
        return Ok(None);
    }
    Ok(Some(VerifiedEmbeddedSignature {
        algorithm_uri: verified_signature_algorithm(document, signature_node)?,
        assertion_directly_covered,
        response_covered,
    }))
}

/// True for a signed `<Reference>` URI that is not same-document (i.e. not a
/// `#id` fragment or the whole document). Such references can pull external or
/// local-file content into the verified set and are rejected for SAML.
fn is_external_reference(uri: &str) -> bool {
    !uri.is_empty() && !uri.starts_with('#')
}

fn has_saml_xml_signature(root: &Node) -> bool {
    !saml_signature_candidates(root).is_empty()
}

fn preflight_saml_reference_uris(signatures: &[&Node]) -> Result<(), SamlError> {
    for signature in signatures {
        for signed_info in children_named(signature, "SignedInfo") {
            for reference in children_named(signed_info, "Reference") {
                verified_target_from_uri(reference.attr("URI").unwrap_or_default())?;
            }
        }
    }
    Ok(())
}

fn dsig_children(
    document: &BergshamraDocument<'_>,
    parent: BergshamraNodeId,
    local_name: &str,
) -> Vec<BergshamraNodeId> {
    document
        .children_iter(parent)
        .filter(|child| {
            document
                .element(*child)
                .is_some_and(|element| element.matches_name_ns(bergshamra_ns::DSIG, local_name))
        })
        .collect()
}

fn exactly_one_dsig_child(
    document: &BergshamraDocument<'_>,
    parent: BergshamraNodeId,
    local_name: &str,
) -> Option<BergshamraNodeId> {
    let mut children = dsig_children(document, parent, local_name).into_iter();
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

/// Check one verifier-accepted signature against the strict RSA-SHA2 profile.
///
/// Callers apply this only to a signature that authenticated the message being
/// accepted. An invalid, untrusted, or unrelated signature therefore cannot
/// reject the message.
fn enforce_strict_profile_on_verified_signature(
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
    if !matches!(
        dsig_algorithm(document, signature_method),
        Some(
            crate::constants::signature_algorithm::RSA_SHA256
                | crate::constants::signature_algorithm::RSA_SHA384
                | crate::constants::signature_algorithm::RSA_SHA512
        )
    ) {
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
    if !matches!(
        dsig_algorithm(document, digest_method),
        Some(
            crate::constants::digest_algorithm::SHA256
                | crate::constants::digest_algorithm::SHA384
                | crate::constants::digest_algorithm::SHA512
        )
    ) {
        return Err(SamlError::AlgorithmUnsupported);
    }
    for transforms in dsig_children(document, reference, bergshamra_ns::node::TRANSFORMS) {
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

pub(crate) fn has_xml_signature_with_limits(
    xml: &str,
    limits: XmlLimits,
) -> Result<bool, SamlError> {
    let doc = dom::parse_with_limits(xml, limits)?;
    Ok(has_saml_xml_signature(&doc.root))
}

/// First `<X509Certificate>` text found inside a candidate `<Signature>` (the
/// cert the sender embedded in the message), if any.
fn inline_signature_cert(signatures: &[&Node]) -> Option<String> {
    fn descendant_cert(node: &Node) -> Option<String> {
        if node.local_name == "X509Certificate" && !node.text.is_empty() {
            return Some(node.text.clone());
        }
        node.children.iter().find_map(descendant_cert)
    }

    signatures
        .iter()
        .find_map(|signature| descendant_cert(signature))
}

/// Verify the XML-DSig signature(s) of `xml` against `metadata_certs`.
///
/// Returns `(verified, signed_content)`:
/// - `(false, None)` when there is no signature or it does not verify;
/// - `(true, Some(xml))` with the signed assertion/response on success;
/// - `Err(PotentialWrappingAttack)` on a detected XSW attempt.
///
/// # Errors
///
/// Returns [`SamlError`] when XML parsing, trust checks, reference resolution,
/// cryptographic verification, or signed-content coverage checks fail.
pub fn verify_signature(
    xml: &str,
    metadata_certs: &[String],
) -> Result<(bool, Option<String>), SamlError> {
    verify_signature_with_limits(xml, metadata_certs, XmlLimits::default())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignatureVerification {
    verified: bool,
    signed_content: Option<String>,
    assertion_directly_covered: bool,
    response_covered: bool,
    verified_embedded_signatures: Vec<VerifiedEmbeddedSignature>,
}

impl SignatureVerification {
    fn unverified() -> Self {
        Self {
            verified: false,
            signed_content: None,
            assertion_directly_covered: false,
            response_covered: false,
            verified_embedded_signatures: Vec::new(),
        }
    }

    pub(crate) fn verified(&self) -> bool {
        self.verified
    }

    pub(crate) fn assertion_directly_covered(&self) -> bool {
        self.assertion_directly_covered
    }

    pub(crate) fn response_covered(&self) -> bool {
        self.response_covered
    }

    pub(crate) fn verified_embedded_signatures(&self) -> &[VerifiedEmbeddedSignature] {
        &self.verified_embedded_signatures
    }

    pub(crate) fn into_signed_content(self) -> Option<String> {
        self.signed_content
    }
}

enum CertificateVerification {
    /// Stop at the first signature reported by bergshamra `verify`.
    SingleSignature,
    /// Verify every signature with `verify_all_document_with_source`.
    AllDocumentSignatures { strict_xml_signature_profile: bool },
}

enum PreparedCertificateVerification<'a> {
    SingleSignature,
    AllDocumentSignatures {
        strict_xml_signature_profile: bool,
        document: Box<BergshamraDocument<'a>>,
    },
}

fn metadata_verification_context(certificate: &str) -> Result<DsigContext, SamlError> {
    let key = load_certificate(certificate)?;
    let mut manager = KeysManager::new();
    manager.add_key(key);
    // Metadata certificates are the only verification keys. Inline KeyInfo
    // is not imported. `with_insecure(true)` skips X.509 chain and time
    // checks only; signature, digest, reference, duplicate-ID, and XSW
    // checks stay on. Do not replace this with `DsigContext::new_permissive()`.
    Ok(DsigContext::new(manager)
        .with_trusted_keys_only(true)
        .with_strict_verification(true)
        .with_require_reference_digests(true)
        .with_hmac_min_out_len(160)
        .with_insecure(true))
}

fn reject_duplicate_saml_ids(root: &Node) -> Result<(), SamlError> {
    let mut seen_ids = HashSet::new();
    if duplicate_saml_id(root, &mut seen_ids).is_some() {
        return Err(SamlError::PotentialWrappingAttack);
    }
    Ok(())
}

fn reject_unpinned_inline_certificate(
    signatures: &[&Node],
    metadata_certs: &[String],
) -> Result<(), SamlError> {
    // If the message embeds a certificate, it must be one declared in metadata
    // (rolling-cert safety). Verification itself still uses only the metadata
    // certs.
    let Some(inline) = inline_signature_cert(signatures) else {
        return Ok(());
    };
    let inline = normalize_cert_string(&inline);
    if !metadata_certs.is_empty()
        && !metadata_certs
            .iter()
            .any(|certificate| normalize_cert_string(certificate) == inline)
    {
        return Err(SamlError::CertificateMismatch);
    }
    Ok(())
}

fn signature_verification_or_certificate_error(
    tried_invalid: bool,
    last_error: Option<SamlError>,
) -> Result<SignatureVerification, SamlError> {
    // A leftover unloadable cert must not poison a rolling-cert verdict.
    // A clean "invalid" (key mismatch / tampered) is a non-error false; only
    // surface a structural error when no loaded certificate produced a verdict.
    match last_error {
        Some(error) if !tried_invalid => Err(error),
        _ => Ok(SignatureVerification::unverified()),
    }
}

/// Run the wrapping, duplicate-ID, inline-certificate, and metadata-certificate
/// checks shared by [`verify_signature_with_limits`] and
/// [`verify_signatures_detailed_with_profile`].
///
/// `SingleSignature` calls bergshamra `verify` and returns the first valid
/// signature. `AllDocumentSignatures` calls `verify_all_document_with_source`
/// and keeps every verified signature.
fn verify_with_metadata_certificates(
    xml: &str,
    metadata_certs: &[String],
    limits: XmlLimits,
    mode: CertificateVerification,
) -> Result<SignatureVerification, SamlError> {
    let doc = dom::parse_with_limits(xml, limits)?;
    let root = &doc.root;
    let protocol_response = root_uses_protocol_response_rules(xml)?;
    if protocol_response && wrapping_detected(root) {
        return Err(SamlError::PotentialWrappingAttack);
    }
    reject_duplicate_saml_ids(root)?;

    // Candidate signatures: message-level (root > Signature) or assertion-level.
    let signature_candidates = saml_signature_candidates(root);
    if signature_candidates.is_empty() {
        return Ok(SignatureVerification::unverified());
    }
    preflight_saml_reference_uris(&signature_candidates)?;
    reject_unpinned_inline_certificate(&signature_candidates, metadata_certs)?;
    super::provider::ensure_crypto_provider_initialized()?;

    let checks_every_signature =
        matches!(&mode, CertificateVerification::AllDocumentSignatures { .. });
    let prepared = match mode {
        CertificateVerification::SingleSignature => {
            PreparedCertificateVerification::SingleSignature
        }
        CertificateVerification::AllDocumentSignatures {
            strict_xml_signature_profile,
        } => {
            // Reuse this exact verifier DOM for every pinned certificate attempt
            // and for evidence extraction from each successful signature node.
            let document = Box::new(
                uppsala::parse(xml).map_err(|error| SamlError::Crypto(error.to_string()))?,
            );
            PreparedCertificateVerification::AllDocumentSignatures {
                strict_xml_signature_profile,
                document,
            }
        }
    };

    let mut have_key = false;
    let mut key_load_error = None;
    let mut tried_invalid = false;
    let mut last_error = None;
    let mut first_signature_verified = false;
    let mut targets = Vec::new();
    let mut verified_signature_nodes = HashSet::new();
    let mut verified_embedded_signatures = Vec::new();

    // Try each metadata certificate individually (rolling-cert support): the
    // signature verifies if any one of the declared keys matches.
    for certificate in metadata_certs {
        let context = match metadata_verification_context(certificate) {
            Ok(context) => context,
            Err(error) => {
                key_load_error.get_or_insert(error);
                continue;
            }
        };
        have_key = true;
        match &prepared {
            PreparedCertificateVerification::SingleSignature => match verify(&context, xml) {
                Ok(VerifyResult::Valid { references, .. }) => {
                    let verified_references = verified_targets(&references)?;
                    return Ok(SignatureVerification {
                        verified: true,
                        signed_content: verified_content(
                            root,
                            xml,
                            &verified_references,
                            protocol_response,
                        )?,
                        assertion_directly_covered: assertion_is_directly_covered(
                            root,
                            &verified_references,
                            protocol_response,
                        ),
                        response_covered: protocol_response
                            && response_is_covered(&verified_references, root),
                        verified_embedded_signatures: Vec::new(),
                    });
                }
                Ok(VerifyResult::Invalid { .. }) => tried_invalid = true,
                Err(error) => last_error = Some(SamlError::Crypto(error.to_string())),
            },
            PreparedCertificateVerification::AllDocumentSignatures {
                strict_xml_signature_profile,
                document,
            } => {
                let strict_xml_signature_profile = *strict_xml_signature_profile;
                match verify_all_document_with_source(&context, document, Some(xml)) {
                    Ok(results) => {
                        first_signature_verified |=
                            matches!(results.first(), Some(VerifyResult::Valid { .. }));
                        for result in results {
                            match result {
                                VerifyResult::Valid {
                                    signature_node,
                                    references,
                                    ..
                                } => {
                                    let signature_targets = verified_targets(&references)?;
                                    if verified_signature_nodes.insert(signature_node) {
                                        let signature = verified_embedded_signature(
                                            document,
                                            signature_node,
                                            &references,
                                            &signature_targets,
                                        )?;
                                        // SSO evidence does not include LogoutRequest or
                                        // LogoutResponse coverage. A protocol Response can
                                        // also be evidence when `verified_content` returns
                                        // no XML. Enforce the profile for either case.
                                        if strict_xml_signature_profile
                                            && (signature.is_some()
                                                || references_cover_direct_assertion(
                                                    document,
                                                    &references,
                                                )
                                                || verified_targets_cover_accepted_content(
                                                    root,
                                                    &signature_targets,
                                                    protocol_response,
                                                ))
                                        {
                                            enforce_strict_profile_on_verified_signature(
                                                document,
                                                signature_node,
                                            )?;
                                        }
                                        if let Some(signature) = signature {
                                            verified_embedded_signatures
                                                .push((signature_node.index(), signature));
                                        }
                                    }
                                    targets.extend(signature_targets);
                                }
                                VerifyResult::Invalid { .. } => tried_invalid = true,
                            }
                        }
                    }
                    Err(error) => last_error = Some(SamlError::Crypto(error.to_string())),
                }
            }
        }
    }

    if !have_key {
        return Err(key_load_error.unwrap_or(SamlError::NoTrustedCertificate));
    }
    if checks_every_signature && first_signature_verified && !targets.is_empty() {
        verified_embedded_signatures.sort_by_key(|(index, _)| *index);
        return Ok(SignatureVerification {
            verified: true,
            signed_content: verified_content(root, xml, &targets, protocol_response)?,
            assertion_directly_covered: assertion_is_directly_covered(
                root,
                &targets,
                protocol_response,
            ),
            response_covered: protocol_response && response_is_covered(&targets, root),
            verified_embedded_signatures: verified_embedded_signatures
                .into_iter()
                .map(|(_, signature)| signature)
                .collect(),
        });
    }
    signature_verification_or_certificate_error(tried_invalid, last_error)
}

/// Verify the XML-DSig signature(s) of `xml` with explicit XML parser limits.
///
/// # Errors
///
/// Returns [`SamlError`] when XML parsing, trust checks, reference resolution,
/// cryptographic verification, or signed-content coverage checks fail.
pub fn verify_signature_with_limits(
    xml: &str,
    metadata_certs: &[String],
    limits: XmlLimits,
) -> Result<(bool, Option<String>), SamlError> {
    let verification = verify_with_metadata_certificates(
        xml,
        metadata_certs,
        limits,
        CertificateVerification::SingleSignature,
    )?;
    let verified = verification.verified();
    Ok((verified, verification.into_signed_content()))
}

pub(crate) fn verify_signatures_detailed_with_profile(
    xml: &str,
    metadata_certs: &[String],
    limits: XmlLimits,
    strict_xml_signature_profile: bool,
) -> Result<SignatureVerification, SamlError> {
    verify_with_metadata_certificates(
        xml,
        metadata_certs,
        limits,
        CertificateVerification::AllDocumentSignatures {
            strict_xml_signature_profile,
        },
    )
}

/// Detailed metadata signature verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSignatureVerification {
    verified: bool,
    signed_entity_descriptor_xml: Option<String>,
}

impl MetadataSignatureVerification {
    pub(crate) fn from_signed_descriptor(signed_entity_descriptor_xml: String) -> Self {
        Self {
            verified: true,
            signed_entity_descriptor_xml: Some(signed_entity_descriptor_xml),
        }
    }

    pub(crate) fn unverified() -> Self {
        Self {
            verified: false,
            signed_entity_descriptor_xml: None,
        }
    }

    /// Whether a metadata signature verified against the pinned certificates.
    pub fn verified(&self) -> bool {
        self.verified
    }

    /// Signed `<EntityDescriptor>` or `<EntitiesDescriptor>` when verification succeeds.
    pub fn signed_entity_descriptor_xml(&self) -> Option<&str> {
        self.signed_entity_descriptor_xml.as_deref()
    }

    pub(crate) fn into_signed_entity_descriptor_xml(self) -> Option<String> {
        self.signed_entity_descriptor_xml
    }
}

/// Verify the enveloped XML-DSig signature on a metadata document against
/// trusted certificate(s); returns whether it is valid and covers the consumed
/// `<EntityDescriptor>` document.
///
/// # Errors
///
/// Returns [`SamlError`] when XML parsing, certificate loading, cryptographic
/// verification, or signed `<EntityDescriptor>` coverage checks fail.
pub fn verify_metadata_signature(
    xml: &str,
    trusted_certificates: &[String],
) -> Result<bool, SamlError> {
    verify_metadata_signature_with_limits(xml, trusted_certificates, XmlLimits::default())
}

/// Verify a metadata XML-DSig signature with explicit XML parser limits.
///
/// # Errors
///
/// Returns [`SamlError`] when XML parsing, certificate loading, cryptographic
/// verification, or signed `<EntityDescriptor>` coverage checks fail.
pub fn verify_metadata_signature_with_limits(
    xml: &str,
    trusted_certificates: &[String],
    limits: XmlLimits,
) -> Result<bool, SamlError> {
    Ok(
        verify_metadata_signature_detailed_with_limits(xml, trusted_certificates, limits)?
            .verified(),
    )
}

/// Verify a metadata XML-DSig signature and preserve signed descriptor coverage
/// using default XML parser limits.
///
/// # Errors
///
/// Returns [`SamlError`] when XML parsing, certificate loading, cryptographic
/// verification, transform policy, or signed `<EntityDescriptor>` coverage
/// checks fail.
pub fn verify_metadata_signature_detailed(
    xml: &str,
    trusted_certificates: &[String],
) -> Result<MetadataSignatureVerification, SamlError> {
    verify_metadata_signature_detailed_with_limits(xml, trusted_certificates, XmlLimits::default())
}

/// Verify a metadata XML-DSig signature and preserve signed descriptor coverage.
///
/// # Errors
///
/// Returns [`SamlError`] when XML parsing, certificate loading, cryptographic
/// verification, transform policy, or signed `<EntityDescriptor>` coverage
/// checks fail.
pub fn verify_metadata_signature_detailed_with_limits(
    xml: &str,
    trusted_certificates: &[String],
    limits: XmlLimits,
) -> Result<MetadataSignatureVerification, SamlError> {
    let doc = dom::parse_with_limits(xml, limits)?;
    ensure_metadata_signature_transforms_preserve_descriptor(&doc.root)?;
    verify_metadata_signature_coverage_with_limits(xml, trusted_certificates, limits)
}

/// Verify metadata signature cryptography and signed-root coverage.
///
/// The caller has already enforced the metadata signature profile.
///
/// # Errors
///
/// Returns [`SamlError`] when XML parsing, certificate loading, cryptographic
/// verification, or signed-root coverage checks fail.
pub(crate) fn verify_metadata_signature_coverage_with_limits(
    xml: &str,
    trusted_certificates: &[String],
    limits: XmlLimits,
) -> Result<MetadataSignatureVerification, SamlError> {
    let (verified, signed_entity_descriptor_xml) =
        verify_signature_with_limits(xml, trusted_certificates, limits)?;
    if !verified {
        return Ok(MetadataSignatureVerification::unverified());
    }
    signed_entity_descriptor_xml
        .map(MetadataSignatureVerification::from_signed_descriptor)
        .ok_or_else(verified_content_not_covered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::signature_algorithm::{RSA_SHA256, RSA_SHA384, RSA_SHA512};
    use crate::constants::{digest_for_signature, namespace, transform_algorithm};
    use crate::crypto::construct_saml_signature;
    use crate::crypto::keys::load_private_key;
    use crate::util::normalize_cert_string;
    use crate::xml::{extract, ExtractorField};
    use bergshamra::sign;

    #[test]
    fn external_reference_detection() {
        assert!(!is_external_reference("")); // whole document
        assert!(!is_external_reference("#_assertion123")); // same-document
        assert!(is_external_reference("https://evil.example.com/x"));
        assert!(is_external_reference("/etc/passwd"));
        assert!(is_external_reference("file:///etc/passwd"));
        assert!(is_external_reference("cid:attachment"));
    }

    #[test]
    fn metadata_signature_transform_allowlist_preserves_canonicalization_interoperability() {
        const XPATH_TRANSFORM: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";
        const XSLT_TRANSFORM: &str = "http://www.w3.org/TR/1999/REC-xslt-19991116";
        const UNKNOWN_TRANSFORM: &str = "urn:example:unknown-transform";

        for algorithm in [
            transform_algorithm::ENVELOPED_SIGNATURE,
            transform_algorithm::EXC_C14N,
            transform_algorithm::EXC_C14N_WITH_COMMENTS,
            XML_C14N_10,
            XML_C14N_10_WITH_COMMENTS,
            XML_C14N_11,
            XML_C14N_11_WITH_COMMENTS,
        ] {
            assert!(
                metadata_signature_transform_allowed(algorithm),
                "{algorithm}"
            );
        }

        for algorithm in [XPATH_TRANSFORM, XSLT_TRANSFORM, UNKNOWN_TRANSFORM] {
            assert!(
                !metadata_signature_transform_allowed(algorithm),
                "{algorithm}"
            );
        }
    }

    #[test]
    fn same_document_reference_target_parsing() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(verified_target_from_uri("")?, VerifiedTarget::WholeDocument);
        assert_eq!(
            verified_target_from_uri("#_assertion123")?,
            VerifiedTarget::Id("_assertion123".to_string())
        );
        assert_eq!(
            verified_target_from_uri("#xpointer(/)")?,
            VerifiedTarget::WholeDocument
        );
        assert_eq!(
            verified_target_from_uri("#xpointer(id('_assertion123'))")?,
            VerifiedTarget::Id("_assertion123".to_string())
        );
        Ok(())
    }

    #[test]
    fn unsupported_reference_target_parsing_fails() {
        assert!(matches!(
            verified_target_from_uri("#"),
            Err(SamlError::ReferenceResolution {
                reason: ReferenceResolutionReason::UnsupportedReferenceUri
            })
        ));
        assert!(matches!(
            verified_target_from_uri("#xpointer(//saml:Assertion)"),
            Err(SamlError::ReferenceResolution {
                reason: ReferenceResolutionReason::UnsupportedReferenceUri
            })
        ));
    }

    fn preflight_signature(
        canonicalization: &str,
        signature: &str,
        digest: &str,
        transform: &str,
        references: usize,
        uri: &str,
    ) -> Result<(), SamlError> {
        let reference = format!(
            "<ds:Reference URI=\"{uri}\"><ds:Transforms><ds:Transform Algorithm=\"{enveloped}\"/><ds:Transform Algorithm=\"{transform}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference>",
            enveloped = transform_algorithm::ENVELOPED_SIGNATURE,
        );
        let xml = format!(
            "<samlp:Response xmlns:samlp=\"{protocol}\" xmlns:ds=\"{dsig}\" ID=\"_response\"><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{canonicalization}\"/><ds:SignatureMethod Algorithm=\"{signature}\"/>{references}</ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature></samlp:Response>",
            protocol = namespace::PROTOCOL,
            dsig = namespace::DSIG,
            references = reference.repeat(references),
        );
        let document =
            uppsala::parse(&xml).map_err(|error| SamlError::Crypto(error.to_string()))?;
        let root = document.document_element().ok_or_else(|| {
            SamlError::Crypto("profile fixture is missing a document element".into())
        })?;
        let signature = bergshamra_child_element(
            &document,
            root,
            bergshamra_ns::DSIG,
            bergshamra_ns::node::SIGNATURE,
        )
        .ok_or(SamlError::SignedReferenceMismatch)?;
        enforce_strict_profile_on_verified_signature(&document, signature)
    }

    #[test]
    fn strict_saml_signature_preflight_accepts_only_the_initial_profile() {
        for (signature, digest) in [
            (RSA_SHA256, crate::constants::digest_algorithm::SHA256),
            (RSA_SHA384, crate::constants::digest_algorithm::SHA384),
            (RSA_SHA512, crate::constants::digest_algorithm::SHA512),
        ] {
            assert!(preflight_signature(
                transform_algorithm::EXC_C14N,
                signature,
                digest,
                transform_algorithm::EXC_C14N,
                1,
                "#_response",
            )
            .is_ok());
        }
    }

    #[test]
    fn strict_saml_signature_preflight_rejects_ambiguous_references_and_algorithms() {
        let accepted = (
            transform_algorithm::EXC_C14N,
            RSA_SHA256,
            crate::constants::digest_algorithm::SHA256,
            transform_algorithm::EXC_C14N,
        );
        for (references, uri) in [(0, "#_response"), (2, "#_response"), (1, "")] {
            assert!(preflight_signature(
                accepted.0, accepted.1, accepted.2, accepted.3, references, uri,
            )
            .is_err());
        }
        for rejected in [
            preflight_signature(
                "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
                accepted.1,
                accepted.2,
                accepted.3,
                1,
                "#_response",
            ),
            preflight_signature(
                accepted.0,
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                accepted.2,
                accepted.3,
                1,
                "#_response",
            ),
            preflight_signature(
                accepted.0,
                accepted.1,
                "http://www.w3.org/2000/09/xmldsig#sha1",
                accepted.3,
                1,
                "#_response",
            ),
            preflight_signature(
                accepted.0,
                accepted.1,
                accepted.2,
                "http://www.w3.org/TR/1999/REC-xslt-19991116",
                1,
                "#_response",
            ),
        ] {
            assert!(matches!(rejected, Err(SamlError::AlgorithmUnsupported)));
        }
    }

    #[test]
    fn advice_assertion_is_not_a_wrapping_shape() -> Result<(), Box<dyn std::error::Error>> {
        let document = dom::parse(&format!(
            "<samlp:Response xmlns:samlp=\"{protocol}\" xmlns:saml=\"{assertion}\"><saml:Assertion ID=\"_outer\"><saml:Advice><saml:Assertion ID=\"_advice\"/></saml:Advice></saml:Assertion></samlp:Response>",
            protocol = namespace::PROTOCOL,
            assertion = namespace::ASSERTION,
        ))?;
        assert!(!wrapping_detected(&document.root));
        Ok(())
    }

    #[test]
    fn subject_confirmation_data_assertion_is_a_wrapping_shape(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let document = dom::parse(&format!(
            "<samlp:Response xmlns:samlp=\"{protocol}\" xmlns:saml=\"{assertion}\"><saml:Assertion ID=\"_outer\"><saml:Subject><saml:SubjectConfirmation><saml:SubjectConfirmationData><saml:Assertion ID=\"_nested\"/></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject></saml:Assertion></samlp:Response>",
            protocol = namespace::PROTOCOL,
            assertion = namespace::ASSERTION,
        ))?;
        assert!(wrapping_detected(&document.root));
        Ok(())
    }

    #[test]
    fn duplicate_saml_id_allows_unique_ids() -> Result<(), Box<dyn std::error::Error>> {
        let doc = dom::parse(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_response"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion"/></samlp:Response>"#,
        )?;
        let mut seen = HashSet::new();
        assert_eq!(duplicate_saml_id(&doc.root, &mut seen), None);
        Ok(())
    }

    #[test]
    fn duplicate_saml_id_returns_repeated_value() -> Result<(), Box<dyn std::error::Error>> {
        let doc = dom::parse(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_same"/><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_same"/></samlp:Response>"#,
        )?;
        let mut seen = HashSet::new();
        assert_eq!(
            duplicate_saml_id(&doc.root, &mut seen),
            Some("_same".to_string())
        );
        Ok(())
    }

    #[test]
    fn duplicate_saml_id_ignores_empty_values() -> Result<(), Box<dyn std::error::Error>> {
        let doc = dom::parse(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID=""><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID=""/></samlp:Response>"#,
        )?;
        let mut seen = HashSet::new();
        assert_eq!(duplicate_saml_id(&doc.root, &mut seen), None);
        Ok(())
    }

    const RESPONSE_SIGNED: &str = include_str!("../../tests/fixtures/response_signed.xml");
    const SIGNED_REQUEST: &str = include_str!("../../tests/fixtures/signed_request_sha256.xml");
    const ATTACK: &str = include_str!("../../tests/fixtures/attack_response_signed.xml");
    const FALSE_SIGNED: &str = include_str!("../../tests/fixtures/false_signed_request_sha256.xml");
    const RESPONSE: &str = include_str!("../../tests/fixtures/response.xml");
    const SP_PRIVKEY: &str = include_str!("../../tests/fixtures/key/sp_privkey.pem");
    // IdP signing cert (matches the response_signed.xml signer / idpmeta).
    const IDP_CERT: &str = include_str!("../../tests/fixtures/key/idp_cert.cer");
    // SP signing cert (matches signed_request_sha256.xml signer).
    const SP_CERT: &str = include_str!("../../tests/fixtures/key/sp_cert.cer");
    const SP_SIGNING_CERT: &str = include_str!("../../tests/fixtures/key/sp_signing_cert.cer");
    const UNTRUSTED_PRIVKEY: &str =
        include_str!("../../tests/fixtures/key/idp/provider_matrix_privkey.pkcs8.pem");
    const UNTRUSTED_CERT: &str = include_str!("../../tests/fixtures/key/idp/cert.cer");

    fn signed_response_with_foreign_extension_certificate(
    ) -> Result<String, Box<dyn std::error::Error>> {
        let response = RESPONSE.replacen(
            "<samlp:Status>",
            r#"<samlp:Extensions><x:Signature xmlns:x="urn:example:extension"><x:X509Certificate>attacker</x:X509Certificate></x:Signature></samlp:Extensions><samlp:Status>"#,
            1,
        );
        let key = load_private_key(SP_PRIVKEY, None)?;
        Ok(construct_saml_signature(
            &response,
            false,
            &key,
            SP_SIGNING_CERT,
            RSA_SHA256,
            &[],
            None,
        )?)
    }

    fn response_with_first_invalid_signature() -> Result<String, Box<dyn std::error::Error>> {
        let cert = normalize_cert_string(IDP_CERT);
        let digest = digest_for_signature(RSA_SHA256).ok_or("unknown digest")?;
        let invalid_signature = format!(
            "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{exc_c14n}\"/><ds:SignatureMethod Algorithm=\"{sig_alg}\"/><ds:Reference URI=\"#_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75\"><ds:Transforms><ds:Transform Algorithm=\"{exc_c14n}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>invalid</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
            dsig = namespace::DSIG,
            exc_c14n = transform_algorithm::EXC_C14N,
            sig_alg = RSA_SHA256,
        );
        Ok(RESPONSE_SIGNED.replacen(
            "<samlp:Status>",
            &format!("{invalid_signature}<samlp:Status>"),
            1,
        ))
    }

    fn signature_over_top_level_issuer(
        key_pem: &str,
        certificate: &str,
        algorithm: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let issuer_id = "_signed_response_issuer";
        let response = RESPONSE.replacen(
            "<saml:Issuer>",
            &format!("<saml:Issuer ID=\"{issuer_id}\">"),
            1,
        );
        let digest = digest_for_signature(algorithm).ok_or("unknown digest")?;
        let signature = format!(
            "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{exc_c14n}\"/><ds:SignatureMethod Algorithm=\"{algorithm}\"/><ds:Reference URI=\"#{issuer_id}\"><ds:Transforms><ds:Transform Algorithm=\"{enveloped}\"/><ds:Transform Algorithm=\"{exc_c14n}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
            dsig = namespace::DSIG,
            exc_c14n = transform_algorithm::EXC_C14N,
            enveloped = transform_algorithm::ENVELOPED_SIGNATURE,
            cert = normalize_cert_string(certificate),
        );
        let template = response.replacen(
            "</saml:Issuer><samlp:Status>",
            &format!("</saml:Issuer>{signature}<samlp:Status>"),
            1,
        );
        let key = load_private_key(key_pem, None)?;
        let mut manager = KeysManager::new();
        manager.add_key(key);
        let context = DsigContext::new(manager).with_insecure(true);
        Ok(sign(&context, &template)?)
    }

    fn signature_over_response_and_assertion() -> Result<String, Box<dyn std::error::Error>> {
        let document = dom::parse(RESPONSE)?;
        let response_id = node_saml_id(&document.root).ok_or("missing Response ID")?;
        let assertion = children_named(&document.root, "Assertion")
            .into_iter()
            .next()
            .ok_or("missing Assertion")?;
        let assertion_id = node_saml_id(assertion).ok_or("missing Assertion ID")?;
        let digest = digest_for_signature(RSA_SHA512).ok_or("unknown digest")?;
        let reference = |id: &str| {
            format!(
                "<ds:Reference URI=\"#{id}\"><ds:Transforms><ds:Transform Algorithm=\"{enveloped}\"/><ds:Transform Algorithm=\"{exc_c14n}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue></ds:DigestValue></ds:Reference>",
                enveloped = transform_algorithm::ENVELOPED_SIGNATURE,
                exc_c14n = transform_algorithm::EXC_C14N,
            )
        };
        let signature = format!(
            "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{exc_c14n}\"/><ds:SignatureMethod Algorithm=\"{algorithm}\"/>{response_reference}{assertion_reference}</ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
            dsig = namespace::DSIG,
            exc_c14n = transform_algorithm::EXC_C14N,
            algorithm = RSA_SHA512,
            response_reference = reference(response_id),
            assertion_reference = reference(assertion_id),
            cert = normalize_cert_string(SP_SIGNING_CERT),
        );
        let template = RESPONSE.replacen(
            "</saml:Issuer><samlp:Status>",
            &format!("</saml:Issuer>{signature}<samlp:Status>"),
            1,
        );
        let key = load_private_key(SP_PRIVKEY, None)?;
        let mut manager = KeysManager::new();
        manager.add_key(key);
        let context = DsigContext::new(manager).with_insecure(true);
        Ok(sign(&context, &template)?)
    }

    fn root_signature(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
        let document = dom::parse(xml)?;
        let signature = children_named(&document.root, "Signature")
            .into_iter()
            .next()
            .ok_or("missing root Signature")?;
        Ok(xml[signature.start..signature.end].to_string())
    }

    fn remove_signature_key_info(signature: &str) -> Result<String, Box<dyn std::error::Error>> {
        let document = dom::parse(signature)?;
        let key_info = children_named(&document.root, "KeyInfo")
            .into_iter()
            .next()
            .ok_or("missing KeyInfo")?;
        Ok(format!(
            "{}{}",
            &signature[..key_info.start],
            &signature[key_info.end..]
        ))
    }

    fn assertion_signed_response_with_extra_signature(
        extra_signature: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let response = RESPONSE.replacen(
            "<saml:Issuer>",
            "<saml:Issuer ID=\"_signed_response_issuer\">",
            1,
        );
        let key = load_private_key(SP_PRIVKEY, None)?;
        let assertion_signed = construct_saml_signature(
            &response,
            false,
            &key,
            SP_SIGNING_CERT,
            RSA_SHA256,
            &[],
            None,
        )?;
        Ok(assertion_signed.replacen(
            "</samlp:Response>",
            &format!("{extra_signature}</samlp:Response>"),
            1,
        ))
    }

    fn sign_template(template: &str) -> Result<String, Box<dyn std::error::Error>> {
        let key = load_private_key(SP_PRIVKEY, None)?;
        let mut manager = KeysManager::new();
        manager.add_key(key);
        let context = DsigContext::new(manager).with_insecure(true);
        Ok(sign(&context, template)?)
    }

    fn response_signed_over_assertion_with_foreign_xpath(
    ) -> Result<String, Box<dyn std::error::Error>> {
        const XPATH_TRANSFORM: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";
        let document = dom::parse(RESPONSE)?;
        let assertion = children_named(&document.root, "Assertion")
            .into_iter()
            .next()
            .ok_or("missing Assertion")?;
        let assertion_id = node_saml_id(assertion).ok_or("missing Assertion ID")?;
        let digest = digest_for_signature(RSA_SHA256).ok_or("unknown digest")?;
        let signature = format!(
            "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{exc}\"/><ds:SignatureMethod Algorithm=\"{algorithm}\"/><ds:Reference URI=\"#{assertion_id}\"><ds:Transforms><ds:Transform Algorithm=\"{enveloped}\"/><Transform xmlns=\"urn:example:other\" Algorithm=\"{xpath}\"><XPath>0</XPath></Transform><ds:Transform Algorithm=\"{exc}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
            dsig = namespace::DSIG,
            exc = transform_algorithm::EXC_C14N,
            algorithm = RSA_SHA256,
            enveloped = transform_algorithm::ENVELOPED_SIGNATURE,
            xpath = XPATH_TRANSFORM,
            digest = digest,
            cert = normalize_cert_string(SP_SIGNING_CERT),
        );
        let template = RESPONSE.replacen(
            "</saml:Issuer><samlp:Status>",
            &format!("</saml:Issuer>{signature}<samlp:Status>"),
            1,
        );
        sign_template(&template)
    }

    fn response_with_issuer_only_signature(
        canonicalization: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let response = RESPONSE.replacen(
            "<saml:Issuer>",
            "<saml:Issuer ID=\"_signed_response_issuer\">",
            1,
        );
        let digest = digest_for_signature(RSA_SHA256).ok_or("unknown digest")?;
        let signature = format!(
            "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{canonicalization}\"/><ds:SignatureMethod Algorithm=\"{algorithm}\"/><ds:Reference URI=\"#_signed_response_issuer\"><ds:Transforms><ds:Transform Algorithm=\"{enveloped}\"/><ds:Transform Algorithm=\"{exc}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
            dsig = namespace::DSIG,
            algorithm = RSA_SHA256,
            enveloped = transform_algorithm::ENVELOPED_SIGNATURE,
            exc = transform_algorithm::EXC_C14N,
            digest = digest,
            cert = normalize_cert_string(SP_SIGNING_CERT),
        );
        let template =
            response.replacen("</saml:Issuer>", &format!("</saml:Issuer>{signature}"), 1);
        sign_template(&template)
    }

    fn cid_reference_response() -> Result<String, Box<dyn std::error::Error>> {
        let cert = normalize_cert_string(SP_SIGNING_CERT);
        let signature = format!(
            "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{exc_c14n}\"/><ds:SignatureMethod Algorithm=\"{sig_alg}\"/><ds:Reference URI=\"cid:attachment-1@example.com\"><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
            dsig = namespace::DSIG,
            exc_c14n = transform_algorithm::EXC_C14N,
            sig_alg = RSA_SHA256,
            digest = digest_for_signature(RSA_SHA256).ok_or("unknown digest")?,
        );
        let template =
            RESPONSE.replacen("<samlp:Status>", &format!("{signature}<samlp:Status>"), 1);
        let key = load_private_key(SP_PRIVKEY, None)?;
        let mut manager = KeysManager::new();
        manager.add_key(key);
        let ctx = DsigContext::new(manager).with_insecure(true);
        Ok(sign(&ctx, &template)?)
    }

    fn assert_reference_resolution(
        result: Result<(bool, Option<String>), SamlError>,
        expected: ReferenceResolutionReason,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match result {
            Err(SamlError::ReferenceResolution { reason }) if reason == expected => Ok(()),
            other => Err(format!("expected reference resolution {expected}, got {other:?}").into()),
        }
    }

    #[test]
    fn dsig_context_secure_defaults_survive_insecure_builder() {
        let ctx = DsigContext::new(KeysManager::new());
        assert!(ctx.trusted_keys_only);
        assert!(ctx.strict_verification);
        assert!(ctx.require_reference_digests);
        assert_eq!(ctx.hmac_min_out_len, 160);
        assert!(!ctx.insecure);

        let insecure = ctx.with_insecure(true);
        assert!(insecure.insecure);
        assert!(insecure.trusted_keys_only);
        assert!(insecure.strict_verification);
        assert!(insecure.require_reference_digests);
        assert_eq!(insecure.hmac_min_out_len, 160);
    }

    #[test]
    fn verifies_signed_response_with_metadata_cert() -> Result<(), Box<dyn std::error::Error>> {
        let (verified, content) = verify_signature(RESPONSE_SIGNED, &[IDP_CERT.to_string()])?;
        assert!(
            verified,
            "response_signed.xml should verify with the IdP cert"
        );
        assert!(content
            .ok_or("expected signed assertion")?
            .contains("Assertion"));
        Ok(())
    }

    #[test]
    fn verifies_generated_same_document_signature() -> Result<(), Box<dyn std::error::Error>> {
        let key = load_private_key(SP_PRIVKEY, None)?;
        let signed = construct_saml_signature(
            RESPONSE,
            false,
            &key,
            SP_SIGNING_CERT,
            RSA_SHA256,
            &[],
            None,
        )?;
        let (verified, content) = verify_signature(&signed, &[SP_SIGNING_CERT.to_string()])?;
        assert!(verified);
        assert!(content
            .ok_or("expected signed assertion")?
            .contains("Assertion"));
        Ok(())
    }

    #[test]
    fn foreign_extension_certificate_is_not_treated_as_signature_key_info(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let signed = signed_response_with_foreign_extension_certificate()?;
        let (verified, content) = verify_signature(&signed, &[SP_SIGNING_CERT.to_string()])?;
        assert!(verified);
        assert!(content
            .ok_or("expected signed assertion")?
            .contains("Assertion"));
        Ok(())
    }

    #[test]
    fn detailed_verification_ignores_foreign_extension_certificate(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let signed = signed_response_with_foreign_extension_certificate()?;
        let result = verify_signatures_detailed_with_profile(
            &signed,
            &[SP_SIGNING_CERT.to_string()],
            XmlLimits::default(),
            false,
        )?;
        assert!(result.verified() && result.assertion_directly_covered());
        Ok(())
    }

    #[test]
    fn inline_certificate_is_not_used_without_metadata_pin(
    ) -> Result<(), Box<dyn std::error::Error>> {
        match verify_signature(RESPONSE_SIGNED, &[]) {
            Err(SamlError::NoTrustedCertificate) => Ok(()),
            other => Err(format!("expected missing pinned certificate, got {other:?}").into()),
        }
    }

    #[test]
    fn first_invalid_signature_prevents_later_valid_signature_from_authorizing_response(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let result = verify_signature(
            &response_with_first_invalid_signature()?,
            &[IDP_CERT.to_string()],
        )?;
        assert_eq!(result, (false, None));
        Ok(())
    }

    #[test]
    fn detailed_verification_rejects_invalid_first_signature_before_later_assertion_coverage(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let result = verify_signatures_detailed_with_profile(
            &response_with_first_invalid_signature()?,
            &[IDP_CERT.to_string()],
            XmlLimits::default(),
            false,
        )?;
        assert!(!result.verified() && !result.response_covered());
        assert!(result.verified_embedded_signatures().is_empty());
        Ok(())
    }

    #[test]
    fn detailed_verification_excludes_untrusted_extra_signature_evidence(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let untrusted = root_signature(&signature_over_top_level_issuer(
            UNTRUSTED_PRIVKEY,
            UNTRUSTED_CERT,
            RSA_SHA512,
        )?)?;
        let untrusted = remove_signature_key_info(&untrusted)?;
        let signed = assertion_signed_response_with_extra_signature(&untrusted)?;
        let result = verify_signatures_detailed_with_profile(
            &signed,
            &[SP_SIGNING_CERT.to_string()],
            XmlLimits::default(),
            false,
        )?;

        let [signature] = result.verified_embedded_signatures() else {
            return Err("expected only the trusted Assertion signature".into());
        };
        assert!(result.verified() && result.assertion_directly_covered());
        assert_eq!(signature.algorithm_uri(), RSA_SHA256);
        assert!(signature.assertion_directly_covered() && !signature.response_covered());
        Ok(())
    }

    #[test]
    fn detailed_verification_excludes_valid_unrelated_signature_evidence(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let unrelated = root_signature(&signature_over_top_level_issuer(
            SP_PRIVKEY,
            SP_SIGNING_CERT,
            RSA_SHA512,
        )?)?;
        let signed = assertion_signed_response_with_extra_signature(&unrelated)?;
        let result = verify_signatures_detailed_with_profile(
            &signed,
            &[SP_SIGNING_CERT.to_string()],
            XmlLimits::default(),
            false,
        )?;

        let [signature] = result.verified_embedded_signatures() else {
            return Err("expected only the Assertion-covering signature".into());
        };
        assert!(result.verified() && result.assertion_directly_covered());
        assert_eq!(signature.algorithm_uri(), RSA_SHA256);
        assert!(signature.assertion_directly_covered() && !signature.response_covered());
        Ok(())
    }

    #[test]
    fn strict_profile_accepts_verified_assertion_beside_nonconforming_extra_signature(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let extra = format!(
            "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><ds:Reference URI=\"#_response\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>",
            dsig = namespace::DSIG,
        );
        let signed = assertion_signed_response_with_extra_signature(&extra)?;
        let result = verify_signatures_detailed_with_profile(
            &signed,
            &[SP_SIGNING_CERT.to_string()],
            XmlLimits::default(),
            true,
        )?;

        let [signature] = result.verified_embedded_signatures() else {
            return Err("expected only the trusted Assertion signature".into());
        };
        assert!(result.verified() && result.assertion_directly_covered());
        assert_eq!(signature.algorithm_uri(), RSA_SHA256);
        assert!(signature.assertion_directly_covered() && !signature.response_covered());
        Ok(())
    }

    #[test]
    fn strict_profile_rejects_verified_covering_signature_with_two_references(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let signed = signature_over_response_and_assertion()?;
        let result = verify_signatures_detailed_with_profile(
            &signed,
            &[SP_SIGNING_CERT.to_string()],
            XmlLimits::default(),
            true,
        );

        assert!(matches!(result, Err(SamlError::SignedReferenceMismatch)));
        Ok(())
    }

    #[test]
    fn strict_profile_rejects_foreign_xpath_transform_on_verified_assertion_signature(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let signed = response_signed_over_assertion_with_foreign_xpath()?;
        let compatible = verify_signatures_detailed_with_profile(
            &signed,
            &[SP_SIGNING_CERT.to_string()],
            XmlLimits::default(),
            false,
        )?;
        let [signature] = compatible.verified_embedded_signatures() else {
            return Err("expected the assertion-covering signature".into());
        };
        assert!(compatible.verified() && compatible.assertion_directly_covered());
        assert!(signature.assertion_directly_covered());

        let strict = verify_signatures_detailed_with_profile(
            &signed,
            &[SP_SIGNING_CERT.to_string()],
            XmlLimits::default(),
            true,
        );
        assert!(matches!(strict, Err(SamlError::AlgorithmUnsupported)));
        Ok(())
    }

    #[test]
    fn strict_profile_ignores_verified_signature_that_does_not_authenticate_the_response(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let signed = response_with_issuer_only_signature(XML_C14N_10)?;
        let result = verify_signatures_detailed_with_profile(
            &signed,
            &[SP_SIGNING_CERT.to_string()],
            XmlLimits::default(),
            true,
        );
        assert!(matches!(result, Err(SamlError::SignedReferenceMismatch)));
        Ok(())
    }

    #[test]
    fn detailed_verification_reports_one_signature_covering_response_and_assertion(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let signed = signature_over_response_and_assertion()?;
        let result = verify_signatures_detailed_with_profile(
            &signed,
            &[SP_SIGNING_CERT.to_string()],
            XmlLimits::default(),
            false,
        )?;

        let [signature] = result.verified_embedded_signatures() else {
            return Err("expected one verified embedded signature".into());
        };
        assert!(result.verified() && result.assertion_directly_covered());
        assert!(result.response_covered());
        assert_eq!(signature.algorithm_uri(), RSA_SHA512);
        assert!(signature.assertion_directly_covered() && signature.response_covered());
        Ok(())
    }

    #[test]
    fn detailed_verification_aggregates_rolling_cert_coverage_after_first_signature_verifies(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let response_key = load_private_key(SP_PRIVKEY, None)?;
        let signed_response_and_assertion = construct_saml_signature(
            RESPONSE_SIGNED,
            true,
            &response_key,
            SP_SIGNING_CERT,
            RSA_SHA256,
            &[],
            None,
        )?;
        let result = verify_signatures_detailed_with_profile(
            &signed_response_and_assertion,
            &[SP_SIGNING_CERT.to_string(), IDP_CERT.to_string()],
            XmlLimits::default(),
            false,
        )?;
        assert!(
            result.verified() && result.assertion_directly_covered() && result.response_covered()
        );
        assert_eq!(result.verified_embedded_signatures().len(), 2);
        Ok(())
    }

    #[test]
    fn signed_cid_reference_is_rejected_before_content_extraction(
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_reference_resolution(
            verify_signature(&cid_reference_response()?, &[SP_SIGNING_CERT.to_string()]),
            ReferenceResolutionReason::ExternalReference,
        )
    }

    #[test]
    fn rejects_signed_request_without_root_coverage() -> Result<(), Box<dyn std::error::Error>> {
        match verify_signature(SIGNED_REQUEST, &[SP_CERT.to_string()]) {
            Err(SamlError::SignedReferenceMismatch) => Ok(()),
            other => {
                Err(format!("expected uncovered AuthnRequest rejection, got {other:?}").into())
            }
        }
    }

    #[test]
    fn rejects_wrong_certificate() -> Result<(), Box<dyn std::error::Error>> {
        // RESPONSE_SIGNED embeds the IdP cert; verifying against the SP cert
        // trips the inline-vs-metadata mismatch guard.
        match verify_signature(RESPONSE_SIGNED, &[SP_CERT.to_string()]) {
            Err(SamlError::CertificateMismatch) => Ok(()),
            other => Err(format!("expected CertificateMismatch, got {other:?}").into()),
        }
    }

    #[test]
    fn rejects_tampered_signature() -> Result<(), Box<dyn std::error::Error>> {
        // false_signed_request_sha256.xml: signature present but content tampered
        let (verified, _) = verify_signature(FALSE_SIGNED, &[SP_CERT.to_string()])?;
        assert!(!verified, "tampered message must not verify");
        Ok(())
    }

    #[test]
    fn rolling_cert_unloadable_peer_keeps_invalid_verdict() -> Result<(), Box<dyn std::error::Error>>
    {
        let garbage = "not a certificate".to_string();
        let signer = SP_CERT.to_string();
        for certs in [vec![garbage.clone(), signer.clone()], vec![signer, garbage]] {
            assert_eq!(
                verify_signature(FALSE_SIGNED, &certs)?,
                (false, None),
                "unloadable leftover must not replace Invalid with Crypto"
            );
        }
        Ok(())
    }

    #[test]
    fn detailed_rolling_cert_unloadable_peer_keeps_invalid_verdict(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let garbage = "not a certificate".to_string();
        let signer = SP_CERT.to_string();
        for certs in [vec![garbage.clone(), signer.clone()], vec![signer, garbage]] {
            let result = verify_signatures_detailed_with_profile(
                FALSE_SIGNED,
                &certs,
                XmlLimits::default(),
                false,
            )?;
            assert!(
                !result.verified()
                    && !result.assertion_directly_covered()
                    && !result.response_covered(),
                "unloadable leftover must not replace Invalid with Crypto"
            );
        }
        Ok(())
    }

    #[test]
    fn rolling_cert_unloadable_peer_does_not_block_valid_signature(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // response_signed.xml is SHA-1; FIPS rejects that digest.
        let key = load_private_key(SP_PRIVKEY, None)?;
        let signed = construct_saml_signature(
            RESPONSE,
            false,
            &key,
            SP_SIGNING_CERT,
            RSA_SHA256,
            &[],
            None,
        )?;
        let (verified, content) = verify_signature(
            &signed,
            &["not a certificate".to_string(), SP_SIGNING_CERT.to_string()],
        )?;
        assert!(verified);
        assert!(content
            .ok_or("expected signed assertion")?
            .contains("Assertion"));
        Ok(())
    }

    #[test]
    fn rejects_multi_root_wrapping_attack_before_signature_verification(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // attack_response_signed.xml places a forged NameID before the signed
        // response. Reject the multi-root document before signature processing.
        match verify_signature(ATTACK, &[IDP_CERT.to_string()]) {
            Err(SamlError::Xml(message)) if message == "multiple document elements" => Ok(()),
            other => Err(format!("expected multi-root XML rejection, got {other:?}").into()),
        }
    }

    #[test]
    fn no_signature_returns_false() -> Result<(), Box<dyn std::error::Error>> {
        // a document without any Signature element verifies to (false, None)
        let (verified, content) = verify_signature("<samlp:Response>x</samlp:Response>", &[])?;
        assert!(!verified);
        assert!(content.is_none());
        // keep the extractor import exercised
        let _ = extract("<a/>", &[ExtractorField::new("x", &["a"])])?;
        Ok(())
    }

    #[test]
    fn protocol_response_roots_match_exact_namespace_aware_names(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let protocol = namespace::PROTOCOL;
        for local_name in [
            "Response",
            "ArtifactResponse",
            "LogoutResponse",
            "ManageNameIDResponse",
            "NameIDMappingResponse",
        ] {
            let prefixed = format!(r#"<samlp:{local_name} xmlns:samlp="{protocol}"/>"#);
            let default_namespace = format!(r#"<{local_name} xmlns="{protocol}"/>"#);
            assert!(
                root_uses_protocol_response_rules(&prefixed)?,
                "{local_name}"
            );
            assert!(
                root_uses_protocol_response_rules(&default_namespace)?,
                "{local_name}"
            );
        }

        let prologue = format!(
            "<?xml version=\"1.0\"?><!-- before --><samlp:Response xmlns:samlp=\"{protocol}\"/>"
        );
        assert!(root_uses_protocol_response_rules(&prologue)?);
        assert!(!root_uses_protocol_response_rules(
            r#"<samlp:Response xmlns:samlp="urn:example:not-saml"/>"#
        )?);
        assert!(!root_uses_protocol_response_rules(&format!(
            r#"<samlp:FooResponse xmlns:samlp="{protocol}"/>"#
        ))?);
        assert!(!root_uses_protocol_response_rules(&format!(
            r#"<samlp:LogoutRequest xmlns:samlp="{protocol}"/>"#
        ))?);
        assert!(!root_uses_protocol_response_rules(
            "<samlp:Response>x</samlp:Response>"
        )?);
        Ok(())
    }

    fn subject_confirmation_wrapping(root_open: &str, root_close: &str) -> String {
        format!(
            "{root_open}<saml:Assertion xmlns:saml=\"{assertion}\"><saml:Subject><saml:SubjectConfirmation><saml:SubjectConfirmationData><saml:Assertion/></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject></saml:Assertion>{root_close}",
            assertion = namespace::ASSERTION,
        )
    }

    #[test]
    fn protocol_responses_reject_subject_confirmation_wrapping(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for local_name in [
            "Response",
            "ArtifactResponse",
            "LogoutResponse",
            "ManageNameIDResponse",
            "NameIDMappingResponse",
        ] {
            let xml = subject_confirmation_wrapping(
                &format!(
                    r#"<samlp:{local_name} xmlns:samlp="{protocol}">"#,
                    protocol = namespace::PROTOCOL,
                ),
                &format!("</samlp:{local_name}>"),
            );
            for result in [
                verify_signature(&xml, &[]).map(|_| ()),
                verify_signatures_detailed_with_profile(&xml, &[], XmlLimits::default(), false)
                    .map(|_| ()),
            ] {
                match result {
                    Err(SamlError::PotentialWrappingAttack) => {}
                    other => {
                        return Err(format!(
                            "{local_name}: expected wrapping rejection, got {other:?}"
                        )
                        .into());
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn substring_and_foreign_namespace_roots_skip_response_wrapping(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let protocol = namespace::PROTOCOL;
        let cases = [
            subject_confirmation_wrapping(
                &format!(r#"<samlp:FooResponse xmlns:samlp="{protocol}">"#),
                "</samlp:FooResponse>",
            ),
            subject_confirmation_wrapping(
                r#"<Response xmlns="urn:example:not-saml">"#,
                "</Response>",
            ),
            subject_confirmation_wrapping(
                r#"<samlp:LogoutResponse xmlns:samlp="urn:example:not-saml">"#,
                "</samlp:LogoutResponse>",
            ),
            subject_confirmation_wrapping(
                r#"<samlp:ArtifactResponse xmlns:samlp="urn:example:not-saml">"#,
                "</samlp:ArtifactResponse>",
            ),
        ];
        for xml in cases {
            let (verified, content) = verify_signature(&xml, &[])?;
            assert!(!verified && content.is_none(), "{xml}");
            let detailed =
                verify_signatures_detailed_with_profile(&xml, &[], XmlLimits::default(), false)?;
            assert!(
                !detailed.verified() && !detailed.response_covered(),
                "{xml}"
            );
        }
        Ok(())
    }

    fn sign_message_root(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
        let key = load_private_key(SP_PRIVKEY, None)?;
        Ok(construct_saml_signature(
            xml,
            true,
            &key,
            SP_SIGNING_CERT,
            RSA_SHA256,
            &[],
            None,
        )?)
    }

    fn signed_protocol_message(
        local_name: &str,
        inner: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let xml = format!(
            r#"<samlp:{local_name} xmlns:samlp="{protocol}" xmlns:saml="{assertion}" ID="_{local_name}" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer>{inner}</samlp:{local_name}>"#,
            protocol = namespace::PROTOCOL,
            assertion = namespace::ASSERTION,
        );
        sign_message_root(&xml)
    }

    fn assert_both_verifiers_agree(
        signed: &str,
        response_covered: bool,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let certificates = [SP_SIGNING_CERT.to_string()];
        let (verified, content) = verify_signature(signed, &certificates)?;
        assert!(verified);
        let detailed = verify_signatures_detailed_with_profile(
            signed,
            &certificates,
            XmlLimits::default(),
            false,
        )?;
        assert!(detailed.verified());
        assert_eq!(detailed.response_covered(), response_covered);
        assert!(!detailed.assertion_directly_covered());
        let detailed_content = detailed.into_signed_content();
        assert_eq!(content.as_deref(), detailed_content.as_deref());
        Ok(content)
    }

    #[test]
    fn logout_and_artifact_responses_keep_signature_coverage(
    ) -> Result<(), Box<dyn std::error::Error>> {
        const NESTED_ASSERTION: &str = r#"<saml:Assertion ID="_nested" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer></saml:Assertion>"#;

        let logout =
            assert_both_verifiers_agree(&signed_protocol_message("LogoutResponse", "")?, true)?;
        let logout = logout.ok_or("expected signed LogoutResponse content")?;
        assert!(logout.contains("LogoutResponse"));

        let logout_assertion = assert_both_verifiers_agree(
            &signed_protocol_message("LogoutResponse", NESTED_ASSERTION)?,
            true,
        )?;
        let logout_assertion =
            logout_assertion.ok_or("expected LogoutResponse assertion content")?;
        assert!(logout_assertion.starts_with("<saml:Assertion"));
        assert!(!logout_assertion.contains("LogoutResponse"));

        let artifact =
            assert_both_verifiers_agree(&signed_protocol_message("ArtifactResponse", "")?, true)?;
        assert!(artifact.is_none());

        let artifact_assertion = assert_both_verifiers_agree(
            &signed_protocol_message("ArtifactResponse", NESTED_ASSERTION)?,
            true,
        )?;
        let artifact_assertion =
            artifact_assertion.ok_or("expected ArtifactResponse assertion content")?;
        assert!(artifact_assertion.starts_with("<saml:Assertion"));
        assert!(!artifact_assertion.contains("ArtifactResponse"));

        let custom = sign_message_root(
            r#"<FooResponse xmlns="urn:example:custom" ID="_foo"><Issuer>https://idp.example.com</Issuer><Assertion ID="_nested">kept</Assertion></FooResponse>"#,
        )?;
        let custom = assert_both_verifiers_agree(&custom, false)?;
        assert!(custom.is_none());
        Ok(())
    }
}
