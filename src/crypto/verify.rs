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

use super::keys::{load_certificate, load_hmac_secret};
use super::response_root::root_uses_protocol_response_rules;
use super::signature_profile::{
    allows_digest_method, allows_signature_method, check_verification_key,
    rejects_present_signature_that_does_not_verify,
};
use crate::assertion_acceptance::consumed_assertion;
use crate::config::{HmacSecret, XmlSignatureProfile};
use crate::constants::transform_algorithm;
use crate::error::{ReferenceResolutionReason, SamlError, SignatureVerificationReason};
use crate::xml::dom::{self, Node, XmlLimits};
use crate::xml::signature_placement::saml_signature_candidates;
use bergshamra::core::ns as bergshamra_ns;
use bergshamra::dsig::verify::{verify_all_document_with_source, verify_document_with_source};
use bergshamra::xml::{uppsala, Document as BergshamraDocument, NodeId as BergshamraNodeId};
use bergshamra::{DsigContext, KeysManager, VerifiedReference, VerifyResult};
use std::collections::HashSet;

fn has_descendant(node: &Node, names: &[&str]) -> bool {
    node.children
        .iter()
        .any(|c| names.contains(&c.local_name.as_str()) || has_descendant(c, names))
}

/// XSW guard: `Response/Assertion/Subject/SubjectConfirmation/SubjectConfirmationData//(Assertion|Signature)`.
fn wrapping_detected(root: &Node) -> bool {
    for assertion in root.children_named("Assertion") {
        for subject in assertion.children_named("Subject") {
            for sc in subject.children_named("SubjectConfirmation") {
                for scd in sc.children_named("SubjectConfirmationData") {
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
    for transforms in reference.children_named("Transforms") {
        for transform in transforms.children_named("Transform") {
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

    for signature in root.children_named("Signature") {
        for signed_info in signature.children_named("SignedInfo") {
            for reference in signed_info.children_named("Reference") {
                ensure_metadata_reference_transforms_preserve_descriptor(reference)?;
            }
        }
    }
    Ok(())
}

fn covered_root<'a>(root: &'a Node, targets: &[VerifiedTarget]) -> Result<&'a Node, SamlError> {
    if target_matches_node(targets, root) {
        return Ok(root);
    }
    Err(verified_content_not_covered())
}

/// The response signature covers every assertion, or every assertion is signed.
/// An unsigned sibling is rejected.
fn response_assertions_covered(root: &Node, targets: &[VerifiedTarget]) -> bool {
    let assertions: Vec<_> = root.children_named("Assertion").collect();
    !assertions.is_empty()
        && (target_matches_node(targets, root)
            || assertions
                .iter()
                .all(|assertion| id_target_matches_node(targets, assertion)))
}

/// The element covered by a verified reference that a caller consumes: the
/// first bearer `<Assertion>`, a consumed root element, or the whole protocol
/// response when assertions are encrypted.
///
/// `Ok(Some(_))` is also the strict-profile gate for signatures that
/// authenticate a message without becoming SSO evidence, including
/// `LogoutRequest` and `LogoutResponse`.
fn covered_content<'a>(
    root: &'a Node,
    targets: &[VerifiedTarget],
    protocol_response: bool,
) -> Result<Option<&'a Node>, SamlError> {
    if root.local_name == "Assertion" {
        return covered_root(root, targets).map(Some);
    }
    if protocol_response {
        let assertions: Vec<_> = root.children_named("Assertion").collect();
        if !assertions.is_empty() {
            if !response_assertions_covered(root, targets) {
                if assertions.len() > 1 {
                    return Err(SamlError::PotentialWrappingAttack);
                }
                return Err(verified_content_not_covered());
            }
            return Ok(consumed_assertion(root));
        }
        if root.child_named("EncryptedAssertion").is_some() {
            return covered_root(root, targets).map(Some);
        }
    }
    if matches!(
        root.local_name.as_str(),
        "EntityDescriptor"
            | "EntitiesDescriptor"
            | "AuthnRequest"
            | "LogoutRequest"
            | "LogoutResponse"
    ) {
        return covered_root(root, targets).map(Some);
    }
    Ok(None)
}

/// Return the source of the [`covered_content`] of `root`.
fn verified_content(
    root: &Node,
    xml: &str,
    targets: &[VerifiedTarget],
    protocol_response: bool,
) -> Result<Option<String>, SamlError> {
    Ok(covered_content(root, targets, protocol_response)?
        .map(|node| xml[node.start..node.end].to_string()))
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
        let assertions: Vec<_> = root.children_named("Assertion").collect();
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

fn verified_signature_algorithm(
    document: &BergshamraDocument<'_>,
    signature_node: BergshamraNodeId,
) -> Result<String, SamlError> {
    let signed_info = document
        .first_child_element_by_name_ns(
            signature_node,
            bergshamra_ns::DSIG,
            bergshamra_ns::node::SIGNED_INFO,
        )
        .ok_or_else(|| SamlError::Crypto("verified signature is missing SignedInfo".into()))?;
    let signature_method = document
        .first_child_element_by_name_ns(
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

/// The `<Assertion>` child of `response` whose source starts at `start`.
fn child_assertion_at(
    document: &BergshamraDocument<'_>,
    response: BergshamraNodeId,
    start: usize,
) -> Option<BergshamraNodeId> {
    document.children_iter(response).find(|child| {
        document.element(*child).is_some_and(|element| {
            element.matches_name_ns(crate::constants::namespace::ASSERTION, "Assertion")
        }) && document
            .node_range(*child)
            .is_some_and(|range| range.start == start)
    })
}

fn verified_embedded_signature(
    document: &BergshamraDocument<'_>,
    signature_node: BergshamraNodeId,
    references: &[VerifiedReference],
    targets: &[VerifiedTarget],
    consumed_assertion: Option<&Node>,
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
    let assertion_node = if root_element
        .matches_name_ns(crate::constants::namespace::ASSERTION, "Assertion")
    {
        Some(root)
    } else if root_element.matches_name_ns(crate::constants::namespace::PROTOCOL, "Response") {
        consumed_assertion.and_then(|consumed| child_assertion_at(document, root, consumed.start))
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

fn preflight_saml_reference_uris(signatures: &[&Node]) -> Result<(), SamlError> {
    for signature in signatures {
        for signed_info in signature.children_named("SignedInfo") {
            for reference in signed_info.children_named("Reference") {
                verified_target_from_uri(reference.attr("URI").unwrap_or_default())?;
            }
        }
    }
    Ok(())
}

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
fn enforce_profile_on_verified_signature(
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

/// The parsed message or metadata document after the checks shared by every
/// signature verifier, with one verification context that trusts every
/// loadable metadata key.
struct PreparedSignatureVerification {
    dom: dom::Document,
    protocol_response: bool,
    context: DsigContext,
}

/// Load every metadata certificate the profile accepts (rolling-cert support),
/// and the peer's HMAC secret when it has one, into one trusted-key context: a
/// signature verifies if any one of those keys matches. An unloadable or
/// profile-rejected certificate is skipped while another key loads.
fn metadata_verification_context(
    metadata_certs: &[String],
    hmac_secret: Option<&HmacSecret>,
    profile: XmlSignatureProfile,
) -> Result<DsigContext, SamlError> {
    let mut manager = KeysManager::new();
    let mut key_load_error = None;
    for certificate in metadata_certs {
        let key = load_certificate(certificate)
            .and_then(|key| check_verification_key(profile, &key).map(|()| key));
        match key {
            Ok(key) => manager.add_key(key),
            Err(error) => {
                key_load_error.get_or_insert(error);
            }
        }
    }
    if let Some(secret) = hmac_secret {
        manager.add_key(load_hmac_secret(secret)?);
    }
    if manager.is_empty() {
        return Err(key_load_error.unwrap_or(SamlError::NoTrustedCertificate));
    }
    // Metadata keys are the only verification keys. Inline KeyInfo is not
    // imported; it only ranks which trusted key is tried first.
    // `with_insecure(true)` skips X.509 chain and time checks only; signature,
    // digest, reference, duplicate-ID, and XSW checks stay on. Do not replace
    // this with `DsigContext::new_permissive()`.
    Ok(DsigContext::new(manager)
        .with_trusted_keys_only(true)
        .with_strict_verification(true)
        .with_require_reference_digests(true)
        .with_hmac_min_out_len(160)
        .with_insecure(true))
}

/// Run the wrapping, duplicate-ID, and reference checks shared by
/// [`verify_first_signature_with_profile`] and
/// [`verify_signatures_detailed_with_profile`], then load the metadata
/// certificates.
///
/// Returns `None` when the document carries no SAML signature.
fn prepare_signature_verification(
    xml: &str,
    dom: dom::Document,
    metadata_certs: &[String],
    hmac_secret: Option<&HmacSecret>,
    profile: XmlSignatureProfile,
) -> Result<Option<PreparedSignatureVerification>, SamlError> {
    let protocol_response = root_uses_protocol_response_rules(xml)?;
    if protocol_response && wrapping_detected(&dom.root) {
        return Err(SamlError::PotentialWrappingAttack);
    }
    let mut seen_ids = HashSet::new();
    if duplicate_saml_id(&dom.root, &mut seen_ids).is_some() {
        return Err(SamlError::PotentialWrappingAttack);
    }

    // Candidate signatures: message-level (root > Signature) or assertion-level.
    let signature_candidates = saml_signature_candidates(&dom.root);
    if signature_candidates.is_empty() {
        return Ok(None);
    }
    preflight_saml_reference_uris(&signature_candidates)?;
    super::provider::ensure_crypto_provider_initialized()?;
    let context = metadata_verification_context(metadata_certs, hmac_secret, profile)?;
    Ok(Some(PreparedSignatureVerification {
        dom,
        protocol_response,
        context,
    }))
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
    verify_first_signature_with_profile(
        xml,
        metadata_certs,
        limits,
        XmlSignatureProfile::AllowProviderSupportedForCompatibility,
    )
}

fn verify_first_signature_with_profile(
    xml: &str,
    metadata_certs: &[String],
    limits: XmlLimits,
    profile: XmlSignatureProfile,
) -> Result<(bool, Option<String>), SamlError> {
    let Some(prepared) = prepare_signature_verification(
        xml,
        dom::parse_with_limits(xml, limits)?,
        metadata_certs,
        None,
        profile,
    )?
    else {
        return Ok((false, None));
    };
    let root = &prepared.dom.root;
    let document = uppsala::parse(xml).map_err(|error| {
        SamlError::Crypto(bergshamra::Error::XmlParse(error.to_string()).to_string())
    })?;
    match verify_document_with_source(&prepared.context, &document, Some(xml)) {
        Ok(VerifyResult::Valid {
            signature_node,
            references,
            ..
        }) => {
            enforce_profile_on_verified_signature(&document, signature_node, profile)?;
            let targets = verified_targets(&references)?;
            let content = verified_content(root, xml, &targets, prepared.protocol_response)?;
            Ok((true, content))
        }
        Ok(VerifyResult::Invalid { .. }) => Ok((false, None)),
        Err(error) => Err(SamlError::Crypto(error.to_string())),
    }
}

/// Reject a `Response` or `Assertion` whose signature in a SAML signature
/// position does not verify, when `profile` rejects one.
fn reject_present_signature_that_does_not_verify(
    prepared: &PreparedSignatureVerification,
    profile: XmlSignatureProfile,
    document: &BergshamraDocument<'_>,
    results: &[VerifyResult],
) -> Result<(), SamlError> {
    let root = &prepared.dom.root;
    let response_or_assertion = root.local_name == "Assertion"
        || (prepared.protocol_response && root.local_name == "Response");
    if !response_or_assertion || !rejects_present_signature_that_does_not_verify(profile) {
        return Ok(());
    }
    let placed: Vec<usize> = saml_signature_candidates(root)
        .into_iter()
        .map(|signature| signature.start)
        .collect();
    // `verify_all_document_with_source` returns one result per `ds:Signature`
    // element, in document order.
    let signatures = document
        .descendants(document.root())
        .into_iter()
        .filter(|node| {
            document.element(*node).is_some_and(|element| {
                element.matches_name_ns(bergshamra_ns::DSIG, bergshamra_ns::node::SIGNATURE)
            })
        });
    let placed_signature_does_not_verify = signatures.zip(results).any(|(signature, result)| {
        matches!(result, VerifyResult::Invalid { .. })
            && document
                .node_range(signature)
                .is_some_and(|range| placed.contains(&range.start))
    });
    if placed_signature_does_not_verify {
        return Err(SamlError::SignatureVerification {
            reason: SignatureVerificationReason::XmlSignature,
        });
    }
    Ok(())
}

/// Reject a `Response` or `Assertion` whose signature in a SAML signature
/// position does not verify, when `profile` rejects one. The coverage of the
/// accepted content is not checked.
pub(crate) fn verify_present_signatures(
    xml: &str,
    metadata_certs: &[String],
    hmac_secret: Option<&HmacSecret>,
    limits: XmlLimits,
    profile: XmlSignatureProfile,
) -> Result<(), SamlError> {
    if !rejects_present_signature_that_does_not_verify(profile) {
        return Ok(());
    }
    let dom = dom::parse_with_limits(xml, limits)?;
    if saml_signature_candidates(&dom.root).is_empty() {
        return Ok(());
    }
    let Some(prepared) =
        prepare_signature_verification(xml, dom, metadata_certs, hmac_secret, profile)?
    else {
        return Ok(());
    };
    let document = uppsala::parse(xml).map_err(|error| SamlError::Crypto(error.to_string()))?;
    let results = verify_all_document_with_source(&prepared.context, &document, Some(xml))
        .map_err(|error| SamlError::Crypto(error.to_string()))?;
    reject_present_signature_that_does_not_verify(&prepared, profile, &document, &results)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignatureVerification {
    signature_present: bool,
    verified: bool,
    signed_content: Option<String>,
    assertion_directly_covered: bool,
    response_covered: bool,
    verified_embedded_signatures: Vec<VerifiedEmbeddedSignature>,
}

impl SignatureVerification {
    fn unverified(signature_present: bool) -> Self {
        Self {
            signature_present,
            verified: false,
            signed_content: None,
            assertion_directly_covered: false,
            response_covered: false,
            verified_embedded_signatures: Vec::new(),
        }
    }

    pub(crate) fn signature_present(&self) -> bool {
        self.signature_present
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

pub(crate) fn verify_signatures_detailed_with_profile(
    xml: &str,
    metadata_certs: &[String],
    hmac_secret: Option<&HmacSecret>,
    limits: XmlLimits,
    profile: XmlSignatureProfile,
) -> Result<SignatureVerification, SamlError> {
    let Some(prepared) = prepare_signature_verification(
        xml,
        dom::parse_with_limits(xml, limits)?,
        metadata_certs,
        hmac_secret,
        profile,
    )?
    else {
        return Ok(SignatureVerification::unverified(false));
    };
    let root = &prepared.dom.root;
    let protocol_response = prepared.protocol_response;
    let consumed = consumed_assertion(root);

    // Signature nodes in the results index this DOM, so evidence is read
    // from the same document the verifier saw.
    let document = uppsala::parse(xml).map_err(|error| SamlError::Crypto(error.to_string()))?;
    let results = verify_all_document_with_source(&prepared.context, &document, Some(xml))
        .map_err(|error| SamlError::Crypto(error.to_string()))?;
    reject_present_signature_that_does_not_verify(&prepared, profile, &document, &results)?;
    let first_signature_verified = matches!(results.first(), Some(VerifyResult::Valid { .. }));
    let mut targets = Vec::new();
    let mut verified_embedded_signatures = Vec::new();
    for result in results {
        match result {
            VerifyResult::Valid {
                signature_node,
                references,
                ..
            } => {
                let signature_targets = verified_targets(&references)?;
                let signature = verified_embedded_signature(
                    &document,
                    signature_node,
                    &references,
                    &signature_targets,
                    consumed,
                )?;
                // SSO evidence does not include LogoutRequest or
                // LogoutResponse coverage. A protocol Response can
                // also be evidence when `covered_content` returns
                // no element. Enforce the profile for either case.
                if signature.is_some()
                    || references_cover_direct_assertion(&document, &references)
                    || matches!(
                        covered_content(root, &signature_targets, protocol_response),
                        Ok(Some(_))
                    )
                {
                    enforce_profile_on_verified_signature(&document, signature_node, profile)?;
                }
                verified_embedded_signatures.extend(signature);
                targets.extend(signature_targets);
            }
            VerifyResult::Invalid { .. } => {}
        }
    }
    if first_signature_verified && !targets.is_empty() {
        let assertion_directly_covered =
            assertion_is_directly_covered(root, &targets, protocol_response);
        let response_covered = protocol_response && target_matches_node(&targets, root);
        return Ok(SignatureVerification {
            signature_present: true,
            verified: true,
            signed_content: verified_content(root, xml, &targets, protocol_response)?,
            assertion_directly_covered,
            response_covered,
            verified_embedded_signatures,
        });
    }
    Ok(SignatureVerification::unverified(true))
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
    verify_metadata_signature_coverage_with_limits(
        xml,
        trusted_certificates,
        limits,
        XmlSignatureProfile::AllowProviderSupportedForCompatibility,
    )
}

/// Verify metadata signature cryptography and signed-root coverage under
/// `profile`.
///
/// The caller has already enforced the metadata signature shape.
///
/// # Errors
///
/// Returns [`SamlError`] when XML parsing, certificate loading, cryptographic
/// verification, the algorithms `profile` allows, or signed-root coverage
/// checks fail.
pub(crate) fn verify_metadata_signature_coverage_with_limits(
    xml: &str,
    trusted_certificates: &[String],
    limits: XmlLimits,
    profile: XmlSignatureProfile,
) -> Result<MetadataSignatureVerification, SamlError> {
    let (verified, signed_entity_descriptor_xml) =
        verify_first_signature_with_profile(xml, trusted_certificates, limits, profile)?;
    if !verified {
        return Ok(MetadataSignatureVerification::unverified());
    }
    signed_entity_descriptor_xml
        .map(MetadataSignatureVerification::from_signed_descriptor)
        .ok_or_else(verified_content_not_covered)
}

#[cfg(test)]
mod tests;
