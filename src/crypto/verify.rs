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
};
use crate::assertion_acceptance::consumed_assertion;
use crate::config::{HmacSecret, XmlSignatureProfile};
use crate::error::{
    crypto_err, xml_err, ReferenceResolutionReason, SamlError, SignatureVerificationReason,
};
use crate::xml::dom::{self, Node, XmlLimits};
use crate::xml::signature_placement::saml_signature_candidates;
use bergshamra::core::ns as bergshamra_ns;
use bergshamra::dsig::verify::verify_document_with_source;
use bergshamra::xml::{uppsala, Document as BergshamraDocument, NodeId as BergshamraNodeId};
use bergshamra::{DsigContext, KeysManager, VerifiedReference, VerifyResult};
use std::collections::HashSet;

mod processing;
#[cfg(test)]
use processing::enforce_strict_profile_on_verified_signature;
use processing::{
    document_signatures, enforce_hmac_truncation_minimum, enforce_profile_on_verified_signature,
    preflight_signature_processing, verified_authn_request_signature, verify_all_signatures,
    SignatureSelection,
};

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
/// Successful coverage is also the strict-profile gate for signatures that
/// authenticate a message without becoming SSO evidence, including
/// `LogoutRequest` and `LogoutResponse`.
fn covered_content<'a>(
    root: &'a Node,
    targets: &[VerifiedTarget],
    protocol_response: bool,
) -> Result<&'a Node, SamlError> {
    if protocol_response {
        let assertions: Vec<_> = root.children_named("Assertion").collect();
        if !assertions.is_empty() {
            if !response_assertions_covered(root, targets) {
                if assertions.len() > 1 {
                    return Err(SamlError::PotentialWrappingAttack);
                }
                return Err(verified_content_not_covered());
            }
            return consumed_assertion(root).ok_or_else(verified_content_not_covered);
        }
    }
    covered_root(root, targets)
}

/// Return the source of the [`covered_content`] of `root`.
fn verified_content(
    root: &Node,
    xml: &str,
    targets: &[VerifiedTarget],
    protocol_response: bool,
) -> Result<String, SamlError> {
    let node = covered_content(root, targets, protocol_response)?;
    Ok(xml[node.start..node.end].to_string())
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
        .ok_or_else(|| SamlError::crypto("verified signature is missing SignedInfo"))?;
    let signature_method = document
        .first_child_element_by_name_ns(
            signed_info,
            bergshamra_ns::DSIG,
            bergshamra_ns::node::SIGNATURE_METHOD,
        )
        .ok_or_else(|| SamlError::crypto("verified signature is missing SignatureMethod"))?;
    document
        .element(signature_method)
        .and_then(|element| element.get_attribute(bergshamra_ns::attr::ALGORITHM))
        .filter(|algorithm| !algorithm.is_empty())
        .map(str::to_string)
        .ok_or_else(|| SamlError::crypto("verified signature is missing SignatureMethod Algorithm"))
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
        .ok_or_else(|| SamlError::crypto("verified document root is not an element"))?;
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

/// Verify the first XML-DSig signature in document order against `metadata_certs`.
///
/// Requires a signature directly under the root or a direct Assertion child.
/// The processed signature's
/// references must stay within this document. A verified signature must cover
/// the root, or the direct assertions returned from a protocol response.
///
/// Returns `(verified, signed_content)`:
/// - `(false, None)` when there is no signature or it does not verify;
/// - `(true, Some(xml))` with the signed assertion or document root on success;
/// - `Err(PotentialWrappingAttack)` on a detected XSW attempt.
///
/// # Errors
///
/// Returns [`SamlError`] when XML parsing, trust checks, reference resolution,
/// cryptographic verification, or signed-content coverage checks fail.
#[cfg(test)]
pub(crate) fn verify_signature(
    xml: &str,
    metadata_certs: &[String],
) -> Result<(bool, Option<String>), SamlError> {
    verify_first_signature_with_profile(
        xml,
        metadata_certs,
        XmlLimits::default(),
        XmlSignatureProfile::AllowWeakAlgorithms,
    )
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

/// Run the wrapping and duplicate-ID checks shared by
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

    super::provider::ensure_crypto_provider_initialized()?;
    let context = metadata_verification_context(metadata_certs, hmac_secret, profile)?;
    Ok(Some(PreparedSignatureVerification {
        dom,
        protocol_response,
        context,
    }))
}

/// Verify the first XML-DSig signature with explicit XML parser limits.
///
/// Uses the same processing and content-coverage rules as [`verify_signature`].
///
/// # Errors
///
/// Returns [`SamlError`] when XML parsing, trust checks, reference resolution,
/// cryptographic verification, or signed-content coverage checks fail.
#[cfg(test)]
pub(crate) fn verify_signature_with_limits(
    xml: &str,
    metadata_certs: &[String],
    limits: XmlLimits,
) -> Result<(bool, Option<String>), SamlError> {
    verify_first_signature_with_profile(
        xml,
        metadata_certs,
        limits,
        XmlSignatureProfile::AllowWeakAlgorithms,
    )
}

pub(crate) fn verify_first_signature_with_profile(
    xml: &str,
    metadata_certs: &[String],
    limits: XmlLimits,
    profile: XmlSignatureProfile,
) -> Result<(bool, Option<String>), SamlError> {
    let Some(prepared) = prepare_signature_verification(
        xml,
        dom::parse_document(xml, limits)?,
        metadata_certs,
        None,
        profile,
    )?
    else {
        return Ok((false, None));
    };
    let root = &prepared.dom.root;
    let document = uppsala::parse(xml).map_err(xml_err)?;
    preflight_signature_processing(&document, SignatureSelection::First, profile)?;
    let mut result =
        verify_document_with_source(&prepared.context, &document, Some(xml)).map_err(crypto_err)?;
    enforce_hmac_truncation_minimum(&document, &mut result);
    match result {
        VerifyResult::Valid {
            signature_node,
            references,
            ..
        } => {
            enforce_profile_on_verified_signature(&document, signature_node, profile)?;
            let targets = verified_targets(&references)?;
            let content = verified_content(root, xml, &targets, prepared.protocol_response)?;
            Ok((true, Some(content)))
        }
        VerifyResult::Invalid { .. } => Ok((false, None)),
    }
}

/// Reject a `Response` or `Assertion` whose signature in a SAML signature
/// position does not verify.
fn reject_present_signature_that_does_not_verify(
    prepared: &PreparedSignatureVerification,
    document: &BergshamraDocument<'_>,
    results: &[VerifyResult],
) -> Result<(), SamlError> {
    let root = &prepared.dom.root;
    let response_or_assertion = root.local_name == "Assertion"
        || (prepared.protocol_response && root.local_name == "Response");
    if !response_or_assertion {
        return Ok(());
    }
    let placed: Vec<usize> = saml_signature_candidates(root)
        .into_iter()
        .map(|signature| signature.start)
        .collect();
    // `verify_all_document_with_source` returns one result per `ds:Signature`
    // element, in document order.
    let signatures = document_signatures(document);
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
/// position does not verify, without requiring it to cover the accepted content.
pub(crate) fn verify_present_signatures(
    xml: &str,
    metadata_certs: &[String],
    hmac_secret: Option<&HmacSecret>,
    limits: XmlLimits,
    profile: XmlSignatureProfile,
) -> Result<(), SamlError> {
    let dom = dom::parse_document(xml, limits)?;
    if saml_signature_candidates(&dom.root).is_empty() {
        return Ok(());
    }
    let Some(prepared) =
        prepare_signature_verification(xml, dom, metadata_certs, hmac_secret, profile)?
    else {
        return Ok(());
    };
    let document = uppsala::parse(xml).map_err(xml_err)?;
    let results = verify_all_signatures(&prepared.context, &document, xml, profile)?;
    reject_present_signature_that_does_not_verify(&prepared, &document, &results)
}

/// What [`verify_signatures_detailed_with_profile`] found in a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SignatureVerification {
    /// The document carries no SAML signature.
    Absent,
    /// The document carries a signature, and no verified signature covers
    /// the content it accepts.
    Unverified,
    /// Verified signatures cover the content.
    Verified(VerifiedSignedContent),
}

impl SignatureVerification {
    /// The verified content of a document whose signature is required.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::SignatureMissing`] when the document carries no
    /// signature, and [`SamlError::SignatureVerification`] when its signature
    /// does not verify.
    pub(crate) fn require_verified(self) -> Result<VerifiedSignedContent, SamlError> {
        match self {
            Self::Verified(verified) => Ok(verified),
            Self::Absent => Err(SamlError::SignatureMissing),
            Self::Unverified => Err(SamlError::SignatureVerification {
                reason: SignatureVerificationReason::XmlSignature,
            }),
        }
    }
}

/// The content that verified signatures cover, and which parts of the
/// document they cover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedSignedContent {
    content: String,
    assertion_directly_covered: bool,
    response_covered: bool,
    signatures: Vec<VerifiedEmbeddedSignature>,
}

impl VerifiedSignedContent {
    pub(crate) fn content(&self) -> &str {
        &self.content
    }

    pub(crate) fn into_content(self) -> String {
        self.content
    }

    pub(crate) fn assertion_directly_covered(&self) -> bool {
        self.assertion_directly_covered
    }

    pub(crate) fn response_covered(&self) -> bool {
        self.response_covered
    }

    pub(crate) fn signatures(&self) -> &[VerifiedEmbeddedSignature] {
        &self.signatures
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
        dom::parse_document(xml, limits)?,
        metadata_certs,
        hmac_secret,
        profile,
    )?
    else {
        return Ok(SignatureVerification::Absent);
    };
    let root = &prepared.dom.root;
    let protocol_response = prepared.protocol_response;
    let consumed = consumed_assertion(root);

    // Signature nodes in the results index this DOM, so evidence is read
    // from the same document the verifier saw.
    let document = uppsala::parse(xml).map_err(xml_err)?;
    let results = verify_all_signatures(&prepared.context, &document, xml, profile)?;
    let results = if root.local_name == "AuthnRequest" {
        let Some(signature) = verified_authn_request_signature(&document, &results) else {
            return Ok(SignatureVerification::Unverified);
        };
        std::slice::from_ref(signature)
    } else {
        &results
    };
    reject_present_signature_that_does_not_verify(&prepared, &document, results)?;
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
                let signature_targets = verified_targets(references)?;
                let signature = verified_embedded_signature(
                    &document,
                    *signature_node,
                    references,
                    &signature_targets,
                    consumed,
                )?;
                if signature.is_some()
                    || references_cover_direct_assertion(&document, references)
                    || covered_content(root, &signature_targets, protocol_response).is_ok()
                {
                    enforce_profile_on_verified_signature(&document, *signature_node, profile)?;
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
        return Ok(SignatureVerification::Verified(VerifiedSignedContent {
            content: verified_content(root, xml, &targets, protocol_response)?,
            assertion_directly_covered,
            response_covered,
            signatures: verified_embedded_signatures,
        }));
    }
    Ok(SignatureVerification::Unverified)
}

/// The signed metadata of `xml` when its signature verifies under `profile`
/// and covers the metadata root, or `None` when it is unsigned or the
/// signature does not verify.
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
) -> Result<Option<String>, SamlError> {
    let (verified, signed_metadata_xml) =
        verify_first_signature_with_profile(xml, trusted_certificates, limits, profile)?;
    if !verified {
        return Ok(None);
    }
    let signed_metadata_xml = signed_metadata_xml.ok_or_else(verified_content_not_covered)?;
    let descriptor = dom::parse_document(xml, limits)?;
    if !matches!(
        descriptor.root.local_name.as_str(),
        "EntityDescriptor" | "EntitiesDescriptor"
    ) {
        return Err(verified_content_not_covered());
    }
    Ok(Some(signed_metadata_xml))
}

#[cfg(test)]
mod tests;
