//! Embedded XML signatures of a received message, and the order in which the
//! assertions it carries encrypted are decrypted and verified.

use super::{
    AssertionSignatureRequirement, FlowOptions, PreparedMessage, ResponseSignatureRequirement,
    VerifiedXmlSignatureEvidence,
};
use crate::assertion_acceptance::first_login_assertion_xml;
use crate::constants::ParserType;
use crate::encrypted_elements::{decrypt_assertions, encrypted_assertion_key};
use crate::error::{SamlError, SignatureVerificationReason};
use crate::xml::dom::Node;

#[derive(Debug)]
struct EmbeddedSignatureEvidence {
    signature_present: bool,
    verified: bool,
    verified_node: Option<String>,
    assertion_directly_covered: bool,
    response_covered: bool,
    verified_xml_signatures: Vec<VerifiedXmlSignatureEvidence>,
}

fn required_xml_signature_failed(signature_present: bool) -> SamlError {
    if signature_present {
        SamlError::SignatureVerification {
            reason: SignatureVerificationReason::XmlSignature,
        }
    } else {
        SamlError::SignatureMissing
    }
}

fn verify_embedded_signature(
    xml: &str,
    opts: &FlowOptions<'_>,
) -> Result<EmbeddedSignatureEvidence, SamlError> {
    let verification = crate::crypto::verify::verify_signatures_detailed_with_profile(
        xml,
        opts.signing_certs,
        opts.hmac_secret,
        opts.xml_limits,
        opts.xml_signatures,
    )?;
    let verified_xml_signatures = verification
        .verified_embedded_signatures()
        .iter()
        .map(|signature| VerifiedXmlSignatureEvidence {
            algorithm_uri: signature.algorithm_uri().to_string(),
            assertion_directly_covered: signature.assertion_directly_covered(),
            response_covered: signature.response_covered(),
        })
        .collect();
    Ok(EmbeddedSignatureEvidence {
        signature_present: verification.signature_present(),
        verified: verification.verified(),
        assertion_directly_covered: verification.assertion_directly_covered(),
        response_covered: verification.response_covered(),
        verified_node: verification.into_signed_content(),
        verified_xml_signatures,
    })
}

pub(super) fn verify_present_signatures(
    xml: &str,
    opts: &FlowOptions<'_>,
) -> Result<(), SamlError> {
    crate::crypto::verify::verify_present_signatures(
        xml,
        opts.signing_certs,
        opts.hmac_secret,
        opts.xml_limits,
        opts.xml_signatures,
    )
}

/// Verify the signature over each decrypted `<Assertion>`, which must cover
/// that assertion directly, and return the evidence of the first decrypted
/// assertion equal to `consumed_assertion`.
fn verify_decrypted_assertions(
    assertions: &[String],
    consumed_assertion: Option<&str>,
    opts: &FlowOptions<'_>,
) -> Result<Vec<VerifiedXmlSignatureEvidence>, SamlError> {
    let consumed = assertions
        .iter()
        .position(|assertion| Some(assertion.as_str()) == consumed_assertion);
    let mut verified_xml_signatures = Vec::new();
    for (index, assertion) in assertions.iter().enumerate() {
        let evidence = verify_embedded_signature(assertion, opts)?;
        if !evidence.verified {
            return Err(required_xml_signature_failed(evidence.signature_present));
        }
        require_direct_assertion_coverage(
            AssertionSignatureRequirement::Direct,
            evidence.assertion_directly_covered,
        )?;
        if consumed == Some(index) {
            verified_xml_signatures.extend(evidence.verified_xml_signatures);
        }
    }
    Ok(verified_xml_signatures)
}

fn require_direct_assertion_coverage(
    assertion_signature: AssertionSignatureRequirement,
    assertion_directly_covered: bool,
) -> Result<(), SamlError> {
    if assertion_signature == AssertionSignatureRequirement::Direct && !assertion_directly_covered {
        return Err(SamlError::AssertionSignatureRequired);
    }
    Ok(())
}

fn response_signature_is_required(
    requirement: ResponseSignatureRequirement,
    xml: &str,
) -> Result<bool, SamlError> {
    match requirement {
        ResponseSignatureRequirement::Optional => Ok(false),
        ResponseSignatureRequirement::RequiredForEncryptedCbc => {
            crate::crypto::enc::response_uses_cbc_encrypted_assertion(xml)
        }
        ResponseSignatureRequirement::Required => Ok(true),
    }
}

/// Verify and optionally decrypt the message, returning the authenticated
/// `(saml_content, assertion)`.
pub(super) fn verify_and_prepare(
    xml: String,
    root: &Node,
    parser_type: ParserType,
    opts: &FlowOptions<'_>,
    assertion_signature: AssertionSignatureRequirement,
    response_signature: ResponseSignatureRequirement,
) -> Result<PreparedMessage, SamlError> {
    let evidence = verify_embedded_signature(&xml, opts)?;
    if response_signature_is_required(response_signature, &xml)? {
        if !evidence.verified {
            return Err(required_xml_signature_failed(evidence.signature_present));
        }
        if !evidence.response_covered {
            return Err(SamlError::SignedReferenceMismatch);
        }
    }
    if let Some(key) = encrypted_assertion_key(root, parser_type, opts) {
        if !evidence.verified {
            return prepare_decrypted_then_verified(
                &xml,
                key,
                parser_type,
                opts,
                assertion_signature,
            );
        }
        if let Some(node) = evidence.verified_node.as_deref() {
            let signed_content = if evidence.response_covered {
                xml.as_str()
            } else {
                node
            };
            return prepare_verified_then_decrypted(
                signed_content,
                &evidence,
                root,
                key,
                parser_type,
                opts,
                assertion_signature,
            );
        }
    }
    prepare_verified(xml, evidence, parser_type, assertion_signature)
}

fn prepare_decrypted_then_verified(
    xml: &str,
    key: &str,
    parser_type: ParserType,
    opts: &FlowOptions<'_>,
    assertion_signature: AssertionSignatureRequirement,
) -> Result<PreparedMessage, SamlError> {
    let (content, _) = decrypt_assertions(xml, key, parser_type, opts)?;
    let evidence = verify_embedded_signature(&content, opts)?;
    if !evidence.verified {
        return Err(required_xml_signature_failed(evidence.signature_present));
    }
    require_direct_assertion_coverage(assertion_signature, evidence.assertion_directly_covered)?;
    Ok(PreparedMessage {
        saml_content: content,
        assertion: evidence.verified_node,
        message_authenticated: false,
        verified_xml_signatures: evidence.verified_xml_signatures,
    })
}

fn prepare_verified_then_decrypted(
    signed_content: &str,
    evidence: &EmbeddedSignatureEvidence,
    root: &Node,
    key: &str,
    parser_type: ParserType,
    opts: &FlowOptions<'_>,
    assertion_signature: AssertionSignatureRequirement,
) -> Result<PreparedMessage, SamlError> {
    let (content, assertions) = decrypt_assertions(signed_content, key, parser_type, opts)?;
    let assertion = first_login_assertion_xml(&content, opts.xml_limits)?;
    let mut verified_xml_signatures = evidence.verified_xml_signatures.clone();
    let consumed_was_decrypted = assertions
        .iter()
        .any(|decrypted| Some(decrypted.as_str()) == assertion.as_deref());
    if consumed_was_decrypted {
        for signature in &mut verified_xml_signatures {
            signature.assertion_directly_covered = false;
        }
    }
    match assertion_signature {
        AssertionSignatureRequirement::Direct => {
            let carries_plaintext_assertion = root
                .children
                .iter()
                .any(|child| child.local_name == "Assertion");
            if carries_plaintext_assertion {
                require_direct_assertion_coverage(
                    assertion_signature,
                    evidence.assertion_directly_covered,
                )?;
            }
            verified_xml_signatures.extend(verify_decrypted_assertions(
                &assertions,
                assertion.as_deref(),
                opts,
            )?);
        }
        AssertionSignatureRequirement::Compatible => {
            for decrypted in &assertions {
                verify_present_signatures(decrypted, opts)?;
            }
        }
    }
    Ok(PreparedMessage {
        assertion,
        saml_content: content,
        message_authenticated: evidence.response_covered,
        verified_xml_signatures,
    })
}

fn prepare_verified(
    xml: String,
    evidence: EmbeddedSignatureEvidence,
    parser_type: ParserType,
    assertion_signature: AssertionSignatureRequirement,
) -> Result<PreparedMessage, SamlError> {
    if !evidence.verified {
        return Err(required_xml_signature_failed(evidence.signature_present));
    }
    require_direct_assertion_coverage(assertion_signature, evidence.assertion_directly_covered)?;
    match parser_type {
        ParserType::SamlResponse => Ok(PreparedMessage {
            saml_content: xml,
            assertion: evidence.verified_node,
            message_authenticated: evidence.response_covered,
            verified_xml_signatures: evidence.verified_xml_signatures,
        }),
        ParserType::SamlRequest
        | ParserType::LogoutRequest
        | ParserType::LogoutResponse
        | ParserType::ManageNameIdRequest
        | ParserType::ManageNameIdResponse => Ok(PreparedMessage {
            saml_content: evidence
                .verified_node
                .ok_or(SamlError::SignedReferenceMismatch)?,
            assertion: None,
            message_authenticated: true,
            verified_xml_signatures: evidence.verified_xml_signatures,
        }),
    }
}
