use super::{
    AssertionSignatureRequirement, FlowOptions, MessageAuthentication, PreparedMessage,
    ResponseSignatureRequirement, VerifiedXmlSignatureEvidence,
};
use crate::assertion_acceptance::first_login_assertion_xml;
use crate::constants::ParserType;
use crate::crypto::verify::{
    SignatureVerification, VerifiedEmbeddedSignature, VerifiedSignedContent,
};
use crate::encrypted_elements::{decrypt_assertions, encrypted_assertion_key};
use crate::error::SamlError;
use crate::xml::dom::Node;
use crate::xml::signature_placement::saml_signature_candidates;

fn verify_embedded_signature(
    xml: &str,
    opts: &FlowOptions<'_>,
) -> Result<SignatureVerification, SamlError> {
    crate::crypto::verify::verify_signatures_detailed_with_profile(
        xml,
        opts.signing_certs,
        opts.hmac_secret,
        opts.xml_limits,
        opts.xml_signatures,
    )
}

fn xml_signature_evidence(
    signatures: &[VerifiedEmbeddedSignature],
) -> Vec<VerifiedXmlSignatureEvidence> {
    signatures
        .iter()
        .map(|signature| VerifiedXmlSignatureEvidence {
            algorithm_uri: signature.algorithm_uri().to_string(),
            assertion_directly_covered: signature.assertion_directly_covered(),
            response_covered: signature.response_covered(),
        })
        .collect()
}

fn response_authentication(verified: &VerifiedSignedContent) -> MessageAuthentication {
    if verified.response_covered() {
        MessageAuthentication::Authenticated
    } else {
        MessageAuthentication::Unauthenticated
    }
}

pub(super) fn verify_present_signatures(
    xml: &str,
    opts: &FlowOptions<'_>,
) -> Result<Vec<VerifiedXmlSignatureEvidence>, SamlError> {
    let signatures = crate::crypto::verify::verify_present_signatures(
        xml,
        opts.signing_certs,
        opts.hmac_secret,
        opts.xml_limits,
        opts.xml_signatures,
    )?;
    Ok(xml_signature_evidence(&signatures))
}

fn verify_decrypted_assertions(
    assertions: &[String],
    consumed_assertion: Option<&str>,
    requirement: AssertionSignatureRequirement,
    opts: &FlowOptions<'_>,
    evidence: &mut Vec<VerifiedXmlSignatureEvidence>,
) -> Result<(), SamlError> {
    let consumed = assertions
        .iter()
        .position(|assertion| Some(assertion.as_str()) == consumed_assertion);
    if consumed.is_some() {
        evidence.retain_mut(|signature| {
            signature.assertion_directly_covered = false;
            signature.response_covered
        });
    }
    for (index, assertion) in assertions.iter().enumerate() {
        let signatures = match requirement {
            AssertionSignatureRequirement::Direct => {
                let verified = verify_embedded_signature(assertion, opts)?.require_verified()?;
                require_direct_assertion_coverage(&verified)?;
                xml_signature_evidence(verified.signatures())
            }
            AssertionSignatureRequirement::Compatible => {
                verify_present_signatures(assertion, opts)?
            }
        };
        if consumed == Some(index) {
            evidence.extend(signatures);
        }
    }
    Ok(())
}

fn require_direct_assertion_coverage(verified: &VerifiedSignedContent) -> Result<(), SamlError> {
    if verified.assertion_directly_covered() {
        Ok(())
    } else {
        Err(SamlError::AssertionSignatureRequired)
    }
}

fn meet_assertion_signature_requirement(
    requirement: AssertionSignatureRequirement,
    verified: &VerifiedSignedContent,
) -> Result<(), SamlError> {
    match requirement {
        AssertionSignatureRequirement::Direct => require_direct_assertion_coverage(verified),
        AssertionSignatureRequirement::Compatible => Ok(()),
    }
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

pub(super) fn prepare_after_detached_signature(
    xml: String,
    root: &Node,
    parser_type: ParserType,
    opts: &FlowOptions<'_>,
    assertion_signature: AssertionSignatureRequirement,
) -> Result<PreparedMessage, SamlError> {
    let signed_request =
        parser_type == ParserType::SamlRequest && !saml_signature_candidates(root).is_empty();
    let direct_assertion_signature = parser_type == ParserType::SamlResponse
        && assertion_signature == AssertionSignatureRequirement::Direct;
    if signed_request || direct_assertion_signature {
        return verify_and_prepare(
            xml,
            root,
            parser_type,
            opts,
            assertion_signature,
            ResponseSignatureRequirement::Optional,
        );
    }
    if parser_type != ParserType::SamlResponse {
        return PreparedMessage::received(xml, parser_type, opts.xml_limits);
    }
    let mut verified_xml_signatures = verify_present_signatures(&xml, opts)?;
    let (saml_content, assertions) = match encrypted_assertion_key(root, parser_type, opts) {
        Some(key) => decrypt_assertions(&xml, key, parser_type, opts)?,
        None => (xml, Vec::new()),
    };
    let assertion = first_login_assertion_xml(&saml_content, opts.xml_limits)?;
    verify_decrypted_assertions(
        &assertions,
        assertion.as_deref(),
        assertion_signature,
        opts,
        &mut verified_xml_signatures,
    )?;
    Ok(PreparedMessage {
        saml_content,
        assertion,
        authentication: MessageAuthentication::Authenticated,
        verified_xml_signatures,
    })
}

pub(super) fn verify_and_prepare(
    xml: String,
    root: &Node,
    parser_type: ParserType,
    opts: &FlowOptions<'_>,
    assertion_signature: AssertionSignatureRequirement,
    response_signature: ResponseSignatureRequirement,
) -> Result<PreparedMessage, SamlError> {
    let verification = verify_embedded_signature(&xml, opts)?;
    let response_signature_required = response_signature_is_required(response_signature, &xml)?;
    let key = encrypted_assertion_key(root, parser_type, opts);
    let verified = match (verification, key) {
        (SignatureVerification::Absent | SignatureVerification::Unverified, Some(key))
            if !response_signature_required =>
        {
            return prepare_decrypted_then_verified(
                &xml,
                key,
                parser_type,
                opts,
                assertion_signature,
            );
        }
        (verification, _) => verification.require_verified()?,
    };
    if response_signature_required && !verified.response_covered() {
        return Err(SamlError::SignedReferenceMismatch);
    }
    let Some(key) = key else {
        return prepare_verified(xml, verified, parser_type, assertion_signature);
    };
    let signed_content = if verified.response_covered() {
        xml.as_str()
    } else {
        verified.content()
    };
    prepare_verified_then_decrypted(
        signed_content,
        &verified,
        root,
        key,
        parser_type,
        opts,
        assertion_signature,
    )
}

fn prepare_decrypted_then_verified(
    xml: &str,
    key: &str,
    parser_type: ParserType,
    opts: &FlowOptions<'_>,
    assertion_signature: AssertionSignatureRequirement,
) -> Result<PreparedMessage, SamlError> {
    let (content, _) = decrypt_assertions(xml, key, parser_type, opts)?;
    let verified = verify_embedded_signature(&content, opts)?.require_verified()?;
    meet_assertion_signature_requirement(assertion_signature, &verified)?;
    Ok(PreparedMessage {
        saml_content: content,
        verified_xml_signatures: xml_signature_evidence(verified.signatures()),
        assertion: Some(verified.into_content()),
        authentication: MessageAuthentication::Unauthenticated,
    })
}

fn prepare_verified_then_decrypted(
    signed_content: &str,
    verified: &VerifiedSignedContent,
    root: &Node,
    key: &str,
    parser_type: ParserType,
    opts: &FlowOptions<'_>,
    assertion_signature: AssertionSignatureRequirement,
) -> Result<PreparedMessage, SamlError> {
    let (content, assertions) = decrypt_assertions(signed_content, key, parser_type, opts)?;
    let assertion = first_login_assertion_xml(&content, opts.xml_limits)?;
    if root.child_named("Assertion").is_some() {
        meet_assertion_signature_requirement(assertion_signature, verified)?;
    }
    let mut verified_xml_signatures = xml_signature_evidence(verified.signatures());
    verify_decrypted_assertions(
        &assertions,
        assertion.as_deref(),
        assertion_signature,
        opts,
        &mut verified_xml_signatures,
    )?;
    Ok(PreparedMessage {
        assertion,
        saml_content: content,
        authentication: response_authentication(verified),
        verified_xml_signatures,
    })
}

fn prepare_verified(
    xml: String,
    verified: VerifiedSignedContent,
    parser_type: ParserType,
    assertion_signature: AssertionSignatureRequirement,
) -> Result<PreparedMessage, SamlError> {
    meet_assertion_signature_requirement(assertion_signature, &verified)?;
    let verified_xml_signatures = xml_signature_evidence(verified.signatures());
    match parser_type {
        ParserType::SamlResponse => Ok(PreparedMessage {
            saml_content: xml,
            authentication: response_authentication(&verified),
            assertion: Some(verified.into_content()),
            verified_xml_signatures,
        }),
        ParserType::SamlRequest
        | ParserType::LogoutRequest
        | ParserType::LogoutResponse
        | ParserType::ManageNameIdRequest
        | ParserType::ManageNameIdResponse => Ok(PreparedMessage {
            saml_content: verified.into_content(),
            assertion: None,
            authentication: MessageAuthentication::Authenticated,
            verified_xml_signatures,
        }),
    }
}
