use super::*;

#[test]
fn detailed_verification_reports_one_signature_covering_response_and_assertion(
) -> Result<(), Box<dyn std::error::Error>> {
    let signed = signature_over_response_and_assertion()?;
    let result = verify_signatures_detailed_with_profile(
        &signed,
        &[SP_SIGNING_CERT.to_string()],
        None,
        XmlLimits::default(),
        XmlSignatureProfile::AllowProviderSupportedForCompatibility,
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

#[cfg(not(feature = "crypto-fips"))]
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
            verify_signatures_detailed_with_profile(
                &xml,
                &[],
                None,
                XmlLimits::default(),
                XmlSignatureProfile::AllowProviderSupportedForCompatibility,
            )
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
        subject_confirmation_wrapping(r#"<Response xmlns="urn:example:not-saml">"#, "</Response>"),
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
        let detailed = verify_signatures_detailed_with_profile(
            &xml,
            &[],
            None,
            XmlLimits::default(),
            XmlSignatureProfile::AllowProviderSupportedForCompatibility,
        )?;
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
        None,
        XmlLimits::default(),
        XmlSignatureProfile::AllowProviderSupportedForCompatibility,
    )?;
    assert!(detailed.verified());
    assert_eq!(detailed.response_covered(), response_covered);
    assert!(!detailed.assertion_directly_covered());
    let detailed_content = detailed.into_signed_content();
    assert_eq!(content.as_deref(), detailed_content.as_deref());
    Ok(content)
}

#[test]
fn logout_and_artifact_responses_keep_signature_coverage() -> Result<(), Box<dyn std::error::Error>>
{
    const NESTED_ASSERTION: &str = r#"<saml:Assertion ID="_nested" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer></saml:Assertion>"#;

    let logout =
        assert_both_verifiers_agree(&signed_protocol_message("LogoutResponse", "")?, true)?;
    let logout = logout.ok_or("expected signed LogoutResponse content")?;
    assert!(logout.contains("LogoutResponse"));

    let logout_assertion = assert_both_verifiers_agree(
        &signed_protocol_message("LogoutResponse", NESTED_ASSERTION)?,
        true,
    )?;
    let logout_assertion = logout_assertion.ok_or("expected LogoutResponse assertion content")?;
    assert!(logout_assertion.starts_with("<saml:Assertion"));
    assert!(!logout_assertion.contains("LogoutResponse"));

    let artifact =
        assert_both_verifiers_agree(&signed_protocol_message("ArtifactResponse", "")?, true)?;
    assert!(artifact
        .ok_or("expected signed ArtifactResponse content")?
        .contains("ArtifactResponse"));

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
    assert!(custom
        .ok_or("expected signed custom root content")?
        .contains("FooResponse"));
    Ok(())
}
#[test]
fn detailed_verification_aggregates_rolling_cert_coverage_after_first_signature_verifies(
) -> Result<(), Box<dyn std::error::Error>> {
    let assertion_key = load_private_key(UNTRUSTED_PRIVKEY, None)?;
    let signed_assertion = construct_saml_signature(
        RESPONSE,
        false,
        &assertion_key,
        IDP_CERT,
        RSA_SHA256,
        &[],
        None,
    )?;
    let response_key = load_private_key(SP_PRIVKEY, None)?;
    let signed_response_and_assertion = construct_saml_signature(
        &signed_assertion,
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
        None,
        XmlLimits::default(),
        XmlSignatureProfile::AllowProviderSupportedForCompatibility,
    )?;
    assert!(result.verified() && result.assertion_directly_covered() && result.response_covered());
    assert_eq!(result.verified_embedded_signatures().len(), 2);
    Ok(())
}
