//! Processing restrictions and content coverage at public XML verification entry points.
#![cfg(crypto)]

use saml_rs::binding::base64_encode;
use saml_rs::constants::ParserType;
use saml_rs::crypto::keys::load_private_key;
use saml_rs::crypto::{
    verify_signature, verify_signature_with_limits, BergshamraBackend, XmlSecurityBackend,
};
use saml_rs::error::ReferenceResolutionReason;
use saml_rs::raw::{flow, Binding, FlowOptions, HttpRequest};
use saml_rs::xml::dom::XmlLimits;
use saml_rs::{SamlError, XmlSignatureProfile};

const KEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const SUCCESS_STATUS: &str = r#"<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>"#;
const C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

fn signature(uri: &str) -> String {
    format!(
        r#"<ds:Signature xmlns:ds="{DSIG}"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{C14N}"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="{uri}"><ds:Transforms><ds:Transform Algorithm="{DSIG}enveloped-signature"/><ds:Transform Algorithm="{C14N}"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>"#
    )
}

fn message(root: &str, signature: &str, children: &str) -> String {
    format!(
        r#"<samlp:{root} xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="_root" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer>{signature}{children}</samlp:{root}>"#
    )
}

fn sign(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut keys = bergshamra::KeysManager::new();
    keys.add_key(load_private_key(KEY, None)?);
    Ok(bergshamra::sign(
        &bergshamra::DsigContext::new(keys).with_insecure(true),
        &xml.replace(">AAAA<", "><"),
    )?)
}

fn verify_flow(xml: &str, profile: XmlSignatureProfile) -> Result<(), SamlError> {
    let certs = [CERT.to_string()];
    let mut options = FlowOptions::default();
    options.binding = Some(Binding::Post);
    options.parser_type = Some(ParserType::SamlResponse);
    options.check_signature = true;
    options.signing_certs = &certs;
    options.xml_signatures = profile;
    flow(
        &options,
        &HttpRequest::post(vec![("SAMLResponse".into(), base64_encode(xml.as_bytes()))]),
    )
    .map(|_| ())
}

#[test]
fn public_verifiers_reject_a_signature_covering_only_a_sibling_object(
) -> Result<(), Box<dyn std::error::Error>> {
    for root in ["ArtifactResolve", "ManageNameIDRequest", "Response"] {
        let xml = sign(&message(
            root,
            &signature("#_payload"),
            r#"<Payload xmlns="urn:example:extension" ID="_payload">signed sibling</Payload>"#,
        ))?;
        for result in [
            verify_signature(&xml, &[CERT.to_string()]).map(|_| ()),
            verify_signature_with_limits(&xml, &[CERT.to_string()], XmlLimits::default())
                .map(|_| ()),
            BergshamraBackend::default().verify_signature(&xml, CERT),
        ] {
            assert!(
                matches!(result, Err(SamlError::SignedReferenceMismatch)),
                "{root}: {result:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn public_verifiers_return_the_covered_root_for_protocol_documents(
) -> Result<(), Box<dyn std::error::Error>> {
    for root in [
        "ArtifactResolve",
        "ManageNameIDRequest",
        "Response",
        "ArtifactResponse",
        "LogoutResponse",
    ] {
        let xml = sign(&message(root, &signature("#_root"), ""))?;
        assert_eq!(
            verify_signature(&xml, &[CERT.to_string()])?,
            (true, Some(xml.clone()))
        );
        BergshamraBackend::default().verify_signature(&xml, CERT)?;
    }
    Ok(())
}

#[test]
fn assertion_only_sso_signature_still_returns_the_assertion(
) -> Result<(), Box<dyn std::error::Error>> {
    let assertion = format!(
        r#"<saml:Assertion ID="_assertion" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer>{}<saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject></saml:Assertion>"#,
        signature("#_assertion")
    );
    let xml = sign(&message("Response", "", &assertion))?;
    let dom = saml_rs::xml::dom::parse(&xml)?;
    let assertion = dom
        .root
        .children
        .iter()
        .find(|node| node.local_name == "Assertion")
        .ok_or("missing assertion")?;
    assert_eq!(
        verify_signature(&xml, &[CERT.to_string()])?,
        (true, Some(xml[assertion.start..assertion.end].into()))
    );
    BergshamraBackend::default().verify_signature(&xml, CERT)?;
    Ok(())
}

#[test]
fn all_signature_processing_preflights_extension_references(
) -> Result<(), Box<dyn std::error::Error>> {
    let extra = signature("Cargo.toml");
    let xml = message(
        "Response",
        &signature("#_root"),
        &format!("<samlp:Extensions>{extra}</samlp:Extensions>{SUCCESS_STATUS}"),
    );
    for profile in [
        XmlSignatureProfile::AllowProviderSupportedForCompatibility,
        XmlSignatureProfile::ExcludeWeakAlgorithms,
        XmlSignatureProfile::StrictRsaSha2,
    ] {
        let result = verify_flow(&xml, profile);
        assert!(
            matches!(
                result,
                Err(SamlError::ReferenceResolution {
                    reason: ReferenceResolutionReason::ExternalReference
                })
            ),
            "{profile:?}: {result:?}"
        );
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn extension_signature_cannot_open_a_local_pipe_before_authentication(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::sync::mpsc;

    let path = format!(".signature-reference-{}.fifo", uuid::Uuid::new_v4());
    let status = std::process::Command::new("mkfifo").arg(&path).status()?;
    assert!(status.success());
    let (opened_tx, opened_rx) = mpsc::channel();
    let writer_path = path.clone();
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        let mut file = OpenOptions::new().write(true).open(writer_path)?;
        let _ = opened_tx.send(());
        file.write_all(b"finite local signature reference fixture")
    });
    let mut extra = signature(&path);
    extra = extra.replace(&format!("<ds:Transforms><ds:Transform Algorithm=\"{DSIG}enveloped-signature\"/><ds:Transform Algorithm=\"{C14N}\"/></ds:Transforms>"), "");
    let xml = message(
        "Response",
        &signature("#_root"),
        &format!("<samlp:Extensions>{extra}</samlp:Extensions>{SUCCESS_STATUS}"),
    );
    let result = verify_flow(
        &xml,
        XmlSignatureProfile::AllowProviderSupportedForCompatibility,
    );
    let opened_before_return = opened_rx.try_recv().is_ok();
    let cleanup_reader = if opened_before_return {
        None
    } else {
        Some(std::fs::File::open(&path)?)
    };
    let writer_result = writer.join().map_err(|_| "pipe writer panicked")?;
    drop(cleanup_reader);
    std::fs::remove_file(path)?;
    writer_result?;
    assert!(
        !opened_before_return,
        "the verifier opened an extension reference before authentication: {result:?}"
    );
    assert!(
        matches!(
            result,
            Err(SamlError::ReferenceResolution {
                reason: ReferenceResolutionReason::ExternalReference
            })
        ),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn first_signature_processing_checks_an_extension_before_an_assertion_candidate(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = message("Response", "", &format!("<samlp:Extensions>{}</samlp:Extensions><saml:Assertion ID=\"_assertion\">{}</saml:Assertion>", signature("Cargo.toml"), signature("#_assertion")));
    let result = verify_signature(&xml, &[CERT.to_string()]);
    assert!(
        matches!(
            result,
            Err(SamlError::ReferenceResolution {
                reason: ReferenceResolutionReason::ExternalReference
            })
        ),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn first_signature_processing_does_not_process_later_extension_signatures(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = sign(&message(
        "Response",
        &signature("#_root"),
        &format!(
            "<samlp:Extensions>{}</samlp:Extensions>",
            signature("Cargo.toml")
        ),
    ))?;
    assert_eq!(
        verify_signature(&xml, &[CERT.to_string()])?,
        (true, Some(xml.clone()))
    );
    let result = verify_flow(
        &xml,
        XmlSignatureProfile::AllowProviderSupportedForCompatibility,
    );
    assert!(
        matches!(
            result,
            Err(SamlError::ReferenceResolution {
                reason: ReferenceResolutionReason::ExternalReference
            })
        ),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn strict_profile_preflights_transforms_on_invalid_extension_signatures(
) -> Result<(), Box<dyn std::error::Error>> {
    for transform in [
        r#"<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>0</ds:XPath></ds:Transform>"#,
        r#"<Transform xmlns="urn:example:other" Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><XPath>0</XPath></Transform>"#,
    ] {
        let extra = signature("#_root")
            .replace(&format!(r#"<ds:Transform Algorithm="{C14N}"/>"#), transform);
        let xml = message(
            "Response",
            &signature("#_root"),
            &format!("<samlp:Extensions>{extra}</samlp:Extensions>{SUCCESS_STATUS}"),
        );
        let result = verify_flow(&xml, XmlSignatureProfile::StrictRsaSha2);
        assert!(
            matches!(result, Err(SamlError::AlgorithmUnsupported)),
            "{result:?}"
        );
    }
    Ok(())
}

#[test]
fn error_response_signature_checks_preflight_extension_references(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = message(
        "Response",
        &signature("#_root"),
        &format!(
            r#"<samlp:Extensions>{}</samlp:Extensions><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/></samlp:Status>"#,
            signature("Cargo.toml")
        ),
    );
    for profile in [
        XmlSignatureProfile::ExcludeWeakAlgorithms,
        XmlSignatureProfile::StrictRsaSha2,
    ] {
        let result = verify_flow(&xml, profile);
        assert!(
            matches!(
                result,
                Err(SamlError::ReferenceResolution {
                    reason: ReferenceResolutionReason::ExternalReference
                })
            ),
            "{profile:?}: {result:?}"
        );
    }
    Ok(())
}

#[test]
fn harmless_invalid_extension_signatures_do_not_reject_a_root_signed_error_response(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = sign(&message(
        "Response",
        &signature("#_root"),
        &format!(
            r#"<samlp:Extensions>{}</samlp:Extensions><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/></samlp:Status>"#,
            signature("#_root")
        ),
    ))?;
    for profile in [
        XmlSignatureProfile::ExcludeWeakAlgorithms,
        XmlSignatureProfile::StrictRsaSha2,
    ] {
        let result = verify_flow(&xml, profile);
        assert!(
            matches!(result, Err(SamlError::StatusNotSuccess { .. })),
            "{profile:?}: {result:?}"
        );
    }
    Ok(())
}
