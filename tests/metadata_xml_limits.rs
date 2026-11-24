use saml_rs::metadata::{IdpMetadata, Metadata, SpMetadata};
use saml_rs::{ResourceLimit, SamlError, XmlPolicy};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const DOCUMENTED_DEFAULT_MAX_BYTES: usize = 1024 * 1024;

fn dual_role_metadata(padding: usize) -> String {
    format!(
        concat!(
            r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://example.com/metadata">{}"#,
            r#"<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">"#,
            r#"<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://example.com/sso"/>"#,
            r#"</IDPSSODescriptor>"#,
            r#"<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">"#,
            r#"<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com/acs" index="0"/>"#,
            r#"</SPSSODescriptor>"#,
            r#"</EntityDescriptor>"#,
        ),
        " ".repeat(padding)
    )
}

fn policy_with_max_bytes(max_bytes: usize) -> XmlPolicy {
    let mut policy = XmlPolicy::default();
    policy.limits.max_bytes = max_bytes;
    policy
}

fn default_constructors(xml: &str) -> [(&'static str, Result<(), SamlError>); 3] {
    [
        ("Metadata::parse", Metadata::parse(xml).map(drop)),
        (
            "IdpMetadata::from_xml",
            IdpMetadata::from_xml(xml).map(drop),
        ),
        ("SpMetadata::from_xml", SpMetadata::from_xml(xml).map(drop)),
    ]
}

fn policy_constructors(
    xml: &str,
    policy: &XmlPolicy,
) -> [(&'static str, Result<(), SamlError>); 3] {
    [
        (
            "Metadata::parse_with_policy",
            Metadata::parse_with_policy(xml, policy).map(drop),
        ),
        (
            "IdpMetadata::from_xml_with_policy",
            IdpMetadata::from_xml_with_policy(xml, policy).map(drop),
        ),
        (
            "SpMetadata::from_xml_with_policy",
            SpMetadata::from_xml_with_policy(xml, policy).map(drop),
        ),
    ]
}

fn expect_xml_bytes_limit(
    constructor: &str,
    result: Result<(), SamlError>,
    expected_maximum: usize,
) -> TestResult {
    match result {
        Err(SamlError::LimitExceeded {
            limit: ResourceLimit::XmlBytes,
            maximum,
            ..
        }) if maximum == expected_maximum => Ok(()),
        other => Err(format!(
            "{constructor}: expected an XmlBytes limit of {expected_maximum}, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn default_constructors_reject_metadata_over_one_mebibyte() -> TestResult {
    let xml = dual_role_metadata(DOCUMENTED_DEFAULT_MAX_BYTES);
    for (constructor, result) in default_constructors(&xml) {
        expect_xml_bytes_limit(constructor, result, DOCUMENTED_DEFAULT_MAX_BYTES)?;
    }
    Ok(())
}

#[test]
fn policy_constructors_parse_metadata_up_to_a_raised_byte_limit() -> TestResult {
    let xml = dual_role_metadata(DOCUMENTED_DEFAULT_MAX_BYTES);
    let policy = policy_with_max_bytes(xml.len());
    for (constructor, result) in policy_constructors(&xml, &policy) {
        result.map_err(|error| format!("{constructor}: {error:?}"))?;
    }
    Ok(())
}

#[test]
fn policy_constructors_reject_metadata_one_byte_over_a_lowered_byte_limit() -> TestResult {
    let xml = dual_role_metadata(0);
    let maximum = xml.len() - 1;
    let policy = policy_with_max_bytes(maximum);
    for (constructor, result) in policy_constructors(&xml, &policy) {
        expect_xml_bytes_limit(constructor, result, maximum)?;
    }
    Ok(())
}
