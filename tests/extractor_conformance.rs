//! Historical regression cases derived from npm `samlify` extractor tests.

use saml_rs::util::Value;
use saml_rs::xml::{extract, ExtractorField};

const RESPONSE: &str = include_str!("fixtures/misc/response_signed.xml");
const SPMETA: &str = include_str!("fixtures/misc/spmeta.xml");

#[test]
fn fetch_multiple_attributes() -> Result<(), Box<dyn std::error::Error>> {
    let r = extract(
        RESPONSE,
        &[ExtractorField::new("response", &["Response"]).attrs(&["ID", "Destination"])],
    )?;
    assert_eq!(
        r.get_str("response.id"),
        Some("_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6")
    );
    assert_eq!(
        r.get_str("response.destination"),
        Some("http://sp.example.com/demo1/index.php?acs")
    );
    Ok(())
}

#[test]
fn fetch_single_attributes() -> Result<(), Box<dyn std::error::Error>> {
    let r = extract(
        RESPONSE,
        &[
            ExtractorField::new("statusCode", &["Response", "Status", "StatusCode"])
                .attrs(&["Value"]),
        ],
    )?;
    assert_eq!(
        r.get_str("statusCode"),
        Some("urn:oasis:names:tc:SAML:2.0:status:Success")
    );
    Ok(())
}

#[test]
fn fetch_inner_context_of_leaf_node() -> Result<(), Box<dyn std::error::Error>> {
    let r = extract(
        RESPONSE,
        &[ExtractorField::new(
            "audience",
            &[
                "Response",
                "Assertion",
                "Conditions",
                "AudienceRestriction",
                "Audience",
            ],
        )],
    )?;
    assert_eq!(
        r.get_str("audience"),
        Some("https://sp.example.com/metadata")
    );
    Ok(())
}

#[test]
fn fetch_entire_context_of_non_existing_node() -> Result<(), Box<dyn std::error::Error>> {
    let r = extract(
        RESPONSE,
        &[ExtractorField::new(
            "assertionSignature",
            &["Response", "Assertion", "Signature"],
        )
        .with_context()],
    )?;
    assert!(r
        .get("assertionSignature")
        .map(Value::is_null)
        .unwrap_or(false));
    Ok(())
}

#[test]
fn fetch_entire_context_of_existing_node() -> Result<(), Box<dyn std::error::Error>> {
    let r = extract(
        RESPONSE,
        &[ExtractorField::new("messageSignature", &["Response", "Signature"]).with_context()],
    )?;
    assert!(!r
        .get("messageSignature")
        .map(Value::is_null)
        .unwrap_or(true));
    Ok(())
}

#[test]
fn fetch_unique_inner_context_of_multiple_nodes() -> Result<(), Box<dyn std::error::Error>> {
    let r = extract(
        RESPONSE,
        &[ExtractorField::multi(
            "issuer",
            &[
                &["Response", "Issuer"],
                &["Response", "Assertion", "Issuer"],
            ],
        )],
    )?;
    let issuer = r.get("issuer").and_then(Value::as_array).unwrap_or(&[]);
    assert_eq!(issuer.len(), 1);
    assert!(issuer
        .iter()
        .all(|i| i.as_str() == Some("https://idp.example.com/metadata")));
    Ok(())
}

#[test]
fn fetch_attribute_with_wildcard_local_path() -> Result<(), Box<dyn std::error::Error>> {
    let r = extract(
        SPMETA,
        &[ExtractorField::new(
            "certificate",
            &["EntityDescriptor", "~SSODescriptor", "KeyDescriptor"],
        )
        .aggregate(&["use"], &["KeyInfo", "X509Data", "X509Certificate"])],
    )?;
    assert!(r.get_str("certificate.signing").is_some());
    assert!(r.get_str("certificate.encryption").is_some());
    Ok(())
}

#[test]
fn fetch_attribute_with_non_wildcard_local_path() -> Result<(), Box<dyn std::error::Error>> {
    let r = extract(
        RESPONSE,
        &[ExtractorField::new(
            "attributes",
            &["Response", "Assertion", "AttributeStatement", "Attribute"],
        )
        .aggregate(&["Name"], &["AttributeValue"])],
    )?;
    assert_eq!(r.get_str("attributes.uid"), Some("test"));
    assert_eq!(r.get_str("attributes.mail"), Some("test@example.com"));
    assert_eq!(
        r.get("attributes.eduPersonAffiliation")
            .and_then(Value::as_array)
            .map(<[_]>::len),
        Some(2)
    );
    Ok(())
}

#[test]
fn fetch_one_attribute_as_key_another_as_value() -> Result<(), Box<dyn std::error::Error>> {
    let r = extract(
        SPMETA,
        &[ExtractorField::new(
            "singleSignOnService",
            &[
                "EntityDescriptor",
                "~SSODescriptor",
                "AssertionConsumerService",
            ],
        )
        .aggregate(&["Binding"], &[])
        .attrs(&["Location"])],
    )?;
    let sso = r.get("singleSignOnService").ok_or("missing sso")?;
    assert_eq!(
        sso.get_key("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
            .and_then(Value::as_str),
        Some("https://sp.example.org/sp/sso")
    );
    assert_eq!(
        sso.get_key("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact")
            .and_then(Value::as_str),
        Some("https://sp.example.org/sp/sso")
    );
    Ok(())
}
