#![cfg(crypto)]

use std::collections::HashSet;

use super::identifier_formats::{
    accept_peer_attribute_statement, alice, exchange, respond, values,
};
use saml_rs::{
    Attribute, AttributeNameFormat, AttributeValue, Attributes, PairwiseId, RespondSso, SamlError,
    SsoAssertion, SubjectId,
};

const SUBJECT_ID: &str = "urn:oasis:names:tc:SAML:attribute:subject-id";
const PAIRWISE_ID: &str = "urn:oasis:names:tc:SAML:attribute:pairwise-id";
const URI: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
const UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified";
const BASIC: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";
const MAIL_OID: &str = "urn:oid:0.9.2342.19200300.100.1.3";

fn statement(attributes: &str) -> String {
    format!("<saml:AttributeStatement>{attributes}</saml:AttributeStatement>")
}

fn uri_attribute(name: &str, values: &[&str]) -> String {
    let values: String = values
        .iter()
        .map(|value| format!("<saml:AttributeValue>{value}</saml:AttributeValue>"))
        .collect();
    format!("<saml:Attribute Name=\"{name}\" NameFormat=\"{URI}\">{values}</saml:Attribute>")
}

#[test]
fn subject_identifiers_accept_the_profile_syntax() -> Result<(), Box<dyn std::error::Error>> {
    let longest_unique_id = format!("a{}", "=".repeat(126));
    let longest_scope = format!("b{}", ".".repeat(126));
    for (value, unique_id, scope) in [
        ("a@b".to_string(), "a", "b"),
        (
            format!("{longest_unique_id}@{longest_scope}"),
            longest_unique_id.as_str(),
            longest_scope.as_str(),
        ),
        ("9A=-z@Y-.0".to_string(), "9A=-z", "Y-.0"),
        ("alice@example..org".to_string(), "alice", "example..org"),
    ] {
        let subject_id = SubjectId::try_new(value.clone())?;
        assert_eq!(
            (
                subject_id.as_str(),
                subject_id.unique_id(),
                subject_id.scope()
            ),
            (value.as_str(), unique_id, scope)
        );
        let pairwise_id = PairwiseId::try_new(value.clone())?;
        assert_eq!(
            (
                pairwise_id.as_str(),
                pairwise_id.unique_id(),
                pairwise_id.scope()
            ),
            (value.as_str(), unique_id, scope)
        );
    }
    Ok(())
}

#[test]
fn subject_identifiers_reject_values_outside_the_profile_syntax() {
    for value in [
        String::new(),
        "alice".into(),
        "@example.org".into(),
        "alice@".into(),
        format!("{}@example.org", "a".repeat(128)),
        format!("alice@{}", "b".repeat(128)),
        "=alice@example.org".into(),
        "-alice@example.org".into(),
        "alice@.example.org".into(),
        "alice@-example.org".into(),
        "alice.smith@example.org".into(),
        "alice_smith@example.org".into(),
        "alice@example=org".into(),
        "alice@ex@mple.org".into(),
        "élise@example.org".into(),
        " alice@example.org".into(),
        "alice@example.org\n".into(),
    ] {
        assert!(
            matches!(
                SubjectId::try_new(value.clone()),
                Err(SamlError::Invalid(_))
            ),
            "subject-id {value:?}"
        );
        assert!(
            matches!(
                PairwiseId::try_new(value.clone()),
                Err(SamlError::Invalid(_))
            ),
            "pairwise-id {value:?}"
        );
    }
}

#[test]
fn subject_identifiers_that_differ_only_in_case_are_equal() -> Result<(), Box<dyn std::error::Error>>
{
    let mixed = SubjectId::try_new("IDM123456789@Example.ORG")?;
    let lower = SubjectId::try_new("idm123456789@example.org")?;
    assert_eq!(mixed, lower);
    assert_ne!(mixed, SubjectId::try_new("idm123456780@example.org")?);
    assert_eq!(mixed.as_str(), "IDM123456789@Example.ORG");
    assert!(HashSet::from([mixed]).contains(&lower));

    let pairwise = PairwiseId::try_new("HA2TKNZZ=@osu.edu")?;
    assert_eq!(pairwise, PairwiseId::try_new("ha2tknzz=@OSU.EDU")?);
    assert!(HashSet::from([pairwise]).contains(&PairwiseId::try_new("ha2tknzz=@OSU.EDU")?));
    Ok(())
}

#[test]
fn identity_provider_issues_and_service_provider_reads_both_identifiers(
) -> Result<(), Box<dyn std::error::Error>> {
    let subject_id = SubjectId::try_new("idm123456789@example.com")?;
    let pairwise_id = PairwiseId::try_new("HA2TKNZZGE2TOZDC=@example.com")?;
    let attributes = Attributes::new([
        Attribute::from(subject_id.clone()),
        Attribute::from(pairwise_id.clone()),
        Attribute::new(MAIL_OID, values(&["a@example.com"]))
            .with_name_format(AttributeNameFormat::Uri),
    ]);

    let exchange = exchange(
        SsoAssertion::new(alice()).attributes(attributes),
        RespondSso::post().sign_response(),
    )?;

    for (name, value) in [
        (SUBJECT_ID, subject_id.as_str()),
        (PAIRWISE_ID, pairwise_id.as_str()),
    ] {
        let element = format!(
            "<saml:Attribute Name=\"{name}\" NameFormat=\"{URI}\">\
             <saml:AttributeValue>{value}</saml:AttributeValue></saml:Attribute>"
        );
        assert!(
            exchange.xml.contains(&element),
            "{element} in {}",
            exchange.xml
        );
    }
    assert_eq!(exchange.session.subject_id()?, Some(subject_id));
    assert_eq!(exchange.session.pairwise_id()?, Some(pairwise_id));
    Ok(())
}

#[test]
fn service_provider_reads_an_identifier_with_the_uri_or_unspecified_name_format_or_none(
) -> Result<(), Box<dyn std::error::Error>> {
    let session = accept_peer_attribute_statement(&statement(&format!(
        "<saml:Attribute Name=\"{SUBJECT_ID}\">\
         <saml:AttributeValue>alice@example.org</saml:AttributeValue></saml:Attribute>\
         <saml:Attribute Name=\"{PAIRWISE_ID}\" NameFormat=\"{UNSPECIFIED}\">\
         <saml:AttributeValue>HA2TKNZZ=@example.org</saml:AttributeValue></saml:Attribute>"
    )))?;
    assert_eq!(
        session.subject_id()?,
        Some(SubjectId::try_new("alice@example.org")?)
    );
    assert_eq!(
        session.pairwise_id()?,
        Some(PairwiseId::try_new("HA2TKNZZ=@example.org")?)
    );

    let session = accept_peer_attribute_statement(&statement(&format!(
        "<saml:Attribute Name=\"{SUBJECT_ID}\" NameFormat=\"{BASIC}\">\
         <saml:AttributeValue>not an identifier</saml:AttributeValue></saml:Attribute>\
         <saml:Attribute Name=\"{PAIRWISE_ID}\" NameFormat=\"https://example.com/format\">\
         <saml:AttributeValue>alice@example.org</saml:AttributeValue></saml:Attribute>"
    )))?;
    assert_eq!(session.subject_id()?, None);
    assert_eq!(session.pairwise_id()?, None);
    Ok(())
}

#[test]
fn service_provider_strips_xml_whitespace_around_an_identifier(
) -> Result<(), Box<dyn std::error::Error>> {
    let session = accept_peer_attribute_statement(&statement(&format!(
        "{}{}",
        uri_attribute(SUBJECT_ID, &["\n  idm123@example.org \t"]),
        uri_attribute(PAIRWISE_ID, &["\r\nHA2TKNZZ=@example.org\n"]),
    )))?;

    let subject_id = session.subject_id()?.ok_or("missing subject-id")?;
    assert_eq!(
        (subject_id.unique_id(), subject_id.scope()),
        ("idm123", "example.org")
    );
    let pairwise_id = session.pairwise_id()?.ok_or("missing pairwise-id")?;
    assert_eq!(pairwise_id.as_str(), "HA2TKNZZ=@example.org");
    Ok(())
}

#[test]
fn service_provider_reports_a_malformed_identifier_as_an_error(
) -> Result<(), Box<dyn std::error::Error>> {
    for attributes in [
        format!("<saml:Attribute Name=\"{SUBJECT_ID}\" NameFormat=\"{URI}\"/>"),
        uri_attribute(SUBJECT_ID, &["alice@example.org", "bob@example.org"]),
        format!(
            "{}{}",
            uri_attribute(SUBJECT_ID, &["alice@example.org"]),
            uri_attribute(SUBJECT_ID, &["bob@example.org"])
        ),
        uri_attribute(SUBJECT_ID, &["alice.smith@example.org"]),
        uri_attribute(SUBJECT_ID, &["alice"]),
        format!(
            "{}<saml:Attribute Name=\"{SUBJECT_ID}\">\
             <saml:AttributeValue>bob@example.org</saml:AttributeValue></saml:Attribute>",
            uri_attribute(SUBJECT_ID, &["alice@example.org"])
        ),
    ] {
        let session = accept_peer_attribute_statement(&statement(&attributes))?;
        assert!(
            matches!(session.subject_id(), Err(SamlError::ProtocolProfile(_))),
            "{attributes}"
        );
        assert_eq!(session.pairwise_id()?, None, "{attributes}");
    }
    let session = accept_peer_attribute_statement(&statement(&uri_attribute(
        PAIRWISE_ID,
        &["HA2TKNZZ+/@example.org"],
    )))?;
    assert!(matches!(
        session.pairwise_id(),
        Err(SamlError::ProtocolProfile(_))
    ));
    Ok(())
}

#[test]
fn identity_provider_does_not_issue_an_identifier_attribute_that_breaks_the_profile(
) -> Result<(), Box<dyn std::error::Error>> {
    let identifier = |name: &str, values: &[&str]| {
        Attribute::new(name, values.iter().copied().map(AttributeValue::new))
            .with_name_format(AttributeNameFormat::Uri)
    };
    for attributes in [
        vec![identifier(SUBJECT_ID, &[])],
        vec![identifier(
            SUBJECT_ID,
            &["alice@example.org", "bob@example.org"],
        )],
        vec![
            identifier(PAIRWISE_ID, &["alice@example.org"]),
            identifier(PAIRWISE_ID, &["bob@example.org"]),
        ],
        vec![identifier(SUBJECT_ID, &["alice.smith@example.org"])],
        vec![identifier(PAIRWISE_ID, &["alice@Example.org"])],
        vec![identifier(SUBJECT_ID, &["Alice@example.org"])],
        vec![Attribute::from(SubjectId::try_new("alice@EXAMPLE.ORG")?)],
        vec![Attribute::new(SUBJECT_ID, values(&["alice@example.org"]))],
        vec![Attribute::new(PAIRWISE_ID, values(&["alice@example.org"]))
            .with_name_format(AttributeNameFormat::Unspecified)],
        vec![
            identifier(PAIRWISE_ID, &["alice@example.org"]),
            Attribute::new(PAIRWISE_ID, values(&["bob@example.org"]))
                .with_name_format(AttributeNameFormat::Unspecified),
        ],
    ] {
        match respond(
            SsoAssertion::new(alice()).attributes(Attributes::new(attributes.clone())),
            RespondSso::post(),
        ) {
            Err(SamlError::Invalid(_)) => {}
            other => {
                return Err(format!("expected an error for {attributes:?}, got {other:?}").into())
            }
        }
    }
    for attributes in [
        vec![identifier(PAIRWISE_ID, &["HA2TKNZZ=@example.org"])],
        vec![
            identifier(SUBJECT_ID, &["alice@example.org"]),
            identifier(PAIRWISE_ID, &["alice@example.org"]),
        ],
        vec![
            Attribute::new(SUBJECT_ID, values(&["alice.smith@Example.org", "bob"]))
                .with_name_format(AttributeNameFormat::Basic),
        ],
    ] {
        respond(
            SsoAssertion::new(alice()).attributes(Attributes::new(attributes)),
            RespondSso::post(),
        )?;
    }
    Ok(())
}
