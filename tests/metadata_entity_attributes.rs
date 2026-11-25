#[path = "common/policies_without_crypto.rs"]
mod policies_without_crypto;

use policies_without_crypto::sp_validation_without_crypto;

use saml_rs::constants::entity_attribute::{
    ASSURANCE_CERTIFICATION, ENTITY_CATEGORY, ENTITY_CATEGORY_SUPPORT, SUBJECT_ID_REQUIREMENT,
};
use saml_rs::constants::Binding;
use saml_rs::metadata::{generate_sp_metadata, Endpoint, Metadata, SpMetadataInput};
use saml_rs::{
    AcsEndpoint, Attribute, AttributeNameFormat, AttributeValue, EntityAttributes, EntityId,
    IdentityProvider, IdpConfig, IdpDescriptor, MetadataTrustPolicy, SamlError, ServiceProvider,
    SpConfig, SpDescriptor, SsoEndpoint, SubjectIdRequirement,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SP: &str = "https://sp.example.com/metadata";
const IDP: &str = "https://idp.example.com/metadata";
const RESEARCH_AND_SCHOLARSHIP: &str = "http://refeds.org/category/research-and-scholarship";
const SIRTFI: &str = "https://refeds.org/sirtfi";
const NAMESPACES: &str = r#"xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion""#;
const SP_ROLE: &str = r#"<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><AssertionConsumerService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs"/></SPSSODescriptor>"#;
const IDP_ROLE: &str = r#"<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso"/></IDPSSODescriptor>"#;

fn uri_attribute(name: &str, values: &[&str]) -> Attribute {
    Attribute::new(name, values.iter().copied().map(AttributeValue::new))
        .with_name_format(AttributeNameFormat::Uri)
}

fn attribute_xml(name: &str, name_format: Option<&str>, values: &[&str]) -> String {
    let name_format = name_format
        .map(|name_format| format!(r#" NameFormat="{name_format}""#))
        .unwrap_or_default();
    let values: String = values
        .iter()
        .map(|value| format!("<saml:AttributeValue>{value}</saml:AttributeValue>"))
        .collect();
    format!(r#"<saml:Attribute Name="{name}"{name_format}>{values}</saml:Attribute>"#)
}

fn uri_attribute_xml(name: &str, values: &[&str]) -> String {
    attribute_xml(
        name,
        Some("urn:oasis:names:tc:SAML:2.0:attrname-format:uri"),
        values,
    )
}

fn extensions(attributes: &str) -> String {
    format!(
        "<Extensions><mdattr:EntityAttributes>{attributes}</mdattr:EntityAttributes></Extensions>"
    )
}

fn sp_entity(entity_id: &str, extensions: &str) -> String {
    format!(r#"<EntityDescriptor entityID="{entity_id}">{extensions}{SP_ROLE}</EntityDescriptor>"#)
}

fn sp_document(extensions: &str) -> String {
    format!(
        r#"<EntityDescriptor {NAMESPACES} entityID="{SP}">{extensions}{SP_ROLE}</EntityDescriptor>"#
    )
}

fn sp_entity_attributes(xml: &str) -> Result<EntityAttributes, SamlError> {
    SpDescriptor::from_metadata_xml(EntityId::try_new(SP)?, xml, MetadataTrustPolicy::Unverified)?
        .entity_attributes()
}

#[test]
fn imported_sp_reads_the_attributes_of_its_entity_and_enclosing_groups() -> TestResult {
    let federation = uri_attribute_xml(ENTITY_CATEGORY, &["https://federation.example.org/member"]);
    let registrar = uri_attribute_xml(ASSURANCE_CERTIFICATION, &[SIRTFI]);
    let entity = [
        uri_attribute_xml(ENTITY_CATEGORY, &[RESEARCH_AND_SCHOLARSHIP]),
        uri_attribute_xml(SUBJECT_ID_REQUIREMENT, &["pairwise-id"]),
        attribute_xml("urn:example:local", None, &["one", "two"]),
    ]
    .concat();
    let xml = format!(
        r#"<EntitiesDescriptor {NAMESPACES} Name="https://federation.example.org">{}<EntitiesDescriptor Name="https://registrar.example.org">{}{}</EntitiesDescriptor></EntitiesDescriptor>"#,
        extensions(&federation),
        extensions(&registrar),
        sp_entity(SP, &extensions(&entity)),
    );

    let attributes = sp_entity_attributes(&xml)?;

    assert_eq!(
        attributes.as_slice(),
        [
            uri_attribute(ENTITY_CATEGORY, &["https://federation.example.org/member"]),
            uri_attribute(ASSURANCE_CERTIFICATION, &[SIRTFI]),
            uri_attribute(ENTITY_CATEGORY, &[RESEARCH_AND_SCHOLARSHIP]),
            uri_attribute(SUBJECT_ID_REQUIREMENT, &["pairwise-id"]),
            Attribute::new(
                "urn:example:local",
                [AttributeValue::new("one"), AttributeValue::new("two")]
            ),
        ]
    );
    assert_eq!(
        attributes.entity_categories(),
        [
            "https://federation.example.org/member",
            RESEARCH_AND_SCHOLARSHIP
        ]
    );
    assert_eq!(attributes.assurance_certifications(), [SIRTFI]);
    assert_eq!(
        attributes.subject_id_requirement()?,
        Some(SubjectIdRequirement::PairwiseId)
    );
    Ok(())
}

#[test]
fn imported_idp_reads_category_support_and_assurance_certification() -> TestResult {
    let attributes = [
        uri_attribute_xml(ENTITY_CATEGORY_SUPPORT, &[RESEARCH_AND_SCHOLARSHIP]),
        uri_attribute_xml(
            ASSURANCE_CERTIFICATION,
            &[SIRTFI, "https://refeds.org/sirtfi2"],
        ),
    ]
    .concat();
    let xml = format!(
        r#"<EntityDescriptor {NAMESPACES} entityID="{IDP}">{}{IDP_ROLE}</EntityDescriptor>"#,
        extensions(&attributes)
    );

    let attributes = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP)?,
        &xml,
        MetadataTrustPolicy::Unverified,
    )?
    .entity_attributes()?;

    assert_eq!(
        attributes.entity_category_support(),
        [RESEARCH_AND_SCHOLARSHIP]
    );
    assert_eq!(
        attributes.assurance_certifications(),
        [SIRTFI, "https://refeds.org/sirtfi2"]
    );
    assert!(attributes.entity_categories().is_empty());
    Ok(())
}

#[test]
fn only_entity_attributes_bound_to_the_entity_are_read() -> TestResult {
    let bound = uri_attribute_xml(ENTITY_CATEGORY, &[RESEARCH_AND_SCHOLARSHIP]);
    let unbound = uri_attribute_xml(ENTITY_CATEGORY, &["https://unbound.example.org"]);
    let role_extensions = SP_ROLE.replace(
        "<AssertionConsumerService",
        &format!("{}<AssertionConsumerService", extensions(&unbound)),
    );
    let assertion = format!(
        r#"<saml:Assertion ID="_a" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>{SP}</saml:Issuer><saml:AttributeStatement>{unbound}</saml:AttributeStatement></saml:Assertion>"#
    );
    for (case, xml) in [
        (
            "role descriptor Extensions",
            format!(
                r#"<EntityDescriptor {NAMESPACES} entityID="{SP}">{}{role_extensions}</EntityDescriptor>"#,
                extensions(&bound)
            ),
        ),
        (
            "Extensions outside the metadata namespace",
            sp_document(&format!(
                r#"{}<x:Extensions xmlns:x="urn:example:other"><mdattr:EntityAttributes>{unbound}</mdattr:EntityAttributes></x:Extensions>"#,
                extensions(&bound)
            )),
        ),
        (
            "EntityAttributes outside the mdattr namespace",
            sp_document(&format!(
                r#"<Extensions><mdattr:EntityAttributes>{bound}</mdattr:EntityAttributes><x:EntityAttributes xmlns:x="urn:example:other">{unbound}</x:EntityAttributes></Extensions>"#
            )),
        ),
        (
            "Assertion inside EntityAttributes",
            sp_document(&extensions(&format!("{bound}{assertion}"))),
        ),
    ] {
        assert_eq!(
            sp_entity_attributes(&xml)?.entity_categories(),
            [RESEARCH_AND_SCHOLARSHIP],
            "{case}"
        );
    }
    Ok(())
}

#[test]
fn subject_id_requirement_reads_each_profile_value() -> TestResult {
    for (value, expected) in [
        ("subject-id", SubjectIdRequirement::SubjectId),
        ("pairwise-id", SubjectIdRequirement::PairwiseId),
        ("none", SubjectIdRequirement::None),
        ("any", SubjectIdRequirement::Any),
    ] {
        let xml = sp_document(&extensions(&uri_attribute_xml(
            SUBJECT_ID_REQUIREMENT,
            &[value],
        )));
        assert_eq!(
            sp_entity_attributes(&xml)?.subject_id_requirement()?,
            Some(expected),
            "{value}"
        );
    }
    Ok(())
}

#[test]
fn well_known_names_match_the_uri_name_format_or_none() -> TestResult {
    for (name_format, expected) in [
        (None, Some(SubjectIdRequirement::Any)),
        (
            Some("urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"),
            Some(SubjectIdRequirement::Any),
        ),
        (
            Some("urn:oasis:names:tc:SAML:2.0:attrname-format:basic"),
            None,
        ),
    ] {
        let xml = sp_document(&extensions(&attribute_xml(
            SUBJECT_ID_REQUIREMENT,
            name_format,
            &["any"],
        )));
        assert_eq!(
            sp_entity_attributes(&xml)?.subject_id_requirement()?,
            expected,
            "{name_format:?}"
        );
    }
    Ok(())
}

#[test]
fn subject_id_requirement_rejects_what_the_profile_rules_out() -> TestResult {
    for (case, attributes) in [
        (
            "two values",
            uri_attribute_xml(SUBJECT_ID_REQUIREMENT, &["subject-id", "pairwise-id"]),
        ),
        ("no value", uri_attribute_xml(SUBJECT_ID_REQUIREMENT, &[])),
        (
            "unknown value",
            uri_attribute_xml(SUBJECT_ID_REQUIREMENT, &["pairwise"]),
        ),
        (
            "different requirements",
            [
                uri_attribute_xml(SUBJECT_ID_REQUIREMENT, &["subject-id"]),
                uri_attribute_xml(SUBJECT_ID_REQUIREMENT, &["pairwise-id"]),
            ]
            .concat(),
        ),
    ] {
        let attributes = sp_entity_attributes(&sp_document(&extensions(&attributes)))?;
        assert!(
            matches!(
                attributes.subject_id_requirement(),
                Err(SamlError::Invalid(_))
            ),
            "{case}"
        );
    }
    Ok(())
}

#[test]
fn an_attribute_without_name_fails_the_read_but_not_the_import() -> TestResult {
    let xml = sp_document(&extensions(
        "<saml:Attribute><saml:AttributeValue>x</saml:AttributeValue></saml:Attribute>",
    ));
    let metadata = Metadata::parse(&xml)?;
    assert!(matches!(
        metadata.entity_attributes(),
        Err(SamlError::Invalid(_))
    ));
    Ok(())
}

#[test]
fn generated_metadata_publishes_entity_attributes_first() -> TestResult {
    let published = vec![
        uri_attribute(ENTITY_CATEGORY, &[RESEARCH_AND_SCHOLARSHIP]),
        Attribute::from(SubjectIdRequirement::PairwiseId),
        Attribute::new("urn:example:flag", []).with_friendly_name("flag & mark"),
    ];
    let mut input = SpMetadataInput::default();
    input.entity_id = SP.into();
    input.assertion_consumer_services =
        vec![Endpoint::new(Binding::Post, "https://sp.example.com/acs")];
    input.entity_attributes = published.clone();

    let xml = generate_sp_metadata(&input)?;

    let extensions = concat!(
        r#"<Extensions><mdattr:EntityAttributes xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">"#,
        r#"<saml:Attribute Name="http://macedir.org/entity-category" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue>http://refeds.org/category/research-and-scholarship</saml:AttributeValue></saml:Attribute>"#,
        r#"<saml:Attribute Name="urn:oasis:names:tc:SAML:profiles:subject-id:req" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue>pairwise-id</saml:AttributeValue></saml:Attribute>"#,
        r#"<saml:Attribute Name="urn:example:flag" FriendlyName="flag &amp; mark"/>"#,
        r#"</mdattr:EntityAttributes></Extensions><SPSSODescriptor "#,
    );
    let after_root = &xml[xml.find('>').ok_or("no root start tag")? + 1..];
    assert!(after_root.starts_with(extensions), "{xml}");
    assert_eq!(
        Metadata::parse(&xml)?.entity_attributes()?.as_slice(),
        published.as_slice()
    );
    Ok(())
}

#[test]
fn typed_builders_publish_entity_attributes_to_peers() -> TestResult {
    let sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP)?,
            AcsEndpoint::post("https://sp.example.com/acs")?,
        )
        .entity_attribute(SubjectIdRequirement::SubjectId.into())
        .entity_attributes([uri_attribute(ENTITY_CATEGORY, &[RESEARCH_AND_SCHOLARSHIP])])
        .validation(sp_validation_without_crypto())
        .build()?,
    );
    let idp = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP)?,
            SsoEndpoint::post("https://idp.example.com/sso")?,
        )
        .entity_attribute(uri_attribute(
            ENTITY_CATEGORY_SUPPORT,
            &[RESEARCH_AND_SCHOLARSHIP],
        ))
        .entity_attribute(uri_attribute(ASSURANCE_CERTIFICATION, &[SIRTFI]))
        .build()?,
    );

    let sp_peer = sp_entity_attributes(sp.metadata_xml())?;
    let idp_peer = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::Unverified,
    )?
    .entity_attributes()?;

    assert_eq!(
        sp_peer.subject_id_requirement()?,
        Some(SubjectIdRequirement::SubjectId)
    );
    assert_eq!(sp_peer.entity_categories(), [RESEARCH_AND_SCHOLARSHIP]);
    assert_eq!(
        idp_peer.entity_category_support(),
        [RESEARCH_AND_SCHOLARSHIP]
    );
    assert_eq!(idp_peer.assurance_certifications(), [SIRTFI]);
    Ok(())
}

#[test]
fn generation_rejects_entity_attributes_it_cannot_write() -> TestResult {
    for (case, attribute) in [
        (
            "blank FriendlyName",
            uri_attribute(ENTITY_CATEGORY, &[RESEARCH_AND_SCHOLARSHIP]).with_friendly_name(" "),
        ),
        (
            "relative NameFormat",
            Attribute::new(
                ENTITY_CATEGORY,
                [AttributeValue::new(RESEARCH_AND_SCHOLARSHIP)],
            )
            .with_name_format(AttributeNameFormat::Custom("relative".into())),
        ),
        (
            "control character",
            uri_attribute(ENTITY_CATEGORY, &["http://example.org/\u{1}"]),
        ),
    ] {
        let builder = SpConfig::builder(
            EntityId::try_new(SP)?,
            AcsEndpoint::post("https://sp.example.com/acs")?,
        )
        .entity_attribute(attribute)
        .validation(sp_validation_without_crypto());
        assert!(
            matches!(builder.build(), Err(SamlError::Invalid(_))),
            "{case}"
        );
    }
    Ok(())
}
