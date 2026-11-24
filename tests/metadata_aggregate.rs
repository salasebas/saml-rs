use saml_rs::{EntityId, MetadataAggregate, MetadataTrustPolicy, SamlError, XmlLimits};

const FEDERATION: &str = include_str!("fixtures/metadata/federation-aggregate.xml");

#[test]
fn federation_import_distinguishes_missing_ids_from_duplicate_ids(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp_id = EntityId::try_new("https://sp.example.com/metadata")?;
    let absent_id = EntityId::try_new("https://missing.example.com/metadata")?;
    let xml = FEDERATION.replacen(
        "https://other.example.com/metadata",
        " https://sp.example.com/metadata ",
        1,
    );
    let aggregate =
        MetadataAggregate::from_xml(&xml, MetadataTrustPolicy::Unverified, XmlLimits::default())?;

    assert!(matches!(
        aggregate.idp_descriptor(&absent_id),
        Err(SamlError::MetadataEntityNotFound { entity_id, .. }) if entity_id == absent_id
    ));
    assert!(matches!(
        aggregate.sp_descriptor(&sp_id),
        Err(SamlError::DuplicateMetadataEntity { entity_id, .. }) if entity_id == sp_id
    ));
    let idp = aggregate.idp_descriptor(&EntityId::try_new("https://idp.example.com/metadata")?)?;
    assert!(idp.signed_metadata_xml().is_none());
    Ok(())
}

#[test]
fn federation_import_requires_a_metadata_group_root() {
    for xml in [
        r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/metadata"/>"#,
        r#"<EntitiesDescriptor xmlns="urn:example:extension"/>"#,
    ] {
        assert!(matches!(
            MetadataAggregate::from_xml(xml, MetadataTrustPolicy::Unverified, XmlLimits::default()),
            Err(SamlError::MissingMetadata(element)) if element == "EntitiesDescriptor"
        ));
    }
}

#[test]
fn entity_descriptors_outside_metadata_groups_are_not_aggregate_members(
) -> Result<(), Box<dyn std::error::Error>> {
    let extension = FEDERATION.replacen(
        "<md:Extensions>",
        r#"<md:Extensions><custom:Extension xmlns:custom="urn:example:extension">
            <md:EntityDescriptor entityID="https://idp.example.com/metadata"/>
        </custom:Extension>"#,
        1,
    );
    let foreign_members = FEDERATION.replacen(
        "<md:EntityDescriptor",
        r#"<EntityDescriptor xmlns="urn:example:extension" entityID="https://idp.example.com/metadata"/>
        <EntitiesDescriptor xmlns="urn:example:extension">
            <md:EntityDescriptor entityID="https://sp.example.com/metadata"/>
        </EntitiesDescriptor>
        <md:EntityDescriptor"#,
        1,
    );
    let idp = EntityId::try_new("https://idp.example.com/metadata")?;
    let sp = EntityId::try_new("https://sp.example.com/metadata")?;
    for xml in [extension, foreign_members] {
        let aggregate = MetadataAggregate::from_xml(
            &xml,
            MetadataTrustPolicy::Unverified,
            XmlLimits::default(),
        )?;
        aggregate.idp_descriptor(&idp)?;
        aggregate.sp_descriptor(&sp)?;
    }
    Ok(())
}
