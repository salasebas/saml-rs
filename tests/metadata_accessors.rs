use saml_rs::constants::Binding;
use saml_rs::metadata::Metadata;
use saml_rs::{
    EndpointUrl, EntityId, IdpDescriptor, LogoutBinding, MetadataTrustPolicy, NameIdFormat,
    SamlError, SpDescriptor, SsoRequestBinding, SsoResponseBinding,
};

const XML: &str = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://peer.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://peer.example.com/idp/logout" ResponseLocation="https://peer.example.com/idp/response"/>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://peer.example.com/sso"/>
  </IDPSSODescriptor>
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://peer.example.com/sp/logout"/>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://peer.example.com/acs/first" index="0"/>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://peer.example.com/acs/default" index="1" isDefault="true"/>
  </SPSSODescriptor>
</EntityDescriptor>"#;

#[test]
fn aggregate_import_counts_only_members_of_metadata_groups(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = format!(
        r#"<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:catalog="urn:catalog" cacheDuration="PT1H">
          <Extensions><catalog:EntityDescriptor>{XML}</catalog:EntityDescriptor></Extensions>
          <EntitiesDescriptor>
            <EntityDescriptor entityID="urn:example:member">
              <Extensions><catalog:EntityDescriptor/></Extensions>
              <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.org/sso"/>
              </IDPSSODescriptor>
            </EntityDescriptor>
          </EntitiesDescriptor>
        </EntitiesDescriptor>"#
    );
    assert_eq!(
        Metadata::parse(&xml)?.entity_id(),
        Some("urn:example:member")
    );
    Ok(())
}

#[test]
fn foreign_names_do_not_supply_a_missing_aggregate_member() {
    let xml = r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns="urn:catalog">
      <EntityDescriptor entityID="urn:catalog:entry"/>
      <EntitiesDescriptor><md:EntityDescriptor entityID="urn:catalog:nested"/></EntitiesDescriptor>
    </md:EntitiesDescriptor>"#;
    assert!(
        matches!(Metadata::parse(xml), Err(SamlError::MissingMetadata(name)) if name == "EntityDescriptor")
    );
}

#[test]
fn descriptors_read_entity_id_with_xml_schema_whitespace_collapsed(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = XML.replace(
        "entityID=\"https://peer.example.com\"",
        "entityID=\" &#x9;https://peer.example.com/hosted&#x9;  identity&#xD;&#xA; \"",
    );
    let expected = EntityId::try_new("https://peer.example.com/hosted identity")?;
    let idp =
        IdpDescriptor::from_metadata_xml(expected.clone(), &xml, MetadataTrustPolicy::Unverified)?;
    let sp =
        SpDescriptor::from_metadata_xml(expected.clone(), &xml, MetadataTrustPolicy::Unverified)?;
    assert_eq!(idp.entity_id(), &expected);
    assert_eq!(sp.entity_id(), &expected);
    assert_eq!(idp.metadata_xml(), xml);
    assert_eq!(sp.metadata_xml(), xml);

    let uncollapsed = " \thttps://peer.example.com/hosted\t  identity\r\n ";
    assert_eq!(Metadata::parse(&xml)?.entity_id(), Some(uncollapsed));
    assert!(matches!(
        IdpDescriptor::from_metadata_xml(
            EntityId::try_new(uncollapsed)?,
            &xml,
            MetadataTrustPolicy::Unverified,
        ),
        Err(SamlError::Invalid(_))
    ));
    Ok(())
}

#[test]
fn peer_endpoints_keep_their_role_direction_and_indexed_default(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = IdpDescriptor::from_metadata_xml(
        EntityId::try_new("https://peer.example.com")?,
        XML,
        MetadataTrustPolicy::Unverified,
    )?;
    let sp = SpDescriptor::from_metadata_xml(
        EntityId::try_new("https://peer.example.com")?,
        XML,
        MetadataTrustPolicy::Unverified,
    )?;
    assert_eq!(idp.name_id_formats(), [NameIdFormat::Persistent]);
    assert_eq!(sp.name_id_formats(), [NameIdFormat::Transient]);
    for (selected, expected) in [
        (
            idp.single_sign_on_location(SsoRequestBinding::Post)?,
            "https://peer.example.com/sso",
        ),
        (
            sp.assertion_consumer_location(SsoResponseBinding::Post)?,
            "https://peer.example.com/acs/default",
        ),
        (
            idp.single_logout_location(LogoutBinding::Post)?,
            "https://peer.example.com/idp/logout",
        ),
        (
            idp.single_logout_response_location(LogoutBinding::Post)?,
            "https://peer.example.com/idp/response",
        ),
        (
            sp.single_logout_location(LogoutBinding::Post)?,
            "https://peer.example.com/sp/logout",
        ),
        (
            sp.single_logout_response_location(LogoutBinding::Post)?,
            "https://peer.example.com/sp/logout",
        ),
    ] {
        assert_eq!(selected, Some(EndpointUrl::try_new(expected)?));
    }
    assert_eq!(
        idp.single_sign_on_location(SsoRequestBinding::Redirect)?,
        None
    );
    assert_eq!(
        sp.assertion_consumer_location(SsoResponseBinding::Artifact)?,
        None
    );
    assert_eq!(idp.single_logout_location(LogoutBinding::Soap)?, None);
    assert_eq!(
        sp.single_logout_response_location(LogoutBinding::Soap)?,
        None
    );
    Ok(())
}

#[test]
fn endpoint_access_validates_selected_urls_without_rejecting_metadata_on_import(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = XML.replace("https://peer.example.com/", "ftp://peer.example.com/");
    let idp = IdpDescriptor::from_metadata_xml(
        EntityId::try_new("https://peer.example.com")?,
        &xml,
        MetadataTrustPolicy::Unverified,
    )?;
    let sp = SpDescriptor::from_metadata_xml(
        EntityId::try_new("https://peer.example.com")?,
        &xml,
        MetadataTrustPolicy::Unverified,
    )?;
    for (selected, element) in [
        (
            idp.single_sign_on_location(SsoRequestBinding::Post),
            "SingleSignOnService",
        ),
        (
            sp.assertion_consumer_location(SsoResponseBinding::Post),
            "AssertionConsumerService",
        ),
        (
            idp.single_logout_location(LogoutBinding::Post),
            "SingleLogoutService",
        ),
        (
            idp.single_logout_response_location(LogoutBinding::Post),
            "SingleLogoutService",
        ),
        (
            sp.single_logout_location(LogoutBinding::Post),
            "SingleLogoutService",
        ),
        (
            sp.single_logout_response_location(LogoutBinding::Post),
            "SingleLogoutService",
        ),
    ] {
        let Err(SamlError::Invalid(detail)) = selected else {
            return Err(format!("expected an invalid {element} location, got {selected:?}").into());
        };
        assert!(detail.contains(element), "missing endpoint name: {detail}");
        assert!(
            detail.contains(Binding::from(SsoRequestBinding::Post).urn()),
            "missing binding: {detail}"
        );
    }
    Ok(())
}

const POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const SOAP: &str = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";

fn indexed_endpoint_metadata(acs: &str, ars: &str) -> String {
    format!(
        r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://peer.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <ArtifactResolutionService Binding="{SOAP}" Location="https://peer.example.com/ars" index="0"/>
    {ars}
    <SingleSignOnService Binding="{POST}" Location="https://peer.example.com/sso"/>
  </IDPSSODescriptor>
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService Binding="{POST}" Location="https://peer.example.com/acs" index="0" isDefault="true"/>
    {acs}
  </SPSSODescriptor>
</EntityDescriptor>"#
    )
}

fn acs_metadata(fields: &str) -> String {
    indexed_endpoint_metadata(
        &format!(
            "<AssertionConsumerService {}/>",
            fields.replace("BINDING", POST)
        ),
        "",
    )
}

fn ars_metadata(fields: &str) -> String {
    indexed_endpoint_metadata(
        "",
        &format!(
            "<ArtifactResolutionService {}/>",
            fields.replace("BINDING", SOAP)
        ),
    )
}

#[test]
fn import_refuses_an_indexed_endpoint_with_a_missing_or_malformed_field(
) -> Result<(), Box<dyn std::error::Error>> {
    let entity_id = EntityId::try_new("https://peer.example.com")?;
    for fields in [
        r#"Location="https://peer.example.com/e" index="1""#,
        r#"Binding="BINDING" index="1""#,
        r#"Binding="BINDING" Location="" index="1""#,
        r#"Binding="BINDING" Location="https://peer.example.com/e""#,
        r#"Binding="BINDING" Location="https://peer.example.com/e" index="""#,
        r#"Binding="BINDING" Location="https://peer.example.com/e" index="one""#,
        r#"Binding="BINDING" Location="https://peer.example.com/e" index="1" isDefault="yes""#,
    ] {
        let sp = SpDescriptor::from_metadata_xml(
            entity_id.clone(),
            &acs_metadata(fields),
            MetadataTrustPolicy::Unverified,
        );
        let Err(SamlError::Invalid(detail)) = &sp else {
            return Err(format!("{fields}: expected an invalid ACS, got {sp:?}").into());
        };
        assert!(
            detail.contains("AssertionConsumerService"),
            "{fields}: {detail}"
        );
        let idp = IdpDescriptor::from_metadata_xml(
            entity_id.clone(),
            &ars_metadata(fields),
            MetadataTrustPolicy::Unverified,
        );
        let Err(SamlError::Invalid(detail)) = &idp else {
            return Err(format!("{fields}: expected an invalid ARS, got {idp:?}").into());
        };
        assert!(
            detail.contains("ArtifactResolutionService"),
            "{fields}: {detail}"
        );
    }
    Ok(())
}

#[test]
fn import_keeps_an_indexed_endpoint_with_a_blank_binding_or_location_or_an_index_out_of_range(
) -> Result<(), Box<dyn std::error::Error>> {
    let entity_id = EntityId::try_new("https://peer.example.com")?;
    for (fields, index) in [
        (
            r#"Binding="BINDING" Location="https://peer.example.com/e" index=" 7 " isDefault=" 1 ""#,
            7,
        ),
        (
            r#"Binding="BINDING" Location="https://peer.example.com/e" index="+1" isDefault="false""#,
            1,
        ),
    ] {
        SpDescriptor::from_metadata_xml(
            entity_id.clone(),
            &acs_metadata(fields),
            MetadataTrustPolicy::Unverified,
        )?;
        let ars = ars_metadata(fields);
        IdpDescriptor::from_metadata_xml(entity_id.clone(), &ars, MetadataTrustPolicy::Unverified)?;
        assert_eq!(
            saml_rs::metadata::IdpMetadata::from_xml(&ars)?
                .artifact_resolution_services()?
                .iter()
                .map(|service| (service.index(), service.location()))
                .collect::<Vec<_>>(),
            [
                (0, "https://peer.example.com/ars"),
                (index, "https://peer.example.com/e")
            ],
            "{fields}"
        );
    }

    for fields in [
        r#"Binding="" Location="https://peer.example.com/e" index="1""#,
        r#"Binding=" &#x9; " Location="https://peer.example.com/e" index="1""#,
        r#"Binding="BINDING" Location=" &#x9; " index="1""#,
        r#"Binding="BINDING" Location="https://peer.example.com/e" index="-1""#,
        r#"Binding="BINDING" Location="https://peer.example.com/e" index="65536""#,
    ] {
        SpDescriptor::from_metadata_xml(
            entity_id.clone(),
            &acs_metadata(fields),
            MetadataTrustPolicy::Unverified,
        )
        .map_err(|error| format!("{fields}: {error}"))?;
        let ars = ars_metadata(fields);
        IdpDescriptor::from_metadata_xml(entity_id.clone(), &ars, MetadataTrustPolicy::Unverified)
            .map_err(|error| format!("{fields}: {error}"))?;
        let services =
            saml_rs::metadata::IdpMetadata::from_xml(&ars)?.artifact_resolution_services();
        assert!(
            matches!(services, Err(SamlError::Invalid(_))),
            "{fields}: {services:?}"
        );
    }
    Ok(())
}
