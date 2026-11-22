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
fn peer_endpoints_keep_their_role_direction_and_indexed_default(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = IdpDescriptor::from_metadata_xml(
        EntityId::try_new("https://peer.example.com")?,
        XML,
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let sp = SpDescriptor::from_metadata_xml(
        EntityId::try_new("https://peer.example.com")?,
        XML,
        MetadataTrustPolicy::AllowUnsigned,
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
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let sp = SpDescriptor::from_metadata_xml(
        EntityId::try_new("https://peer.example.com")?,
        &xml,
        MetadataTrustPolicy::AllowUnsigned,
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
