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
            idp.single_sign_on_service(SsoRequestBinding::Post)?,
            "https://peer.example.com/sso",
        ),
        (
            sp.assertion_consumer_service(SsoResponseBinding::Post)?,
            "https://peer.example.com/acs/default",
        ),
        (
            idp.single_logout_service(LogoutBinding::Post)?,
            "https://peer.example.com/idp/logout",
        ),
        (
            idp.single_logout_response_service(LogoutBinding::Post)?,
            "https://peer.example.com/idp/response",
        ),
        (
            sp.single_logout_service(LogoutBinding::Post)?,
            "https://peer.example.com/sp/logout",
        ),
        (
            sp.single_logout_response_service(LogoutBinding::Post)?,
            "https://peer.example.com/sp/logout",
        ),
    ] {
        assert_eq!(selected, Some(EndpointUrl::try_new(expected)?));
    }
    assert_eq!(
        idp.single_sign_on_service(SsoRequestBinding::Redirect)?,
        None
    );
    assert_eq!(
        sp.assertion_consumer_service(SsoResponseBinding::Artifact)?,
        None
    );
    assert_eq!(idp.single_logout_service(LogoutBinding::Soap)?, None);
    assert_eq!(
        sp.single_logout_response_service(LogoutBinding::Soap)?,
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
    for selected in [
        idp.single_sign_on_service(SsoRequestBinding::Post),
        sp.assertion_consumer_service(SsoResponseBinding::Post),
        idp.single_logout_service(LogoutBinding::Post),
        idp.single_logout_response_service(LogoutBinding::Post),
        sp.single_logout_service(LogoutBinding::Post),
        sp.single_logout_response_service(LogoutBinding::Post),
    ] {
        assert!(
            matches!(selected, Err(SamlError::Invalid(_))),
            "{selected:?}"
        );
    }
    Ok(())
}
