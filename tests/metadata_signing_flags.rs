use saml_rs::metadata::{IdpMetadata, SpMetadata};
use saml_rs::SamlError;

#[test]
fn rejects_invalid_signing_flags_without_a_schema_validator() {
    for (attribute, value, idp_flag) in [
        ("AuthnRequestsSigned", "TRUE", false),
        ("WantAssertionsSigned", "", false),
        ("WantAuthnRequestsSigned", "yes", true),
    ] {
        let flag = format!(r#"{attribute}="{value}""#);
        let (idp_flags, sp_flags) = if idp_flag { (&*flag, "") } else { ("", &*flag) };
        let xml = format!(
            r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://peer.example.com">
  <IDPSSODescriptor {idp_flags} protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://peer.example.com/sso"/>
  </IDPSSODescriptor>
  <SPSSODescriptor {sp_flags} protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://peer.example.com/acs" index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>"#
        );

        let result = if idp_flag {
            IdpMetadata::from_xml(&xml).map(|_| ())
        } else {
            SpMetadata::from_xml(&xml).map(|_| ())
        };
        assert!(
            matches!(result, Err(SamlError::Invalid(ref message)) if message.contains(attribute)),
            "expected an error naming {attribute}, got {result:?}"
        );
    }
}

#[test]
fn rejects_an_invalid_signing_flag_after_a_true_flag() {
    let xml = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com">
  <SPSSODescriptor AuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0"/>
  </SPSSODescriptor>
  <SPSSODescriptor AuthnRequestsSigned="2" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/second/acs" index="1"/>
  </SPSSODescriptor>
</EntityDescriptor>"#;

    assert!(matches!(
        SpMetadata::from_xml(xml),
        Err(SamlError::Invalid(message)) if message.contains("AuthnRequestsSigned")
    ));
}

#[test]
fn rejects_a_signing_flag_qualified_with_the_metadata_namespace() {
    let xml = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com">
  <SPSSODescriptor md:AuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>"#;

    assert!(matches!(
        SpMetadata::from_xml(xml),
        Err(SamlError::Invalid(message)) if message.contains("AuthnRequestsSigned")
    ));
}

#[test]
fn reads_only_unqualified_signing_flags() -> Result<(), Box<dyn std::error::Error>> {
    let xml = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ext="urn:example:metadata" entityID="https://peer.example.com">
  <IDPSSODescriptor ext:WantAuthnRequestsSigned="2" WantAuthnRequestsSigned="1" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://peer.example.com/sso"/>
  </IDPSSODescriptor>
  <SPSSODescriptor ext:AuthnRequestsSigned="2" AuthnRequestsSigned="1" ext:WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://peer.example.com/acs" index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>"#;

    let idp = IdpMetadata::from_xml(xml)?;
    let sp = SpMetadata::from_xml(xml)?;
    assert_eq!(
        (
            idp.want_authn_requests_signed(),
            sp.authn_requests_signed(),
            sp.want_assertions_signed(),
        ),
        (true, true, false),
    );
    Ok(())
}

#[test]
fn reads_the_first_idp_role_that_specifies_the_signing_flag(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/first/sso"/>
  </IDPSSODescriptor>
  <IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/second/sso"/>
  </IDPSSODescriptor>
  <IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/third/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>"#;

    assert!(IdpMetadata::from_xml(xml)?.want_authn_requests_signed());
    Ok(())
}
