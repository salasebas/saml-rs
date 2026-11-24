use saml_rs::metadata::IdpMetadata;
use saml_rs::{
    Attribute, EntityId, IdentityProvider, IdpConfig, IdpDescriptor, MetadataScope,
    MetadataTrustPolicy, SamlError, SsoEndpoint,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const IDP: &str = "https://idp.example.org/metadata";
const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";

fn metadata(entity_extensions: &str, roles: &str) -> String {
    format!(
        r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
             xmlns:s="urn:mace:shibboleth:metadata:1.0" xmlns:other="urn:example:other"
             entityID="{IDP}">{entity_extensions}{roles}</EntityDescriptor>"#
    )
}

#[test]
fn reads_scopes_on_the_entity_and_its_saml2_idp_roles() -> TestResult {
    let xml = metadata(
        r#"<Extensions>
            <s:Scope>Entity.example.org</s:Scope>
            <other:Scope>foreign.example.org</other:Scope>
            <other:wrapper><s:Scope>nested.example.org</s:Scope></other:wrapper>
        </Extensions>"#,
        &format!(
            r#"<IDPSSODescriptor protocolSupportEnumeration="{PROTOCOL}">
                <other:Extensions><s:Scope>foreign-extension.example.org</s:Scope></other:Extensions>
                <Extensions>
                    <s:Scope regexp=" 0 ">role.example.org</s:Scope>
                    <s:Scope regexp="1">.*\.example\.org</s:Scope>
                </Extensions>
            </IDPSSODescriptor>
            <IDPSSODescriptor protocolSupportEnumeration="{PROTOCOL}">
                <Extensions><s:Scope regexp="true">.*\.example\.net</s:Scope></Extensions>
            </IDPSSODescriptor>
            <SPSSODescriptor protocolSupportEnumeration="{PROTOCOL}">
                <Extensions><s:Scope>sp.example.org</s:Scope></Extensions>
            </SPSSODescriptor>
            <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol">
                <Extensions><s:Scope>saml1.example.org</s:Scope></Extensions>
            </IDPSSODescriptor>"#
        ),
    );
    let xml = format!(
        r#"<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
            xmlns:s="urn:mace:shibboleth:metadata:1.0">
            <Extensions><s:Scope>group.example.org</s:Scope></Extensions>
            {xml}
        </EntitiesDescriptor>"#
    );
    let idp = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP)?,
        &xml,
        MetadataTrustPolicy::Unverified,
    )?;
    let scopes = idp.scopes()?;
    let declarations: Vec<_> = scopes
        .iter()
        .map(|scope| (scope.value.as_str(), scope.regexp))
        .collect();
    assert_eq!(
        declarations,
        [
            ("Entity.example.org", false),
            ("role.example.org", false),
            (r".*\.example\.org", true),
            (r".*\.example\.net", true),
        ]
    );
    Ok(())
}

#[test]
fn ignores_entity_scopes_when_the_entity_element_is_in_a_foreign_namespace() -> TestResult {
    let xml = format!(
        r#"<other:EntityDescriptor xmlns:other="urn:example:partner"
             xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
             xmlns:s="urn:mace:shibboleth:metadata:1.0" entityID="{IDP}">
            <Extensions><s:Scope>wrong.example.org</s:Scope></Extensions>
            <IDPSSODescriptor protocolSupportEnumeration="{PROTOCOL}">
                <Extensions><s:Scope>role.example.org</s:Scope></Extensions>
                <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    Location="https://idp.example.org/sso"/>
            </IDPSSODescriptor>
        </other:EntityDescriptor>"#
    );
    assert_eq!(
        IdpMetadata::from_xml(&xml)?.scopes()?,
        [MetadataScope {
            value: "role.example.org".into(),
            regexp: false,
        }]
    );
    Ok(())
}

#[test]
fn malformed_declarations_fail_the_scope_read() -> TestResult {
    for element in [
        r#"<s:Scope regexp="yes">example.org</s:Scope>"#,
        r#"<s:Scope s:regexp="true">example.org</s:Scope>"#,
        r#"<s:Scope>example.org<other:part/></s:Scope>"#,
    ] {
        let xml = metadata(
            &format!("<Extensions>{element}</Extensions>"),
            &format!(r#"<IDPSSODescriptor protocolSupportEnumeration="{PROTOCOL}"/>"#),
        );
        let parsed = IdpMetadata::from_xml(&xml)?;
        assert!(
            matches!(parsed.scopes(), Err(SamlError::Invalid(_))),
            "{element}"
        );
    }
    Ok(())
}

#[test]
fn builder_rejects_a_scope_with_invalid_xml_text() -> TestResult {
    let result = IdpConfig::builder(
        EntityId::try_new(IDP)?,
        SsoEndpoint::post("https://idp.example.org/sso")?,
    )
    .scopes([MetadataScope {
        value: "example\0.org".into(),
        regexp: false,
    }])
    .build();
    assert!(matches!(result, Err(SamlError::Invalid(_))), "{result:?}");
    Ok(())
}

#[test]
fn builder_rejects_a_literal_scope_with_uppercase_letters() -> TestResult {
    let result = IdpConfig::builder(
        EntityId::try_new(IDP)?,
        SsoEndpoint::post("https://idp.example.org/sso")?,
    )
    .scopes([MetadataScope {
        value: "Research.example.org".into(),
        regexp: false,
    }])
    .build();
    assert!(matches!(result, Err(SamlError::Invalid(_))), "{result:?}");
    Ok(())
}

#[test]
fn publishes_scopes_in_role_extensions_alongside_existing_entity_extensions() -> TestResult {
    let scopes = [
        MetadataScope {
            value: "example.org".into(),
            regexp: false,
        },
        MetadataScope {
            value: "^Research&Teaching$".into(),
            regexp: true,
        },
    ];
    let config = IdpConfig::builder(
        EntityId::try_new(IDP)?,
        SsoEndpoint::post("https://idp.example.org/sso")?,
    )
    .entity_attribute(Attribute::new("urn:example:entity-attribute", []))
    .scopes(scopes.clone())
    .build()?;
    assert_eq!(config.metadata().scopes(), scopes);
    let idp = IdentityProvider::new(config);
    let xml = roxmltree::Document::parse(idp.metadata_xml())?;
    let root = xml.root_element();
    let role = root
        .children()
        .find(|node| node.has_tag_name("IDPSSODescriptor"))
        .ok_or("missing IDPSSODescriptor")?;
    let extensions = role
        .first_element_child()
        .ok_or("missing role Extensions")?;
    assert!(extensions.has_tag_name(("urn:oasis:names:tc:SAML:2.0:metadata", "Extensions")));
    let literals: Vec<_> = extensions
        .children()
        .filter(|node| node.has_tag_name(("urn:mace:shibboleth:metadata:1.0", "Scope")))
        .map(|node| (node.text(), node.attribute("regexp")))
        .collect();
    assert_eq!(
        literals,
        [
            (Some("example.org"), Some("false")),
            (Some("^Research&Teaching$"), Some("true")),
        ]
    );
    let parsed = IdpMetadata::from_xml(idp.metadata_xml())?;
    assert_eq!(parsed.scopes()?, scopes);
    assert_eq!(
        parsed.as_metadata().entity_attributes()?.as_slice().len(),
        1
    );
    Ok(())
}
