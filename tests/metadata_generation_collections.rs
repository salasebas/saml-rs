use saml_rs::constants::{name_id_format, namespace, Binding};
use saml_rs::metadata::{
    generate_idp_metadata, generate_sp_metadata, Endpoint, IdpMetadataInput, SpMetadataInput,
};
use saml_rs::{ArtifactResolutionService, EndpointUrl};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn role_children(
    xml: &str,
    role: &str,
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let document = roxmltree::Document::parse(xml)?;
    let descriptor = document
        .descendants()
        .find(|node| node.has_tag_name((namespace::METADATA, role)))
        .ok_or("missing role descriptor")?;
    Ok(descriptor
        .children()
        .filter(roxmltree::Node::is_element)
        .map(|node| {
            let value = node
                .attribute("Location")
                .or_else(|| node.text())
                .unwrap_or_default();
            (node.tag_name().name().to_string(), value.to_string())
        })
        .collect())
}

#[test]
fn sp_metadata_input_plural_fields_preserve_order_and_empty_defaults() -> TestResult {
    let mut input = SpMetadataInput::default();
    input.entity_id = "https://sp.example.com/metadata".into();
    input.name_id_formats = vec![
        name_id_format::TRANSIENT.into(),
        name_id_format::PERSISTENT.into(),
    ];
    input.single_logout_services = vec![
        Endpoint::new(Binding::Redirect, "https://sp.example.com/slo-z"),
        Endpoint::new(Binding::Post, "https://sp.example.com/slo-a"),
    ];
    input.manage_name_id_services = vec![
        Endpoint::new(Binding::Redirect, "https://sp.example.com/mni-z"),
        Endpoint::new(Binding::Soap, "https://sp.example.com/mni-a"),
    ];
    input.assertion_consumer_services = vec![
        Endpoint::new(Binding::Post, "https://sp.example.com/acs-z"),
        Endpoint::new(Binding::Artifact, "https://sp.example.com/acs-a"),
    ];

    let xml = generate_sp_metadata(&input)?;
    assert_eq!(
        role_children(&xml, "SPSSODescriptor")?,
        vec![
            (
                "SingleLogoutService".into(),
                "https://sp.example.com/slo-z".into(),
            ),
            (
                "SingleLogoutService".into(),
                "https://sp.example.com/slo-a".into(),
            ),
            (
                "ManageNameIDService".into(),
                "https://sp.example.com/mni-z".into(),
            ),
            (
                "ManageNameIDService".into(),
                "https://sp.example.com/mni-a".into(),
            ),
            ("NameIDFormat".into(), name_id_format::TRANSIENT.into()),
            ("NameIDFormat".into(), name_id_format::PERSISTENT.into()),
            (
                "AssertionConsumerService".into(),
                "https://sp.example.com/acs-z".into(),
            ),
            (
                "AssertionConsumerService".into(),
                "https://sp.example.com/acs-a".into(),
            ),
        ]
    );

    let mut minimal = SpMetadataInput::default();
    minimal.entity_id = "https://sp.example.com/metadata".into();
    minimal.assertion_consumer_services =
        vec![Endpoint::new(Binding::Post, "https://sp.example.com/acs")];
    let minimal_xml = generate_sp_metadata(&minimal)?;
    assert_eq!(
        role_children(&minimal_xml, "SPSSODescriptor")?,
        vec![
            ("NameIDFormat".into(), name_id_format::EMAIL_ADDRESS.into()),
            (
                "AssertionConsumerService".into(),
                "https://sp.example.com/acs".into(),
            ),
        ]
    );

    Ok(())
}

#[test]
fn idp_metadata_input_plural_fields_preserve_order_and_empty_omission() -> TestResult {
    let mut input = IdpMetadataInput::default();
    input.entity_id = "https://idp.example.com/metadata".into();
    input.name_id_formats = vec![
        name_id_format::TRANSIENT.into(),
        name_id_format::PERSISTENT.into(),
    ];
    input.single_sign_on_services = vec![
        Endpoint::new(Binding::Redirect, "https://idp.example.com/sso-z"),
        Endpoint::new(Binding::Post, "https://idp.example.com/sso-a"),
    ];
    input.single_logout_services = vec![
        Endpoint::new(Binding::Redirect, "https://idp.example.com/slo-z"),
        Endpoint::new(Binding::Post, "https://idp.example.com/slo-a"),
    ];
    input.artifact_resolution_services = vec![
        ArtifactResolutionService::new(2, EndpointUrl::try_new("https://idp.example.com/ars-z")?),
        ArtifactResolutionService::new(0, EndpointUrl::try_new("https://idp.example.com/ars-a")?),
    ];
    input.manage_name_id_services = vec![
        Endpoint::new(Binding::Soap, "https://idp.example.com/mni-z"),
        Endpoint::new(Binding::Redirect, "https://idp.example.com/mni-a"),
    ];

    let xml = generate_idp_metadata(&input)?;
    assert_eq!(
        role_children(&xml, "IDPSSODescriptor")?,
        vec![
            (
                "ArtifactResolutionService".into(),
                "https://idp.example.com/ars-z".into(),
            ),
            (
                "ArtifactResolutionService".into(),
                "https://idp.example.com/ars-a".into(),
            ),
            (
                "SingleLogoutService".into(),
                "https://idp.example.com/slo-z".into(),
            ),
            (
                "SingleLogoutService".into(),
                "https://idp.example.com/slo-a".into(),
            ),
            (
                "ManageNameIDService".into(),
                "https://idp.example.com/mni-z".into(),
            ),
            (
                "ManageNameIDService".into(),
                "https://idp.example.com/mni-a".into(),
            ),
            ("NameIDFormat".into(), name_id_format::TRANSIENT.into()),
            ("NameIDFormat".into(), name_id_format::PERSISTENT.into()),
            (
                "SingleSignOnService".into(),
                "https://idp.example.com/sso-z".into(),
            ),
            (
                "SingleSignOnService".into(),
                "https://idp.example.com/sso-a".into(),
            ),
        ]
    );

    let mut minimal = IdpMetadataInput::default();
    minimal.entity_id = "https://idp.example.com/metadata".into();
    minimal.single_sign_on_services =
        vec![Endpoint::new(Binding::Post, "https://idp.example.com/sso")];
    let minimal_xml = generate_idp_metadata(&minimal)?;
    assert_eq!(
        role_children(&minimal_xml, "IDPSSODescriptor")?,
        vec![(
            "SingleSignOnService".into(),
            "https://idp.example.com/sso".into(),
        )]
    );

    Ok(())
}
