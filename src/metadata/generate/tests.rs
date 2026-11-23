use super::*;
use crate::constants::CertUse;
use crate::entity::EntitySetting;
use crate::metadata::{IdpMetadata, SpMetadata};
use crate::sp;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn sp_metadata_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = SpMetadataInput {
        entity_id: "https://sp.example.com/metadata".into(),
        signing_certs: vec!["MIIBsigning".into()],
        encrypt_certs: vec!["MIIBencrypt".into()],
        authn_requests_signed: true,
        want_assertions_signed: true,
        name_id_format: vec![name_id_format::EMAIL_ADDRESS.to_string()],
        single_logout_service: vec![Endpoint::new(
            Binding::Redirect,
            "https://sp.example.com/slo",
        )],
        assertion_consumer_service: vec![
            Endpoint {
                binding: Binding::Post,
                location: "https://sp.example.com/acs".into(),
                index: None,
                is_default: true,
            },
            Endpoint::new(Binding::Redirect, "https://sp.example.com/acs-redirect"),
        ],
        manage_name_id_service: Vec::new(),
        lifetime: None,
        organization: None,
        contacts: Vec::new(),
        error_url: None,
        entity_attributes: Vec::new(),
    };
    let xml = generate_sp_metadata(&cfg)?;
    let parsed = SpMetadata::from_xml(&xml)?;
    assert_eq!(
        parsed.as_metadata().entity_id(),
        Some("https://sp.example.com/metadata")
    );
    assert!(parsed.authn_requests_signed());
    assert!(parsed.want_assertions_signed());
    assert_eq!(
        parsed.assertion_consumer_location(Binding::Post).as_deref(),
        Some("https://sp.example.com/acs")
    );
    assert_eq!(
        parsed
            .as_metadata()
            .single_logout_location(Binding::Redirect)
            .as_deref(),
        Some("https://sp.example.com/slo")
    );
    assert_eq!(
        parsed
            .as_metadata()
            .x509_certificates(CertUse::Signing)
            .first()
            .map(String::as_str),
        Some("MIIBsigning")
    );
    assert_eq!(
        parsed
            .as_metadata()
            .x509_certificates(CertUse::Encryption)
            .first()
            .map(String::as_str),
        Some("MIIBencrypt")
    );
    Ok(())
}

#[test]
fn typed_sp_metadata_reserves_explicit_acs_indexes() -> TestResult {
    let config = crate::SpConfig::builder(
        crate::EntityId::try_new("https://sp.example.com/metadata")?,
        crate::AcsEndpoint::post("https://sp/acs-implicit")?,
    )
    .acs_endpoint(crate::AcsEndpoint::post("https://sp/acs-zero")?.with_index(0))
    .validation(crate::tests::policies_without_crypto::sp_validation_without_crypto())
    .build()?;

    let sp = crate::ServiceProvider::new(config);
    let parsed = SpMetadata::from_xml(sp.metadata_xml())?;

    let endpoint = |index, location: &str| crate::metadata::sp::AcsMetadataEndpoint {
        binding: Binding::Post,
        location: location.into(),
        index: Some(index),
        is_default: crate::metadata::DefaultMarking::Unmarked,
    };
    assert_eq!(
        parsed.assertion_consumer_service_by_index(0)?,
        Some(endpoint(0, "https://sp/acs-zero"))
    );
    assert_eq!(
        parsed.assertion_consumer_service_by_index(1)?,
        Some(endpoint(1, "https://sp/acs-implicit"))
    );
    Ok(())
}

#[test]
fn sp_metadata_keeps_free_positions_and_fills_taken_ones() -> TestResult {
    let acs = |index, location: &str| Endpoint {
        index,
        ..Endpoint::new(Binding::Post, location)
    };
    let cfg = SpMetadataInput {
        entity_id: "https://sp.example.com/metadata".into(),
        assertion_consumer_service: vec![
            acs(None, "https://sp/a"),
            acs(None, "https://sp/b"),
            acs(Some(0), "https://sp/c"),
            acs(None, "https://sp/d"),
            acs(Some(7), "https://sp/e"),
        ],
        ..Default::default()
    };

    let xml = generate_sp_metadata(&cfg)?;

    let post = Binding::Post.urn();
    let written = [("2", "a"), ("1", "b"), ("0", "c"), ("3", "d"), ("7", "e")]
        .map(|(index, name)| {
            format!(
                r#"<AssertionConsumerService index="{index}" Binding="{post}" Location="https://sp/{name}"/>"#
            )
        })
        .concat();
    assert!(xml.contains(&written), "{xml}");
    Ok(())
}

#[test]
fn sp_metadata_rejects_duplicate_explicit_acs_index() {
    let acs = |location: &str| Endpoint {
        index: Some(3),
        ..Endpoint::new(Binding::Post, location)
    };
    let cfg = SpMetadataInput {
        entity_id: "https://sp.example.com/metadata".into(),
        assertion_consumer_service: vec![acs("https://sp/a"), acs("https://sp/b")],
        ..Default::default()
    };

    let result = generate_sp_metadata(&cfg);

    assert!(matches!(
        result,
        Err(SamlError::Invalid(message))
            if message == "duplicate AssertionConsumerService index 3"
    ));
}

#[test]
fn sp_metadata_rejects_more_acs_endpoints_than_indexes() {
    let cfg = SpMetadataInput {
        entity_id: "https://sp.example.com/metadata".into(),
        assertion_consumer_service: vec![
            Endpoint::new(Binding::Post, "https://sp/acs");
            usize::from(u16::MAX) + 2
        ],
        ..Default::default()
    };

    let result = generate_sp_metadata(&cfg);

    assert!(matches!(
        result,
        Err(SamlError::Invalid(message))
            if message == "more AssertionConsumerService endpoints than indexes"
    ));
}

#[test]
fn idp_metadata_rejects_duplicate_artifact_resolution_index() -> TestResult {
    let service = |location: &str| -> Result<_, SamlError> {
        Ok(crate::ArtifactResolutionService::new(
            1,
            crate::EndpointUrl::try_new(location)?,
        ))
    };
    let cfg = IdpMetadataInput {
        entity_id: "https://idp.example.com/metadata".into(),
        single_sign_on_service: vec![Endpoint::new(Binding::Redirect, "https://idp/sso")],
        artifact_resolution_service: vec![
            service("https://idp/ars-a")?,
            service("https://idp/ars-b")?,
        ],
        ..Default::default()
    };

    let result = generate_idp_metadata(&cfg);

    assert!(matches!(
        result,
        Err(SamlError::Invalid(message))
            if message == "duplicate ArtifactResolutionService index 1"
    ));
    Ok(())
}

#[test]
fn metadata_writes_only_absolute_endpoint_locations() -> TestResult {
    let sp = |location: &str| {
        generate_sp_metadata(&SpMetadataInput {
            entity_id: "https://sp.example.com/metadata".into(),
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, location)],
            ..Default::default()
        })
    };
    let idp = |location: &str| {
        generate_idp_metadata(&IdpMetadataInput {
            entity_id: "https://idp.example.com/metadata".into(),
            single_sign_on_service: vec![Endpoint::new(Binding::Redirect, location)],
            ..Default::default()
        })
    };

    assert!(matches!(
        sp("/acs"),
        Err(SamlError::Invalid(message))
            if message == "AssertionConsumerService Location must be an absolute URI reference"
    ));
    assert!(matches!(
        idp("/sso"),
        Err(SamlError::Invalid(message))
            if message == "SingleSignOnService Location must be an absolute URI reference"
    ));
    assert!(sp("urn:example:acs")?.contains(r#"Location="urn:example:acs""#));
    Ok(())
}

#[test]
fn metadata_writes_is_default_only_on_indexed_endpoints() -> TestResult {
    let default = |binding, location: &str| Endpoint {
        is_default: true,
        ..Endpoint::new(binding, location)
    };
    let sp = generate_sp_metadata(&SpMetadataInput {
        entity_id: "https://sp.example.com/metadata".into(),
        single_logout_service: vec![default(Binding::Redirect, "https://sp/slo")],
        assertion_consumer_service: vec![default(Binding::Post, "https://sp/acs")],
        manage_name_id_service: vec![default(Binding::Redirect, "https://sp/nameid")],
        ..Default::default()
    })?;
    let idp = generate_idp_metadata(&IdpMetadataInput {
        entity_id: "https://idp.example.com/metadata".into(),
        single_sign_on_service: vec![default(Binding::Redirect, "https://idp/sso")],
        single_logout_service: vec![default(Binding::Redirect, "https://idp/slo")],
        manage_name_id_service: vec![default(Binding::Soap, "https://idp/nameid")],
        ..Default::default()
    })?;

    let redirect = Binding::Redirect.urn();
    let soap = Binding::Soap.urn();
    let post = Binding::Post.urn();
    for (xml, element) in [
        (
            &sp,
            format!(r#"<SingleLogoutService Binding="{redirect}" Location="https://sp/slo"/>"#),
        ),
        (
            &sp,
            format!(r#"<ManageNameIDService Binding="{redirect}" Location="https://sp/nameid"/>"#),
        ),
        (
            &sp,
            format!(
                r#"<AssertionConsumerService index="0" isDefault="true" Binding="{post}" Location="https://sp/acs"/>"#
            ),
        ),
        (
            &idp,
            format!(r#"<SingleSignOnService Binding="{redirect}" Location="https://idp/sso"/>"#),
        ),
        (
            &idp,
            format!(r#"<SingleLogoutService Binding="{redirect}" Location="https://idp/slo"/>"#),
        ),
        (
            &idp,
            format!(r#"<ManageNameIDService Binding="{soap}" Location="https://idp/nameid"/>"#),
        ),
    ] {
        assert!(xml.contains(&element), "{element} not in {xml}");
    }
    assert_eq!(sp.matches("isDefault").count(), 1);
    assert!(!idp.contains("isDefault"));
    Ok(())
}

#[test]
fn idp_metadata_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = IdpMetadataInput {
        entity_id: "https://idp.example.com/metadata".into(),
        signing_certs: vec!["MIIBidp".into()],
        want_authn_requests_signed: true,
        single_sign_on_service: vec![Endpoint::new(
            Binding::Redirect,
            "https://idp.example.com/sso",
        )],
        ..Default::default()
    };
    let xml = generate_idp_metadata(&cfg)?;
    let parsed = IdpMetadata::from_xml(&xml)?;
    assert!(parsed.want_authn_requests_signed());
    assert_eq!(
        parsed.single_sign_on_location(Binding::Redirect).as_deref(),
        Some("https://idp.example.com/sso")
    );
    assert_eq!(
        parsed
            .as_metadata()
            .x509_certificates(CertUse::Signing)
            .first()
            .map(String::as_str),
        Some("MIIBidp")
    );
    Ok(())
}

#[test]
fn metadata_is_not_generated_without_the_role_endpoint_the_schema_requires() {
    let sp = generate_sp_metadata(&SpMetadataInput {
        entity_id: "https://sp.example.com/metadata".into(),
        ..Default::default()
    });
    let idp = generate_idp_metadata(&IdpMetadataInput {
        entity_id: "https://idp.example.com/metadata".into(),
        ..Default::default()
    });

    assert!(matches!(
        sp,
        Err(SamlError::MissingMetadata(name)) if name == "AssertionConsumerService"
    ));
    assert!(matches!(
        idp,
        Err(SamlError::MissingMetadata(name)) if name == "SingleSignOnService"
    ));
}

#[test]
fn sp_from_config_escapes_name_id_format_xml_markup() -> TestResult {
    let injected_format = format!(
        "{}</NameIDFormat><SingleLogoutService Binding=\"{}\" Location=\"https://evil.example/slo\"/><NameIDFormat>",
        name_id_format::EMAIL_ADDRESS,
        Binding::Redirect.urn()
    );
    let cfg = SpMetadataInput {
        entity_id: "https://sp.example.com/metadata".into(),
        name_id_format: vec![injected_format.clone()],
        assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
        ..Default::default()
    };

    let sp = sp::Engine::from_config(&cfg, EntitySetting::default())?;

    assert!(sp
        .metadata
        .as_metadata()
        .single_logout_location(Binding::Redirect)
        .is_none());
    assert_eq!(sp.setting.name_id_format, vec![injected_format]);
    assert!(sp.metadata_xml().contains("&lt;SingleLogoutService"));
    Ok(())
}

#[test]
fn sp_metadata_escapes_entity_id_attribute_markup() -> TestResult {
    let entity_id = "https://sp.example.com/metadata\" ID=\"_evil";
    let cfg = SpMetadataInput {
        entity_id: entity_id.into(),
        assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
        ..Default::default()
    };

    let xml = generate_sp_metadata(&cfg)?;
    let parsed = SpMetadata::from_xml(&xml)?;

    assert!(!xml.contains(" ID=\"_evil\""));
    assert!(xml.contains("&quot; ID=&quot;_evil"));
    assert_eq!(parsed.as_metadata().entity_id(), Some(entity_id));
    Ok(())
}

#[test]
fn sp_metadata_escapes_certificate_text_markup() -> TestResult {
    let injected_cert = concat!(
        "MIIB</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>",
        "<NameIDFormat>evil</NameIDFormat>",
        "<KeyDescriptor><ds:KeyInfo><ds:X509Data><ds:X509Certificate>tail"
    );
    let cfg = SpMetadataInput {
        entity_id: "https://sp.example.com/metadata".into(),
        signing_certs: vec![injected_cert.into()],
        assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
        ..Default::default()
    };

    let xml = generate_sp_metadata(&cfg)?;
    let parsed = SpMetadata::from_xml(&xml)?;

    assert!(xml.contains("&lt;NameIDFormat&gt;evil&lt;/NameIDFormat&gt;"));
    assert_eq!(
        parsed.as_metadata().name_id_formats(),
        [crate::NameIdFormat::EmailAddress]
    );
    assert_eq!(
        parsed
            .as_metadata()
            .x509_certificates(CertUse::Signing)
            .len(),
        1
    );
    Ok(())
}

#[test]
fn idp_metadata_escapes_endpoint_location_attribute_markup() -> TestResult {
    let injected_location = format!(
        "https://idp/sso\"/><SingleLogoutService Binding=\"{}\" Location=\"https://evil.example/slo",
        Binding::Redirect.urn()
    );
    let cfg = IdpMetadataInput {
        entity_id: "https://idp.example.com/metadata".into(),
        single_sign_on_service: vec![Endpoint::new(Binding::Redirect, injected_location.clone())],
        ..Default::default()
    };

    let xml = generate_idp_metadata(&cfg)?;
    let parsed = IdpMetadata::from_xml(&xml)?;

    assert!(!xml.contains("<SingleLogoutService"));
    assert_eq!(
        parsed.single_sign_on_location(Binding::Redirect).as_deref(),
        Some(injected_location.as_str())
    );
    assert!(parsed
        .as_metadata()
        .single_logout_location(Binding::Redirect)
        .is_none());
    Ok(())
}

#[test]
fn idp_metadata_omits_empty_groups() -> TestResult {
    let cfg = IdpMetadataInput {
        entity_id: "https://idp.example.com/metadata".into(),
        single_sign_on_service: vec![Endpoint::new(Binding::Redirect, "https://idp/sso")],
        single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://idp/slo")],
        ..Default::default()
    };

    let xml = generate_idp_metadata(&cfg)?;

    assert!(!xml.contains("<KeyDescriptor"));
    assert!(!xml.contains("<NameIDFormat"));
    assert!(xml.contains("<SingleSignOnService"));
    assert!(xml.contains("<SingleLogoutService"));
    Ok(())
}

#[test]
fn role_children_follow_schema_order_and_keep_endpoint_order() -> TestResult {
    let idp = generate_idp_metadata(&IdpMetadataInput {
        entity_id: "https://idp.example.com/metadata".into(),
        signing_certs: vec!["MIIBsigning".into()],
        name_id_format: vec![name_id_format::PERSISTENT.to_string()],
        single_sign_on_service: vec![
            Endpoint::new(Binding::Redirect, "https://idp/z"),
            Endpoint::new(Binding::Post, "https://idp/a"),
        ],
        single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://idp/slo")],
        artifact_resolution_service: vec![crate::ArtifactResolutionService::new(
            0,
            crate::EndpointUrl::try_new("https://idp/artifact")?,
        )],
        manage_name_id_service: vec![Endpoint::new(Binding::Soap, "https://idp/nameid")],
        ..Default::default()
    })?;
    let sp = generate_sp_metadata(&SpMetadataInput {
        entity_id: "https://sp.example.com/metadata".into(),
        signing_certs: vec!["MIIBsigning".into()],
        name_id_format: vec![name_id_format::PERSISTENT.to_string()],
        single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://sp/slo")],
        manage_name_id_service: vec![Endpoint::new(Binding::Redirect, "https://sp/nameid")],
        assertion_consumer_service: vec![
            Endpoint::new(Binding::Post, "https://sp/z"),
            Endpoint::new(Binding::Post, "https://sp/a"),
        ],
        ..Default::default()
    })?;

    for (xml, role, expected) in [
        (
            &idp,
            "IDPSSODescriptor",
            &[
                ("KeyDescriptor", None),
                ("ArtifactResolutionService", Some("https://idp/artifact")),
                ("SingleLogoutService", Some("https://idp/slo")),
                ("ManageNameIDService", Some("https://idp/nameid")),
                ("NameIDFormat", None),
                ("SingleSignOnService", Some("https://idp/z")),
                ("SingleSignOnService", Some("https://idp/a")),
            ][..],
        ),
        (
            &sp,
            "SPSSODescriptor",
            &[
                ("KeyDescriptor", None),
                ("SingleLogoutService", Some("https://sp/slo")),
                ("ManageNameIDService", Some("https://sp/nameid")),
                ("NameIDFormat", None),
                ("AssertionConsumerService", Some("https://sp/z")),
                ("AssertionConsumerService", Some("https://sp/a")),
            ][..],
        ),
    ] {
        let doc = roxmltree::Document::parse(xml)?;
        let children: Vec<_> = doc
            .descendants()
            .find(|node| node.has_tag_name((namespace::METADATA, role)))
            .ok_or("missing role descriptor")?
            .children()
            .filter(roxmltree::Node::is_element)
            .map(|node| (node.tag_name().name(), node.attribute("Location")))
            .collect();
        assert_eq!(children, expected, "{role}");
    }
    Ok(())
}
