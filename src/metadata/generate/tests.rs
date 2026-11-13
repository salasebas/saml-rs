use super::*;
use crate::constants::CertUse;
use crate::entity::EntitySetting;
use crate::metadata::{IdpMetadata, SpMetadata};
use crate::sp::ServiceProvider;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn sp_metadata_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = SpMetadataConfig {
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
        elements_order: None,
        lifetime: None,
        organization: None,
        contacts: Vec::new(),
        error_url: None,
    };
    let xml = generate_sp_metadata(&cfg)?;
    let parsed = SpMetadata::from_xml(&xml)?;
    assert_eq!(
        parsed.get_entity_id(),
        Some("https://sp.example.com/metadata")
    );
    assert!(parsed.is_authn_request_signed());
    assert!(parsed.is_want_assertions_signed());
    assert_eq!(
        parsed
            .get_assertion_consumer_service(Binding::Post)
            .as_deref(),
        Some("https://sp.example.com/acs")
    );
    assert_eq!(
        parsed
            .get_single_logout_service(Binding::Redirect)
            .as_deref(),
        Some("https://sp.example.com/slo")
    );
    assert_eq!(
        parsed.get_x509_certificate(CertUse::Signing).as_deref(),
        Some("MIIBsigning")
    );
    assert_eq!(
        parsed.get_x509_certificate(CertUse::Encryption).as_deref(),
        Some("MIIBencrypt")
    );
    Ok(())
}

#[test]
fn typed_sp_metadata_reserves_explicit_acs_indexes() -> TestResult {
    let config =
        crate::SpConfig::builder(crate::EntityId::try_new("https://sp.example.com/metadata")?)
            .acs_endpoint(crate::AcsEndpoint::post("https://sp/acs-implicit")?)
            .acs_endpoint(crate::AcsEndpoint::post("https://sp/acs-zero")?.with_index(0))
            .validation(crate::SpValidationPolicy::compatibility())
            .build()?;

    let sp = crate::Saml::sp(config)?;
    let parsed = SpMetadata::from_xml(sp.metadata_xml())?;

    let endpoint = |index, location: &str| crate::metadata::sp::AcsMetadataEndpoint {
        binding: Binding::Post,
        location: location.into(),
        index: Some(index),
        is_default: false,
        is_default_false: false,
    };
    assert_eq!(
        parsed.get_assertion_consumer_service_by_index(0)?,
        Some(endpoint(0, "https://sp/acs-zero"))
    );
    assert_eq!(
        parsed.get_assertion_consumer_service_by_index(1)?,
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
    let cfg = SpMetadataConfig {
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
    let cfg = SpMetadataConfig {
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
    let cfg = SpMetadataConfig {
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
fn metadata_writes_is_default_only_on_indexed_endpoints() -> TestResult {
    let default = |binding, location: &str| Endpoint {
        is_default: true,
        ..Endpoint::new(binding, location)
    };
    let sp = generate_sp_metadata(&SpMetadataConfig {
        entity_id: "https://sp.example.com/metadata".into(),
        single_logout_service: vec![default(Binding::Redirect, "https://sp/slo")],
        assertion_consumer_service: vec![default(Binding::Post, "https://sp/acs")],
        manage_name_id_service: vec![default(Binding::Redirect, "https://sp/nameid")],
        ..Default::default()
    })?;
    let idp = generate_idp_metadata(&IdpMetadataConfig {
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
fn sp_elements_order_respected() -> TestResult {
    let cfg = SpMetadataConfig {
        entity_id: "https://sp.example.com/metadata".into(),
        single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://sp/slo")],
        assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
        ..Default::default()
    };
    let xml = generate_sp_metadata(&cfg)?;
    let slo = xml.find("SingleLogoutService").unwrap_or(usize::MAX);
    let acs = xml.find("AssertionConsumerService").unwrap_or(0);
    // default order places SingleLogoutService before AssertionConsumerService
    assert!(slo < acs);
    Ok(())
}

#[test]
fn idp_metadata_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = IdpMetadataConfig {
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
    assert!(parsed.is_want_authn_requests_signed());
    assert_eq!(
        parsed
            .get_single_sign_on_service(Binding::Redirect)
            .as_deref(),
        Some("https://idp.example.com/sso")
    );
    assert_eq!(
        parsed.get_x509_certificate(CertUse::Signing).as_deref(),
        Some("MIIBidp")
    );
    Ok(())
}

#[test]
fn try_generate_idp_metadata_rejects_missing_sso() {
    let cfg = IdpMetadataConfig {
        entity_id: "https://idp.example.com/metadata".into(),
        ..Default::default()
    };

    let result = try_generate_idp_metadata(&cfg);

    assert!(matches!(
        result,
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
    let cfg = SpMetadataConfig {
        entity_id: "https://sp.example.com/metadata".into(),
        name_id_format: vec![injected_format.clone()],
        assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
        ..Default::default()
    };

    let sp = ServiceProvider::from_config(&cfg, EntitySetting::default())?;

    assert!(sp
        .metadata
        .get_single_logout_service(Binding::Redirect)
        .is_none());
    assert_eq!(sp.setting.name_id_format, vec![injected_format]);
    assert!(sp.metadata_xml().contains("&lt;SingleLogoutService"));
    Ok(())
}

#[test]
fn sp_metadata_escapes_entity_id_attribute_markup() -> TestResult {
    let entity_id = "https://sp.example.com/metadata\" ID=\"_evil";
    let cfg = SpMetadataConfig {
        entity_id: entity_id.into(),
        assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
        ..Default::default()
    };

    let xml = generate_sp_metadata(&cfg)?;
    let parsed = SpMetadata::from_xml(&xml)?;

    assert!(!xml.contains(" ID=\"_evil\""));
    assert!(xml.contains("&quot; ID=&quot;_evil"));
    assert_eq!(parsed.get_entity_id(), Some(entity_id));
    Ok(())
}

#[test]
fn sp_metadata_escapes_certificate_text_markup() -> TestResult {
    let injected_cert = concat!(
        "MIIB</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>",
        "<NameIDFormat>evil</NameIDFormat>",
        "<KeyDescriptor><ds:KeyInfo><ds:X509Data><ds:X509Certificate>tail"
    );
    let cfg = SpMetadataConfig {
        entity_id: "https://sp.example.com/metadata".into(),
        signing_certs: vec![injected_cert.into()],
        assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
        elements_order: Some(vec![
            "KeyDescriptor".into(),
            "AssertionConsumerService".into(),
        ]),
        ..Default::default()
    };

    let xml = generate_sp_metadata(&cfg)?;
    let parsed = SpMetadata::from_xml(&xml)?;

    assert!(xml.contains("&lt;NameIDFormat&gt;evil&lt;/NameIDFormat&gt;"));
    assert!(parsed.get_name_id_format().is_empty());
    assert_eq!(parsed.x509_certificates(CertUse::Signing).len(), 1);
    Ok(())
}

#[test]
fn sp_custom_elements_order_preserves_omitted_populated_acs() -> TestResult {
    let cfg = SpMetadataConfig {
        entity_id: "https://sp.example.com/metadata".into(),
        signing_certs: vec!["MIIBsigning".into()],
        name_id_format: vec![name_id_format::EMAIL_ADDRESS.to_string()],
        single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://sp/slo")],
        assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
        elements_order: Some(vec!["KeyDescriptor".into()]),
        ..Default::default()
    };

    let xml = generate_sp_metadata(&cfg)?;
    let key = xml.find("<KeyDescriptor").unwrap_or(usize::MAX);
    let acs = xml.find("<AssertionConsumerService").unwrap_or(usize::MAX);

    assert_eq!(xml.matches("<AssertionConsumerService").count(), 1);
    assert!(key < acs);
    assert!(!xml.contains("<NameIDFormat"));
    assert!(!xml.contains("<SingleLogoutService"));
    Ok(())
}

#[test]
fn idp_metadata_escapes_endpoint_location_attribute_markup() -> TestResult {
    let injected_location = format!(
        "https://idp/sso\"/><SingleLogoutService Binding=\"{}\" Location=\"https://evil.example/slo",
        Binding::Redirect.urn()
    );
    let cfg = IdpMetadataConfig {
        entity_id: "https://idp.example.com/metadata".into(),
        single_sign_on_service: vec![Endpoint::new(Binding::Redirect, injected_location.clone())],
        ..Default::default()
    };

    let xml = try_generate_idp_metadata(&cfg)?;
    let parsed = IdpMetadata::from_xml(&xml)?;

    assert!(!xml.contains("<SingleLogoutService"));
    assert_eq!(
        parsed
            .get_single_sign_on_service(Binding::Redirect)
            .as_deref(),
        Some(injected_location.as_str())
    );
    assert!(parsed
        .get_single_logout_service(Binding::Redirect)
        .is_none());
    Ok(())
}

#[test]
fn idp_custom_elements_order_can_place_sso_before_key_descriptor() -> TestResult {
    let cfg = IdpMetadataConfig {
        entity_id: "https://idp.example.com/metadata".into(),
        signing_certs: vec!["MIIBsigning".into()],
        name_id_format: vec![name_id_format::EMAIL_ADDRESS.to_string()],
        single_sign_on_service: vec![Endpoint::new(Binding::Redirect, "https://idp/sso")],
        single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://idp/slo")],
        elements_order: Some(vec![
            "SingleSignOnService".into(),
            "KeyDescriptor".into(),
            "NameIDFormat".into(),
            "SingleLogoutService".into(),
        ]),
        ..Default::default()
    };

    let xml = generate_idp_metadata(&cfg)?;
    let sso = xml.find("<SingleSignOnService").unwrap_or(usize::MAX);
    let key = xml.find("<KeyDescriptor").unwrap_or(usize::MAX);
    let name_id = xml.find("<NameIDFormat").unwrap_or(usize::MAX);
    let slo = xml.find("<SingleLogoutService").unwrap_or(usize::MAX);

    assert!(sso < key);
    assert!(key < name_id);
    assert!(name_id < slo);
    Ok(())
}

#[test]
fn idp_elements_order_filters_empty_groups() -> TestResult {
    let cfg = IdpMetadataConfig {
        entity_id: "https://idp.example.com/metadata".into(),
        single_sign_on_service: vec![Endpoint::new(Binding::Redirect, "https://idp/sso")],
        single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://idp/slo")],
        elements_order: Some(vec![
            "KeyDescriptor".into(),
            "NameIDFormat".into(),
            "SingleSignOnService".into(),
            "SingleLogoutService".into(),
        ]),
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
fn idp_custom_elements_order_omits_unlisted_optional_groups() -> TestResult {
    let cfg = IdpMetadataConfig {
        entity_id: "https://idp.example.com/metadata".into(),
        signing_certs: vec!["MIIBsigning".into()],
        name_id_format: vec![name_id_format::EMAIL_ADDRESS.to_string()],
        single_sign_on_service: vec![Endpoint::new(Binding::Redirect, "https://idp/sso")],
        single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://idp/slo")],
        elements_order: Some(vec!["SingleSignOnService".into()]),
        ..Default::default()
    };

    let xml = generate_idp_metadata(&cfg)?;

    assert_eq!(xml.matches("<SingleSignOnService").count(), 1);
    assert!(!xml.contains("<KeyDescriptor"));
    assert!(!xml.contains("<NameIDFormat"));
    assert!(!xml.contains("<SingleLogoutService"));
    Ok(())
}

#[test]
fn idp_custom_elements_order_preserves_omitted_populated_sso() -> TestResult {
    let cfg = IdpMetadataConfig {
        entity_id: "https://idp.example.com/metadata".into(),
        signing_certs: vec!["MIIBsigning".into()],
        single_sign_on_service: vec![Endpoint::new(Binding::Redirect, "https://idp/sso")],
        elements_order: Some(vec!["KeyDescriptor".into()]),
        ..Default::default()
    };

    let xml = generate_idp_metadata(&cfg)?;
    let key = xml.find("<KeyDescriptor").unwrap_or(usize::MAX);
    let sso = xml.find("<SingleSignOnService").unwrap_or(usize::MAX);

    assert_eq!(xml.matches("<SingleSignOnService").count(), 1);
    assert!(key < sso);
    Ok(())
}

#[test]
fn idp_custom_elements_order_writes_omitted_manage_name_id_service_after_logout() -> TestResult {
    let cfg = IdpMetadataConfig {
        entity_id: "https://idp.example.com/metadata".into(),
        name_id_format: vec![name_id_format::PERSISTENT.to_string()],
        single_sign_on_service: vec![Endpoint::new(Binding::Redirect, "https://idp/sso")],
        single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://idp/slo")],
        manage_name_id_service: vec![Endpoint::new(Binding::Soap, "https://idp/nameid")],
        elements_order: Some(
            elements_order::idp::SHIBBOLETH
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
        ),
        ..Default::default()
    };

    let xml = generate_idp_metadata(&cfg)?;
    let positions = [
        "<SingleLogoutService",
        "<ManageNameIDService",
        "<NameIDFormat",
        "<SingleSignOnService",
    ]
    .map(|element| xml.find(element));

    assert!(xml.contains(
        r#"<ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://idp/nameid"/>"#
    ));
    assert_eq!(xml.matches("<ManageNameIDService").count(), 1);
    assert!(positions.iter().all(Option::is_some));
    assert!(positions.is_sorted());
    Ok(())
}

#[test]
fn idp_custom_elements_order_writes_omitted_artifact_resolution_after_keys() -> TestResult {
    let cfg = IdpMetadataConfig {
        entity_id: "https://idp.example.com/metadata".into(),
        signing_certs: vec!["MIIBsigning".into()],
        name_id_format: vec![name_id_format::EMAIL_ADDRESS.to_string()],
        single_sign_on_service: vec![Endpoint::new(Binding::Redirect, "https://idp/sso")],
        single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://idp/slo")],
        artifact_resolution_service: vec![ArtifactResolutionEndpoint {
            index: 0,
            location: "https://idp/artifact".into(),
        }],
        elements_order: Some(
            elements_order::idp::SHIBBOLETH
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
        ),
        ..Default::default()
    };

    let xml = generate_idp_metadata(&cfg)?;
    let positions = [
        "<KeyDescriptor",
        "<ArtifactResolutionService",
        "<SingleLogoutService",
        "<NameIDFormat",
        "<SingleSignOnService",
    ]
    .map(|element| xml.find(element));

    assert_eq!(xml.matches("<ArtifactResolutionService").count(), 1);
    assert!(positions.iter().all(Option::is_some));
    assert!(positions.is_sorted());
    Ok(())
}

#[test]
fn default_orders_follow_the_metadata_schema_sequence() -> TestResult {
    let idp = generate_idp_metadata(&IdpMetadataConfig {
        entity_id: "https://idp.example.com/metadata".into(),
        signing_certs: vec!["MIIBsigning".into()],
        name_id_format: vec![name_id_format::PERSISTENT.to_string()],
        single_sign_on_service: vec![Endpoint::new(Binding::Redirect, "https://idp/sso")],
        single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://idp/slo")],
        artifact_resolution_service: vec![ArtifactResolutionEndpoint {
            index: 0,
            location: "https://idp/artifact".into(),
        }],
        manage_name_id_service: vec![Endpoint::new(Binding::Soap, "https://idp/nameid")],
        ..Default::default()
    })?;
    let sp = generate_sp_metadata(&SpMetadataConfig {
        entity_id: "https://sp.example.com/metadata".into(),
        signing_certs: vec!["MIIBsigning".into()],
        name_id_format: vec![name_id_format::PERSISTENT.to_string()],
        single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://sp/slo")],
        assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
        ..Default::default()
    })?;

    let idp_positions = [
        "<KeyDescriptor",
        "<ArtifactResolutionService",
        "<SingleLogoutService",
        "<ManageNameIDService",
        "<NameIDFormat",
        "<SingleSignOnService",
    ]
    .map(|element| idp.find(element));
    let sp_positions = [
        "<KeyDescriptor",
        "<SingleLogoutService",
        "<NameIDFormat",
        "<AssertionConsumerService",
    ]
    .map(|element| sp.find(element));

    for positions in [&idp_positions[..], &sp_positions[..]] {
        assert!(positions.iter().all(Option::is_some));
        assert!(positions.is_sorted());
    }
    Ok(())
}

#[test]
fn idp_elements_order_profiles_match_upstream() {
    assert_eq!(
        elements_order::idp::DEFAULT,
        [
            "KeyDescriptor",
            "ArtifactResolutionService",
            "SingleLogoutService",
            "ManageNameIDService",
            "NameIDFormat",
            "SingleSignOnService",
        ]
    );
    assert_eq!(
        elements_order::idp::ONELOGIN,
        [
            "KeyDescriptor",
            "NameIDFormat",
            "SingleLogoutService",
            "SingleSignOnService",
        ]
    );
    assert_eq!(
        elements_order::idp::SHIBBOLETH,
        [
            "KeyDescriptor",
            "SingleLogoutService",
            "NameIDFormat",
            "SingleSignOnService",
        ]
    );
}
