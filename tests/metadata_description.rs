use std::time::Duration;

use saml_rs::constants::{elements_order, name_id_format};
use saml_rs::metadata::{
    generate_idp_metadata, generate_sp_metadata, Endpoint, IdpMetadata,
    IdpMetadataConfig as RawIdpMetadataConfig, Metadata, SpMetadata,
    SpMetadataConfig as RawSpMetadataConfig,
};
use saml_rs::raw::Binding;
use saml_rs::{
    AcsEndpoint, ContactPerson, ContactType, EntityId, IdpConfig, IdpDescriptor,
    IdpValidationPolicy, LocalizedValue, MetadataLifetime, MetadataTrustPolicy, Organization, Saml,
    SamlError, SpConfig, SpDescriptor, SpValidationPolicy, SsoEndpoint,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const SP_XML: &str = include_str!("fixtures/metadata/description-sp.xml");
const IDP_XML: &str = include_str!("fixtures/metadata/description-idp.xml");
const ERROR_URL: &str = "https://example.com/error?one=1&two=2";

fn organization() -> Organization {
    Organization {
        names: vec![
            LocalizedValue::new("en", "Example & Co"),
            LocalizedValue::new("es-MX", "Ejemplo"),
        ],
        display_names: vec![
            LocalizedValue::new("en", "Example <SSO>"),
            LocalizedValue::new("es", "Ejemplo SSO"),
        ],
        urls: vec![
            LocalizedValue::new("en", "https://example.com/?one=1&two=2"),
            LocalizedValue::new("es", "https://example.com/es"),
        ],
    }
}

fn contacts() -> Vec<ContactPerson> {
    let mut technical = ContactPerson::new(ContactType::Technical);
    technical.company = Some("Example & Co".into());
    technical.given_name = Some("Alice <Admin>".into());
    technical.surname = Some("O'Connor".into());
    technical.email_addresses = vec![
        "mailto:alice@example.com".into(),
        "mailto:team@example.com?subject=SSO&cc=backup@example.com".into(),
    ];
    technical.telephone_numbers = vec!["+1 555 0100".into(), "+1 555 0101".into()];
    let mut security = ContactPerson::new(ContactType::Security);
    security.given_name = Some("Security Response Team".into());
    security.email_addresses = vec!["mailto:security@example.com".into()];
    vec![
        technical,
        ContactPerson::new(ContactType::Support),
        ContactPerson::new(ContactType::Administrative),
        ContactPerson::new(ContactType::Billing),
        ContactPerson::new(ContactType::Other),
        security,
    ]
}

fn raw_sp() -> RawSpMetadataConfig {
    RawSpMetadataConfig {
        entity_id: "https://sp.example.com/metadata".into(),
        assertion_consumer_service: vec![Endpoint::new(
            Binding::Post,
            "https://sp.example.com/acs",
        )],
        organization: Some(organization()),
        contacts: contacts(),
        error_url: Some(ERROR_URL.into()),
        lifetime: Some(MetadataLifetime::CacheDuration(Duration::from_secs(3600))),
        ..Default::default()
    }
}

fn raw_idp() -> RawIdpMetadataConfig {
    RawIdpMetadataConfig {
        entity_id: "https://idp.example.com/metadata".into(),
        single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp.example.com/sso")],
        name_id_format: vec![name_id_format::EMAIL_ADDRESS.into()],
        organization: Some(organization()),
        contacts: contacts(),
        error_url: Some(ERROR_URL.into()),
        lifetime: Some(MetadataLifetime::CacheDuration(Duration::from_secs(3600))),
        ..Default::default()
    }
}

#[test]
fn raw_metadata_writes_descriptions_after_roles_with_every_order_profile() -> TestResult {
    for profile in [
        None,
        Some(elements_order::DEFAULT),
        Some(elements_order::ONELOGIN),
        Some(elements_order::SHIBBOLETH),
        Some(&[
            "ContactPerson",
            "Organization",
            "NameIDFormat",
            "AssertionConsumerService",
        ]),
    ] {
        let mut cfg = raw_sp();
        cfg.elements_order =
            profile.map(|names| names.iter().map(|name| name.to_string()).collect());
        let xml = generate_sp_metadata(&cfg)?;
        assert_eq!(xml, SP_XML.trim_end());
        let parsed = SpMetadata::from_xml(&xml)?;
        assert_eq!(parsed.organization()?, Some(organization()));
        assert_eq!(parsed.contacts()?, contacts());
    }
    for profile in [
        None,
        Some(elements_order::idp::DEFAULT),
        Some(elements_order::idp::ONELOGIN),
        Some(elements_order::idp::SHIBBOLETH),
        Some(&[
            "ContactPerson",
            "Organization",
            "NameIDFormat",
            "SingleSignOnService",
        ]),
    ] {
        let mut cfg = raw_idp();
        cfg.elements_order =
            profile.map(|names| names.iter().map(|name| name.to_string()).collect());
        let xml = generate_idp_metadata(&cfg)?;
        assert_eq!(xml, IDP_XML.trim_end());
        let parsed = IdpMetadata::from_xml(&xml)?;
        assert_eq!(parsed.organization()?, Some(organization()));
        assert_eq!(parsed.contacts()?, contacts());
    }
    Ok(())
}

#[test]
fn typed_builders_publish_the_same_descriptions() -> TestResult {
    let mut sp = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
        .organization(organization())
        .error_url(ERROR_URL)
        .metadata_lifetime(MetadataLifetime::CacheDuration(Duration::from_secs(3600)))
        .validation(SpValidationPolicy::compatibility());
    let mut idp = IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
        .sso_endpoint(SsoEndpoint::post("https://idp.example.com/sso")?)
        .name_id_format(saml_rs::NameIdFormat::EmailAddress)
        .organization(organization())
        .error_url(ERROR_URL)
        .metadata_lifetime(MetadataLifetime::CacheDuration(Duration::from_secs(3600)))
        .validation(IdpValidationPolicy::compatibility());
    for contact in contacts() {
        sp = sp.contact(contact.clone());
        idp = idp.contact(contact);
    }
    let sp = Saml::sp(sp.build()?)?;
    let idp = Saml::idp(idp.build()?)?;
    assert_eq!(sp.metadata_xml(), SP_XML.trim_end());
    assert_eq!(idp.metadata_xml(), IDP_XML.trim_end());
    let sp_peer = SpDescriptor::from_metadata_xml(
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let idp_peer = IdpDescriptor::from_metadata_xml(
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    assert_eq!(sp_peer.metadata().organization()?, Some(organization()));
    assert_eq!(idp_peer.metadata().contacts()?, contacts());
    Ok(())
}

#[test]
fn unset_descriptions_leave_existing_output_unchanged() -> TestResult {
    let mut cfg = raw_sp();
    cfg.organization = None;
    cfg.contacts.clear();
    cfg.error_url = None;
    let xml = generate_sp_metadata(&cfg)?;
    assert_eq!(xml, concat!(
        "<EntityDescriptor entityID=\"https://sp.example.com/metadata\" cacheDuration=\"PT3600S\" xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:assertion=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">",
        "<SPSSODescriptor AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"false\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">",
        "<NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>",
        "<AssertionConsumerService index=\"0\" Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://sp.example.com/acs\"/>",
        "</SPSSODescriptor></EntityDescriptor>"
    ));
    let parsed = SpMetadata::from_xml(&xml)?;
    assert_eq!(parsed.organization()?, None);
    assert!(parsed.contacts()?.is_empty());
    let mut idp = raw_idp();
    idp.organization = None;
    idp.contacts.clear();
    idp.error_url = None;
    let xml = generate_idp_metadata(&idp)?;
    assert!(!xml.contains("Organization"));
    assert!(!xml.contains("ContactPerson"));
    assert!(!xml.contains("errorURL"));
    Ok(())
}

#[test]
fn generation_validates_localized_values_contacts_and_error_uris() -> TestResult {
    for lang in [
        "",
        "en_US",
        "en-",
        "123",
        "abcdefghi",
        "en-123456789",
        " en",
        "en\n",
    ] {
        let mut cfg = raw_sp();
        if let Some(org) = &mut cfg.organization {
            org.names[0].lang = lang.into();
        }
        assert!(
            matches!(generate_sp_metadata(&cfg), Err(SamlError::Invalid(_))),
            "{lang:?}"
        );
    }
    for lang in [
        "en",
        "es-MX",
        "zh-Hant-TW",
        "x-private",
        "i-klingon",
        "en-001",
    ] {
        let mut cfg = raw_sp();
        if let Some(org) = &mut cfg.organization {
            org.names[0].lang = lang.into();
        }
        generate_sp_metadata(&cfg)?;
    }
    for email in [
        "alice@example.com",
        "https://example.com",
        "mailto:",
        "mailto:alice%zz@example.com",
        "mailto:alice@example.com#fragment",
    ] {
        let mut cfg = raw_sp();
        cfg.contacts[0].email_addresses = vec![email.into()];
        assert!(
            matches!(generate_sp_metadata(&cfg), Err(SamlError::Invalid(_))),
            "{email:?}"
        );
    }
    let mut cfg = raw_sp();
    cfg.contacts[0].email_addresses = vec!["MAILTO:alice@example.com".into()];
    generate_sp_metadata(&cfg)?;
    for missing in 0..3 {
        let mut cfg = raw_sp();
        if let Some(org) = &mut cfg.organization {
            match missing {
                0 => org.names.clear(),
                1 => org.display_names.clear(),
                _ => org.urls.clear(),
            }
        }
        assert!(matches!(
            generate_sp_metadata(&cfg),
            Err(SamlError::Invalid(_))
        ));
    }
    let mut cfg = raw_sp();
    if let Some(org) = &mut cfg.organization {
        org.urls[0].value = "/relative".into();
    }
    assert!(matches!(
        generate_sp_metadata(&cfg),
        Err(SamlError::Invalid(_))
    ));
    cfg = raw_sp();
    cfg.contacts[0].given_name = Some("invalid\u{1}".into());
    assert!(matches!(
        generate_sp_metadata(&cfg),
        Err(SamlError::Invalid(_))
    ));
    let mut cfg = raw_idp();
    cfg.error_url = Some("/relative".into());
    assert!(matches!(
        generate_idp_metadata(&cfg),
        Err(SamlError::Invalid(_))
    ));
    let mut config = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
        .validation(SpValidationPolicy::compatibility())
        .build()?;
    config.metadata.contacts = vec![ContactPerson {
        email_addresses: vec!["invalid".into()],
        ..ContactPerson::new(ContactType::Technical)
    }];
    assert!(matches!(config.validate(), Err(SamlError::Invalid(_))));
    Ok(())
}

#[test]
fn imported_descriptions_use_entity_scope_and_resolved_namespaces() -> TestResult {
    let xml = r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:r="http://refeds.org/metadata" xmlns:f="urn:foreign">
        <md:EntityDescriptor entityID="https://idp.example.com/metadata">
          <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <md:ContactPerson contactType="billing"/>
            <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso"/>
          </md:IDPSSODescriptor>
          <f:Organization><f:OrganizationName xml:lang="en">Wrong</f:OrganizationName></f:Organization>
          <md:Organization>
            <f:OrganizationName xml:lang="en">Wrong</f:OrganizationName>
            <md:OrganizationName xml:lang="en">Example</md:OrganizationName>
            <md:OrganizationDisplayName xml:lang="en">Example SSO</md:OrganizationDisplayName>
            <md:OrganizationURL xml:lang="en">https://example.com</md:OrganizationURL>
          </md:Organization>
          <f:ContactPerson contactType="billing"/>
          <md:ContactPerson r:contactType="http://refeds.org/metadata/contactType/security" contactType="other">
            <f:EmailAddress>mailto:wrong@example.com</f:EmailAddress>
            <md:EmailAddress>mailto:security@example.com</md:EmailAddress>
          </md:ContactPerson>
          <md:ContactPerson f:contactType="http://refeds.org/metadata/contactType/security" contactType="other"/>
        </md:EntityDescriptor>
      </md:EntitiesDescriptor>"#;
    let metadata = IdpMetadata::from_xml(xml)?;
    assert_eq!(
        metadata.organization()?.map(|org| org.names),
        Some(vec![LocalizedValue::new("en", "Example")])
    );
    assert_eq!(
        metadata.contacts()?,
        vec![
            ContactPerson {
                email_addresses: vec!["mailto:security@example.com".into()],
                ..ContactPerson::new(ContactType::Security)
            },
            ContactPerson::new(ContactType::Other)
        ]
    );
    assert_eq!(metadata.get_metadata(), xml);
    assert_eq!(
        Metadata::parse(xml, Vec::new())?.contacts()?,
        metadata.contacts()?
    );
    Ok(())
}

#[test]
fn malformed_optional_descriptions_do_not_change_import_acceptance() -> TestResult {
    let xml = IDP_XML
        .replace("contactType=\"technical\"", "contactType=\"unknown\"")
        .replace("xml:lang=\"en\"", "lang=\"en\"");
    let parsed = IdpMetadata::from_xml(&xml)?;
    assert!(matches!(parsed.contacts(), Err(SamlError::Invalid(_))));
    assert!(matches!(parsed.organization(), Err(SamlError::Invalid(_))));
    IdpDescriptor::from_metadata_xml(&xml, MetadataTrustPolicy::UnsignedForCompatibility)?;
    Ok(())
}
