#[path = "common/policies_without_crypto.rs"]
mod policies_without_crypto;

use std::time::{Duration, SystemTime};

use policies_without_crypto::sp_validation_without_crypto;
use saml_rs::constants::Binding;
use saml_rs::metadata::{
    generate_idp_metadata, generate_sp_metadata, Endpoint, IdpMetadataInput, SpMetadataInput,
};
use saml_rs::{
    AcsEndpoint, EntityId, IdentityProvider, IdpConfig, MetadataLifetime, ServiceProvider,
    SpConfig, SsoEndpoint,
};

#[test]
fn generated_root_carries_the_default_or_configured_lifetime(
) -> Result<(), Box<dyn std::error::Error>> {
    let valid_until = SystemTime::UNIX_EPOCH;
    let lifetimes = [
        (None, (None, Some("PT86400S"))),
        (
            Some(MetadataLifetime::ValidUntil(valid_until)),
            (Some("1970-01-01T00:00:00Z"), None),
        ),
        (
            Some(MetadataLifetime::CacheDuration(Duration::from_secs(3600))),
            (None, Some("PT3600S")),
        ),
        (
            Some(MetadataLifetime::ValidUntilAndCacheDuration {
                valid_until: valid_until + Duration::from_millis(900),
                cache_duration: Duration::from_millis(1500),
            }),
            (Some("1970-01-01T00:00:00Z"), Some("PT1.500000000S")),
        ),
    ];
    let sp_entity_id = "https://sp.example.com/metadata";
    let idp_entity_id = "https://idp.example.com/metadata";
    let acs_url = "https://sp.example.com/acs";
    let sso_url = "https://idp.example.com/sso";

    for (lifetime, expected) in lifetimes {
        let mut sp_input = SpMetadataInput::default();
        sp_input.entity_id = sp_entity_id.into();
        sp_input.assertion_consumer_services = vec![Endpoint::new(Binding::Post, acs_url)];
        sp_input.lifetime = lifetime;
        let sp_xml = generate_sp_metadata(&sp_input)?;

        let mut idp_input = IdpMetadataInput::default();
        idp_input.entity_id = idp_entity_id.into();
        idp_input.single_sign_on_services = vec![Endpoint::new(Binding::Post, sso_url)];
        idp_input.lifetime = lifetime;
        let idp_xml = generate_idp_metadata(&idp_input)?;

        let mut sp = SpConfig::builder(
            EntityId::try_new(sp_entity_id)?,
            AcsEndpoint::post(acs_url)?,
        )
        .validation(sp_validation_without_crypto());
        let mut idp = IdpConfig::builder(
            EntityId::try_new(idp_entity_id)?,
            SsoEndpoint::post(sso_url)?,
        );
        if let Some(lifetime) = lifetime {
            sp = sp.metadata_lifetime(lifetime);
            idp = idp.metadata_lifetime(lifetime);
        }
        let sp = ServiceProvider::new(sp.build()?);
        let idp = IdentityProvider::new(idp.build()?);

        for (entry_point, xml) in [
            ("generate_sp_metadata", sp_xml.as_str()),
            ("generate_idp_metadata", idp_xml.as_str()),
            ("SpConfigBuilder::build", sp.metadata_xml()),
            ("IdpConfigBuilder::build", idp.metadata_xml()),
        ] {
            let document = roxmltree::Document::parse(xml)?;
            let root = document.root_element();
            assert_eq!(root.tag_name().name(), "EntityDescriptor", "{entry_point}");
            assert_eq!(
                (
                    root.attribute("validUntil"),
                    root.attribute("cacheDuration")
                ),
                expected,
                "{entry_point} with {lifetime:?}"
            );
        }
    }
    Ok(())
}
