//! Metadata `validUntil` and `cacheDuration`.
//!
//! SAML Metadata §§2.3.1-2.3.2 and Approved Errata 05 E76 and E94.
#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use std::time::{Duration, SystemTime};

use saml_rs::xml::dom::parse;
use saml_rs::{
    AcsEndpoint, EntityId, IdpConfig, IdpValidationPolicy, MetadataLifetime, Saml, SamlError,
    SpConfig, SpValidationPolicy, SsoEndpoint,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const Y2001: u64 = 978_307_200;

fn at(unix_seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(unix_seconds)
}

fn sp(lifetime: Option<MetadataLifetime>) -> Result<Saml<saml_rs::Sp>, SamlError> {
    let builder = SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?.mark_default())
        .validation(SpValidationPolicy::compatibility());
    let builder = match lifetime {
        Some(lifetime) => builder.metadata_lifetime(lifetime),
        None => builder,
    };
    Saml::sp(builder.build()?)
}

fn idp(lifetime: Option<MetadataLifetime>) -> Result<Saml<saml_rs::Idp>, SamlError> {
    let builder = IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::post("https://idp.example.com/sso")?)
        .validation(IdpValidationPolicy::compatibility());
    let builder = match lifetime {
        Some(lifetime) => builder.metadata_lifetime(lifetime),
        None => builder,
    };
    Saml::idp(builder.build()?)
}

#[test]
fn generated_root_carries_the_configured_lifetime() -> Result<(), Box<dyn std::error::Error>> {
    let lifetimes = [
        (None, None, None),
        (
            Some(MetadataLifetime::ValidUntil(at(Y2001))),
            Some("2001-01-01T00:00:00Z"),
            None,
        ),
        (
            Some(MetadataLifetime::CacheDuration(Duration::from_secs(86_400))),
            None,
            Some("PT86400S"),
        ),
        (
            Some(MetadataLifetime::ValidUntilAndCacheDuration {
                valid_until: at(Y2001) + Duration::from_millis(900),
                cache_duration: Duration::from_millis(1500),
            }),
            Some("2001-01-01T00:00:00Z"),
            Some("PT1.500000000S"),
        ),
    ];

    for (lifetime, valid_until, cache_duration) in lifetimes {
        let sp = sp(lifetime)?;
        let idp = idp(lifetime)?;
        for xml in [sp.metadata_xml(), idp.metadata_xml()] {
            let root = parse(xml)?.root;
            assert_eq!(root.local_name, "EntityDescriptor");
            assert_eq!(root.attr("validUntil"), valid_until, "{xml}");
            assert_eq!(root.attr("cacheDuration"), cache_duration, "{xml}");
        }
    }
    Ok(())
}
