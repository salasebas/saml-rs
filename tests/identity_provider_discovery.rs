use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use saml_rs::{
    CommonDomainCookie, CommonDomainCookieLifetime, EntityId, IdentityProvider, IdpConfig,
    RememberIdentityProvider, SamlError, SsoEndpoint,
};

const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const IDP_ENTITY_COOKIE_VALUE: &str = "aHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vbWV0YWRhdGE%3D";

fn identity_provider(entity_id: &str) -> Result<IdentityProvider, SamlError> {
    let config = IdpConfig::builder(
        EntityId::try_new(entity_id)?,
        SsoEndpoint::post("https://idp.example.com/sso")?,
    )
    .build()?;
    Ok(IdentityProvider::new(config))
}

fn remember(
    entity_id: &str,
    common_domain: &str,
    lifetime: CommonDomainCookieLifetime,
    existing_cookie: Option<&str>,
) -> Result<CommonDomainCookie, SamlError> {
    let mut request = RememberIdentityProvider::new(common_domain, lifetime);
    if let Some(value) = existing_cookie {
        request = request.existing_cookie(value);
    }
    identity_provider(entity_id)?.common_domain_cookie(request)
}

#[test]
fn identity_provider_writes_a_session_common_domain_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let cookie = remember(
        IDP_ENTITY_ID,
        "example.org",
        CommonDomainCookieLifetime::Session,
        None,
    )?;

    assert_eq!(cookie.value(), IDP_ENTITY_COOKIE_VALUE);
    assert_eq!(cookie.domain(), ".example.org");
    assert_eq!(cookie.lifetime(), CommonDomainCookieLifetime::Session);
    assert_eq!(
        cookie.set_cookie_header(),
        "_saml_idp=aHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vbWV0YWRhdGE%3D; Path=/; Domain=.example.org; Secure"
    );
    Ok(())
}

#[test]
fn persistent_cookie_records_max_age_in_whole_seconds() -> Result<(), Box<dyn std::error::Error>> {
    let cookie = remember(
        IDP_ENTITY_ID,
        "example.org",
        CommonDomainCookieLifetime::Persistent {
            max_age: Duration::from_secs(86_400),
        },
        None,
    )?;

    assert_eq!(
        cookie.lifetime(),
        CommonDomainCookieLifetime::Persistent {
            max_age: Duration::from_secs(86_400),
        }
    );
    assert_eq!(
        cookie.set_cookie_header(),
        "_saml_idp=aHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vbWV0YWRhdGE%3D; Path=/; Domain=.example.org; Secure; Max-Age=86400"
    );
    Ok(())
}

#[test]
fn empty_existing_cookie_starts_a_new_list() -> Result<(), Box<dyn std::error::Error>> {
    let cookie = remember(
        IDP_ENTITY_ID,
        "example.org",
        CommonDomainCookieLifetime::Session,
        Some(""),
    )?;
    assert_eq!(cookie.value(), IDP_ENTITY_COOKIE_VALUE);
    Ok(())
}

#[test]
fn writer_appends_this_identity_provider_and_moves_it_to_the_end(
) -> Result<(), Box<dyn std::error::Error>> {
    const OTHER: &str = "aHR0cHM6Ly9vdGhlci5leGFtcGxlLm5ldC9tZXRhZGF0YQ%3D%3D";
    const MOVED: &str = "aHR0cHM6Ly9vdGhlci5leGFtcGxlLm5ldC9tZXRhZGF0YQ%3D%3D%20aHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vbWV0YWRhdGE%3D";

    let appended = remember(
        IDP_ENTITY_ID,
        "example.org",
        CommonDomainCookieLifetime::Session,
        Some(OTHER),
    )?;
    assert_eq!(appended.value(), MOVED);

    let moved = remember(
        IDP_ENTITY_ID,
        "example.org",
        CommonDomainCookieLifetime::Session,
        Some(&format!("{IDP_ENTITY_COOKIE_VALUE}%20{OTHER}")),
    )?;
    assert_eq!(moved.value(), MOVED);

    let collapsed = remember(
        IDP_ENTITY_ID,
        "example.org",
        CommonDomainCookieLifetime::Session,
        Some(&format!(
            "{IDP_ENTITY_COOKIE_VALUE}%20{OTHER}%20{IDP_ENTITY_COOKIE_VALUE}"
        )),
    )?;
    assert_eq!(collapsed.value(), MOVED);

    let form_encoded = remember(
        IDP_ENTITY_ID,
        "example.org",
        CommonDomainCookieLifetime::Session,
        Some(&format!("{IDP_ENTITY_COOKIE_VALUE}+{OTHER}")),
    )?;
    assert_eq!(form_encoded.value(), MOVED);

    let unpadded = [
        "https://a.io",
        "https://b.io",
        "https://c.io",
        "https://d.io",
        "https://e.io",
    ]
    .map(|entity_id| STANDARD.encode(entity_id));
    let form_encoded_unpadded = remember(
        IDP_ENTITY_ID,
        "example.org",
        CommonDomainCookieLifetime::Session,
        Some(&unpadded.join("+")),
    )?;
    assert_eq!(
        form_encoded_unpadded.value(),
        format!("{}%20{IDP_ENTITY_COOKIE_VALUE}", unpadded.join("%20"))
    );

    let already_decoded = remember(
        IDP_ENTITY_ID,
        "example.org",
        CommonDomainCookieLifetime::Session,
        Some(
            "aHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vbWV0YWRhdGE= aHR0cHM6Ly9vdGhlci5leGFtcGxlLm5ldC9tZXRhZGF0YQ==",
        ),
    )?;
    assert_eq!(already_decoded.value(), MOVED);
    Ok(())
}

#[test]
fn common_domain_must_be_a_hostname_not_an_ip_address() -> Result<(), Box<dyn std::error::Error>> {
    for domain in ["192.168.1.1", "127.0.0.1", "10.0.0.1", "1.2.3.4"] {
        assert_invalid(
            remember(
                IDP_ENTITY_ID,
                domain,
                CommonDomainCookieLifetime::Session,
                None,
            ),
            "ASCII hostname",
        )?;
    }

    let local = remember(
        IDP_ENTITY_ID,
        "localhost",
        CommonDomainCookieLifetime::Session,
        None,
    )?;
    assert_eq!(local.domain(), ".localhost");

    let numeric_label = remember(
        IDP_ENTITY_ID,
        "example.123",
        CommonDomainCookieLifetime::Session,
        None,
    )?;
    assert_eq!(numeric_label.domain(), ".example.123");
    Ok(())
}

#[test]
fn remembered_cookie_value_stays_within_browser_cookie_limits(
) -> Result<(), Box<dyn std::error::Error>> {
    let entity = format!("https://idp.example.net/{}", "a".repeat(400));
    let single = identity_provider(&entity)?.common_domain_cookie(
        RememberIdentityProvider::new("example.org", CommonDomainCookieLifetime::Session),
    )?;
    let copies = 4096 / (single.value().len() + 3) + 2;
    let bloated = vec![single.value(); copies].join("%20");
    assert!(bloated.len() > 4096);
    assert!(bloated.len() <= 8192);
    let cookie = remember(
        IDP_ENTITY_ID,
        "example.org",
        CommonDomainCookieLifetime::Session,
        Some(&bloated),
    )?;
    assert!(CommonDomainCookie::NAME.len() + cookie.value().len() <= 4096);
    assert!(cookie
        .value()
        .ends_with(&format!("%20{IDP_ENTITY_COOKIE_VALUE}")));
    Ok(())
}

#[test]
fn cookie_name_counts_toward_the_4096_byte_limit() -> Result<(), Box<dyn std::error::Error>> {
    fn listed(tail: usize) -> Result<String, Box<dyn std::error::Error>> {
        let entity = format!("https://idp.example.net/{}", "a".repeat(tail));
        let cookie = identity_provider(&entity)?.common_domain_cookie(
            RememberIdentityProvider::new("example.org", CommonDomainCookieLifetime::Session),
        )?;
        Ok(cookie.value().to_string())
    }
    let name = CommonDomainCookie::NAME.len();
    let appended = "%20".len() + IDP_ENTITY_COOKIE_VALUE.len();

    let fits = [listed(999)?, listed(999)?, listed(954)?].join("%20");
    assert_eq!(name + fits.len() + appended, 4096);
    let cookie = remember(
        IDP_ENTITY_ID,
        "example.org",
        CommonDomainCookieLifetime::Session,
        Some(&fits),
    )?;
    assert_eq!(name + cookie.value().len(), 4096);

    let over = [listed(999)?, listed(999)?, listed(957)?].join("%20");
    assert!(over.len() + appended <= 4096);
    assert!(name + over.len() + appended > 4096);
    let evicted = remember(
        IDP_ENTITY_ID,
        "example.org",
        CommonDomainCookieLifetime::Session,
        Some(&over),
    )?;
    assert_eq!(
        evicted.value(),
        [
            listed(999)?,
            listed(957)?,
            IDP_ENTITY_COOKIE_VALUE.to_string()
        ]
        .join("%20")
    );
    Ok(())
}

#[test]
fn writer_keeps_valid_history_and_omits_invalid_entity_ids(
) -> Result<(), Box<dyn std::error::Error>> {
    let entries: [&[u8]; 5] = [
        b"urn:example:archive-idp",
        b"legacy-idp",
        &[0xfb],
        b"https://archive.example/idp%",
        b"https://other.example.net/metadata",
    ];
    let existing = entries.map(|entry| STANDARD.encode(entry)).join(" ");
    let cookie = remember(
        IDP_ENTITY_ID,
        "example.org",
        CommonDomainCookieLifetime::Persistent {
            max_age: Duration::from_secs(86_400),
        },
        Some(&existing),
    )?;
    assert_eq!(
        cookie.set_cookie_header(),
        concat!(
            "_saml_idp=dXJuOmV4YW1wbGU6YXJjaGl2ZS1pZHA%3D%20",
            "aHR0cHM6Ly9vdGhlci5leGFtcGxlLm5ldC9tZXRhZGF0YQ%3D%3D%20",
            "aHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vbWV0YWRhdGE%3D",
            "; Path=/; Domain=.example.org; Secure; Max-Age=86400",
        )
    );
    Ok(())
}

#[test]
fn writer_filters_existing_entity_ids_above_1024_characters(
) -> Result<(), Box<dyn std::error::Error>> {
    let prefix = "https://archive.example/";
    let longest = format!("{prefix}{}", "a".repeat(1024 - prefix.len()));
    let within = STANDARD.encode(&longest);
    let over = STANDARD.encode(format!("{longest}a"));
    let cookie = remember(
        IDP_ENTITY_ID,
        "example.org",
        CommonDomainCookieLifetime::Session,
        Some(&format!("{within} {over}")),
    )?;

    assert_eq!(
        cookie.value(),
        format!("{}%20{IDP_ENTITY_COOKIE_VALUE}", within.replace('=', "%3D"))
    );
    Ok(())
}

#[test]
fn cookie_value_percent_encodes_base64_plus_and_slash() -> Result<(), Box<dyn std::error::Error>> {
    let plus = remember(
        "https://idp.example/~",
        "example.org",
        CommonDomainCookieLifetime::Session,
        None,
    )?;
    assert_eq!(plus.value(), "aHR0cHM6Ly9pZHAuZXhhbXBsZS9%2B");

    let slash = remember(
        "https://idp.example.com/metadata?x=1",
        "example.org",
        CommonDomainCookieLifetime::Session,
        None,
    )?;
    assert_eq!(
        slash.value(),
        "aHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vbWV0YWRhdGE%2FeD0x"
    );

    let again = remember(
        "https://idp.example/~",
        "example.org",
        CommonDomainCookieLifetime::Session,
        Some(plus.value()),
    )?;
    assert_eq!(again.value(), plus.value());

    let decoded_plus = remember(
        "https://idp.example/~",
        "example.org",
        CommonDomainCookieLifetime::Session,
        Some("aHR0cHM6Ly9vdGhlci5leGFtcGxlLm5ldC9tZXRhZGF0YQ== aHR0cHM6Ly9pZHAuZXhhbXBsZS9+"),
    )?;
    assert_eq!(
        decoded_plus.value(),
        "aHR0cHM6Ly9vdGhlci5leGFtcGxlLm5ldC9tZXRhZGF0YQ%3D%3D%20aHR0cHM6Ly9pZHAuZXhhbXBsZS9%2B"
    );
    Ok(())
}

#[test]
fn discovery_cookie_rejects_input_that_cannot_be_written() -> Result<(), Box<dyn std::error::Error>>
{
    assert_invalid(
        remember(
            IDP_ENTITY_ID,
            ".example.org",
            CommonDomainCookieLifetime::Session,
            None,
        ),
        "without a leading period",
    )?;
    assert_invalid(
        remember(IDP_ENTITY_ID, "", CommonDomainCookieLifetime::Session, None),
        "must not be empty",
    )?;
    assert_invalid(
        remember(
            IDP_ENTITY_ID,
            "example.org/idp",
            CommonDomainCookieLifetime::Session,
            None,
        ),
        "ASCII hostname",
    )?;
    assert_invalid(
        remember(
            IDP_ENTITY_ID,
            "ex ample.org",
            CommonDomainCookieLifetime::Session,
            None,
        ),
        "ASCII hostname",
    )?;
    assert_invalid(
        remember(
            IDP_ENTITY_ID,
            "example.org",
            CommonDomainCookieLifetime::Persistent {
                max_age: Duration::ZERO,
            },
            None,
        ),
        "at least one second",
    )?;
    assert_invalid(
        remember(
            IDP_ENTITY_ID,
            "example.org",
            CommonDomainCookieLifetime::Persistent {
                max_age: Duration::from_millis(1_500),
            },
            None,
        ),
        "whole number of seconds",
    )?;
    assert_invalid(
        remember(
            IDP_ENTITY_ID,
            "example.org",
            CommonDomainCookieLifetime::Persistent {
                max_age: Duration::from_secs(2_147_483_648),
            },
            None,
        ),
        "at most 2147483647 seconds",
    )?;
    let longest = remember(
        IDP_ENTITY_ID,
        "example.org",
        CommonDomainCookieLifetime::Persistent {
            max_age: Duration::from_secs(2_147_483_647),
        },
        None,
    )?;
    assert!(longest
        .set_cookie_header()
        .ends_with("; Max-Age=2147483647"));
    assert_invalid(
        remember(
            IDP_ENTITY_ID,
            "example.org",
            CommonDomainCookieLifetime::Session,
            Some("%"),
        ),
        "truncated percent escape",
    )?;
    assert_invalid(
        remember(
            IDP_ENTITY_ID,
            "example.org",
            CommonDomainCookieLifetime::Session,
            Some("%ZZ"),
        ),
        "not hexadecimal",
    )?;
    assert_invalid(
        remember(
            IDP_ENTITY_ID,
            "example.org",
            CommonDomainCookieLifetime::Session,
            Some("%20"),
        ),
        "empty entry",
    )?;
    assert_invalid(
        remember(
            IDP_ENTITY_ID,
            "example.org",
            CommonDomainCookieLifetime::Session,
            Some("not-valid"),
        ),
        "not base64",
    )?;
    assert_invalid(
        remember(
            IDP_ENTITY_ID,
            "example.org",
            CommonDomainCookieLifetime::Session,
            Some(&"a".repeat(8_193)),
        ),
        "larger than 8192 bytes",
    )?;

    let prefix = "https://idp.example/";
    let within = format!("{prefix}{}", "a".repeat(1024 - prefix.len()));
    assert_eq!(within.chars().count(), 1024);
    let accepted = remember(
        &within,
        "example.org",
        CommonDomainCookieLifetime::Session,
        None,
    )?;
    assert!(accepted.set_cookie_header().starts_with("_saml_idp="));
    let too_long = format!("{within}a");
    assert_invalid(
        remember(
            &too_long,
            "example.org",
            CommonDomainCookieLifetime::Session,
            None,
        ),
        "1024 characters",
    )?;
    assert_invalid(
        remember(
            "not-a-uri",
            "example.org",
            CommonDomainCookieLifetime::Session,
            None,
        ),
        "URI",
    )?;
    assert_invalid(
        remember(
            "https://例え.jp/metadata",
            "example.org",
            CommonDomainCookieLifetime::Session,
            None,
        ),
        "URI",
    )?;
    assert_invalid(
        remember(
            "https://idp.example/metadata/{version}",
            "example.org",
            CommonDomainCookieLifetime::Session,
            None,
        ),
        "URI",
    )?;
    Ok(())
}

fn assert_invalid(
    result: Result<CommonDomainCookie, SamlError>,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Err(SamlError::Invalid(actual)) if actual.contains(message) => Ok(()),
        Err(SamlError::Invalid(actual)) => {
            Err(format!("error {actual:?} does not contain {message:?}").into())
        }
        Err(error) => Err(format!("expected Invalid, got {error}").into()),
        Ok(_) => Err(format!("expected Invalid containing {message:?}").into()),
    }
}
