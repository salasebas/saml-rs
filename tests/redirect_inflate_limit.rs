#![allow(deprecated)]
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::binding::{deflate_raw_encode, MAX_DEFLATE_RAW_DECODE_BYTES};
use saml_rs::constants::{Binding, ParserType};
use saml_rs::entity::EntitySetting;
use saml_rs::flow::{flow, FlowOptions, HttpRequest};
use saml_rs::metadata::{Endpoint, IdpMetadataInput, SpMetadataInput};
use saml_rs::raw::{IdentityProvider, LoginRequestOptions, ServiceProvider};
use saml_rs::{ResourceLimit, SamlError};
use url::Url;

fn oversized_deflate_payload() -> Result<Vec<u8>, SamlError> {
    let oversized = vec![b'A'; MAX_DEFLATE_RAW_DECODE_BYTES + 1];
    deflate_raw_encode(&oversized)
}

fn redirect_request(url: &str) -> Result<HttpRequest, SamlError> {
    let parsed = Url::parse(url).map_err(|e| SamlError::Invalid(e.to_string()))?;
    Ok(HttpRequest::redirect(
        parsed
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect(),
    ))
}

fn unsigned_sp() -> Result<ServiceProvider, SamlError> {
    let mut config = SpMetadataInput::default();
    config.entity_id = "https://sp.example.com/metadata".into();
    config.assertion_consumer_service = vec![Endpoint::new(Binding::Post, "https://sp/acs")];
    ServiceProvider::from_config(&config, EntitySetting::default())
}

fn unsigned_idp(setting: EntitySetting) -> Result<IdentityProvider, SamlError> {
    let mut config = IdpMetadataInput::default();
    config.entity_id = "https://idp.example.com/metadata".into();
    config.single_sign_on_service = vec![Endpoint::new(Binding::Redirect, "https://idp/sso")];
    IdentityProvider::from_config(&config, setting)
}

#[test]
fn redirect_flow_rejects_oversized_compressed_input_before_inflate(
) -> Result<(), Box<dyn std::error::Error>> {
    let request =
        HttpRequest::redirect(vec![("SAMLRequest".to_string(), STANDARD.encode([0u8; 9]))]);
    let mut opts = FlowOptions::default();
    opts.binding = Some(Binding::Redirect);
    opts.parser_type = Some(ParserType::SamlRequest);
    opts.redirect_inflate_max_bytes = 8;

    let err = flow(&opts, &request)
        .err()
        .ok_or("redirect flow unexpectedly succeeded")?;

    assert!(matches!(
        err,
        SamlError::LimitExceeded {
            limit: ResourceLimit::Base64DecodedBytes,
            ..
        }
    ));
    Ok(())
}

#[test]
fn flow_options_custom_redirect_inflate_limit_is_enforced() -> Result<(), Box<dyn std::error::Error>>
{
    let inflated = vec![b'A'; 64];
    let compressed = deflate_raw_encode(&inflated)?;
    if compressed.len() >= inflated.len() {
        return Err("test payload did not compress below inflated size".into());
    }
    let request = HttpRequest::redirect(vec![(
        "SAMLRequest".to_string(),
        STANDARD.encode(&compressed),
    )]);
    let mut opts = FlowOptions::default();
    opts.binding = Some(Binding::Redirect);
    opts.parser_type = Some(ParserType::SamlRequest);
    opts.redirect_inflate_max_bytes = compressed.len();

    let err = flow(&opts, &request)
        .err()
        .ok_or("redirect flow unexpectedly succeeded")?;

    assert!(matches!(
        err,
        SamlError::LimitExceeded {
            limit: ResourceLimit::InflatedBytes,
            ..
        }
    ));
    Ok(())
}

#[test]
fn entity_setting_custom_redirect_compressed_limit_is_enforced(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = unsigned_sp()?;
    let mut idp = unsigned_idp(EntitySetting::default())?;
    let ctx = sp.create_login_request(&idp, Binding::Redirect, &LoginRequestOptions::default())?;
    let request = redirect_request(&ctx.context)?;
    idp.setting.redirect_inflate_max_bytes = 8;

    let err = idp
        .parse_login_request(&sp, Binding::Redirect, &request)
        .err()
        .ok_or("redirect parse unexpectedly succeeded")?;

    assert!(matches!(
        err,
        SamlError::LimitExceeded {
            limit: ResourceLimit::Base64DecodedBytes,
            ..
        }
    ));
    Ok(())
}

#[test]
fn redirect_flow_rejects_oversized_inflated_message() -> Result<(), Box<dyn std::error::Error>> {
    let compressed = oversized_deflate_payload()?;
    let request = HttpRequest::redirect(vec![(
        "SAMLRequest".to_string(),
        STANDARD.encode(&compressed),
    )]);
    let mut opts = FlowOptions::default();
    opts.binding = Some(Binding::Redirect);
    opts.parser_type = Some(ParserType::SamlRequest);

    let err = flow(&opts, &request)
        .err()
        .ok_or("redirect flow unexpectedly succeeded")?;

    assert!(matches!(
        err,
        SamlError::LimitExceeded {
            limit: ResourceLimit::InflatedBytes,
            ..
        }
    ));
    Ok(())
}

#[test]
fn post_flow_rejects_decoded_xml_byte_limit() -> Result<(), Box<dyn std::error::Error>> {
    let request = HttpRequest::post(vec![(
        "SAMLRequest".to_string(),
        STANDARD.encode(b"<AuthnRequest/>"),
    )]);
    let mut opts = FlowOptions::default();
    opts.binding = Some(Binding::Post);
    opts.parser_type = Some(ParserType::SamlRequest);
    opts.xml_limits.max_bytes = 8;

    let err = flow(&opts, &request)
        .err()
        .ok_or("POST flow unexpectedly succeeded")?;

    assert!(matches!(
        err,
        SamlError::LimitExceeded {
            limit: ResourceLimit::Base64DecodedBytes,
            ..
        }
    ));
    Ok(())
}

#[test]
fn simplesign_flow_rejects_decoded_xml_byte_limit() -> Result<(), Box<dyn std::error::Error>> {
    let request = HttpRequest::post(vec![(
        "SAMLRequest".to_string(),
        STANDARD.encode(b"<AuthnRequest/>"),
    )]);
    let mut opts = FlowOptions::default();
    opts.binding = Some(Binding::SimpleSign);
    opts.parser_type = Some(ParserType::SamlRequest);
    opts.xml_limits.max_bytes = 8;

    let err = flow(&opts, &request)
        .err()
        .ok_or("SimpleSign flow unexpectedly succeeded")?;

    assert!(matches!(
        err,
        SamlError::LimitExceeded {
            limit: ResourceLimit::Base64DecodedBytes,
            ..
        }
    ));
    Ok(())
}

#[test]
fn post_flow_rejects_dom_node_budget_before_authentication(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = format!("<AuthnRequest>{}</AuthnRequest>", "<Extra/>".repeat(4));
    let request = HttpRequest::post(vec![(
        "SAMLRequest".to_string(),
        STANDARD.encode(xml.as_bytes()),
    )]);
    let mut opts = FlowOptions::default();
    opts.binding = Some(Binding::Post);
    opts.parser_type = Some(ParserType::SamlRequest);
    opts.xml_limits.max_nodes = 3;

    let err = flow(&opts, &request)
        .err()
        .ok_or("POST flow unexpectedly succeeded")?;

    assert!(matches!(
        err,
        SamlError::LimitExceeded {
            limit: ResourceLimit::XmlNodes,
            ..
        }
    ));
    Ok(())
}
