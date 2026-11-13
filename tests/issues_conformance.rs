//! Historical regression cases derived from npm `samlify` issue tests.

use saml_rs::binding::{base64_decode, deflate_raw_decode};
use saml_rs::constants::{Binding, ParserType};
use saml_rs::entity::EntitySetting;
use saml_rs::metadata::{generate_sp_metadata, Endpoint, IdpMetadataConfig, SpMetadataConfig};
use saml_rs::util::Value;
use saml_rs::xml::{extract, ExtractorField};
use saml_rs::{IdentityProvider, ServiceProvider};

const DUMPES_ISSUER: &str = include_str!("fixtures/misc/dumpes_issuer_response.xml");
#[cfg(crypto)]
const RESPONSE: &str = include_str!("fixtures/misc/response.xml");
const SP_META_98: &str = include_str!("fixtures/misc/sp_metadata_98.xml");

fn sp_config() -> SpMetadataConfig {
    SpMetadataConfig {
        entity_id: "https://sp.example.com/metadata".into(),
        name_id_format: vec!["urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".into()],
        assertion_consumer_service: vec![
            Endpoint::new(Binding::Post, "sp.example.com/acs"),
            Endpoint::new(Binding::Redirect, "sp.example.com/acs"),
        ],
        single_logout_service: vec![
            Endpoint::new(Binding::Post, "sp.example.com/slo"),
            Endpoint::new(Binding::Redirect, "sp.example.com/slo"),
        ],
        ..Default::default()
    }
}

fn idp_config() -> IdpMetadataConfig {
    IdpMetadataConfig {
        entity_id: "https://idp.example.com/metadata".into(),
        single_sign_on_service: vec![
            Endpoint::new(Binding::Post, "idp.example.com/sso"),
            Endpoint::new(Binding::Redirect, "idp.example.com/sso"),
        ],
        single_logout_service: vec![
            Endpoint::new(Binding::Post, "idp.example.com/sso/slo"),
            Endpoint::new(Binding::Redirect, "idp.example.com/sso/slo"),
        ],
        ..Default::default()
    }
}

fn objects(value: Option<&Value>) -> Vec<&Value> {
    match value {
        Some(Value::Array(items)) => items.iter().collect(),
        Some(obj @ Value::Object(_)) => vec![obj],
        _ => Vec::new(),
    }
}

#[test]
fn issue_31_query_param_request() {
    assert_eq!(ParserType::SamlRequest.query_param(), "SAMLRequest");
    assert_eq!(ParserType::LogoutRequest.query_param(), "SAMLRequest");
}

#[test]
fn issue_31_query_param_response() {
    assert_eq!(ParserType::SamlResponse.query_param(), "SAMLResponse");
    assert_eq!(ParserType::LogoutResponse.query_param(), "SAMLResponse");
}

#[test]
fn issue_31_query_param_invalid() {
    // Invalid keywords resolve to no binding/type (samlify throws on a bad type).
    assert!(Binding::from_short_name("samlRequest").is_none());
    assert!(Binding::from_urn("not-a-binding").is_none());
}

#[test]
fn issue_33_sp_acs_index_increments() -> Result<(), Box<dyn std::error::Error>> {
    let xml = generate_sp_metadata(&sp_config())?;
    let r = extract(
        &xml,
        &[ExtractorField::new(
            "acs",
            &[
                "EntityDescriptor",
                "SPSSODescriptor",
                "AssertionConsumerService",
            ],
        )
        .attrs(&["Binding", "Location", "isDefault", "index"])],
    )?;
    let acs = objects(r.get("acs"));
    assert_eq!(acs.len(), 2);
    assert_eq!(acs[0].get_str("index"), Some("0"));
    assert_eq!(acs[1].get_str("index"), Some("1"));
    Ok(())
}

#[test]
fn issue_352_no_index_on_sp_slo() -> Result<(), Box<dyn std::error::Error>> {
    let xml = generate_sp_metadata(&sp_config())?;
    let r = extract(
        &xml,
        &[ExtractorField::new(
            "slo",
            &["EntityDescriptor", "SPSSODescriptor", "SingleLogoutService"],
        )
        .attrs(&["Binding", "Location", "index"])],
    )?;
    let slo = objects(r.get("slo"));
    assert_eq!(slo.len(), 2);
    assert!(slo.iter().all(|s| s.get_str("index").is_none()));
    Ok(())
}

#[test]
fn issue_352_no_index_on_idp_sso() -> Result<(), Box<dyn std::error::Error>> {
    let idp = IdentityProvider::from_config(&idp_config(), EntitySetting::default())?;
    let r = extract(
        idp.metadata_xml(),
        &[ExtractorField::new(
            "sso",
            &[
                "EntityDescriptor",
                "IDPSSODescriptor",
                "SingleSignOnService",
            ],
        )
        .attrs(&["Binding", "Location", "index"])],
    )?;
    let sso = objects(r.get("sso"));
    assert_eq!(sso.len(), 2);
    assert!(sso.iter().all(|s| s.get_str("index").is_none()));
    Ok(())
}

#[test]
fn issue_352_no_index_on_idp_slo() -> Result<(), Box<dyn std::error::Error>> {
    let idp = IdentityProvider::from_config(&idp_config(), EntitySetting::default())?;
    let r = extract(
        idp.metadata_xml(),
        &[ExtractorField::new(
            "slo",
            &[
                "EntityDescriptor",
                "IDPSSODescriptor",
                "SingleLogoutService",
            ],
        )
        .attrs(&["Binding", "Location", "index"])],
    )?;
    let slo = objects(r.get("slo"));
    assert_eq!(slo.len(), 2);
    assert!(slo.iter().all(|s| s.get_str("index").is_none()));
    Ok(())
}

#[test]
fn issue_86_duplicate_issuer_deduped() -> Result<(), Box<dyn std::error::Error>> {
    let r = extract(
        DUMPES_ISSUER,
        &[ExtractorField::multi(
            "issuer",
            &[
                &["Response", "Issuer"],
                &["Response", "Assertion", "Issuer"],
            ],
        )],
    )?;
    let issuer = r.get("issuer").and_then(Value::as_array).unwrap_or(&[]);
    assert_eq!(issuer.len(), 1);
    assert!(issuer
        .iter()
        .all(|i| i.as_str() == Some("http://www.okta.com/dummyIssuer")));
    Ok(())
}

#[cfg(crypto)]
#[test]
fn issue_87_existence_check_for_signature() -> Result<(), Box<dyn std::error::Error>> {
    // An unsigned response verifies to false (no signature present).
    let (verified, _) = saml_rs::crypto::verify_signature(RESPONSE, &[])?;
    assert!(!verified);
    Ok(())
}

#[test]
fn issue_91_idp_single_sign_on_service_from_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let idp = IdentityProvider::from_config(&idp_config(), EntitySetting::default())?;
    assert_eq!(
        idp.metadata
            .get_single_sign_on_service(Binding::Post)
            .as_deref(),
        Some("idp.example.com/sso")
    );
    Ok(())
}

#[test]
fn issue_98_undefined_acs_url_with_redirect() -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::from_metadata(SP_META_98, EntitySetting::default())?;
    let idp = IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            single_sign_on_service: vec![Endpoint::new(Binding::Redirect, "https://idp/sso")],
            ..Default::default()
        },
        EntitySetting::default(),
    )?;
    let ctx = sp.create_login_request(&idp, Binding::Redirect, None)?;
    let url = url::Url::parse(&ctx.context)?;
    let (_, value) = url
        .query_pairs()
        .find(|(k, _)| k == "SAMLRequest")
        .ok_or("missing SAMLRequest")?;
    let xml = String::from_utf8(deflate_raw_decode(&base64_decode(&value)?)?)?;
    assert!(xml.contains("AssertionConsumerServiceURL=\"https://example.org/response\""));
    Ok(())
}
