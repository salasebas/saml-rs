//! Black-box conformance scenarios over the public API, including historical
//! regression cases derived from npm `samlify` behavior.

use saml_rs::binding::{base64_decode, deflate_raw_decode};
use saml_rs::constants::Binding;
use saml_rs::entity::EntitySetting;
use saml_rs::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
use saml_rs::{IdentityProvider, ServiceProvider};

fn sp(setting: EntitySetting) -> Result<ServiceProvider, saml_rs::SamlError> {
    ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            authn_requests_signed: setting.private_key.is_some(),
            want_assertions_signed: setting.private_key.is_some(),
            signing_certs: setting
                .signing_cert
                .clone()
                .map(|c| vec![c])
                .unwrap_or_default(),
            single_logout_service: vec![Endpoint::new(Binding::Post, "https://sp/slo")],
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
            ..Default::default()
        },
        setting,
    )
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn idp(setting: EntitySetting) -> Result<IdentityProvider, saml_rs::SamlError> {
    IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: setting
                .signing_cert
                .clone()
                .map(|c| vec![c])
                .unwrap_or_default(),
            want_authn_requests_signed: setting.private_key.is_some(),
            single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
            single_logout_service: vec![Endpoint::new(Binding::Post, "https://idp/slo")],
            ..Default::default()
        },
        setting,
    )
}

#[test]
fn unsigned_authn_request_redirect_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp(EntitySetting::default())?;
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
    assert!(xml.contains("<samlp:AuthnRequest"));
    Ok(())
}

#[test]
fn sp_metadata_generate_parse_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp(EntitySetting::default())?;
    let reparsed = ServiceProvider::from_metadata(sp.metadata_xml(), EntitySetting::default())?;
    assert_eq!(
        reparsed.metadata.get_entity_id(),
        Some("https://sp.example.com/metadata")
    );
    assert_eq!(
        reparsed
            .metadata
            .get_assertion_consumer_service(Binding::Post)
            .as_deref(),
        Some("https://sp/acs")
    );
    Ok(())
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
mod signed {
    use super::*;
    use saml_rs::constants::signature_algorithm::RSA_SHA256;
    use saml_rs::flow::HttpRequest;
    use saml_rs::logout::{create_logout_request, parse_logout_request};

    const PRIVKEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
    const CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");

    fn signing_setting() -> EntitySetting {
        let mut setting = EntitySetting::default();
        setting.private_key = Some(PRIVKEY.into());
        setting.signing_cert = Some(CERT.into());
        setting.request_signature_algorithm = RSA_SHA256.into();
        setting
    }

    #[test]
    fn full_signed_sso() -> Result<(), Box<dyn std::error::Error>> {
        let sp = sp(signing_setting())?;
        let idp = idp(signing_setting())?;
        // IdP issues a signed Response; SP consumes it.
        let response = idp.create_login_response(
            &sp,
            Binding::Post,
            &saml_rs::entity::User::new("alice@example.com"),
            &saml_rs::idp::LoginResponseOptions {
                in_response_to: Some("_r1"),
                ..Default::default()
            },
        )?;
        let request = HttpRequest::post(vec![("SAMLResponse".into(), response.context)]);
        let parsed =
            sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, "_r1")?;
        assert_eq!(parsed.extract.get_str("nameID"), Some("alice@example.com"));
        Ok(())
    }

    #[test]
    fn signed_logout_request_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let sp = sp(signing_setting())?;
        let idp = idp(signing_setting())?;
        let ctx = create_logout_request(
            &sp.setting,
            &sp.metadata,
            &idp.metadata,
            Binding::Post,
            &saml_rs::entity::User::new("alice@example.com"),
            None,
            true, // want signed
        )?;
        // IdP requires logout requests to be signed and verifies it.
        let mut idp_signed = idp;
        idp_signed.setting.want_logout_request_signed = true;
        let request = HttpRequest::post(vec![("SAMLRequest".into(), ctx.context)]);
        let parsed =
            parse_logout_request(&idp_signed.setting, &sp.metadata, Binding::Post, &request)?;
        assert_eq!(
            parsed.extract.get_str("issuer"),
            Some("https://sp.example.com/metadata")
        );
        Ok(())
    }
}
