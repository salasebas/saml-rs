use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::binding::{deflate_raw_decode, MAX_DEFLATE_RAW_DECODE_BYTES};
use saml_rs::constants::Binding;
use saml_rs::entity::EntitySetting;
use saml_rs::idp;
use saml_rs::metadata::{Endpoint, IdpMetadataInput, SpMetadataInput};
use saml_rs::sp;
use saml_rs::sp::LoginRequestOptions;
use saml_rs::tests::engine::SpMessages;

fn sp(setting: EntitySetting) -> Result<sp::Engine, saml_rs::SamlError> {
    let config = SpMetadataInput {
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
        ..SpMetadataInput::default()
    };
    sp::Engine::from_config(&config, setting)
}

#[cfg(crypto)]
fn idp(setting: EntitySetting) -> Result<idp::Engine, saml_rs::SamlError> {
    let config = IdpMetadataInput {
        entity_id: "https://idp.example.com/metadata".into(),
        signing_certs: setting
            .signing_cert
            .clone()
            .map(|c| vec![c])
            .unwrap_or_default(),
        want_authn_requests_signed: setting.private_key.is_some(),
        single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
        single_logout_service: vec![Endpoint::new(Binding::Post, "https://idp/slo")],
        ..IdpMetadataInput::default()
    };
    idp::Engine::from_config(&config, setting)
}

#[test]
fn unsigned_authn_request_redirect_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp(EntitySetting::default())?;
    let idp_config = IdpMetadataInput {
        entity_id: "https://idp.example.com/metadata".into(),
        single_sign_on_service: vec![Endpoint::new(Binding::Redirect, "https://idp/sso")],
        ..IdpMetadataInput::default()
    };
    let idp = idp::Engine::from_config(&idp_config, EntitySetting::default())?;
    let ctx = sp.create_login_request(&idp, Binding::Redirect, &LoginRequestOptions::default())?;
    let url = url::Url::parse(&ctx.context)?;
    let (_, value) = url
        .query_pairs()
        .find(|(k, _)| k == "SAMLRequest")
        .ok_or("missing SAMLRequest")?;
    let xml = String::from_utf8(deflate_raw_decode(
        &STANDARD.decode(value.as_bytes())?,
        MAX_DEFLATE_RAW_DECODE_BYTES,
    )?)?;
    assert!(xml.contains("<samlp:AuthnRequest"));
    Ok(())
}

#[test]
fn sp_metadata_generate_parse_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp(EntitySetting::default())?;
    let reparsed = sp::Engine::from_metadata(sp.metadata_xml(), EntitySetting::default())?;
    assert_eq!(
        reparsed.metadata.as_metadata().entity_id(),
        Some("https://sp.example.com/metadata")
    );
    assert_eq!(
        reparsed
            .metadata
            .assertion_consumer_location(Binding::Post)
            .as_deref(),
        Some("https://sp/acs")
    );
    Ok(())
}

#[cfg(crypto)]
mod signed {
    use super::*;
    use saml_rs::constants::signature_algorithm::RSA_SHA256;
    use saml_rs::flow::HttpRequest;
    use saml_rs::tests::engine::{
        create_logout_request, parse_logout_request, IdpMessages, LogoutUser,
    };

    const PRIVKEY: &str = include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
    const CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");

    fn signing_setting() -> EntitySetting {
        EntitySetting {
            private_key: Some(PRIVKEY.into()),
            signing_cert: Some(CERT.into()),
            request_signature_algorithm: RSA_SHA256.into(),
            ..EntitySetting::default()
        }
    }

    #[test]
    fn full_signed_sso() -> Result<(), Box<dyn std::error::Error>> {
        let sp = sp(signing_setting())?;
        let idp = idp(signing_setting())?;
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
            sp.metadata.as_metadata(),
            idp.metadata.as_metadata(),
            Binding::Post,
            &LogoutUser::new("alice@example.com"),
            None,
            true,
        )?;
        let request = HttpRequest::post(vec![("SAMLRequest".into(), ctx.context)]);
        let parsed = parse_logout_request(
            &idp.setting,
            sp.metadata.as_metadata(),
            Binding::Post,
            &request,
        )?;
        assert_eq!(
            parsed.extract.get_str("issuer"),
            Some("https://sp.example.com/metadata")
        );
        Ok(())
    }
}
