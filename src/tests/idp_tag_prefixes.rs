#![cfg(crypto)]

use saml_rs::tests::engine::LogoutUser;
use saml_rs::tests::engine::{IdpMessages, SpMessages};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::binding::{deflate_raw_decode, MAX_DEFLATE_RAW_DECODE_BYTES};
use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::constants::Binding;
use saml_rs::entity::{BindingContext, EntitySetting, User};
use saml_rs::flow::HttpRequest;
use saml_rs::idp::IdentityProvider;
use saml_rs::idp::LoginResponseOptions;
use saml_rs::metadata::{Endpoint, IdpMetadataInput, SpMetadataInput};
use saml_rs::sp::ServiceProvider;
use saml_rs::template::LoginResponseTemplate;
use saml_rs::tests::engine::{create_logout_request, create_logout_response};
use saml_rs::SamlError;

const PRIVKEY: &str = include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const REQUEST_ID: &str = "_prefix_req";

fn signing() -> EntitySetting {
    EntitySetting {
        private_key: Some(PRIVKEY.into()),
        signing_cert: Some(CERT.into()),
        request_signature_algorithm: RSA_SHA256.into(),
        ..EntitySetting::default()
    }
}

fn idp_with_setting(setting: EntitySetting) -> Result<IdentityProvider, SamlError> {
    let config = IdpMetadataInput {
        entity_id: "https://idp.example.com/metadata".into(),
        signing_certs: vec![CERT.into()],
        single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
        single_logout_service: vec![
            Endpoint::new(Binding::Post, "https://idp/slo"),
            Endpoint::new(Binding::Redirect, "https://idp/slo"),
            Endpoint::new(Binding::SimpleSign, "https://idp/slo"),
        ],
        ..IdpMetadataInput::default()
    };
    IdentityProvider::from_config(&config, setting)
}

fn sp(want_assertions_signed: bool) -> Result<ServiceProvider, SamlError> {
    let config = SpMetadataInput {
        entity_id: "https://sp.example.com/metadata".into(),
        want_assertions_signed,
        signing_certs: vec![CERT.into()],
        assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
        single_logout_service: vec![
            Endpoint::new(Binding::Post, "https://sp/slo"),
            Endpoint::new(Binding::Redirect, "https://sp/slo"),
            Endpoint::new(Binding::SimpleSign, "https://sp/slo"),
        ],
        ..SpMetadataInput::default()
    };
    ServiceProvider::from_config(&config, signing())
}

fn decode_post_or_simplesign(ctx: &BindingContext) -> Result<String, Box<dyn std::error::Error>> {
    match ctx.binding {
        Binding::Post | Binding::SimpleSign => {
            Ok(String::from_utf8(STANDARD.decode(&ctx.context)?)?)
        }
        _ => Err("expected POST or SimpleSign context".into()),
    }
}

fn decode_logout_context(ctx: &BindingContext) -> Result<String, Box<dyn std::error::Error>> {
    match ctx.binding {
        Binding::Post | Binding::SimpleSign => {
            Ok(String::from_utf8(STANDARD.decode(&ctx.context)?)?)
        }
        Binding::Redirect => {
            let url = url::Url::parse(&ctx.context)?;
            let value = url
                .query_pairs()
                .find_map(|(key, value)| (key == ctx.request_type).then_some(value.into_owned()))
                .ok_or("missing SAML logout message")?;
            Ok(String::from_utf8(deflate_raw_decode(
                &STANDARD.decode(value.as_bytes())?,
                MAX_DEFLATE_RAW_DECODE_BYTES,
            )?)?)
        }
        Binding::Soap => Ok(ctx.context.clone()),
        _ => Err("binding does not render logout messages here".into()),
    }
}

fn login_response_xml(
    setting: EntitySetting,
) -> Result<(IdentityProvider, ServiceProvider, BindingContext, String), Box<dyn std::error::Error>>
{
    let idp = idp_with_setting(setting)?;
    let sp = sp(true)?;
    let ctx = idp.create_login_response(
        &sp,
        Binding::Post,
        &User::new("prefix@example.com"),
        &LoginResponseOptions {
            in_response_to: Some(REQUEST_ID),
            ..Default::default()
        },
    )?;
    let xml = decode_post_or_simplesign(&ctx)?;
    Ok((idp, sp, ctx, xml))
}

fn prefixed_setting(protocol: &str, assertion: &str) -> EntitySetting {
    let mut setting = signing();
    setting.tag_prefix_protocol = protocol.to_string();
    setting.tag_prefix_assertion = assertion.to_string();
    setting
}

fn logout_user() -> LogoutUser {
    let mut user = LogoutUser::new("logout@example.com");
    user.session_index = Some("_session".into());
    user
}

#[test]
fn login_response_default_prefixes_remain_samlp_and_saml() -> Result<(), Box<dyn std::error::Error>>
{
    let (_, _, _, xml) = login_response_xml(signing())?;

    assert!(xml.contains("<samlp:Response"));
    assert!(xml.contains("xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\""));
    assert!(xml.contains("<saml:Issuer>"));
    assert!(xml.contains("<saml:Assertion"));
    assert!(xml.contains("xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\""));
    assert!(!xml.contains("<samlp2:Response"));
    assert!(!xml.contains("<saml2:Assertion"));
    Ok(())
}

#[test]
fn login_response_protocol_prefix_can_be_overridden() -> Result<(), Box<dyn std::error::Error>> {
    let (_, _, _, xml) = login_response_xml(prefixed_setting("samlp2", "saml"))?;

    assert!(xml.contains("<samlp2:Response"));
    assert!(xml.contains("xmlns:samlp2=\"urn:oasis:names:tc:SAML:2.0:protocol\""));
    assert!(xml.contains("</samlp2:Response>"));
    assert!(!xml.contains("<samlp:Response"));
    Ok(())
}

#[test]
fn login_response_assertion_prefix_can_be_overridden() -> Result<(), Box<dyn std::error::Error>> {
    let (_, _, _, xml) = login_response_xml(prefixed_setting("samlp", "saml2"))?;

    assert!(xml.contains("<saml2:Issuer>"));
    assert!(xml.contains("<saml2:Assertion"));
    assert!(xml.contains("xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\""));
    assert!(!xml.contains("<saml:Assertion"));
    Ok(())
}

#[test]
fn login_response_both_prefixes_can_be_overridden_and_signed_post_parses(
) -> Result<(), Box<dyn std::error::Error>> {
    let (idp, sp, ctx, xml) = login_response_xml(prefixed_setting("samlp2", "saml2"))?;

    assert!(xml.contains("<samlp2:Response"));
    assert!(xml.contains("<saml2:Assertion"));
    let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);
    let parsed =
        sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, REQUEST_ID)?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("prefix@example.com"));
    Ok(())
}

#[test]
fn caller_login_response_template_is_rewritten_with_configured_prefixes(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut setting = prefixed_setting("samlp2", "saml2");
    setting.login_response_template = Some(LoginResponseTemplate {
        context: Some(saml_rs::config::SSO_RESPONSE_TEMPLATE.into()),
        attributes: Vec::new(),
    });
    let (idp, sp, ctx, xml) = login_response_xml(setting)?;

    assert!(xml.contains("<samlp2:Response"), "{xml}");
    assert!(xml.contains("<saml2:Assertion"), "{xml}");
    assert!(!xml.contains("<samlp:Response"), "{xml}");
    assert!(!xml.contains("<saml:Assertion"), "{xml}");
    let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);
    let parsed =
        sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, REQUEST_ID)?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("prefix@example.com"));
    Ok(())
}

#[test]
fn caller_login_response_template_rewrites_each_prefix_once(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut setting = prefixed_setting("saml", "a");
    setting.login_response_template = Some(LoginResponseTemplate {
        context: Some(saml_rs::config::SSO_RESPONSE_TEMPLATE.into()),
        attributes: Vec::new(),
    });
    let (idp, sp, ctx, xml) = login_response_xml(setting)?;

    assert!(
        xml.starts_with(concat!(
            r#"<saml:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:protocol" "#,
            r#"xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion" ID=""#,
        )),
        "{xml}"
    );
    assert!(xml.contains("</a:Issuer><saml:Status>"), "{xml}");
    let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);
    let parsed =
        sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, REQUEST_ID)?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("prefix@example.com"));
    Ok(())
}

#[test]
fn logout_request_defaults_render_overridden_prefixes_for_post_redirect_and_simplesign(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp_with_setting(prefixed_setting("samlp2", "saml2"))?;
    let sp = sp(false)?;
    let user = logout_user();

    for binding in [Binding::Post, Binding::Redirect, Binding::SimpleSign] {
        let ctx = create_logout_request(
            &idp.setting,
            idp.metadata.as_metadata(),
            sp.metadata.as_metadata(),
            binding,
            &user,
            None,
            false,
        )?;
        let xml = decode_logout_context(&ctx)?;
        assert!(xml.contains("<samlp2:LogoutRequest"));
        assert!(xml.contains("xmlns:samlp2=\"urn:oasis:names:tc:SAML:2.0:protocol\""));
        assert!(xml.contains("<saml2:Issuer>"));
        assert!(xml.contains("<saml2:NameID>"));
        assert!(xml.contains("<samlp2:SessionIndex>_session</samlp2:SessionIndex>"));
    }
    Ok(())
}

#[test]
fn logout_response_defaults_render_overridden_prefixes_for_post_redirect_and_simplesign(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp_with_setting(prefixed_setting("samlp2", "saml2"))?;
    let sp = sp(false)?;

    for binding in [Binding::Post, Binding::Redirect, Binding::SimpleSign] {
        let ctx = create_logout_response(
            &idp.setting,
            idp.metadata.as_metadata(),
            sp.metadata.as_metadata(),
            binding,
            Some("_logout_req"),
            None,
            false,
        )?;
        let xml = decode_logout_context(&ctx)?;
        assert!(xml.contains("<samlp2:LogoutResponse"));
        assert!(xml.contains("xmlns:samlp2=\"urn:oasis:names:tc:SAML:2.0:protocol\""));
        assert!(xml.contains("<saml2:Issuer>"));
        assert!(xml.contains("<samlp2:Status>"));
    }
    Ok(())
}

#[test]
fn invalid_prefixes_are_rejected_before_rendering() -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp_with_setting(prefixed_setting("", "saml"))?;
    let sp = sp(true)?;
    assert!(matches!(
        idp.create_login_response(
            &sp,
            Binding::Post,
            &User::new("invalid@example.com"),
            &LoginResponseOptions {
                in_response_to: Some(REQUEST_ID),
                ..Default::default()
            },
        ),
        Err(SamlError::Invalid(message)) if message.contains("protocol")
    ));

    for invalid in ["bad prefix", "1a", "a,b", "-x", "xml", "xmlns"] {
        let idp = idp_with_setting(prefixed_setting(invalid, "saml"))?;
        let result = idp.create_login_response(
            &sp,
            Binding::Post,
            &User::new("invalid@example.com"),
            &LoginResponseOptions {
                in_response_to: Some(REQUEST_ID),
                ..Default::default()
            },
        );
        assert!(
            matches!(&result, Err(SamlError::Invalid(message)) if message.contains("protocol tag prefix")),
            "{invalid:?}: {result:?}"
        );

        let idp = idp_with_setting(prefixed_setting("samlp", invalid))?;
        let result = create_logout_response(
            &idp.setting,
            idp.metadata.as_metadata(),
            sp.metadata.as_metadata(),
            Binding::Post,
            Some("_logout_req"),
            None,
            false,
        );
        assert!(
            matches!(&result, Err(SamlError::Invalid(message)) if message.contains("assertion tag prefix")),
            "{invalid:?}: {result:?}"
        );
    }

    let idp = idp_with_setting(prefixed_setting("p", "p"))?;
    let result = create_logout_response(
        &idp.setting,
        idp.metadata.as_metadata(),
        sp.metadata.as_metadata(),
        Binding::Post,
        Some("_logout_req"),
        None,
        false,
    );
    assert!(
        matches!(&result, Err(SamlError::Invalid(message)) if message.contains("tag prefixes must differ")),
        "{result:?}"
    );
    Ok(())
}
