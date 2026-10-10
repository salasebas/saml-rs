#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use std::cell::RefCell;

use saml_rs::binding::{base64_decode, deflate_raw_decode};
use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::constants::Binding;
use saml_rs::entity::{iso8601_offset, BindingContext, EntitySetting, User};
use saml_rs::flow::HttpRequest;
use saml_rs::idp::LoginResponseOptions;
use saml_rs::logout::{create_logout_request, create_logout_response};
use saml_rs::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
use saml_rs::template::{replace_tags_by_value, LoginResponseTemplate};
use saml_rs::{IdentityProvider, SamlError, ServiceProvider};

const PRIVKEY: &str = include_str!("fixtures/key/sp_privkey.pem");
const CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");
const REQUEST_ID: &str = "_prefix_req";

fn signing() -> EntitySetting {
    let mut setting = EntitySetting::default();
    setting.private_key = Some(PRIVKEY.into());
    setting.signing_cert = Some(CERT.into());
    setting.request_signature_algorithm = RSA_SHA256.into();
    setting
}

fn idp_with_setting(setting: EntitySetting) -> Result<IdentityProvider, SamlError> {
    IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec![CERT.into()],
            single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
            single_logout_service: vec![
                Endpoint::new(Binding::Post, "https://idp/slo"),
                Endpoint::new(Binding::Redirect, "https://idp/slo"),
                Endpoint::new(Binding::SimpleSign, "https://idp/slo"),
            ],
            ..Default::default()
        },
        setting,
    )
}

fn sp(want_assertions_signed: bool) -> Result<ServiceProvider, SamlError> {
    ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            want_assertions_signed,
            signing_certs: vec![CERT.into()],
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
            single_logout_service: vec![
                Endpoint::new(Binding::Post, "https://sp/slo"),
                Endpoint::new(Binding::Redirect, "https://sp/slo"),
                Endpoint::new(Binding::SimpleSign, "https://sp/slo"),
            ],
            ..Default::default()
        },
        signing(),
    )
}

fn decode_post_or_simplesign(ctx: &BindingContext) -> Result<String, Box<dyn std::error::Error>> {
    match ctx.binding {
        Binding::Post | Binding::SimpleSign => Ok(String::from_utf8(base64_decode(&ctx.context)?)?),
        Binding::Redirect | Binding::Artifact => Err("expected POST or SimpleSign context".into()),
    }
}

fn decode_logout_context(ctx: &BindingContext) -> Result<String, Box<dyn std::error::Error>> {
    match ctx.binding {
        Binding::Post | Binding::SimpleSign => Ok(String::from_utf8(base64_decode(&ctx.context)?)?),
        Binding::Redirect => {
            let url = url::Url::parse(&ctx.context)?;
            let value = url
                .query_pairs()
                .find_map(|(key, value)| (key == ctx.request_type).then_some(value.into_owned()))
                .ok_or("missing SAML logout message")?;
            Ok(String::from_utf8(deflate_raw_decode(&base64_decode(
                &value,
            )?)?)?)
        }
        Binding::Artifact => Err("artifact binding does not render logout messages here".into()),
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

fn fill_login_response(template: &str, name_id: &str) -> (String, String) {
    let id = "_custom_prefix_response".to_string();
    let now = iso8601_offset(-60);
    let later = iso8601_offset(300);
    let xml = replace_tags_by_value(
        template,
        &[
            ("ID", id.clone()),
            ("AssertionID", "_custom_prefix_assertion".into()),
            ("Destination", "https://sp/acs".into()),
            ("SubjectRecipient", "https://sp/acs".into()),
            ("AssertionConsumerServiceURL", "https://sp/acs".into()),
            ("Audience", "https://sp.example.com/metadata".into()),
            ("Issuer", "https://idp.example.com/metadata".into()),
            ("IssueInstant", now.clone()),
            (
                "StatusCode",
                "urn:oasis:names:tc:SAML:2.0:status:Success".into(),
            ),
            ("ConditionsNotBefore", now),
            ("ConditionsNotOnOrAfter", later.clone()),
            ("SubjectConfirmationDataNotOnOrAfter", later),
            (
                "NameIDFormat",
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".into(),
            ),
            ("NameID", name_id.to_string()),
            ("InResponseTo", "_custom_prefix_req".into()),
            ("AuthnStatement", String::new()),
        ],
    );
    (id, xml)
}

fn prefixed_setting(protocol: &str, assertion: &str) -> EntitySetting {
    let mut setting = signing();
    setting.tag_prefix_protocol = protocol.to_string();
    setting.tag_prefix_assertion = assertion.to_string();
    setting
}

fn logout_user() -> User {
    let mut user = User::new("logout@example.com");
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
fn caller_login_response_template_is_rewritten_before_custom_callback(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut setting = prefixed_setting("samlp2", "saml2");
    setting.login_response_template = Some(LoginResponseTemplate {
        context: Some(saml_rs::template::LOGIN_RESPONSE_TEMPLATE.into()),
        attributes: Vec::new(),
    });
    let idp = idp_with_setting(setting)?;
    let sp = sp(true)?;
    let seen_template = RefCell::new(None);
    let callback = |template: &str| {
        seen_template.replace(Some(template.to_string()));
        fill_login_response(template, "callback@example.com")
    };

    let ctx = idp.create_login_response(
        &sp,
        Binding::Post,
        &User::new("callback@example.com"),
        &LoginResponseOptions {
            in_response_to: Some("_ignored_by_callback"),
            custom: Some(&callback as &dyn Fn(&str) -> (String, String)),
            ..Default::default()
        },
    )?;

    let captured = seen_template
        .into_inner()
        .ok_or("custom callback did not receive a template")?;
    assert!(captured.contains("<samlp2:Response"));
    assert!(captured.contains("<saml2:Assertion"));
    assert!(!captured.contains("<samlp:Response"));
    assert!(!captured.contains("<saml:Assertion"));

    let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);
    let parsed = sp.parse_login_response_with_request_id(
        &idp,
        Binding::Post,
        &request,
        "_custom_prefix_req",
    )?;
    assert_eq!(
        parsed.extract.get_str("nameID"),
        Some("callback@example.com")
    );
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
            &idp.metadata,
            &sp.metadata,
            binding,
            &user,
            None,
            false,
        )?;
        let xml = decode_logout_context(&ctx)?;
        assert!(xml.contains("<samlp2:LogoutRequest"));
        assert!(xml.contains("xmlns:samlp2=\"urn:oasis:names:tc:SAML:2.0:protocol\""));
        assert!(xml.contains("<saml2:Issuer>"));
        assert!(xml.contains("<saml2:NameID"));
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
            &idp.metadata,
            &sp.metadata,
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

    let idp = idp_with_setting(prefixed_setting("samlp", "bad prefix"))?;
    assert!(matches!(
        create_logout_response(
            &idp.setting,
            &idp.metadata,
            &sp.metadata,
            Binding::Post,
            Some("_logout_req"),
            None,
            false,
        ),
        Err(SamlError::Invalid(message)) if message.contains("assertion")
    ));
    Ok(())
}
