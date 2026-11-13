use saml_rs::binding::{base64_decode, deflate_raw_decode};
use saml_rs::constants::Binding;
use saml_rs::entity::{BindingContext, EntitySetting};
use saml_rs::flow::HttpRequest;
use saml_rs::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
use saml_rs::sp::LoginRequestOptions;
use saml_rs::{IdentityProvider, SamlError, ServiceProvider};
use url::Url;

fn idp_config(want_authn_requests_signed: bool) -> IdpMetadataConfig {
    IdpMetadataConfig {
        entity_id: "https://idp.example.com/metadata".into(),
        want_authn_requests_signed,
        single_sign_on_service: vec![
            Endpoint::new(Binding::Redirect, "https://idp.example.com/sso"),
            Endpoint::new(Binding::Post, "https://idp.example.com/sso"),
            Endpoint::new(Binding::SimpleSign, "https://idp.example.com/sso"),
        ],
        ..Default::default()
    }
}

fn sp_config(authn_requests_signed: bool) -> SpMetadataConfig {
    SpMetadataConfig {
        entity_id: "https://sp.example.com/metadata".into(),
        authn_requests_signed,
        assertion_consumer_service: vec![
            Endpoint::new(Binding::Post, "https://sp.example.com/acs"),
            Endpoint::new(Binding::Redirect, "https://sp.example.com/redirect-acs"),
            Endpoint::new(Binding::SimpleSign, "https://sp.example.com/simplesign-acs"),
        ],
        ..Default::default()
    }
}

fn unsigned_idp() -> Result<IdentityProvider, SamlError> {
    IdentityProvider::from_config(&idp_config(false), EntitySetting::default())
}

fn unsigned_sp_with_setting(setting: EntitySetting) -> Result<ServiceProvider, SamlError> {
    ServiceProvider::from_config(&sp_config(false), setting)
}

fn unsigned_sp() -> Result<ServiceProvider, SamlError> {
    unsigned_sp_with_setting(EntitySetting::default())
}

fn request_xml(ctx: &BindingContext) -> Result<String, Box<dyn std::error::Error>> {
    match ctx.binding {
        Binding::Redirect => {
            let url = Url::parse(&ctx.context)?;
            let (_, value) = url
                .query_pairs()
                .find(|(key, _)| key == "SAMLRequest")
                .ok_or("missing SAMLRequest")?;
            Ok(String::from_utf8(deflate_raw_decode(&base64_decode(
                &value,
            )?)?)?)
        }
        Binding::Post | Binding::SimpleSign => Ok(String::from_utf8(base64_decode(&ctx.context)?)?),
        Binding::Artifact | Binding::Soap => Err("binding is unsupported".into()),
    }
}

fn redirect_relay_state(url: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    Ok(Url::parse(url)?
        .query_pairs()
        .find_map(|(key, value)| (key == "RelayState").then_some(value.into_owned())))
}

const HOSTILE_SP_ENTITY_ID: &str = concat!(
    "https://sp.example.com/metadata",
    "</saml:Issuer>",
    "<evil:Injected>issuer</evil:Injected>",
    "<saml:Issuer>"
);
const HOSTILE_IDP_SSO_DESTINATION: &str = concat!(
    "https://idp.example.com/sso?",
    "continue=%3Cevil:Injected%3Edestination%3C%2Fevil:Injected%3E",
    "&quote=%22"
);
const HOSTILE_ACS_URL: &str = concat!(
    "https://sp.example.com/acs\"/>",
    "<evil:Injected>acs</evil:Injected>",
    "<samlp:AuthnRequest foo=\""
);
const HOSTILE_NAME_ID_FORMAT: &str = concat!(
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\"/>",
    "<evil:Injected>nameid</evil:Injected>",
    "<samlp:NameIDPolicy Format=\""
);

fn hostile_unsigned_idp() -> Result<IdentityProvider, SamlError> {
    IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            single_sign_on_service: vec![
                Endpoint::new(Binding::Redirect, HOSTILE_IDP_SSO_DESTINATION),
                Endpoint::new(Binding::Post, HOSTILE_IDP_SSO_DESTINATION),
                Endpoint::new(Binding::SimpleSign, HOSTILE_IDP_SSO_DESTINATION),
            ],
            ..Default::default()
        },
        EntitySetting::default(),
    )
}

fn hostile_unsigned_sp() -> Result<ServiceProvider, SamlError> {
    ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: HOSTILE_SP_ENTITY_ID.into(),
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, HOSTILE_ACS_URL)],
            name_id_format: vec![HOSTILE_NAME_ID_FORMAT.into()],
            ..Default::default()
        },
        EntitySetting::default(),
    )
}

fn login_request_http_request(
    ctx: &BindingContext,
) -> Result<HttpRequest, Box<dyn std::error::Error>> {
    match ctx.binding {
        Binding::Redirect => {
            let query = Url::parse(&ctx.context)?
                .query_pairs()
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect();
            Ok(HttpRequest {
                query,
                ..Default::default()
            })
        }
        Binding::Post | Binding::SimpleSign => Ok(HttpRequest::post(vec![(
            "SAMLRequest".into(),
            ctx.context.clone(),
        )])),
        Binding::Artifact | Binding::Soap => Err("binding is unsupported".into()),
    }
}

fn assert_hostile_values_are_escaped(xml: &str, acs_index: Option<u16>) {
    assert_eq!(xml.matches("<samlp:AuthnRequest").count(), 1);
    assert_eq!(xml.matches("<saml:Issuer").count(), 1);
    assert!(!xml.contains("<evil:Injected"));
    assert!(!xml.contains("</evil:Injected"));
    assert!(xml.contains(
        "<saml:Issuer>https://sp.example.com/metadata&lt;/saml:Issuer&gt;\
         &lt;evil:Injected&gt;issuer&lt;/evil:Injected&gt;&lt;saml:Issuer&gt;</saml:Issuer>"
    ));
    assert!(xml.contains(
        "Destination=\"https://idp.example.com/sso?continue=%3Cevil:Injected%3Edestination%3C%2Fevil:Injected%3E&amp;quote=%22\""
    ));
    assert!(xml.contains("Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress&quot;/"));
    assert!(xml.contains("nameid&lt;/evil:Injected"));

    if let Some(index) = acs_index {
        assert!(xml.contains(&format!("AssertionConsumerServiceIndex=\"{index}\"")));
        assert!(!xml.contains("AssertionConsumerServiceURL="));
        assert!(!xml.contains("ProtocolBinding="));
    } else {
        assert!(xml.contains("AssertionConsumerServiceURL=\"https://sp.example.com/acs&quot;/"));
        assert!(xml.contains("acs&lt;/evil:Injected"));
        assert!(xml.contains("ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\""));
        assert!(!xml.contains("AssertionConsumerServiceIndex="));
    }
}

fn assert_hostile_request_parses(
    idp: &IdentityProvider,
    sp: &ServiceProvider,
    ctx: &BindingContext,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = login_request_http_request(ctx)?;
    let parsed = idp.parse_login_request(sp, ctx.binding, &request)?;
    assert_eq!(parsed.extract.get_str("request.id"), Some(ctx.id.as_str()));
    assert_eq!(parsed.extract.get_str("issuer"), Some(HOSTILE_SP_ENTITY_ID));
    Ok(())
}

#[cfg(crypto)]
#[test]
fn identity_provider_metadata_want_authn_requests_signed_1_rejects_an_unsigned_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = IdentityProvider::from_config(&idp_config(true), EntitySetting::default())?
        .metadata
        .get_metadata()
        .replace(
            r#"WantAuthnRequestsSigned="true""#,
            r#"WantAuthnRequestsSigned="1""#,
        );
    assert!(metadata.contains(r#"WantAuthnRequestsSigned="1""#));
    let idp = IdentityProvider::from_metadata(&metadata, EntitySetting::default())?;
    let sp = unsigned_sp()?;
    let ctx = sp.create_login_request(&unsigned_idp()?, Binding::Post, None)?;

    match idp.parse_login_request(&sp, Binding::Post, &login_request_http_request(&ctx)?) {
        Err(SamlError::SignatureMissing) => Ok(()),
        other => Err(format!("expected SignatureMissing, got {other:?}").into()),
    }
}

#[test]
fn legacy_create_login_request_callback_still_works() -> Result<(), Box<dyn std::error::Error>> {
    let replace = |_template: &str| {
        (
            "_custom".to_string(),
            "<samlp:AuthnRequest ID=\"_custom\"/>".to_string(),
        )
    };
    let ctx = unsigned_sp()?.create_login_request(
        &unsigned_idp()?,
        Binding::Post,
        Some(&replace as &dyn Fn(&str) -> (String, String)),
    )?;

    assert_eq!(ctx.id, "_custom");
    assert!(request_xml(&ctx)?.contains("ID=\"_custom\""));
    Ok(())
}

#[test]
fn hostile_authn_request_values_escape_for_all_login_request_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = hostile_unsigned_sp()?;
    let idp = hostile_unsigned_idp()?;

    for binding in [Binding::Redirect, Binding::Post, Binding::SimpleSign] {
        let ctx = sp.create_login_request_with_options(
            &idp,
            binding,
            &LoginRequestOptions {
                force_authn: Some(true),
                ..Default::default()
            },
        )?;
        let xml = request_xml(&ctx)?;

        assert_hostile_values_are_escaped(&xml, None);
        assert!(xml.contains("ForceAuthn=\"true\""));
        assert_hostile_request_parses(&idp, &sp, &ctx)?;
    }
    Ok(())
}

#[test]
fn hostile_authn_request_values_escape_with_acs_index_for_all_login_request_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = hostile_unsigned_sp()?;
    let idp = hostile_unsigned_idp()?;

    for binding in [Binding::Redirect, Binding::Post, Binding::SimpleSign] {
        let ctx = sp.create_login_request_with_options(
            &idp,
            binding,
            &LoginRequestOptions {
                force_authn: Some(false),
                assertion_consumer_service_index: Some(7),
                ..Default::default()
            },
        )?;
        let xml = request_xml(&ctx)?;

        assert_hostile_values_are_escaped(&xml, Some(7));
        assert!(xml.contains("ForceAuthn=\"false\""));
        assert_hostile_request_parses(&idp, &sp, &ctx)?;
    }
    Ok(())
}

#[test]
fn redirect_per_request_relay_state_appears_in_url() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = unsigned_sp()?.create_login_request_with_options(
        &unsigned_idp()?,
        Binding::Redirect,
        &LoginRequestOptions {
            relay_state: Some("request state"),
            ..Default::default()
        },
    )?;

    assert_eq!(ctx.relay_state.as_deref(), Some("request state"));
    assert_eq!(
        redirect_relay_state(&ctx.context)?.as_deref(),
        Some("request state")
    );
    Ok(())
}

#[test]
fn post_and_simplesign_per_request_relay_state_appear_in_context(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in [Binding::Post, Binding::SimpleSign] {
        let ctx = unsigned_sp()?.create_login_request_with_options(
            &unsigned_idp()?,
            binding,
            &LoginRequestOptions {
                relay_state: Some("request state"),
                ..Default::default()
            },
        )?;

        assert_eq!(ctx.relay_state.as_deref(), Some("request state"));
    }
    Ok(())
}

#[test]
fn per_request_relay_state_overrides_entity_state_without_leaking(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut setting = EntitySetting::default();
    setting.relay_state = "entity state".into();
    let sp = unsigned_sp_with_setting(setting)?;
    let idp = unsigned_idp()?;

    let first = sp.create_login_request_with_options(
        &idp,
        Binding::Redirect,
        &LoginRequestOptions {
            relay_state: Some("request state"),
            ..Default::default()
        },
    )?;
    let second = sp.create_login_request_with_options(
        &idp,
        Binding::Redirect,
        &LoginRequestOptions::default(),
    )?;
    let third = sp.create_login_request_with_options(
        &idp,
        Binding::Redirect,
        &LoginRequestOptions {
            relay_state: Some(""),
            ..Default::default()
        },
    )?;

    assert_eq!(first.relay_state.as_deref(), Some("request state"));
    assert_eq!(
        redirect_relay_state(&first.context)?.as_deref(),
        Some("request state")
    );
    assert_eq!(second.relay_state.as_deref(), Some("entity state"));
    assert_eq!(
        redirect_relay_state(&second.context)?.as_deref(),
        Some("entity state")
    );
    assert_eq!(third.relay_state.as_deref(), Some(""));
    assert_eq!(redirect_relay_state(&third.context)?.as_deref(), Some(""));
    Ok(())
}

#[test]
fn force_authn_renders_true_and_false_for_all_login_request_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in [Binding::Redirect, Binding::Post, Binding::SimpleSign] {
        for force_authn in [true, false] {
            let ctx = unsigned_sp()?.create_login_request_with_options(
                &unsigned_idp()?,
                binding,
                &LoginRequestOptions {
                    force_authn: Some(force_authn),
                    ..Default::default()
                },
            )?;

            assert!(request_xml(&ctx)?.contains(&format!("ForceAuthn=\"{force_authn}\"")));
        }
    }
    Ok(())
}

#[test]
fn force_authn_is_omitted_by_default() -> Result<(), Box<dyn std::error::Error>> {
    for binding in [Binding::Redirect, Binding::Post, Binding::SimpleSign] {
        let ctx = unsigned_sp()?.create_login_request_with_options(
            &unsigned_idp()?,
            binding,
            &LoginRequestOptions::default(),
        )?;

        assert!(!request_xml(&ctx)?.contains("ForceAuthn="));
    }
    Ok(())
}

#[test]
fn acs_index_renders_and_omits_url_and_protocol_binding_for_all_login_request_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in [Binding::Redirect, Binding::Post, Binding::SimpleSign] {
        for index in [0, 7] {
            let ctx = unsigned_sp()?.create_login_request_with_options(
                &unsigned_idp()?,
                binding,
                &LoginRequestOptions {
                    assertion_consumer_service_index: Some(index),
                    ..Default::default()
                },
            )?;
            let xml = request_xml(&ctx)?;

            assert!(xml.contains(&format!("AssertionConsumerServiceIndex=\"{index}\"")));
            assert!(!xml.contains("AssertionConsumerServiceURL="));
            assert!(!xml.contains("ProtocolBinding="));
        }
    }
    Ok(())
}

#[test]
fn no_options_rendering_keeps_acs_url_and_protocol_binding(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in [Binding::Redirect, Binding::Post, Binding::SimpleSign] {
        let ctx = unsigned_sp()?.create_login_request_with_options(
            &unsigned_idp()?,
            binding,
            &LoginRequestOptions::default(),
        )?;
        let xml = request_xml(&ctx)?;

        assert!(xml.contains("AssertionConsumerServiceURL=\"https://sp.example.com/acs\""));
        assert!(xml.contains("ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\""));
        assert!(!xml.contains("AssertionConsumerServiceIndex="));
    }
    Ok(())
}

#[test]
fn requested_response_binding_without_acs_returns_missing_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            assertion_consumer_service: vec![Endpoint::new(
                Binding::Post,
                "https://sp.example.com/acs",
            )],
            ..Default::default()
        },
        EntitySetting::default(),
    )?;

    match sp.create_login_request_with_options(
        &unsigned_idp()?,
        Binding::Post,
        &LoginRequestOptions {
            response_binding: Some(Binding::SimpleSign),
            ..Default::default()
        },
    ) {
        Err(SamlError::MissingMetadata(name)) => {
            assert_eq!(name, "AssertionConsumerService");
            Ok(())
        }
        other => Err(format!("expected MissingMetadata, got {other:?}").into()),
    }
}

#[cfg(crypto)]
mod signed {
    use super::*;
    use saml_rs::constants::signature_algorithm::RSA_SHA256;

    const PRIVKEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
    const CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");

    fn signing_setting() -> EntitySetting {
        let mut setting = EntitySetting::default();
        setting.private_key = Some(PRIVKEY.into());
        setting.signing_cert = Some(CERT.into());
        setting.request_signature_algorithm = RSA_SHA256.into();
        setting
    }

    fn signed_idp() -> Result<IdentityProvider, SamlError> {
        IdentityProvider::from_config(
            &IdpMetadataConfig {
                signing_certs: vec![CERT.into()],
                ..idp_config(true)
            },
            signing_setting(),
        )
    }

    fn signed_sp() -> Result<ServiceProvider, SamlError> {
        ServiceProvider::from_config(
            &SpMetadataConfig {
                signing_certs: vec![CERT.into()],
                ..sp_config(true)
            },
            signing_setting(),
        )
    }

    fn redirect_request(url: &str) -> Result<HttpRequest, Box<dyn std::error::Error>> {
        let parsed = Url::parse(url)?;
        let raw_query = parsed.query().unwrap_or_default();
        let octet = raw_query
            .split_once("&Signature=")
            .map(|(signed, _)| signed)
            .unwrap_or(raw_query)
            .to_string();
        let query = parsed
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        Ok(HttpRequest {
            query,
            octet_string: Some(octet),
            ..Default::default()
        })
    }

    fn simplesign_request(ctx: &BindingContext) -> Result<HttpRequest, Box<dyn std::error::Error>> {
        let xml = String::from_utf8(base64_decode(&ctx.context)?)?;
        let relay_state = ctx.relay_state.clone().ok_or("missing RelayState")?;
        let sig_alg = ctx.sig_alg.clone().ok_or("missing SigAlg")?;
        let signature = ctx.signature.clone().ok_or("missing Signature")?;
        let octet = format!("SAMLRequest={xml}&RelayState={relay_state}&SigAlg={sig_alg}");
        Ok(HttpRequest {
            body: vec![
                ("SAMLRequest".into(), ctx.context.clone()),
                ("RelayState".into(), relay_state),
                ("SigAlg".into(), sig_alg),
                ("Signature".into(), signature),
            ],
            octet_string: Some(octet),
            ..Default::default()
        })
    }

    #[test]
    fn signed_detached_requests_parse_with_per_request_relay_state(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for binding in [Binding::Redirect, Binding::SimpleSign] {
            let sp = signed_sp()?;
            let idp = signed_idp()?;
            let ctx = sp.create_login_request_with_options(
                &idp,
                binding,
                &LoginRequestOptions {
                    relay_state: Some("signed request state"),
                    ..Default::default()
                },
            )?;
            let request = match binding {
                Binding::Redirect => redirect_request(&ctx.context)?,
                Binding::SimpleSign => simplesign_request(&ctx)?,
                Binding::Post | Binding::Artifact | Binding::Soap => {
                    return Err("unexpected binding".into())
                }
            };
            let parsed = idp.parse_login_request(&sp, binding, &request)?;

            assert_eq!(ctx.relay_state.as_deref(), Some("signed request state"));
            assert_eq!(parsed.extract.get_str("request.id"), Some(ctx.id.as_str()));
        }
        Ok(())
    }
}
