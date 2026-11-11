#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use saml_rs::binding::base64_decode;
use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::constants::Binding;
use saml_rs::constants::{
    data_encryption_algorithm::AES_256, key_encryption_algorithm::RSA_OAEP_MGF1P,
};
use saml_rs::crypto::keys::load_private_key;
use saml_rs::crypto::{construct_saml_signature, encrypt_assertion, verify_signature};
#[cfg(not(feature = "crypto-fips"))]
use saml_rs::crypto::{decrypt_assertion, AssertionDecryptionOptions};
use saml_rs::entity::{EntitySetting, SignatureAction, SignatureConfig, User};
use saml_rs::flow::HttpRequest;
use saml_rs::idp::LoginResponseOptions;
use saml_rs::logout::{create_logout_request, create_logout_response};
use saml_rs::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
use saml_rs::template::{LoginResponseAttribute, LoginResponseTemplate, LOGIN_RESPONSE_TEMPLATE};
use saml_rs::xml::dom::{parse_roots, Node};
use saml_rs::{IdentityProvider, SamlError, ServiceProvider};

const PRIVKEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const RESPONSE: &str = include_str!("fixtures/misc/response.xml");

const AUTHN_REQUEST: &str = "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_req1\" Version=\"2.0\" IssueInstant=\"2024-01-01T00:00:00Z\"><saml:Issuer>https://sp.example.com/metadata</saml:Issuer></samlp:AuthnRequest>";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn signing() -> EntitySetting {
    let mut setting = EntitySetting::default();
    setting.private_key = Some(PRIVKEY.into());
    setting.signing_cert = Some(CERT.into());
    setting.request_signature_algorithm = RSA_SHA256.into();
    setting
}

fn idp(setting: EntitySetting) -> TestResult<IdentityProvider> {
    Ok(IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec![CERT.into()],
            single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
            single_logout_service: vec![Endpoint::new(Binding::Post, "https://idp/slo")],
            ..Default::default()
        },
        setting,
    )?)
}

fn sp() -> TestResult<ServiceProvider> {
    Ok(ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            signing_certs: vec![CERT.into()],
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
            single_logout_service: vec![Endpoint::new(Binding::Post, "https://sp/slo")],
            ..Default::default()
        },
        signing(),
    )?)
}

fn decode_binding_context(context: &str) -> TestResult<String> {
    Ok(String::from_utf8(base64_decode(context)?)?)
}

fn login_response_shape(xml: &str) -> TestResult {
    let roots = parse_roots(xml)?;
    assert_eq!(roots.len(), 1);
    let response = roots.first().ok_or("missing response root")?;
    assert_eq!(response.local_name, "Response");
    assert_eq!(direct_children(response, "Assertion").count(), 1);
    assert_eq!(direct_children(response, "Issuer").count(), 1);

    let assertion = direct_children(response, "Assertion")
        .next()
        .ok_or("missing assertion")?;
    assert_eq!(direct_children(assertion, "Issuer").count(), 1);
    Ok(())
}

fn direct_children<'a>(node: &'a Node, local_name: &'a str) -> impl Iterator<Item = &'a Node> {
    node.children
        .iter()
        .filter(move |child| child.local_name == local_name)
}

fn assert_invalid(result: Result<String, SamlError>) {
    assert!(
        matches!(result, Err(SamlError::Invalid(_))),
        "expected invalid input to fail before crypto rendering, got {result:?}"
    );
}

#[test]
fn crypto_signature_custom_prefix_still_verifies() -> TestResult {
    let key = load_private_key(PRIVKEY, None)?;
    let config = SignatureConfig {
        prefix: "ds2".into(),
        reference: Some("/*[local-name(.)='AuthnRequest']/*[local-name(.)='Issuer']".into()),
        action: SignatureAction::Before,
    };

    let signed = construct_saml_signature(
        AUTHN_REQUEST,
        true,
        &key,
        CERT,
        RSA_SHA256,
        &[],
        Some(&config),
    )?;

    assert!(signed.contains("<ds2:Signature"));
    let (verified, _) = verify_signature(&signed, &[CERT.to_string()])?;
    assert!(verified, "custom-prefix signature should verify");
    Ok(())
}

#[test]
fn crypto_signature_prefix_rejects_invalid_ncname() -> TestResult {
    let key = load_private_key(PRIVKEY, None)?;
    for prefix in ["", "ds sig", "ds:sig", "1ds", "xml", "xmlns"] {
        let config = SignatureConfig {
            prefix: prefix.into(),
            reference: None,
            action: SignatureAction::After,
        };

        assert_invalid(construct_saml_signature(
            AUTHN_REQUEST,
            true,
            &key,
            CERT,
            RSA_SHA256,
            &[],
            Some(&config),
        ));
    }
    Ok(())
}

#[test]
fn crypto_signature_escapes_transform_algorithm() -> TestResult {
    let key = load_private_key(PRIVKEY, None)?;
    let malicious_transform = "urn:example\" injected=\"yes\"><ds:Transform Algorithm=\"evil";
    let transforms = [malicious_transform.to_string()];

    let result = construct_saml_signature(
        AUTHN_REQUEST,
        true,
        &key,
        CERT,
        RSA_SHA256,
        &transforms,
        None,
    );

    assert!(
        matches!(result, Err(SamlError::Crypto(ref message)) if message.contains("unsupported algorithm") && !message.contains("XML parsing error")),
        "expected escaped transform to fail closed without XML parser structure errors, got {result:?}"
    );
    Ok(())
}

#[test]
fn crypto_signature_escapes_reference_uri_id() -> TestResult {
    let key = load_private_key(PRIVKEY, None)?;
    let xml = concat!(
        "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ",
        "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ",
        "ID=\"_req1&quot; injected=&quot;yes&quot;&gt;&lt;ds:Reference URI=&quot;#evil\" ",
        "Version=\"2.0\" IssueInstant=\"2024-01-01T00:00:00Z\">",
        "<saml:Issuer>https://sp.example.com/metadata</saml:Issuer>",
        "</samlp:AuthnRequest>"
    );

    let signed = construct_saml_signature(xml, true, &key, CERT, RSA_SHA256, &[], None)?;

    assert!(!signed.contains(" injected=\"yes\""));
    assert!(!signed.contains("<ds:Reference URI=\"#evil"));
    assert!(signed.contains("URI=\"#_req1&quot; injected=&quot;yes&quot;&gt;&lt;ds:Reference"));
    Ok(())
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn crypto_encrypt_assertion_prefix_still_round_trips() -> TestResult {
    let encrypted = encrypt_assertion(RESPONSE, CERT, AES_256, RSA_OAEP_MGF1P, "saml2")?;
    assert!(encrypted.contains("<saml2:EncryptedAssertion"));

    let key = load_private_key(PRIVKEY, None)?;
    let (response, assertion) =
        decrypt_assertion(&encrypted, &key, AssertionDecryptionOptions::default())?;

    assert!(assertion.contains("Assertion"));
    assert!(response.contains("Assertion"));
    assert!(!response.contains("EncryptedAssertion"));
    Ok(())
}

#[test]
fn crypto_encrypt_assertion_prefix_rejects_invalid_ncname() -> TestResult {
    for prefix in ["", "saml enc", "saml:enc", "1saml", "xml", "xmlns"] {
        assert_invalid(encrypt_assertion(
            RESPONSE,
            CERT,
            AES_256,
            RSA_OAEP_MGF1P,
            prefix,
        ));
    }
    Ok(())
}

#[test]
fn crypto_encrypt_assertion_escapes_algorithm_attributes() -> TestResult {
    let malicious_data_alg = "urn:example:data\" injected=\"yes\"><xenc:CipherData>";
    let malicious_key_alg = "urn:example:key\" key_injected=\"yes\"><xenc:CipherValue>";

    let result = encrypt_assertion(
        RESPONSE,
        CERT,
        malicious_data_alg,
        malicious_key_alg,
        "saml",
    );

    assert!(
        matches!(result, Err(SamlError::Crypto(ref message)) if !message.contains("XML parsing error") && !message.contains("Mismatched end tag")),
        "expected escaped algorithms to fail closed without XML parser structure errors, got {result:?}"
    );
    Ok(())
}

#[test]
fn login_response_name_id_escapes_xml_markup_before_signing() -> TestResult {
    let idp = idp(signing())?;
    let sp = sp()?;
    let injected_name_id = concat!(
        "attacker@example.com",
        "</saml:NameID>",
        "<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">",
        "admin@example.com",
        "</saml:NameID>",
        "<saml:NameID>"
    );

    let ctx = idp.create_login_response(
        &sp,
        Binding::Post,
        &User::new(injected_name_id),
        &LoginResponseOptions {
            in_response_to: Some("_req1"),
            ..Default::default()
        },
    )?;
    let xml = decode_binding_context(&ctx.context)?;

    assert!(xml.contains("<ds:Signature"));
    assert_eq!(xml.matches("<saml:NameID").count(), 1);
    assert!(xml.contains("&lt;/saml:NameID&gt;"));
    assert!(xml.contains("&lt;saml:NameID Format=&quot;"));
    assert!(!xml.contains("<saml:NameID>admin@example.com</saml:NameID>"));
    Ok(())
}

#[test]
fn login_response_wrapper_fields_escape_xml_markup_before_signing() -> TestResult {
    const HOSTILE_IDP_ENTITY_ID: &str =
        "https://idp.example.com/metadata</saml:Issuer><InjectedIssuer>evil</InjectedIssuer>";
    const HOSTILE_SP_ENTITY_ID: &str =
        "https://sp.example.com/metadata</saml:Audience><InjectedAudience>evil</InjectedAudience>";
    const HOSTILE_ACS: &str =
        "https://sp.example.com/acs\" injected=\"yes\"><InjectedDestination/>";
    const HOSTILE_REQUEST_ID: &str =
        "_req\" injected=\"yes\"></samlp:Response><samlp:Response ID=\"evil\">";
    const HOSTILE_NAME_ID_FORMAT: &str =
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\" injected=\"yes";

    let mut idp_setting = signing();
    idp_setting.name_id_format = vec![HOSTILE_NAME_ID_FORMAT.into()];
    let idp = IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: HOSTILE_IDP_ENTITY_ID.into(),
            signing_certs: vec![CERT.into()],
            single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
            single_logout_service: vec![Endpoint::new(Binding::Post, "https://idp/slo")],
            ..Default::default()
        },
        idp_setting,
    )?;
    let sp = ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: HOSTILE_SP_ENTITY_ID.into(),
            signing_certs: vec![CERT.into()],
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, HOSTILE_ACS)],
            single_logout_service: vec![Endpoint::new(Binding::Post, "https://sp/slo")],
            ..Default::default()
        },
        signing(),
    )?;

    let ctx = idp.create_login_response(
        &sp,
        Binding::Post,
        &User::new("wrapper@example.com"),
        &LoginResponseOptions {
            in_response_to: Some(HOSTILE_REQUEST_ID),
            ..Default::default()
        },
    )?;
    let xml = decode_binding_context(&ctx.context)?;

    assert!(xml.contains("<ds:Signature"));
    login_response_shape(&xml)?;
    assert!(!xml.contains("<InjectedIssuer>"));
    assert!(!xml.contains("<InjectedAudience>"));
    assert!(!xml.contains("<InjectedDestination"));
    assert!(!xml.contains("<samlp:Response ID=\"evil\""));
    assert!(!xml.contains(" injected=\"yes"));
    assert!(xml.contains("&lt;InjectedIssuer&gt;evil&lt;/InjectedIssuer&gt;"));
    assert!(xml.contains("&lt;InjectedAudience&gt;evil&lt;/InjectedAudience&gt;"));
    assert!(
        xml.contains("Destination=\"https://sp.example.com/acs&quot; injected=&quot;yes&quot;&gt;")
    );
    assert!(
        xml.contains("Recipient=\"https://sp.example.com/acs&quot; injected=&quot;yes&quot;&gt;")
    );
    assert!(xml.contains("InResponseTo=\"_req&quot; injected=&quot;yes&quot;&gt;"));
    assert!(xml.contains("Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress&quot; injected=&quot;yes\""));

    let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);
    let parsed =
        sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, HOSTILE_REQUEST_ID)?;
    assert_eq!(
        parsed.extract.get_str("nameID"),
        Some("wrapper@example.com")
    );
    Ok(())
}

#[test]
fn login_response_attribute_values_escape_xml_markup_before_signing() -> TestResult {
    let mut setting = signing();
    setting.login_response_template = Some(LoginResponseTemplate {
        context: Some(LOGIN_RESPONSE_TEMPLATE.into()),
        attributes: vec![LoginResponseAttribute {
            name: "role".into(),
            name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".into(),
            value_xsi_type: "xs:string".into(),
            value_tag: "user.role".into(),
            value_xmlns_xs: None,
            value_xmlns_xsi: None,
        }],
    });
    let idp = idp(setting)?;
    let sp = sp()?;
    let injected_role = concat!(
        "user",
        "</saml:AttributeValue></saml:Attribute>",
        "<saml:Attribute Name=\"admin\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">",
        "<saml:AttributeValue xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" ",
        "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">",
        "true",
        "</saml:AttributeValue>",
        "</saml:Attribute>",
        "<saml:Attribute Name=\"role\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">",
        "<saml:AttributeValue xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" ",
        "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">",
        "user"
    );
    let user = User {
        name_id: "attacker@example.com".into(),
        attributes: vec![("user.role".into(), injected_role.into())],
        session_index: None,
    };

    let ctx = idp.create_login_response(
        &sp,
        Binding::Post,
        &user,
        &LoginResponseOptions {
            in_response_to: Some("_req1"),
            ..Default::default()
        },
    )?;
    let xml = decode_binding_context(&ctx.context)?;

    assert!(xml.contains("<ds:Signature"));
    assert_eq!(xml.matches("<saml:Attribute ").count(), 1);
    assert_eq!(xml.matches("<saml:AttributeValue ").count(), 1);
    assert!(xml.contains("&lt;/saml:AttributeValue&gt;"));
    assert!(xml.contains("&lt;saml:Attribute Name=&quot;admin&quot;"));
    assert!(!xml.contains("<saml:Attribute Name=\"admin\""));
    Ok(())
}

#[test]
fn login_response_attribute_default_rendering_uses_exact_value_tags() -> TestResult {
    const DOT_EMAIL: &str = "dot@example.com";
    const UNDERSCORE_EMAIL: &str = "underscore@example.com";

    let mut setting = signing();
    setting.login_response_template = Some(LoginResponseTemplate {
        context: None,
        attributes: vec![
            LoginResponseAttribute {
                name: "dot-email".into(),
                name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".into(),
                value_xsi_type: "xs:string".into(),
                value_tag: "user.email".into(),
                value_xmlns_xs: None,
                value_xmlns_xsi: None,
            },
            LoginResponseAttribute {
                name: "underscore-email".into(),
                name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".into(),
                value_xsi_type: "xs:string".into(),
                value_tag: "user_email".into(),
                value_xmlns_xs: None,
                value_xmlns_xsi: None,
            },
        ],
    });
    let idp = idp(setting)?;
    let sp = sp()?;
    let user = User {
        name_id: "attacker@example.com".into(),
        attributes: vec![
            ("user.email".into(), DOT_EMAIL.into()),
            ("user_email".into(), UNDERSCORE_EMAIL.into()),
        ],
        session_index: None,
    };

    let ctx = idp.create_login_response(
        &sp,
        Binding::Post,
        &user,
        &LoginResponseOptions {
            in_response_to: Some("_req1"),
            ..Default::default()
        },
    )?;
    let xml = decode_binding_context(&ctx.context)?;
    assert!(!xml.contains("{attr"));

    let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);
    let parsed = sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, "_req1")?;
    let attributes = parsed
        .extract
        .get("attributes")
        .ok_or("missing parsed attributes")?;
    assert_eq!(
        attributes
            .get_key("dot-email")
            .and_then(|value| value.as_str()),
        Some(DOT_EMAIL)
    );
    assert_eq!(
        attributes
            .get_key("underscore-email")
            .and_then(|value| value.as_str()),
        Some(UNDERSCORE_EMAIL)
    );
    Ok(())
}

#[test]
fn login_response_attribute_missing_value_fails_before_signing() -> TestResult {
    let mut setting = signing();
    setting.login_response_template = Some(LoginResponseTemplate {
        context: None,
        attributes: vec![LoginResponseAttribute {
            name: "mail".into(),
            name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".into(),
            value_xsi_type: "xs:string".into(),
            value_tag: "user.email".into(),
            value_xmlns_xs: None,
            value_xmlns_xsi: None,
        }],
    });
    let idp = idp(setting)?;
    let sp = sp()?;

    let result = idp.create_login_response(
        &sp,
        Binding::Post,
        &User::new("attacker@example.com"),
        &LoginResponseOptions {
            in_response_to: Some("_req1"),
            ..Default::default()
        },
    );

    assert!(
        matches!(result, Err(SamlError::Invalid(_))),
        "expected missing attribute to fail closed, got {result:?}"
    );
    Ok(())
}

#[test]
fn login_response_attribute_default_rendering_leaves_no_attr_placeholders() -> TestResult {
    let mut setting = signing();
    setting.login_response_template = Some(LoginResponseTemplate {
        context: None,
        attributes: vec![LoginResponseAttribute {
            name: "mail".into(),
            name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".into(),
            value_xsi_type: "xs:string".into(),
            value_tag: "user.email".into(),
            value_xmlns_xs: None,
            value_xmlns_xsi: None,
        }],
    });
    let idp = idp(setting)?;
    let sp = sp()?;
    let user = User {
        name_id: "attacker@example.com".into(),
        attributes: vec![("user.email".into(), "user@example.com".into())],
        session_index: None,
    };

    let ctx = idp.create_login_response(
        &sp,
        Binding::Post,
        &user,
        &LoginResponseOptions {
            in_response_to: Some("_req1"),
            ..Default::default()
        },
    )?;
    let xml = decode_binding_context(&ctx.context)?;

    assert!(!xml.contains("{attr"));
    Ok(())
}

#[test]
fn login_response_attribute_metadata_escapes_xml_markup_before_signing() -> TestResult {
    const ATTRIBUTE_NAME: &str = "mail\" FriendlyName=\"pwned\" injected=\"yes";
    const ATTRIBUTE_VALUE: &str = "user@example.com";

    let mut setting = signing();
    setting.login_response_template = Some(LoginResponseTemplate {
        context: Some(LOGIN_RESPONSE_TEMPLATE.into()),
        attributes: vec![LoginResponseAttribute {
            name: ATTRIBUTE_NAME.into(),
            name_format: "urn:format\" injected_format=\"yes".into(),
            value_xsi_type: "xs:string'\" injected_type=\"yes".into(),
            value_tag: "user.email".into(),
            value_xmlns_xs: Some("http://www.w3.org/2001/XMLSchema\" injected_xs=\"yes".into()),
            value_xmlns_xsi: Some(
                "http://www.w3.org/2001/XMLSchema-instance\" injected_xsi=\"yes".into(),
            ),
        }],
    });
    let idp = idp(setting)?;
    let sp = sp()?;
    let user = User {
        name_id: "attacker@example.com".into(),
        attributes: vec![("user.email".into(), ATTRIBUTE_VALUE.into())],
        session_index: None,
    };

    let ctx = idp.create_login_response(
        &sp,
        Binding::Post,
        &user,
        &LoginResponseOptions {
            in_response_to: Some("_req1"),
            ..Default::default()
        },
    )?;
    let xml = decode_binding_context(&ctx.context)?;

    assert!(xml.contains("<ds:Signature"));
    assert_eq!(xml.matches("<saml:Attribute ").count(), 1);
    assert_eq!(xml.matches("<saml:AttributeValue ").count(), 1);
    assert!(!xml.contains(" FriendlyName=\"pwned\""));
    assert!(!xml.contains(" injected=\"yes\""));
    assert!(!xml.contains(" injected_format=\"yes\""));
    assert!(!xml.contains(" injected_xs=\"yes\""));
    assert!(!xml.contains(" injected_xsi=\"yes\""));
    assert!(!xml.contains(" injected_type=\"yes\""));
    assert!(xml.contains("Name=\"mail&quot; FriendlyName=&quot;pwned&quot; injected=&quot;yes\""));
    assert!(xml.contains("NameFormat=\"urn:format&quot; injected_format=&quot;yes\""));
    assert!(
        xml.contains("xmlns:xs=\"http://www.w3.org/2001/XMLSchema&quot; injected_xs=&quot;yes\"")
    );
    assert!(xml.contains(
        "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance&quot; injected_xsi=&quot;yes\""
    ));
    assert!(xml.contains("xsi:type=\"xs:string&apos;&quot; injected_type=&quot;yes\""));

    let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);
    let parsed = sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, "_req1")?;
    assert_eq!(
        parsed
            .extract
            .get("attributes")
            .and_then(|attributes| attributes.get_key(ATTRIBUTE_NAME))
            .and_then(|value| value.as_str()),
        Some(ATTRIBUTE_VALUE)
    );
    Ok(())
}

#[test]
fn login_response_attribute_metadata_placeholders_are_written_literally() -> TestResult {
    const BASIC: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";
    let attribute = |name: &str, name_format: &str, value_tag: &str| LoginResponseAttribute {
        name: name.into(),
        name_format: name_format.into(),
        value_xsi_type: "xs:string".into(),
        value_tag: value_tag.into(),
        value_xmlns_xs: None,
        value_xmlns_xsi: None,
    };

    let mut setting = signing();
    setting.login_response_template = Some(LoginResponseTemplate {
        context: Some(LOGIN_RESPONSE_TEMPLATE.into()),
        attributes: vec![
            attribute("role{NameFormat}", BASIC, "user.role"),
            attribute("{Value}", BASIC, "user.email"),
            attribute("{NameID}", "urn:example:{attrUserRole}", "user.role"),
        ],
    });
    let idp = idp(setting)?;
    let sp = sp()?;
    let user = User {
        name_id: "subject@example.com".into(),
        attributes: vec![
            ("user.role".into(), "admin".into()),
            ("user.email".into(), "user@example.com".into()),
        ],
        session_index: None,
    };

    let ctx = idp.create_login_response(
        &sp,
        Binding::Post,
        &user,
        &LoginResponseOptions {
            in_response_to: Some("_req1"),
            ..Default::default()
        },
    )?;
    let xml = decode_binding_context(&ctx.context)?;

    let roots = parse_roots(&xml)?;
    let response = roots.first().ok_or("missing response root")?;
    let assertion = direct_children(response, "Assertion")
        .next()
        .ok_or("missing assertion")?;
    let statement = direct_children(assertion, "AttributeStatement")
        .next()
        .ok_or("missing attribute statement")?;
    let rendered: Vec<(Option<&str>, Option<&str>, Vec<&str>)> =
        direct_children(statement, "Attribute")
            .map(|attribute| {
                (
                    attribute.attr("Name"),
                    attribute.attr("NameFormat"),
                    direct_children(attribute, "AttributeValue")
                        .map(|value| value.text.as_str())
                        .collect(),
                )
            })
            .collect();
    assert_eq!(
        rendered,
        vec![
            (Some("role{NameFormat}"), Some(BASIC), vec!["admin"]),
            (Some("{Value}"), Some(BASIC), vec!["user@example.com"]),
            (
                Some("{NameID}"),
                Some("urn:example:{attrUserRole}"),
                vec!["admin"]
            ),
        ]
    );
    Ok(())
}

#[test]
fn logout_request_name_id_escapes_xml_markup_before_signing() -> TestResult {
    let idp = idp(signing())?;
    let sp = sp()?;
    let injected_name_id = concat!(
        "attacker@example.com",
        "</saml:NameID>",
        "<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">",
        "admin@example.com",
        "</saml:NameID>",
        "<saml:NameID>"
    );

    let ctx = create_logout_request(
        &idp.setting,
        &idp.metadata,
        &sp.metadata,
        Binding::Post,
        &User::new(injected_name_id),
        None,
        true,
    )?;
    let xml = decode_binding_context(&ctx.context)?;

    assert!(xml.contains("<ds:Signature"));
    assert_eq!(xml.matches("<saml:NameID").count(), 1);
    assert!(xml.contains("&lt;/saml:NameID&gt;"));
    assert!(xml.contains("&lt;saml:NameID Format=&quot;"));
    assert!(!xml.contains("<saml:NameID>admin@example.com</saml:NameID>"));
    Ok(())
}

#[test]
fn logout_request_session_index_escapes_xml_markup_before_signing() -> TestResult {
    let idp = idp(signing())?;
    let sp = sp()?;
    let injected_session_index = concat!(
        "_session\"quoted",
        "</samlp:SessionIndex>",
        "<samlp:SessionIndex>admin-session</samlp:SessionIndex>",
        "<samlp:SessionIndex>"
    );
    let mut user = User::new("attacker@example.com");
    user.session_index = Some(injected_session_index.into());

    let ctx = create_logout_request(
        &idp.setting,
        &idp.metadata,
        &sp.metadata,
        Binding::Post,
        &user,
        None,
        true,
    )?;
    let xml = decode_binding_context(&ctx.context)?;

    assert!(xml.contains("<ds:Signature"));
    assert_eq!(xml.matches("<samlp:SessionIndex>").count(), 1);
    assert!(xml.contains("&lt;/samlp:SessionIndex&gt;"));
    assert!(xml.contains("&lt;samlp:SessionIndex&gt;admin-session"));
    assert!(!xml.contains("<samlp:SessionIndex>admin-session</samlp:SessionIndex>"));
    Ok(())
}

#[test]
fn logout_response_rejects_non_ncname_in_response_to_before_signing() -> TestResult {
    let idp = idp(signing())?;
    let sp = sp()?;
    let injected_request_id = concat!(
        "_req\" injected=\"yes",
        "\"></samlp:LogoutResponse>",
        "<samlp:LogoutResponse ID=\"evil\">"
    );

    let result = create_logout_response(
        &idp.setting,
        &idp.metadata,
        &sp.metadata,
        Binding::Post,
        Some(injected_request_id),
        None,
        true,
    );

    match result {
        Err(SamlError::ProtocolProfile(message))
            if message.contains(
                "LogoutResponse InResponseTo must use the XML Schema NCName lexical form",
            ) =>
        {
            Ok(())
        }
        other => Err(format!("expected NCName rejection before signing, got {other:?}").into()),
    }
}
