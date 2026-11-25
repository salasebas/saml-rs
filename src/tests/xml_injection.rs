#![cfg(crypto)]

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::constants::Binding;
use saml_rs::constants::{
    data_encryption_algorithm::AES_256, key_encryption_algorithm::RSA_OAEP_MGF1P,
};
use saml_rs::crypto::keys::read_private_key;
#[cfg(not(feature = "crypto-fips"))]
use saml_rs::crypto::{decrypt_assertion_with_limits, AssertionDecryptionOptions};
use saml_rs::crypto::{encrypt_assertion, sign_saml_xml, verify_signature};
use saml_rs::entity::{EntitySetting, User};
use saml_rs::flow::HttpRequest;
use saml_rs::idp;
use saml_rs::idp::LoginResponseOptions;
use saml_rs::metadata::{Endpoint, IdpMetadataInput, SpMetadataInput};
use saml_rs::sp;
use saml_rs::tests::engine::LogoutUser;
use saml_rs::tests::engine::{create_logout_request, create_logout_response};
use saml_rs::tests::engine::{IdpMessages, SpMessages};
use saml_rs::xml::dom::{parse_all_roots, Node};
use saml_rs::SamlError;
use saml_rs::{SignatureAction, SignatureConfig};

const PRIVKEY: &str = include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const RESPONSE: &str = include_str!("../../tests/fixtures/misc/response.xml");

const AUTHN_REQUEST: &str = "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_req1\" Version=\"2.0\" IssueInstant=\"2024-01-01T00:00:00Z\"><saml:Issuer>https://sp.example.com/metadata</saml:Issuer></samlp:AuthnRequest>";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn signing() -> EntitySetting {
    EntitySetting {
        private_key: Some(PRIVKEY.into()),
        signing_cert: Some(CERT.into()),
        request_signature_algorithm: RSA_SHA256.into(),
        ..EntitySetting::default()
    }
}

fn idp(setting: EntitySetting) -> TestResult<idp::Engine> {
    Ok(idp::Engine::from_config(
        &IdpMetadataInput {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec![CERT.into()],
            single_sign_on_services: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
            single_logout_services: vec![Endpoint::new(Binding::Post, "https://idp/slo")],
            ..Default::default()
        },
        setting,
    )?)
}

fn sp() -> TestResult<sp::Engine> {
    Ok(sp::Engine::from_config(
        &SpMetadataInput {
            entity_id: "https://sp.example.com/metadata".into(),
            signing_certs: vec![CERT.into()],
            assertion_consumer_services: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
            single_logout_services: vec![Endpoint::new(Binding::Post, "https://sp/slo")],
            ..Default::default()
        },
        signing(),
    )?)
}

fn decode_binding_context(context: &str) -> TestResult<String> {
    Ok(String::from_utf8(STANDARD.decode(context)?)?)
}

fn login_response_shape(xml: &str) -> TestResult {
    let roots = parse_all_roots(xml, saml_rs::XmlLimits::default())?;
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

fn assert_invalid(result: &Result<String, SamlError>) {
    assert!(
        matches!(result, Err(SamlError::Invalid(_))),
        "expected invalid input to fail before crypto rendering, got {result:?}"
    );
}

#[test]
fn crypto_signature_custom_prefix_still_verifies() -> TestResult {
    let key = read_private_key(PRIVKEY, None)?;
    let config = SignatureConfig {
        prefix: "ds2".into(),
        reference: Some("/*[local-name(.)='AuthnRequest']/*[local-name(.)='Issuer']".into()),
        action: SignatureAction::Before,
    };

    let signed = sign_saml_xml(
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
    let key = read_private_key(PRIVKEY, None)?;
    for prefix in ["", "ds sig", "ds:sig", "1ds", "xml", "xmlns"] {
        let config = SignatureConfig {
            prefix: prefix.into(),
            reference: None,
            action: SignatureAction::After,
        };

        assert_invalid(&sign_saml_xml(
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
    let key = read_private_key(PRIVKEY, None)?;
    let malicious_transform = "urn:example\" injected=\"yes\"><ds:Transform Algorithm=\"evil";
    let transforms = [malicious_transform.to_string()];

    let result = sign_saml_xml(
        AUTHN_REQUEST,
        true,
        &key,
        CERT,
        RSA_SHA256,
        &transforms,
        None,
    );

    assert!(
        matches!(result, Err(SamlError::Crypto { source: Some(ref source), .. }) if source.to_string().contains("unsupported algorithm") && !source.to_string().contains("XML parsing error")),
        "expected escaped transform to fail closed without XML parser structure errors, got {result:?}"
    );
    Ok(())
}

#[test]
fn crypto_signature_escapes_reference_uri_id() -> TestResult {
    let key = read_private_key(PRIVKEY, None)?;
    let xml = concat!(
        "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ",
        "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ",
        "ID=\"_req1&quot; injected=&quot;yes&quot;&gt;&lt;ds:Reference URI=&quot;#evil\" ",
        "Version=\"2.0\" IssueInstant=\"2024-01-01T00:00:00Z\">",
        "<saml:Issuer>https://sp.example.com/metadata</saml:Issuer>",
        "</samlp:AuthnRequest>"
    );

    let signed = sign_saml_xml(xml, true, &key, CERT, RSA_SHA256, &[], None)?;

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

    let key = read_private_key(PRIVKEY, None)?;
    let (response, assertion) = decrypt_assertion_with_limits(
        &encrypted,
        &key,
        AssertionDecryptionOptions::default(),
        saml_rs::XmlLimits::default(),
    )?;

    assert!(assertion.contains("Assertion"));
    assert!(response.contains("Assertion"));
    assert!(!response.contains("EncryptedAssertion"));
    Ok(())
}

#[test]
fn crypto_encrypt_assertion_prefix_rejects_invalid_ncname() {
    for prefix in ["", "saml enc", "saml:enc", "1saml", "xml", "xmlns"] {
        assert_invalid(&encrypt_assertion(
            RESPONSE,
            CERT,
            AES_256,
            RSA_OAEP_MGF1P,
            prefix,
        ));
    }
}

#[test]
fn crypto_encrypt_assertion_escapes_algorithm_attributes() {
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
        matches!(result, Err(SamlError::Crypto { source: Some(ref source), .. }) if !source.to_string().contains("XML parsing error") && !source.to_string().contains("Mismatched end tag")),
        "expected escaped algorithms to fail closed without XML parser structure errors, got {result:?}"
    );
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
    let idp = idp::Engine::from_config(
        &IdpMetadataInput {
            entity_id: HOSTILE_IDP_ENTITY_ID.into(),
            signing_certs: vec![CERT.into()],
            single_sign_on_services: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
            single_logout_services: vec![Endpoint::new(Binding::Post, "https://idp/slo")],
            ..Default::default()
        },
        idp_setting,
    )?;
    let sp = sp::Engine::from_config(
        &SpMetadataInput {
            entity_id: HOSTILE_SP_ENTITY_ID.into(),
            signing_certs: vec![CERT.into()],
            assertion_consumer_services: vec![Endpoint::new(Binding::Post, HOSTILE_ACS)],
            single_logout_services: vec![Endpoint::new(Binding::Post, "https://sp/slo")],
            ..Default::default()
        },
        signing(),
    )?;

    let hostile_request = idp.create_login_response(
        &sp,
        Binding::Post,
        &User::new("wrapper@example.com"),
        &LoginResponseOptions {
            in_response_to: Some(HOSTILE_REQUEST_ID),
            ..Default::default()
        },
    );
    assert!(
        matches!(hostile_request, Err(SamlError::Invalid(_))),
        "{:?}",
        hostile_request.err()
    );
    let ctx = idp.create_login_response(
        &sp,
        Binding::Post,
        &User::new("wrapper@example.com"),
        &LoginResponseOptions {
            in_response_to: Some("_req1"),
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
    assert!(xml.contains("Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress&quot; injected=&quot;yes\""));

    let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);
    let parsed = sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, "_req1")?;
    assert_eq!(
        parsed.extract.get_str("nameID"),
        Some("wrapper@example.com")
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
        idp.metadata.as_metadata(),
        sp.metadata.as_metadata(),
        Binding::Post,
        &LogoutUser::new(injected_name_id),
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
    let mut user = LogoutUser::new("attacker@example.com");
    user.session_index = Some(injected_session_index.into());

    let ctx = create_logout_request(
        &idp.setting,
        idp.metadata.as_metadata(),
        sp.metadata.as_metadata(),
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
        idp.metadata.as_metadata(),
        sp.metadata.as_metadata(),
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
