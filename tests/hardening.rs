//! Production-hardening tests: Audience restriction and InResponseTo / anti-replay.
#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
#![allow(clippy::unwrap_used)]

use saml_rs::binding::base64_decode;
use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::constants::Binding;
use saml_rs::entity::{iso8601_offset, EntitySetting, User};
use saml_rs::error::SubjectConfirmationReason;
use saml_rs::flow::HttpRequest;
use saml_rs::idp::LoginResponseOptions;
use saml_rs::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
use saml_rs::template::replace_tags_by_value;
use saml_rs::{IdentityProvider, SamlError, ServiceProvider};

const PRIVKEY: &str = include_str!("fixtures/key/sp_privkey.pem");
const CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");

fn signing() -> EntitySetting {
    let mut setting = EntitySetting::default();
    setting.private_key = Some(PRIVKEY.into());
    setting.signing_cert = Some(CERT.into());
    setting.request_signature_algorithm = RSA_SHA256.into();
    setting
}

fn idp() -> IdentityProvider {
    IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec![CERT.into()],
            single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
            ..Default::default()
        },
        signing(),
    )
    .unwrap()
}

fn sp_with(entity_id: &str, setting: EntitySetting) -> ServiceProvider {
    ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: entity_id.into(),
            want_assertions_signed: true,
            signing_certs: vec![CERT.into()],
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
            ..Default::default()
        },
        setting,
    )
    .unwrap()
}

fn response_for(sp: &ServiceProvider) -> String {
    idp()
        .create_login_response(
            sp,
            Binding::Post,
            &User::new("a@example.com"),
            &LoginResponseOptions {
                in_response_to: Some("_req1"),
                ..Default::default()
            },
        )
        .unwrap()
        .context
}

fn response_for_audience_restrictions(
    sp: &ServiceProvider,
    audience_restrictions: &[&[&str]],
) -> Result<String, SamlError> {
    let idp = idp();
    let audience_restrictions = audience_restrictions
        .iter()
        .map(|audiences| {
            let audiences = audiences
                .iter()
                .map(|audience| format!("<saml:Audience>{audience}</saml:Audience>"))
                .collect::<String>();
            format!("<saml:AudienceRestriction>{audiences}</saml:AudienceRestriction>")
        })
        .collect::<String>();
    let cb = |template: &str| {
        let id = "_response_audience_restrictions".to_string();
        let now = iso8601_offset(-60);
        let later = iso8601_offset(300);
        let prepared = template.replacen(
            "<saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction>",
            &audience_restrictions,
            1,
        );
        assert_ne!(
            prepared, template,
            "grouped audience tests must replace the template audience restriction"
        );
        let xml = replace_tags_by_value(
            &prepared,
            &[
                ("ID", id.clone()),
                ("AssertionID", "_assertion_audience_restrictions".into()),
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
                ("NameID", "a@example.com".into()),
                ("InResponseTo", "_req1".into()),
                ("AuthnStatement", String::new()),
            ],
        );
        (id, xml)
    };
    Ok(idp
        .create_login_response(
            sp,
            Binding::Post,
            &User::new("a@example.com"),
            &LoginResponseOptions {
                in_response_to: Some("_req1"),
                custom: Some(&cb),
                ..Default::default()
            },
        )?
        .context)
}

struct SubjectConfirmationCase<'a> {
    method: &'a str,
    recipient: &'a str,
    not_on_or_after: String,
    response_in_response_to: &'a str,
    subject_in_response_to: &'a str,
}

fn response_for_subject_confirmation(
    sp: &ServiceProvider,
    case: &SubjectConfirmationCase<'_>,
) -> Result<String, SamlError> {
    let idp = idp();
    let cb = |template: &str| {
        let id = "_response_subject_confirmation".to_string();
        let now = iso8601_offset(-60);
        let later = iso8601_offset(300);
        let prepared = template
            .replacen(
                "Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"",
                &format!("Method=\"{}\"", case.method),
                1,
            )
            .replacen(
                "Recipient=\"{SubjectRecipient}\" InResponseTo=\"{InResponseTo}\"",
                "Recipient=\"{SubjectRecipient}\" InResponseTo=\"{SubjectInResponseTo}\"",
                1,
            );
        let xml = replace_tags_by_value(
            &prepared,
            &[
                ("ID", id.clone()),
                ("AssertionID", "_assertion_subject_confirmation".into()),
                ("Destination", "https://sp/acs".into()),
                ("SubjectRecipient", case.recipient.to_string()),
                ("AssertionConsumerServiceURL", "https://sp/acs".into()),
                ("Audience", "https://sp.example.com/metadata".into()),
                ("Issuer", "https://idp.example.com/metadata".into()),
                ("IssueInstant", now.clone()),
                (
                    "StatusCode",
                    "urn:oasis:names:tc:SAML:2.0:status:Success".into(),
                ),
                ("ConditionsNotBefore", now),
                ("ConditionsNotOnOrAfter", later),
                (
                    "SubjectConfirmationDataNotOnOrAfter",
                    case.not_on_or_after.clone(),
                ),
                (
                    "NameIDFormat",
                    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".into(),
                ),
                ("NameID", "a@example.com".into()),
                ("InResponseTo", case.response_in_response_to.to_string()),
                (
                    "SubjectInResponseTo",
                    case.subject_in_response_to.to_string(),
                ),
                ("AuthnStatement", String::new()),
            ],
        );
        (id, xml)
    };
    Ok(idp
        .create_login_response(
            sp,
            Binding::Post,
            &User::new("a@example.com"),
            &LoginResponseOptions {
                in_response_to: Some(case.response_in_response_to),
                custom: Some(&cb),
                ..Default::default()
            },
        )?
        .context)
}

fn assert_subject_confirmation_reason(
    result: Result<saml_rs::flow::FlowResult, SamlError>,
    expected: SubjectConfirmationReason,
) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Err(SamlError::SubjectConfirmationInvalid { reason }) if reason == expected => Ok(()),
        other => Err(format!("expected subject confirmation {expected}, got {other:?}").into()),
    }
}

fn response_for_destination(
    sp: &ServiceProvider,
    destination: Option<&str>,
) -> Result<String, SamlError> {
    let idp = idp();
    let cb = |template: &str| {
        let id = "_response_destination".to_string();
        let now = iso8601_offset(-60);
        let later = iso8601_offset(300);
        let prepared = if destination.is_some() {
            template.to_string()
        } else {
            template.replacen(" Destination=\"{Destination}\"", "", 1)
        };
        let xml = replace_tags_by_value(
            &prepared,
            &[
                ("ID", id.clone()),
                ("AssertionID", "_assertion_destination".into()),
                (
                    "Destination",
                    destination.unwrap_or("https://sp/acs").to_string(),
                ),
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
                ("NameID", "a@example.com".into()),
                ("InResponseTo", "_req1".into()),
                ("AuthnStatement", String::new()),
            ],
        );
        (id, xml)
    };
    Ok(idp
        .create_login_response(
            sp,
            Binding::Post,
            &User::new("a@example.com"),
            &LoginResponseOptions {
                in_response_to: Some("_req1"),
                custom: Some(&cb),
                ..Default::default()
            },
        )?
        .context)
}

#[test]
fn hardening_audience_match_accepts() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing());
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response_for(&sp))]);
    let parsed = sp.parse_login_response_with_request_id(&idp(), Binding::Post, &req, "_req1")?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("a@example.com"));
    Ok(())
}

#[test]
fn hardening_audience_mismatch_rejected() {
    // Response is addressed (Audience) to sp1; sp2 must reject it.
    let sp1 = sp_with("https://sp1.example.com/metadata", signing());
    let sp2 = sp_with("https://sp2.example.com/metadata", signing());
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response_for(&sp1))]);
    assert!(matches!(
        sp2.parse_login_response_with_request_id(&idp(), Binding::Post, &req, "_req1"),
        Err(SamlError::AudienceMismatch { .. })
    ));
}

#[test]
fn hardening_audience_validation_opt_out() -> Result<(), Box<dyn std::error::Error>> {
    let sp1 = sp_with("https://sp1.example.com/metadata", signing());
    let mut setting = signing();
    setting.validate_audience = false;
    let sp2 = sp_with("https://sp2.example.com/metadata", setting);
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response_for(&sp1))]);
    // With audience validation disabled, sp2 accepts it (signature still checked).
    sp2.parse_login_response_with_request_id(&idp(), Binding::Post, &req, "_req1")?;
    Ok(())
}

#[test]
fn hardening_audience_restrictions_reject_when_missing() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing());
    let response = response_for_audience_restrictions(&sp, &[])?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response)]);

    assert!(matches!(
        sp.parse_login_response_with_request_id(&idp(), Binding::Post, &req, "_req1"),
        Err(SamlError::AudienceMismatch { .. })
    ));
    Ok(())
}

#[test]
fn hardening_audience_restrictions_reject_empty_group() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing());
    let response = response_for_audience_restrictions(&sp, &[&[]])?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response)]);

    assert!(matches!(
        sp.parse_login_response_with_request_id(&idp(), Binding::Post, &req, "_req1"),
        Err(SamlError::AudienceMismatch { .. })
    ));
    Ok(())
}

#[test]
fn hardening_audience_restrictions_require_every_group_to_match(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing());
    let response = response_for_audience_restrictions(
        &sp,
        &[
            &["https://wrong.example.com/metadata"],
            &["https://sp.example.com/metadata"],
        ],
    )?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response)]);

    assert!(matches!(
        sp.parse_login_response_with_request_id(&idp(), Binding::Post, &req, "_req1"),
        Err(SamlError::AudienceMismatch { .. })
    ));
    Ok(())
}

#[test]
fn hardening_audience_restrictions_accept_any_matching_audience_within_group(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing());
    let response = response_for_audience_restrictions(
        &sp,
        &[&[
            "https://wrong.example.com/metadata",
            "https://sp.example.com/metadata",
        ]],
    )?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response)]);

    sp.parse_login_response_with_request_id(&idp(), Binding::Post, &req, "_req1")?;
    Ok(())
}

#[test]
fn hardening_audience_restrictions_accept_when_every_group_matches(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing());
    let response = response_for_audience_restrictions(
        &sp,
        &[
            &["https://sp.example.com/metadata"],
            &[
                "https://wrong.example.com/metadata",
                "https://sp.example.com/metadata",
            ],
        ],
    )?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response)]);

    sp.parse_login_response_with_request_id(&idp(), Binding::Post, &req, "_req1")?;
    Ok(())
}

#[test]
fn hardening_in_response_to_match_accepts() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing());
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response_for(&sp))]);
    sp.parse_login_response_with_request_id(&idp(), Binding::Post, &req, "_req1")?;
    Ok(())
}

#[test]
fn hardening_in_response_to_mismatch_rejected() {
    let sp = sp_with("https://sp.example.com/metadata", signing());
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response_for(&sp))]);
    assert!(matches!(
        sp.parse_login_response_with_request_id(&idp(), Binding::Post, &req, "_wrong"),
        Err(SamlError::InResponseToMismatch { .. })
    ));
}

#[test]
fn hardening_default_login_response_rejects_non_empty_in_response_to() {
    let sp = sp_with("https://sp.example.com/metadata", signing());
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response_for(&sp))]);
    assert!(matches!(
        sp.parse_login_response(&idp(), Binding::Post, &req),
        Err(SamlError::InResponseToMismatch { .. })
    ));
}

#[test]
fn hardening_unsolicited_response_accepts_empty_in_response_to(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing());
    let response = response_for_subject_confirmation(
        &sp,
        &SubjectConfirmationCase {
            method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
            recipient: "https://sp/acs",
            not_on_or_after: iso8601_offset(300),
            response_in_response_to: "",
            subject_in_response_to: "",
        },
    )?;
    let xml = String::from_utf8(base64_decode(&response)?)?;
    assert_eq!(xml.matches("InResponseTo=\"\"").count(), 2, "{xml}");
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response)]);
    sp.parse_unsolicited_login_response(&idp(), Binding::Post, &req)?;
    Ok(())
}

#[test]
fn hardening_unsolicited_response_rejects_subject_confirmation_in_response_to(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing());
    let response = response_for_subject_confirmation(
        &sp,
        &SubjectConfirmationCase {
            method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
            recipient: "https://sp/acs",
            not_on_or_after: iso8601_offset(300),
            response_in_response_to: "",
            subject_in_response_to: "_req1",
        },
    )?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response)]);
    assert!(matches!(
        sp.parse_unsolicited_login_response(&idp(), Binding::Post, &req),
        Err(SamlError::InResponseToMismatch { .. })
    ));
    Ok(())
}

#[test]
fn hardening_subject_confirmation_method_must_be_bearer() -> Result<(), Box<dyn std::error::Error>>
{
    let sp = sp_with("https://sp.example.com/metadata", signing());
    let response = response_for_subject_confirmation(
        &sp,
        &SubjectConfirmationCase {
            method: "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key",
            recipient: "https://sp/acs",
            not_on_or_after: iso8601_offset(300),
            response_in_response_to: "_req1",
            subject_in_response_to: "_req1",
        },
    )?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response)]);
    assert_subject_confirmation_reason(
        sp.parse_login_response_with_request_id(&idp(), Binding::Post, &req, "_req1"),
        SubjectConfirmationReason::InvalidMethod,
    )
}

#[test]
fn hardening_subject_confirmation_data_expiry_is_enforced() -> Result<(), Box<dyn std::error::Error>>
{
    let sp = sp_with("https://sp.example.com/metadata", signing());
    let response = response_for_subject_confirmation(
        &sp,
        &SubjectConfirmationCase {
            method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
            recipient: "https://sp/acs",
            not_on_or_after: iso8601_offset(-300),
            response_in_response_to: "_req1",
            subject_in_response_to: "_req1",
        },
    )?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response)]);
    assert_subject_confirmation_reason(
        sp.parse_login_response_with_request_id(&idp(), Binding::Post, &req, "_req1"),
        SubjectConfirmationReason::TimeWindowInvalid,
    )
}

#[test]
fn hardening_subject_confirmation_recipient_must_match_acs(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing());
    let response = response_for_subject_confirmation(
        &sp,
        &SubjectConfirmationCase {
            method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
            recipient: "https://evil.example/acs",
            not_on_or_after: iso8601_offset(300),
            response_in_response_to: "_req1",
            subject_in_response_to: "_req1",
        },
    )?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response)]);
    assert_subject_confirmation_reason(
        sp.parse_login_response_with_request_id(&idp(), Binding::Post, &req, "_req1"),
        SubjectConfirmationReason::RecipientMismatch,
    )
}

#[test]
fn hardening_response_destination_must_match_acs_when_present(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing());
    let response = response_for_destination(&sp, Some("https://evil.example/acs"))?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response)]);
    assert!(matches!(
        sp.parse_login_response_with_request_id(&idp(), Binding::Post, &req, "_req1"),
        Err(SamlError::DestinationMismatch { .. })
    ));
    Ok(())
}

#[test]
fn hardening_missing_destination_accepts_matching_recipient(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing());
    let response = response_for_destination(&sp, None)?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response)]);
    let parsed = sp.parse_login_response_with_request_id(&idp(), Binding::Post, &req, "_req1")?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("a@example.com"));
    Ok(())
}

#[test]
fn hardening_subject_confirmation_request_id_must_match() -> Result<(), Box<dyn std::error::Error>>
{
    let sp = sp_with("https://sp.example.com/metadata", signing());
    let response = response_for_subject_confirmation(
        &sp,
        &SubjectConfirmationCase {
            method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
            recipient: "https://sp/acs",
            not_on_or_after: iso8601_offset(300),
            response_in_response_to: "_req1",
            subject_in_response_to: "_wrong",
        },
    )?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response)]);
    assert_subject_confirmation_reason(
        sp.parse_login_response_with_request_id(&idp(), Binding::Post, &req, "_req1"),
        SubjectConfirmationReason::InResponseToMismatch,
    )
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn hardening_sign_then_encrypt_message_auto_resolves() -> Result<(), Box<dyn std::error::Error>> {
    // Request sign-then-encrypt (encrypt_then_sign=false) with an encrypted,
    // message-signed response. The IdP must produce a verifiable response
    // (it signs the message after encryption, since the other order is unsound).
    let mut idp_setting = signing();
    idp_setting.is_assertion_encrypted = true;
    let idp = IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec![CERT.into()],
            single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
            ..Default::default()
        },
        idp_setting,
    )?;
    let mut sp_setting = signing();
    sp_setting.is_assertion_encrypted = true;
    sp_setting.enc_private_key = Some(PRIVKEY.into());
    sp_setting.allow_insecure_software_rsa_key_transport_decryption = true;
    let sp = ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            want_assertions_signed: false, // message gets signed
            signing_certs: vec![CERT.into()],
            encrypt_certs: vec![CERT.into()],
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
            ..Default::default()
        },
        sp_setting,
    )?;
    let ctx = idp.create_login_response(
        &sp,
        Binding::Post,
        &User::new("a@example.com"),
        &LoginResponseOptions {
            in_response_to: Some("_req1"),
            encrypt_then_sign: false, // requested sign-then-encrypt; resolved safely
            ..Default::default()
        },
    )?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);
    let parsed = sp.parse_login_response_with_request_id(&idp, Binding::Post, &req, "_req1")?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("a@example.com"));
    Ok(())
}

#[test]
fn hardening_signed_metadata_verifies_against_trust_anchor(
) -> Result<(), Box<dyn std::error::Error>> {
    use saml_rs::crypto::keys::load_private_key;
    use saml_rs::crypto::{construct_saml_signature, verify_metadata_signature};
    use saml_rs::entity::{SignatureAction, SignatureConfig};
    use saml_rs::metadata::IdpMetadata;

    let md = "<EntityDescriptor ID=\"_md1\" entityID=\"https://idp.example.com/metadata\" xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://idp/sso\"/></IDPSSODescriptor></EntityDescriptor>";
    let key = load_private_key(PRIVKEY, None)?;
    let config = SignatureConfig {
        prefix: "ds".into(),
        reference: Some("/*[local-name(.)='EntityDescriptor']".into()),
        action: SignatureAction::Prepend,
    };
    let signed = construct_saml_signature(md, true, &key, CERT, RSA_SHA256, &[], Some(&config))?;

    // Valid against the trust anchor.
    assert!(verify_metadata_signature(&signed, &[CERT.to_string()])?);
    // Also reachable via the parsed Metadata.
    assert!(IdpMetadata::from_xml(&signed)?.verify_signature(&[CERT.to_string()])?);
    // Tampered entityID no longer verifies.
    let tampered = signed.replacen(
        "https://idp.example.com/metadata",
        "https://evil/metadata",
        1,
    );
    assert!(!verify_metadata_signature(&tampered, &[CERT.to_string()])?);
    Ok(())
}

#[test]
fn hardening_metadata_signature_requires_root_coverage() -> Result<(), Box<dyn std::error::Error>> {
    use bergshamra::{sign, DsigContext, KeysManager};
    use saml_rs::constants::{digest_for_signature, namespace, transform_algorithm};
    use saml_rs::crypto::keys::load_private_key;
    use saml_rs::crypto::verify_metadata_signature;
    use saml_rs::metadata::IdpMetadata;
    use saml_rs::util::normalize_cert_string;

    let digest = digest_for_signature(RSA_SHA256).ok_or("unknown digest")?;
    let signature = format!(
        "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{exc_c14n}\"/><ds:SignatureMethod Algorithm=\"{sig_alg}\"/><ds:Reference URI=\"#_signed_child\"><ds:Transforms><ds:Transform Algorithm=\"{enveloped}\"/><ds:Transform Algorithm=\"{exc_c14n}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
        dsig = namespace::DSIG,
        exc_c14n = transform_algorithm::EXC_C14N,
        sig_alg = RSA_SHA256,
        enveloped = transform_algorithm::ENVELOPED_SIGNATURE,
        cert = normalize_cert_string(CERT),
    );
    let template = format!(
        "<EntityDescriptor ID=\"_evil_root\" entityID=\"https://evil.example.com/metadata\" xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">{signature}<IDPSSODescriptor ID=\"_signed_child\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://trusted.example.com/sso\"/></IDPSSODescriptor></EntityDescriptor>"
    );
    let key = load_private_key(PRIVKEY, None)?;
    let mut manager = KeysManager::new();
    manager.add_key(key);
    let ctx = DsigContext::new(manager).with_insecure(true);
    let wrapped_metadata = sign(&ctx, &template)?;

    assert_eq!(
        IdpMetadata::from_xml(&wrapped_metadata)?.get_entity_id(),
        Some("https://evil.example.com/metadata")
    );
    match verify_metadata_signature(&wrapped_metadata, &[CERT.to_string()]) {
        Err(SamlError::SignedReferenceMismatch) => Ok(()),
        other => Err(format!(
            "metadata verification must reject signatures that do not cover the consumed root: {other:?}"
        )
        .into()),
    }
}
