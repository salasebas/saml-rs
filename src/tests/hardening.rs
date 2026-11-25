#![cfg(crypto)]

use crate::tests::template::{fill_template, AUTHN_STATEMENT};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::constants::Binding;
use saml_rs::entity::{iso8601_offset, EntitySetting, User};
use saml_rs::error::SubjectConfirmationReason;
use saml_rs::flow::HttpRequest;
use saml_rs::idp;
use saml_rs::idp::LoginResponseOptions;
use saml_rs::metadata::{Endpoint, IdpMetadataInput, SpMetadataInput};
use saml_rs::sp;
use saml_rs::tests::engine::{IdpMessages, SpMessages};
use saml_rs::SamlError;

const PRIVKEY: &str = include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");

fn signing() -> EntitySetting {
    EntitySetting {
        private_key: Some(PRIVKEY.into()),
        signing_cert: Some(CERT.into()),
        request_signature_algorithm: RSA_SHA256.into(),
        ..EntitySetting::default()
    }
}

fn idp() -> Result<idp::Engine, SamlError> {
    idp::Engine::from_config(
        &IdpMetadataInput {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec![CERT.into()],
            single_sign_on_services: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
            ..Default::default()
        },
        signing(),
    )
}

fn sp_with(entity_id: &str, setting: EntitySetting) -> Result<sp::Engine, SamlError> {
    sp::Engine::from_config(
        &SpMetadataInput {
            entity_id: entity_id.into(),
            want_assertions_signed: true,
            signing_certs: vec![CERT.into()],
            assertion_consumer_services: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
            ..Default::default()
        },
        setting,
    )
}

fn response_for(sp: &sp::Engine) -> Result<String, SamlError> {
    let response = idp()?.create_login_response(
        sp,
        Binding::Post,
        &User::new("a@example.com"),
        &LoginResponseOptions {
            in_response_to: Some("_req1"),
            ..Default::default()
        },
    )?;
    Ok(response.context)
}

fn response_for_audience_restrictions(
    sp: &sp::Engine,
    audience_restrictions: &[&[&str]],
) -> Result<String, SamlError> {
    let idp = idp()?;
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
    let cb = |template: &str| -> Result<(String, String), SamlError> {
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
        let xml = fill_template(
            &prepared.replacen("{AuthnStatement}", AUTHN_STATEMENT, 1),
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
            ],
        );
        Ok((id, xml))
    };
    Ok(idp
        .create_rendered_login_response(sp, Binding::Post, &cb)?
        .context)
}

struct SubjectConfirmationCase<'a> {
    method: &'a str,
    recipient: &'a str,
    not_on_or_after: String,
    response_in_response_to: Option<&'a str>,
    subject_in_response_to: &'a str,
}

fn response_for_subject_confirmation(
    sp: &sp::Engine,
    case: &SubjectConfirmationCase<'_>,
) -> Result<String, SamlError> {
    let idp = idp()?;
    let cb = |template: &str| -> Result<(String, String), SamlError> {
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
        let prepared = match case.response_in_response_to {
            Some(_) => prepared,
            None => prepared.replacen(" InResponseTo=\"{InResponseTo}\"", "", 1),
        };
        let xml = fill_template(
            &prepared.replacen("{AuthnStatement}", AUTHN_STATEMENT, 1),
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
                (
                    "InResponseTo",
                    case.response_in_response_to.unwrap_or_default().to_string(),
                ),
                (
                    "SubjectInResponseTo",
                    case.subject_in_response_to.to_string(),
                ),
            ],
        );
        Ok((id, xml))
    };
    Ok(idp
        .create_rendered_login_response(sp, Binding::Post, &cb)?
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
    sp: &sp::Engine,
    destination: Option<&str>,
) -> Result<String, SamlError> {
    let idp = idp()?;
    let cb = |template: &str| -> Result<(String, String), SamlError> {
        let id = "_response_destination".to_string();
        let now = iso8601_offset(-60);
        let later = iso8601_offset(300);
        let prepared = if destination.is_some() {
            template.to_string()
        } else {
            template.replacen(" Destination=\"{Destination}\"", "", 1)
        };
        let xml = fill_template(
            &prepared.replacen("{AuthnStatement}", AUTHN_STATEMENT, 1),
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
            ],
        );
        Ok((id, xml))
    };
    Ok(idp
        .create_rendered_login_response(sp, Binding::Post, &cb)?
        .context)
}

#[test]
fn hardening_audience_match_accepts() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing())?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response_for(&sp)?)]);
    let parsed = sp.parse_login_response_with_request_id(&idp()?, Binding::Post, &req, "_req1")?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("a@example.com"));
    Ok(())
}

#[test]
fn hardening_audience_mismatch_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let sp1 = sp_with("https://sp1.example.com/metadata", signing())?;
    let sp2 = sp_with("https://sp2.example.com/metadata", signing())?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response_for(&sp1)?)]);
    assert!(matches!(
        sp2.parse_login_response_with_request_id(&idp()?, Binding::Post, &req, "_req1"),
        Err(SamlError::AudienceMismatch { .. })
    ));
    Ok(())
}

#[test]
fn hardening_audience_restrictions_reject_when_missing() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing())?;
    let response = response_for_audience_restrictions(&sp, &[])?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response)]);

    assert!(matches!(
        sp.parse_login_response_with_request_id(&idp()?, Binding::Post, &req, "_req1"),
        Err(SamlError::AudienceMismatch { .. })
    ));
    Ok(())
}

#[test]
fn hardening_audience_restrictions_reject_empty_group() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing())?;
    let response = response_for_audience_restrictions(&sp, &[&[]])?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response)]);

    assert!(matches!(
        sp.parse_login_response_with_request_id(&idp()?, Binding::Post, &req, "_req1"),
        Err(SamlError::AudienceMismatch { .. })
    ));
    Ok(())
}

#[test]
fn hardening_audience_restrictions_require_every_group_to_match(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing())?;
    let response = response_for_audience_restrictions(
        &sp,
        &[
            &["https://wrong.example.com/metadata"],
            &["https://sp.example.com/metadata"],
        ],
    )?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response)]);

    assert!(matches!(
        sp.parse_login_response_with_request_id(&idp()?, Binding::Post, &req, "_req1"),
        Err(SamlError::AudienceMismatch { .. })
    ));
    Ok(())
}

#[test]
fn hardening_audience_restrictions_accept_any_matching_audience_within_group(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing())?;
    let response = response_for_audience_restrictions(
        &sp,
        &[&[
            "https://wrong.example.com/metadata",
            "https://sp.example.com/metadata",
        ]],
    )?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response)]);

    sp.parse_login_response_with_request_id(&idp()?, Binding::Post, &req, "_req1")?;
    Ok(())
}

#[test]
fn hardening_audience_restrictions_accept_when_every_group_matches(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing())?;
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

    sp.parse_login_response_with_request_id(&idp()?, Binding::Post, &req, "_req1")?;
    Ok(())
}

#[test]
fn hardening_in_response_to_match_accepts() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing())?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response_for(&sp)?)]);
    sp.parse_login_response_with_request_id(&idp()?, Binding::Post, &req, "_req1")?;
    Ok(())
}

#[test]
fn hardening_in_response_to_mismatch_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing())?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response_for(&sp)?)]);
    assert!(matches!(
        sp.parse_login_response_with_request_id(&idp()?, Binding::Post, &req, "_wrong"),
        Err(SamlError::InResponseToMismatch { .. })
    ));
    Ok(())
}

#[test]
fn hardening_unsolicited_response_rejects_non_empty_in_response_to(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing())?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response_for(&sp)?)]);
    assert!(matches!(
        sp.parse_unsolicited_login_response(&idp()?, Binding::Post, &req),
        Err(SamlError::InResponseToMismatch { .. })
    ));
    Ok(())
}

#[test]
fn hardening_unsolicited_response_rejects_empty_in_response_to(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing())?;
    let response = response_for_subject_confirmation(
        &sp,
        &SubjectConfirmationCase {
            method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
            recipient: "https://sp/acs",
            not_on_or_after: iso8601_offset(300),
            response_in_response_to: Some(""),
            subject_in_response_to: "",
        },
    )?;
    let xml = String::from_utf8(STANDARD.decode(&response)?)?;
    assert_eq!(xml.matches("InResponseTo=\"\"").count(), 2, "{xml}");
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response)]);
    assert!(matches!(
        sp.parse_unsolicited_login_response(&idp()?, Binding::Post, &req),
        Err(SamlError::InResponseToMismatch { expected: None, actual }) if actual.as_deref() == Some("")
    ));

    let bearer_only = response_for_subject_confirmation(
        &sp,
        &SubjectConfirmationCase {
            method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
            recipient: "https://sp/acs",
            not_on_or_after: iso8601_offset(300),
            response_in_response_to: None,
            subject_in_response_to: "",
        },
    )?;
    let xml = String::from_utf8(STANDARD.decode(&bearer_only)?)?;
    assert_eq!(xml.matches("InResponseTo=").count(), 1, "{xml}");
    let req = HttpRequest::post(vec![("SAMLResponse".into(), bearer_only)]);
    assert!(matches!(
        sp.parse_unsolicited_login_response(&idp()?, Binding::Post, &req),
        Err(SamlError::SubjectConfirmationInvalid {
            reason: SubjectConfirmationReason::InResponseToMismatch
        })
    ));
    Ok(())
}

#[test]
fn hardening_unsolicited_response_rejects_subject_confirmation_in_response_to(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing())?;
    let response = response_for_subject_confirmation(
        &sp,
        &SubjectConfirmationCase {
            method: " urn:oasis:names:tc:SAML:2.0:cm:bearer&#9;",
            recipient: "https://sp/acs",
            not_on_or_after: iso8601_offset(300),
            response_in_response_to: None,
            subject_in_response_to: "_req1",
        },
    )?;
    let xml = String::from_utf8(STANDARD.decode(&response)?)?;
    assert_eq!(xml.matches("InResponseTo=").count(), 1, "{xml}");
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response)]);
    assert!(matches!(
        sp.parse_unsolicited_login_response(&idp()?, Binding::Post, &req),
        Err(SamlError::SubjectConfirmationInvalid {
            reason: SubjectConfirmationReason::InResponseToMismatch
        })
    ));
    Ok(())
}

#[test]
fn hardening_subject_confirmation_method_must_be_bearer() -> Result<(), Box<dyn std::error::Error>>
{
    let sp = sp_with("https://sp.example.com/metadata", signing())?;
    let response = response_for_subject_confirmation(
        &sp,
        &SubjectConfirmationCase {
            method: " urn:oasis:names:tc:SAML:2.0:cm:holder-of-key&#9;",
            recipient: "https://sp/acs",
            not_on_or_after: iso8601_offset(300),
            response_in_response_to: Some("_req1"),
            subject_in_response_to: "_req1",
        },
    )?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response)]);
    assert_subject_confirmation_reason(
        sp.parse_login_response_with_request_id(&idp()?, Binding::Post, &req, "_req1"),
        SubjectConfirmationReason::InvalidMethod,
    )
}

#[test]
fn hardening_subject_confirmation_data_expiry_is_enforced() -> Result<(), Box<dyn std::error::Error>>
{
    let sp = sp_with("https://sp.example.com/metadata", signing())?;
    let response = response_for_subject_confirmation(
        &sp,
        &SubjectConfirmationCase {
            method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
            recipient: "https://sp/acs",
            not_on_or_after: iso8601_offset(-300),
            response_in_response_to: Some("_req1"),
            subject_in_response_to: "_req1",
        },
    )?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response)]);
    assert_subject_confirmation_reason(
        sp.parse_login_response_with_request_id(&idp()?, Binding::Post, &req, "_req1"),
        SubjectConfirmationReason::TimeWindowInvalid,
    )
}

#[test]
fn hardening_subject_confirmation_recipient_must_match_acs(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing())?;
    let response = response_for_subject_confirmation(
        &sp,
        &SubjectConfirmationCase {
            method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
            recipient: "https://evil.example/acs",
            not_on_or_after: iso8601_offset(300),
            response_in_response_to: Some("_req1"),
            subject_in_response_to: "_req1",
        },
    )?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response)]);
    assert_subject_confirmation_reason(
        sp.parse_login_response_with_request_id(&idp()?, Binding::Post, &req, "_req1"),
        SubjectConfirmationReason::RecipientMismatch,
    )
}

#[test]
fn hardening_response_destination_must_match_acs_when_present(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing())?;
    let response = response_for_destination(&sp, Some("https://evil.example/acs"))?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response)]);
    assert!(matches!(
        sp.parse_login_response_with_request_id(&idp()?, Binding::Post, &req, "_req1"),
        Err(SamlError::DestinationMismatch { .. })
    ));
    Ok(())
}

#[test]
fn hardening_missing_destination_accepts_matching_recipient(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing())?;
    let response = response_for_destination(&sp, None)?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response)]);
    let parsed = sp.parse_login_response_with_request_id(&idp()?, Binding::Post, &req, "_req1")?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("a@example.com"));
    Ok(())
}

#[test]
fn hardening_subject_confirmation_request_id_must_match() -> Result<(), Box<dyn std::error::Error>>
{
    let sp = sp_with("https://sp.example.com/metadata", signing())?;
    let response = response_for_subject_confirmation(
        &sp,
        &SubjectConfirmationCase {
            method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
            recipient: "https://sp/acs",
            not_on_or_after: iso8601_offset(300),
            response_in_response_to: Some("_req1"),
            subject_in_response_to: "_wrong",
        },
    )?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response)]);
    assert_subject_confirmation_reason(
        sp.parse_login_response_with_request_id(&idp()?, Binding::Post, &req, "_req1"),
        SubjectConfirmationReason::InResponseToMismatch,
    )
}

fn resigned_response_request(xml: &str) -> Result<HttpRequest, SamlError> {
    let document = saml_rs::xml::dom::parse_document(xml, crate::XmlLimits::default())?;
    let signature = document
        .root
        .children
        .iter()
        .filter(|child| child.local_name == "Assertion")
        .flat_map(|assertion| &assertion.children)
        .find(|child| child.local_name == "Signature")
        .ok_or_else(|| SamlError::xml("missing assertion signature"))?;
    let mut xml = xml.to_string();
    xml.replace_range(signature.start..signature.end, "");
    let key = saml_rs::crypto::keys::read_private_key(PRIVKEY, None)?;
    let signed = saml_rs::crypto::sign_saml_xml(&xml, false, &key, CERT, RSA_SHA256, &[], None)?;
    Ok(HttpRequest::post(vec![(
        "SAMLResponse".into(),
        STANDARD.encode(signed.as_bytes()),
    )]))
}

#[test]
fn hardening_duplicate_confirmation_data_keeps_the_missing_expiry_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing())?;
    let xml = String::from_utf8(STANDARD.decode(response_for(&sp)?)?)?;
    let xml = xml
        .replacen(
            "</saml:SubjectConfirmation>",
            "<saml:SubjectConfirmationData/></saml:SubjectConfirmation>",
            1,
        )
        .replace(
            "<saml:Audience>https://sp.example.com/metadata</saml:Audience>",
            "<saml:Audience>https://other.example/metadata</saml:Audience>",
        );
    assert_subject_confirmation_reason(
        sp.parse_login_response_with_request_id(
            &idp()?,
            Binding::Post,
            &resigned_response_request(&xml)?,
            "_req1",
        ),
        SubjectConfirmationReason::MissingNotOnOrAfter,
    )
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn hardening_encrypted_message_signed_response_verifies() -> Result<(), Box<dyn std::error::Error>>
{
    let mut idp_setting = signing();
    idp_setting.is_assertion_encrypted = true;
    let idp = idp::Engine::from_config(
        &IdpMetadataInput {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec![CERT.into()],
            single_sign_on_services: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
            ..Default::default()
        },
        idp_setting,
    )?;
    let mut sp_setting = signing();
    sp_setting.is_assertion_encrypted = true;
    sp_setting.enc_private_key = Some(PRIVKEY.into());
    let sp = sp::Engine::from_config(
        &SpMetadataInput {
            entity_id: "https://sp.example.com/metadata".into(),
            want_assertions_signed: false,
            signing_certs: vec![CERT.into()],
            encrypt_certs: vec![CERT.into()],
            assertion_consumer_services: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
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
    use saml_rs::crypto::keys::read_private_key;
    use saml_rs::crypto::sign_saml_xml;
    use saml_rs::{
        CertificatePem, EntityId, IdpDescriptor, MetadataTrustPolicy, SignatureAction,
        SignatureConfig, SignatureVerificationReason,
    };

    let md = "<EntityDescriptor ID=\"_md1\" entityID=\"https://idp.example.com/metadata\" xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://idp/sso\"/></IDPSSODescriptor></EntityDescriptor>";
    let key = read_private_key(PRIVKEY, None)?;
    let config = SignatureConfig {
        prefix: "ds".into(),
        reference: Some("/*[local-name(.)='EntityDescriptor']".into()),
        action: SignatureAction::Prepend,
    };
    let signed = sign_saml_xml(md, true, &key, CERT, RSA_SHA256, &[], Some(&config))?;

    let trusted_certificates = [CertificatePem::new(CERT)];
    let trust = MetadataTrustPolicy::RequireSignature {
        trusted_certificates: &trusted_certificates,
    };
    let descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new("https://idp.example.com/metadata")?,
        &signed,
        trust,
    )?;
    assert!(descriptor.signed_metadata_xml().is_some());

    let tampered = signed.replacen(
        "https://idp.example.com/metadata",
        "https://evil/metadata",
        1,
    );
    assert!(matches!(
        IdpDescriptor::from_metadata_xml(
            EntityId::try_new("https://evil/metadata")?,
            &tampered,
            trust,
        ),
        Err(SamlError::SignatureVerification {
            reason: SignatureVerificationReason::XmlSignature
        })
    ));
    Ok(())
}
