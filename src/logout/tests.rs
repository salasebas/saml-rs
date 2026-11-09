use super::*;
use crate::binding::{base64_decode, base64_encode, deflate_raw_decode};
use crate::constants::Binding;
use crate::entity::{BindingContext, EntitySetting, User};
use crate::error::SamlError;
use crate::flow::HttpRequest;
use crate::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
use crate::{IdentityProvider, ServiceProvider};
use std::time::{Duration, SystemTime};
use url::Url;

fn sp() -> Result<ServiceProvider, SamlError> {
    ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            single_logout_service: vec![
                Endpoint::new(Binding::Redirect, "https://sp/slo"),
                Endpoint::new(Binding::Post, "https://sp/slo"),
                Endpoint::new(Binding::SimpleSign, "https://sp/slo"),
            ],
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
            ..Default::default()
        },
        EntitySetting::default(),
    )
}

fn idp() -> Result<IdentityProvider, SamlError> {
    IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
            single_logout_service: vec![
                Endpoint::new(Binding::Redirect, "https://idp/slo"),
                Endpoint::new(Binding::Post, "https://idp/slo"),
                Endpoint::new(Binding::SimpleSign, "https://idp/slo"),
            ],
            ..Default::default()
        },
        EntitySetting::default(),
    )
}

fn unsigned_setting() -> EntitySetting {
    EntitySetting {
        want_logout_request_signed: false,
        ..Default::default()
    }
}

fn unsigned_sp(entity_id: &str) -> Result<ServiceProvider, SamlError> {
    ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: entity_id.into(),
            single_logout_service: vec![Endpoint::new(Binding::Post, "https://sp/slo")],
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
            ..Default::default()
        },
        unsigned_setting(),
    )
}

fn custom_logout_response_template(issue_instant_attribute: &str) -> String {
    format!(
        r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:custom="urn:example:custom" ID="{{ID}}" Version="2.0" {issue_instant_attribute} Destination="{{Destination}}" InResponseTo="{{InResponseTo}}"><saml:Issuer>{{Issuer}}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{{StatusCode}}"/></samlp:Status></samlp:LogoutResponse>"#
    )
}

fn create_custom_logout_response(
    issue_instant_attribute: &str,
    binding: Binding,
    want_signed: bool,
) -> Result<BindingContext, SamlError> {
    let mut sender = idp()?;
    let target = sp()?;
    sender.setting.logout_response_template =
        Some(custom_logout_response_template(issue_instant_attribute));
    create_logout_response(
        &sender.setting,
        &sender.metadata,
        &target.metadata,
        binding,
        Some("_req1"),
        None,
        want_signed,
    )
}

fn assert_protocol_profile_error(
    result: Result<BindingContext, SamlError>,
    expected_message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Err(SamlError::ProtocolProfile(message)) if message.contains(expected_message) => Ok(()),
        Err(SamlError::ProtocolProfile(message)) => {
            Err(format!("unexpected ProtocolProfile error: {message}").into())
        }
        Err(other) => Err(format!("expected ProtocolProfile, got {other:?}").into()),
        Ok(_) => Err("expected ProtocolProfile, got successful LogoutResponse".into()),
    }
}

fn decode_logout_response_context(
    context: &BindingContext,
) -> Result<String, Box<dyn std::error::Error>> {
    match context.binding {
        Binding::Post | Binding::SimpleSign => {
            Ok(String::from_utf8(base64_decode(&context.context)?)?)
        }
        Binding::Redirect => {
            let url = Url::parse(&context.context)?;
            let encoded = url
                .query_pairs()
                .find_map(|(key, value)| (key == "SAMLResponse").then_some(value.into_owned()))
                .ok_or("missing SAMLResponse")?;
            Ok(String::from_utf8(deflate_raw_decode(&base64_decode(
                &encoded,
            )?)?)?)
        }
        Binding::Artifact => Err("Artifact binding is unsupported".into()),
    }
}

fn logout_response_request(issue_instant_attribute: &str) -> HttpRequest {
    let xml = format!(
        r#"<samlp:LogoutResponse
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_response1" Version="2.0" {issue_instant_attribute}
    Destination="https://sp/slo" InResponseTo="_req1">
  <saml:Issuer>https://idp.example.com/metadata</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
</samlp:LogoutResponse>"#
    );
    HttpRequest::post(vec![("SAMLResponse".into(), base64_encode(xml.as_bytes()))])
}

fn parse_unsigned_logout_response(
    issue_instant_attribute: &str,
) -> Result<crate::flow::FlowResult, SamlError> {
    let mut sp = sp()?;
    let idp = idp()?;
    sp.setting.want_logout_response_signed = false;
    parse_logout_response(
        &sp.setting,
        &idp.metadata,
        Binding::Post,
        &logout_response_request(issue_instant_attribute),
        "_req1",
    )
}

fn logout_request_request(issue_instant: &str, not_on_or_after: Option<&str>) -> HttpRequest {
    let not_on_or_after = not_on_or_after
        .map(|value| format!(r#" NotOnOrAfter="{value}""#))
        .unwrap_or_default();
    let xml = format!(
        r#"<samlp:LogoutRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_request1" Version="2.0" IssueInstant="{issue_instant}"{not_on_or_after}
    Destination="https://idp/slo">
  <saml:Issuer>https://sp.example.com/metadata</saml:Issuer>
  <saml:NameID>alice@example.com</saml:NameID>
</samlp:LogoutRequest>"#
    );
    HttpRequest::post(vec![("SAMLRequest".into(), base64_encode(xml.as_bytes()))])
}

fn parse_unsigned_logout_request_at(
    issue_instant: &str,
    not_on_or_after: Option<&str>,
    now: SystemTime,
    clock_drifts: (i64, i64),
) -> Result<crate::flow::FlowResult, SamlError> {
    let mut receiver = idp()?;
    let sender = sp()?;
    receiver.setting.want_logout_request_signed = false;
    parse_logout_request_at(
        &receiver.setting,
        &sender.metadata,
        Binding::Post,
        &logout_request_request(issue_instant, not_on_or_after),
        LogoutFlowValidation::typed("https://idp/slo", now, clock_drifts),
    )
}

fn unix_time(seconds: u64) -> Result<SystemTime, Box<dyn std::error::Error>> {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or_else(|| "platform SystemTime cannot represent the test instant".into())
}

#[test]
fn logout_request_accepts_old_issue_instant_without_not_on_or_after(
) -> Result<(), Box<dyn std::error::Error>> {
    let result = parse_unsigned_logout_request_at(
        "2000-01-01T00:00:00Z",
        None,
        unix_time(1_735_689_600)?,
        (0, 0),
    )?;

    assert_eq!(
        result.extract.get_str("request.issueInstant"),
        Some("2000-01-01T00:00:00Z")
    );
    Ok(())
}

#[test]
fn logout_request_extracts_future_not_on_or_after() -> Result<(), Box<dyn std::error::Error>> {
    let result = parse_unsigned_logout_request_at(
        "2000-01-01T00:00:00Z",
        Some("2025-01-01T00:01:00Z"),
        unix_time(1_735_689_600)?,
        (0, 0),
    )?;

    assert_eq!(
        result.extract.get_str("request.notOnOrAfter"),
        Some("2025-01-01T00:01:00Z")
    );
    Ok(())
}

#[test]
fn logout_request_rejects_not_on_or_after_at_exact_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    match parse_unsigned_logout_request_at(
        "2000-01-01T00:00:00Z",
        Some("2025-01-01T00:00:00Z"),
        unix_time(1_735_689_600)?,
        (0, 0),
    ) {
        Err(SamlError::TimeWindowInvalid { field }) => {
            assert_eq!(
                field,
                crate::error::TimeWindowField::LogoutRequestNotOnOrAfter
            );
            Ok(())
        }
        other => Err(format!("expected LogoutRequest NotOnOrAfter error, got {other:?}").into()),
    }
}

#[test]
fn logout_request_runtime_unrepresentable_not_on_or_after_fails_as_time_window_policy(
) -> Result<(), Box<dyn std::error::Error>> {
    for not_on_or_after in [
        "2025-01-01T00:00:60Z",
        "2025-01-01T24:00:00Z",
        "12345-01-01T00:00:00Z",
    ] {
        match parse_unsigned_logout_request_at(
            "2000-01-01T00:00:00Z",
            Some(not_on_or_after),
            unix_time(1_735_689_600)?,
            (0, 0),
        ) {
            Err(SamlError::TimeWindowInvalid { field }) => {
                assert_eq!(
                    field,
                    crate::error::TimeWindowField::LogoutRequestNotOnOrAfter
                );
            }
            other => {
                return Err(format!(
                    "expected runtime time-window failure for {not_on_or_after}, got {other:?}"
                )
                .into());
            }
        }
    }
    Ok(())
}

#[test]
fn logout_request_redirect_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, mut idp) = (sp()?, idp()?);
    idp.setting.want_logout_request_signed = false;
    let ctx = create_logout_request(
        &sp.setting,
        &sp.metadata,
        &idp.metadata,
        Binding::Redirect,
        &User::new("user@example.com"),
        None,
        false,
    )?;
    assert_eq!(ctx.entity_endpoint, "https://idp/slo");
    let url = Url::parse(&ctx.context)?;
    let (_, value) = url
        .query_pairs()
        .find(|(k, _)| k == "SAMLRequest")
        .ok_or("missing SAMLRequest")?;
    let xml = String::from_utf8(deflate_raw_decode(&base64_decode(&value)?)?)?;
    assert!(xml.contains("<samlp:LogoutRequest"));
    assert!(xml.contains("user@example.com"));

    // IdP parses it (unsigned)
    let request = HttpRequest::redirect(vec![("SAMLRequest".into(), value.into_owned())]);
    let result = parse_logout_request(&idp.setting, &sp.metadata, Binding::Redirect, &request)?;
    assert_eq!(
        result.extract.get_str("issuer"),
        Some("https://sp.example.com/metadata")
    );
    Ok(())
}

#[test]
fn logout_requests_require_signatures_by_default() {
    assert!(EntitySetting::default().want_logout_request_signed);
}

#[test]
fn unsigned_logout_request_rejects_unexpected_issuer_when_explicitly_allowed(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut idp = idp()?;
    idp.setting.want_logout_request_signed = false;
    let expected_sp = unsigned_sp("https://expected-sp.example.com/metadata")?;
    let attacker_sp = unsigned_sp("https://attacker-sp.example.com/metadata")?;
    let ctx = create_logout_request(
        &attacker_sp.setting,
        &attacker_sp.metadata,
        &idp.metadata,
        Binding::Post,
        &User::new("victim@example.com"),
        None,
        false,
    )?;
    let request = HttpRequest::post(vec![("SAMLRequest".into(), ctx.context)]);

    let result = parse_logout_request(&idp.setting, &expected_sp.metadata, Binding::Post, &request);

    assert!(matches!(result, Err(SamlError::IssuerMismatch { .. })));
    Ok(())
}

#[test]
fn raw_logout_request_parser_does_not_infer_actual_recipient(
) -> Result<(), Box<dyn std::error::Error>> {
    let sender = sp()?;
    let mut receiver = idp()?;
    receiver.setting.want_logout_request_signed = false;
    let context = create_logout_request(
        &sender.setting,
        &sender.metadata,
        &receiver.metadata,
        Binding::Post,
        &User::new("victim@example.com"),
        None,
        false,
    )?;
    let xml = String::from_utf8(base64_decode(&context.context)?)?.replace(
        r#"Destination="https://idp/slo""#,
        r#"Destination="https://different.example/slo""#,
    );
    let request = HttpRequest::post(vec![("SAMLRequest".into(), base64_encode(xml.as_bytes()))]);

    let result =
        parse_logout_request(&receiver.setting, &sender.metadata, Binding::Post, &request)?;

    assert_eq!(
        result.extract.get_str("request.destination"),
        Some("https://different.example/slo")
    );
    Ok(())
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
mod signed_tests {
    use super::*;
    use crate::constants::signature_algorithm::RSA_SHA256;
    use crate::entity::{SignatureAction, SignatureConfig};

    const PRIVKEY: &str = include_str!("../../tests/fixtures/key/sp_privkey.pem");
    const CERT: &str = include_str!("../../tests/fixtures/key/sp_signing_cert.cer");

    fn signing_setting() -> EntitySetting {
        EntitySetting {
            private_key: Some(PRIVKEY.into()),
            signing_cert: Some(CERT.into()),
            request_signature_algorithm: RSA_SHA256.into(),
            ..Default::default()
        }
    }

    fn signed_sp(entity_id: &str) -> Result<ServiceProvider, SamlError> {
        ServiceProvider::from_config(
            &SpMetadataConfig {
                entity_id: entity_id.into(),
                signing_certs: vec![CERT.into()],
                single_logout_service: vec![Endpoint::new(Binding::Post, "https://sp/slo")],
                assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
                ..Default::default()
            },
            signing_setting(),
        )
    }

    #[test]
    fn signed_logout_request_rejects_unexpected_issuer() -> Result<(), Box<dyn std::error::Error>> {
        let idp = idp()?;
        let expected_sp = signed_sp("https://expected-sp.example.com/metadata")?;
        let attacker_sp = signed_sp("https://attacker-sp.example.com/metadata")?;
        let ctx = create_logout_request(
            &attacker_sp.setting,
            &attacker_sp.metadata,
            &idp.metadata,
            Binding::Post,
            &User::new("victim@example.com"),
            None,
            true,
        )?;
        let request = HttpRequest::post(vec![("SAMLRequest".into(), ctx.context)]);

        let result =
            parse_logout_request(&idp.setting, &expected_sp.metadata, Binding::Post, &request);

        assert!(matches!(result, Err(SamlError::IssuerMismatch { .. })));
        Ok(())
    }

    #[test]
    fn signed_post_logout_response_rejects_signature_after_status_for_default_and_custom_renderers(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for template in [
            None,
            Some(custom_logout_response_template(
                r#"IssueInstant="{IssueInstant}""#,
            )),
        ] {
            let mut sender = idp()?;
            let target = sp()?;
            sender.setting = signing_setting();
            sender.setting.logout_response_template = template;
            sender.setting.signature_config = Some(SignatureConfig {
                prefix: "ds".into(),
                reference: Some(
                    "/*[local-name(.)='LogoutResponse']/*[local-name(.)='Status']".into(),
                ),
                action: SignatureAction::After,
            });

            let result = create_logout_response(
                &sender.setting,
                &sender.metadata,
                &target.metadata,
                Binding::Post,
                Some("_req1"),
                None,
                true,
            );

            assert_protocol_profile_error(
                result,
                "LogoutResponse children must be Issuer, optional Signature, optional Extensions, and exactly one final Status",
            )?;
        }
        Ok(())
    }

    #[test]
    fn signed_custom_post_logout_response_rejects_signature_inside_extensions(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut sender = idp()?;
        let target = sp()?;
        sender.setting = signing_setting();
        sender.setting.logout_response_template = Some(
            custom_logout_response_template(r#"IssueInstant="{IssueInstant}""#).replace(
                "<samlp:Status>",
                "<samlp:Extensions><custom:Marker/></samlp:Extensions><samlp:Status>",
            ),
        );
        sender.setting.signature_config = Some(SignatureConfig {
            prefix: "ds".into(),
            reference: Some(
                "/*[local-name(.)='LogoutResponse']/*[local-name(.)='Extensions']".into(),
            ),
            action: SignatureAction::Append,
        });

        let result = create_logout_response(
            &sender.setting,
            &sender.metadata,
            &target.metadata,
            Binding::Post,
            Some("_req1"),
            None,
            true,
        );

        assert_protocol_profile_error(
            result,
            "signed POST LogoutResponse must contain a root ds:Signature in schema order",
        )
    }

    fn signed_idp() -> Result<IdentityProvider, SamlError> {
        IdentityProvider::from_config(
            &IdpMetadataConfig {
                entity_id: "https://idp.example.com/metadata".into(),
                signing_certs: vec![CERT.into()],
                single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
                single_logout_service: vec![Endpoint::new(Binding::Post, "https://idp/slo")],
                ..Default::default()
            },
            signing_setting(),
        )
    }

    fn strict_sp() -> Result<ServiceProvider, SamlError> {
        let mut service_provider = sp()?;
        service_provider.setting.strict_xml_signature_profile = true;
        Ok(service_provider)
    }

    fn post_logout_request(context: String) -> HttpRequest {
        HttpRequest::post(vec![("SAMLRequest".into(), context)])
    }

    fn post_logout_response(context: String) -> HttpRequest {
        HttpRequest::post(vec![("SAMLResponse".into(), context)])
    }

    #[test]
    fn strict_profile_accepts_signed_post_logout_messages() -> Result<(), Box<dyn std::error::Error>>
    {
        let idp = signed_idp()?;
        let service_provider = strict_sp()?;
        let request = create_logout_request(
            &idp.setting,
            &idp.metadata,
            &service_provider.metadata,
            Binding::Post,
            &User::new("user@example.com"),
            None,
            true,
        )?;
        let parsed = parse_logout_request(
            &service_provider.setting,
            &idp.metadata,
            Binding::Post,
            &post_logout_request(request.context),
        )?;
        assert_eq!(
            parsed.extract.get_str("issuer"),
            Some("https://idp.example.com/metadata")
        );

        let response = create_logout_response(
            &idp.setting,
            &idp.metadata,
            &service_provider.metadata,
            Binding::Post,
            Some("_req1"),
            None,
            true,
        )?;
        let parsed = parse_logout_response(
            &service_provider.setting,
            &idp.metadata,
            Binding::Post,
            &post_logout_response(response.context),
            "_req1",
        )?;
        assert_eq!(
            parsed.extract.get_str("issuer"),
            Some("https://idp.example.com/metadata")
        );
        Ok(())
    }

    #[test]
    fn strict_profile_rejects_logout_signatures_with_inclusive_canonicalization(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut idp = signed_idp()?;
        idp.setting.transformation_algorithms = vec![
            crate::constants::transform_algorithm::ENVELOPED_SIGNATURE.to_string(),
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315".to_string(),
        ];
        let mut compatible = sp()?;
        compatible.setting.want_logout_request_signed = true;
        compatible.setting.want_logout_response_signed = true;
        let strict = strict_sp()?;

        let request = create_logout_request(
            &idp.setting,
            &idp.metadata,
            &strict.metadata,
            Binding::Post,
            &User::new("user@example.com"),
            None,
            true,
        )?;
        let request_message = post_logout_request(request.context);
        assert_eq!(
            parse_logout_request(
                &compatible.setting,
                &idp.metadata,
                Binding::Post,
                &request_message,
            )?
            .extract
            .get_str("issuer"),
            Some("https://idp.example.com/metadata")
        );
        assert!(matches!(
            parse_logout_request(
                &strict.setting,
                &idp.metadata,
                Binding::Post,
                &request_message
            ),
            Err(SamlError::AlgorithmUnsupported)
        ));

        let response = create_logout_response(
            &idp.setting,
            &idp.metadata,
            &strict.metadata,
            Binding::Post,
            Some("_req1"),
            None,
            true,
        )?;
        let response_message = post_logout_response(response.context);
        assert_eq!(
            parse_logout_response(
                &compatible.setting,
                &idp.metadata,
                Binding::Post,
                &response_message,
                "_req1",
            )?
            .extract
            .get_str("issuer"),
            Some("https://idp.example.com/metadata")
        );
        assert!(matches!(
            parse_logout_response(
                &strict.setting,
                &idp.metadata,
                Binding::Post,
                &response_message,
                "_req1",
            ),
            Err(SamlError::AlgorithmUnsupported)
        ));
        Ok(())
    }

    #[cfg(feature = "crypto-legacy-algorithms")]
    #[test]
    fn strict_profile_rejects_logout_request_signed_with_rsa_sha1(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut idp = signed_idp()?;
        idp.setting.request_signature_algorithm =
            crate::constants::signature_algorithm::RSA_SHA1.to_string();
        let mut compatible = sp()?;
        compatible.setting.want_logout_request_signed = true;
        let strict = strict_sp()?;
        let request = create_logout_request(
            &idp.setting,
            &idp.metadata,
            &strict.metadata,
            Binding::Post,
            &User::new("user@example.com"),
            None,
            true,
        )?;
        let message = post_logout_request(request.context);
        assert!(
            parse_logout_request(&compatible.setting, &idp.metadata, Binding::Post, &message,)
                .is_ok()
        );
        assert!(matches!(
            parse_logout_request(&strict.setting, &idp.metadata, Binding::Post, &message),
            Err(SamlError::AlgorithmUnsupported)
        ));
        Ok(())
    }
}

#[test]
fn logout_response_post_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    let (mut sp, idp) = (sp()?, idp()?);
    sp.setting.want_logout_response_signed = false;
    // IdP responds to SP's logout; target is the SP (SLO via redirect endpoint)
    let ctx = create_logout_response(
        &idp.setting,
        &idp.metadata,
        &sp.metadata,
        Binding::Post,
        Some("_req1"),
        None,
        false,
    )?;
    let xml = String::from_utf8(base64_decode(&ctx.context)?)?;
    assert!(xml.contains("<samlp:LogoutResponse"));

    let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);
    let result =
        parse_logout_response(&sp.setting, &idp.metadata, Binding::Post, &request, "_req1")?;
    assert_eq!(
        result.extract.get_str("issuer"),
        Some("https://idp.example.com/metadata")
    );
    Ok(())
}

#[test]
fn custom_logout_response_rejects_missing_issue_instant_before_post_encoding(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_protocol_profile_error(
        create_custom_logout_response("", Binding::Post, false),
        "LogoutResponse is missing required unqualified attribute IssueInstant",
    )
}

#[test]
fn custom_logout_response_rejects_qualified_issue_instant_before_redirect_encoding(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_protocol_profile_error(
        create_custom_logout_response(
            r#"custom:IssueInstant="2000-01-01T00:00:00Z""#,
            Binding::Redirect,
            false,
        ),
        "attribute IssueInstant on LogoutResponse must be unqualified",
    )
}

#[test]
fn custom_logout_response_rejects_malformed_issue_instant_before_simplesign_encoding(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_protocol_profile_error(
        create_custom_logout_response(r#"IssueInstant="not-a-date""#, Binding::SimpleSign, false),
        "LogoutResponse IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z",
    )
}

#[test]
fn custom_logout_response_rejects_offset_issue_instant_before_post_signing(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_protocol_profile_error(
        create_custom_logout_response(
            r#"IssueInstant="2000-01-01T00:00:00+00:00""#,
            Binding::Post,
            true,
        ),
        "LogoutResponse IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z",
    )
}

#[test]
fn custom_logout_response_rejects_leap_second_before_redirect_signing(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_protocol_profile_error(
        create_custom_logout_response(
            r#"IssueInstant="2000-01-01T00:00:60Z""#,
            Binding::Redirect,
            true,
        ),
        "LogoutResponse IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z",
    )
}

#[test]
fn public_custom_logout_response_enforces_in_response_to_correlation(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut sender = idp()?;
    let target = sp()?;
    sender.setting.logout_response_template = Some(
        custom_logout_response_template(r#"IssueInstant="{IssueInstant}""#).replace(
            r#"InResponseTo="{InResponseTo}""#,
            r#"InResponseTo="_wrong""#,
        ),
    );

    let result = create_logout_response(
        &sender.setting,
        &sender.metadata,
        &target.metadata,
        Binding::Post,
        Some("_req1"),
        None,
        false,
    );

    match result {
        Err(SamlError::InResponseToMismatch { expected, actual })
            if expected.as_deref() == Some("_req1") && actual.as_deref() == Some("_wrong") =>
        {
            Ok(())
        }
        other => Err(format!("expected public InResponseToMismatch, got {other:?}").into()),
    }
}

#[test]
fn custom_logout_response_omits_optional_in_response_to_placeholder(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut sender = idp()?;
    let target = sp()?;
    sender.setting.logout_response_template = Some(custom_logout_response_template(
        r#"IssueInstant="{IssueInstant}""#,
    ));

    let context = create_logout_response(
        &sender.setting,
        &sender.metadata,
        &target.metadata,
        Binding::Post,
        None,
        None,
        false,
    )?;
    let xml = decode_logout_response_context(&context)?;

    assert!(!xml.contains("InResponseTo"));
    Ok(())
}

#[test]
fn custom_logout_response_rejects_root_signature_before_each_supported_binding(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut sender = idp()?;
    let target = sp()?;
    sender.setting.logout_response_template = Some(
        custom_logout_response_template(r#"IssueInstant="{IssueInstant}""#)
            .replace(
                r#"xmlns:custom="urn:example:custom""#,
                &format!(
                    r#"xmlns:custom="urn:example:custom" xmlns:ds="{}""#,
                    crate::constants::namespace::DSIG
                ),
            )
            .replace(
                "<samlp:Status>",
                "<ds:Signature><ds:SignedInfo/></ds:Signature><samlp:Status>",
            ),
    );

    for binding in [Binding::Post, Binding::Redirect, Binding::SimpleSign] {
        assert_protocol_profile_error(
            create_logout_response(
                &sender.setting,
                &sender.metadata,
                &target.metadata,
                binding,
                Some("_req1"),
                None,
                false,
            ),
            "must not contain a root ds:Signature before library signing",
        )?;
    }
    Ok(())
}

#[test]
fn custom_logout_response_rejects_doctype_before_profile_validation(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut sender = idp()?;
    let target = sp()?;
    sender.setting.logout_response_template = Some(format!(
        r#"<!DOCTYPE samlp:LogoutResponse>{}"#,
        custom_logout_response_template(r#"IssueInstant="2000-01-01T00:00:00Z""#)
    ));

    match create_logout_response(
        &sender.setting,
        &sender.metadata,
        &target.metadata,
        Binding::Post,
        Some("_req1"),
        None,
        false,
    ) {
        Err(SamlError::Xml(message)) if message.contains("DOCTYPE is not allowed") => Ok(()),
        other => Err(format!("expected structural DOCTYPE rejection, got {other:?}").into()),
    }
}

#[test]
fn custom_logout_response_accepts_issue_instant_placeholder_for_all_supported_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut sender = idp()?;
    let target = sp()?;
    sender.setting.logout_response_template = Some(custom_logout_response_template(
        r#"IssueInstant="{IssueInstant}""#,
    ));

    for binding in [Binding::Post, Binding::Redirect, Binding::SimpleSign] {
        let context = create_logout_response(
            &sender.setting,
            &sender.metadata,
            &target.metadata,
            binding,
            Some("_req1"),
            None,
            false,
        )?;
        let xml = decode_logout_response_context(&context)?;
        let document = crate::xml::dom::parse(&xml)?;
        let issue_instant = document
            .root
            .attr("IssueInstant")
            .ok_or("missing rendered IssueInstant")?;
        assert!(
            issue_instant.ends_with('Z'),
            "expected generated UTC IssueInstant for {binding:?}, got {issue_instant}"
        );
    }
    Ok(())
}

#[test]
fn custom_logout_response_preserves_valid_literal_without_destination(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut sender = idp()?;
    let target = sp()?;
    sender.setting.logout_response_template = Some(
        r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="2000-01-01T00:00:00Z" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status></samlp:LogoutResponse>"#.to_string(),
    );

    let context = create_logout_response_with_id(
        &sender.setting,
        &sender.metadata,
        &target.metadata,
        Binding::Post,
        Some("_req1"),
        None,
        false,
        Some("_fixed"),
    )?;
    let xml = decode_logout_response_context(&context)?;

    assert_eq!(
        xml,
        r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_fixed" Version="2.0" IssueInstant="2000-01-01T00:00:00Z" InResponseTo="_req1"><saml:Issuer>https://idp.example.com/metadata</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>"#
    );
    Ok(())
}

#[test]
fn logout_response_rejects_missing_issue_instant() {
    let result = parse_unsigned_logout_response("");

    assert!(matches!(
        result,
        Err(SamlError::ProtocolProfile(message))
            if message.contains("LogoutResponse is missing required unqualified attribute IssueInstant")
    ));
}

#[test]
fn logout_response_rejects_malformed_issue_instant() {
    let result = parse_unsigned_logout_response("IssueInstant=\"not-a-date\"");

    assert!(matches!(
        result,
        Err(SamlError::ProtocolProfile(message))
            if message.contains("LogoutResponse IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z")
    ));
}

#[test]
fn logout_response_rejects_non_utc_issue_instant() {
    let result = parse_unsigned_logout_response("IssueInstant=\"2024-01-01T00:00:00+00:00\"");

    assert!(matches!(
        result,
        Err(SamlError::ProtocolProfile(message))
            if message.contains("LogoutResponse IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z")
    ));
}

#[test]
fn logout_response_accepts_well_formed_utc_issue_instant_without_age_policy(
) -> Result<(), Box<dyn std::error::Error>> {
    let parsed = parse_unsigned_logout_response("IssueInstant=\"2000-01-01T00:00:00Z\"")?;

    assert_eq!(
        parsed.extract.get_str("response.issueInstant"),
        Some("2000-01-01T00:00:00Z")
    );
    Ok(())
}

#[test]
fn logout_response_rejects_empty_request_id() -> Result<(), Box<dyn std::error::Error>> {
    let (mut sp, idp) = (sp()?, idp()?);
    sp.setting.want_logout_response_signed = false;
    let ctx = create_logout_response(
        &idp.setting,
        &idp.metadata,
        &sp.metadata,
        Binding::Post,
        Some("_req1"),
        None,
        false,
    )?;
    let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);

    assert!(matches!(
        parse_logout_response(&sp.setting, &idp.metadata, Binding::Post, &request, ""),
        Err(SamlError::InvalidInResponseTo)
    ));
    Ok(())
}

#[test]
fn logout_response_rejects_wrong_request_id() -> Result<(), Box<dyn std::error::Error>> {
    let (mut sp, idp) = (sp()?, idp()?);
    sp.setting.want_logout_response_signed = false;
    let ctx = create_logout_response(
        &idp.setting,
        &idp.metadata,
        &sp.metadata,
        Binding::Post,
        Some("_req1"),
        None,
        false,
    )?;
    let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);

    assert!(matches!(
        parse_logout_response(
            &sp.setting,
            &idp.metadata,
            Binding::Post,
            &request,
            "_other"
        ),
        Err(SamlError::InResponseToMismatch { .. })
    ));
    Ok(())
}

#[test]
fn default_logout_response_parsing_requires_signature() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = (sp()?, idp()?);
    let ctx = create_logout_response(
        &idp.setting,
        &idp.metadata,
        &sp.metadata,
        Binding::Post,
        Some("_req1"),
        None,
        false,
    )?;
    let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);

    let result =
        parse_logout_response(&sp.setting, &idp.metadata, Binding::Post, &request, "_req1");

    #[cfg(any(
        feature = "crypto-rustcrypto",
        feature = "crypto-aws-lc",
        feature = "crypto-fips"
    ))]
    assert!(matches!(result, Err(SamlError::SignatureMissing)));

    #[cfg(not(any(
        feature = "crypto-rustcrypto",
        feature = "crypto-aws-lc",
        feature = "crypto-fips"
    )))]
    assert!(matches!(result, Err(SamlError::Unsupported(_))));

    Ok(())
}

#[test]
fn logout_response_uses_response_location_and_request_uses_location(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp_xml = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/metadata">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/slo/request" ResponseLocation="https://sp.example.com/slo/response"/>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>"#;
    let target = ServiceProvider::from_metadata(sp_xml, EntitySetting::default())?;
    let sender = idp()?;
    let response = create_logout_response(
        &sender.setting,
        &sender.metadata,
        &target.metadata,
        Binding::Post,
        Some("_req1"),
        None,
        false,
    )?;
    assert_eq!(
        response.entity_endpoint,
        "https://sp.example.com/slo/response"
    );
    let request = create_logout_request(
        &sender.setting,
        &sender.metadata,
        &target.metadata,
        Binding::Post,
        &User::new("alice"),
        None,
        false,
    )?;
    assert_eq!(
        request.entity_endpoint,
        "https://sp.example.com/slo/request"
    );
    Ok(())
}
