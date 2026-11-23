use super::*;
use crate::binding::{
    decode_base64, deflate_raw_decode, encode_base64, MAX_DEFLATE_RAW_DECODE_BYTES,
};

use crate::constants::Binding;
use crate::entity::{BindingContext, EntitySetting};
use crate::error::SamlError;
use crate::flow::HttpRequest;
use crate::idp;
use crate::metadata::{Endpoint, IdpMetadataInput, SpMetadataInput};
use crate::model::ClockSkew;
use crate::sp;
use crate::tests::engine::{
    create_logout_request, create_logout_response, parse_logout_response, LogoutUser,
};
use std::time::{Duration, SystemTime};
use url::Url;

fn sp() -> Result<sp::Engine, SamlError> {
    sp::Engine::from_config(
        &SpMetadataInput {
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

fn idp() -> Result<idp::Engine, SamlError> {
    idp::Engine::from_config(
        &IdpMetadataInput {
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
    HttpRequest::post(vec![("SAMLResponse".into(), encode_base64(xml.as_bytes()))])
}

fn parse_attested_soap_logout_response(
    issue_instant_attribute: &str,
) -> Result<crate::flow::FlowResult, SamlError> {
    parse_logout_response_at(
        &sp()?.setting,
        idp()?.metadata.as_metadata(),
        LogoutReceipt::soap(crate::SoapChannel::mutually_authenticated_confidential()),
        &logout_response_request(issue_instant_attribute),
        "_req1",
        LogoutFlowValidation::typed(None, SystemTime::now(), ClockSkew::strict(), None),
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
    HttpRequest::post(vec![("SAMLRequest".into(), encode_base64(xml.as_bytes()))])
}

fn parse_attested_soap_logout_request_at(
    issue_instant: &str,
    not_on_or_after: Option<&str>,
    now: SystemTime,
    clock_skew: ClockSkew,
) -> Result<crate::flow::FlowResult, SamlError> {
    let receiver = idp()?;
    let sender = sp()?;
    parse_logout_request_at(
        &receiver.setting,
        sender.metadata.as_metadata(),
        LogoutReceipt::soap(crate::SoapChannel::mutually_authenticated_confidential()),
        &logout_request_request(issue_instant, not_on_or_after),
        LogoutFlowValidation::typed(Some("https://idp/slo"), now, clock_skew, None),
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
    let result = parse_attested_soap_logout_request_at(
        "2000-01-01T00:00:00Z",
        None,
        unix_time(1_735_689_600)?,
        ClockSkew::strict(),
    )?;

    assert_eq!(
        result.extract.get_str("request.issueInstant"),
        Some("2000-01-01T00:00:00Z")
    );
    Ok(())
}

#[test]
fn logout_request_extracts_future_not_on_or_after() -> Result<(), Box<dyn std::error::Error>> {
    let result = parse_attested_soap_logout_request_at(
        "2000-01-01T00:00:00Z",
        Some("2025-01-01T00:01:00Z"),
        unix_time(1_735_689_600)?,
        ClockSkew::strict(),
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
    match parse_attested_soap_logout_request_at(
        "2000-01-01T00:00:00Z",
        Some("2025-01-01T00:00:00Z"),
        unix_time(1_735_689_600)?,
        ClockSkew::strict(),
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
        match parse_attested_soap_logout_request_at(
            "2000-01-01T00:00:00Z",
            Some(not_on_or_after),
            unix_time(1_735_689_600)?,
            ClockSkew::strict(),
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
fn logout_request_redirect_encodes_the_subject_and_endpoint(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = (sp()?, idp()?);
    let ctx = create_logout_request(
        &sp.setting,
        sp.metadata.as_metadata(),
        idp.metadata.as_metadata(),
        Binding::Redirect,
        &LogoutUser::new("user@example.com"),
        None,
        false,
    )?;
    assert_eq!(ctx.entity_endpoint, "https://idp/slo");
    let url = Url::parse(&ctx.context)?;
    let (_, value) = url
        .query_pairs()
        .find(|(k, _)| k == "SAMLRequest")
        .ok_or("missing SAMLRequest")?;
    let xml = String::from_utf8(deflate_raw_decode(
        &decode_base64(&value)?,
        MAX_DEFLATE_RAW_DECODE_BYTES,
    )?)?;
    assert!(xml.contains("<samlp:LogoutRequest"));
    assert!(xml.contains("user@example.com"));

    Ok(())
}

#[test]
fn raw_logout_request_parser_does_not_infer_actual_recipient(
) -> Result<(), Box<dyn std::error::Error>> {
    let sender = sp()?;
    let receiver = idp()?;
    let context = create_logout_request(
        &sender.setting,
        sender.metadata.as_metadata(),
        receiver.metadata.as_metadata(),
        Binding::Post,
        &LogoutUser::new("victim@example.com"),
        None,
        false,
    )?;
    let xml = String::from_utf8(decode_base64(&context.context)?)?.replace(
        r#"Destination="https://idp/slo""#,
        r#"Destination="https://different.example/slo""#,
    );
    let request = HttpRequest::post(vec![("SAMLRequest".into(), encode_base64(xml.as_bytes()))]);

    let result = parse_logout_request_at(
        &receiver.setting,
        sender.metadata.as_metadata(),
        LogoutReceipt::soap(crate::SoapChannel::mutually_authenticated_confidential()),
        &request,
        LogoutFlowValidation::typed(None, SystemTime::now(), ClockSkew::strict(), None),
    )?;

    assert_eq!(
        result.extract.get_str("request.destination"),
        Some("https://different.example/slo")
    );
    Ok(())
}

#[cfg(crypto)]
mod signed_tests {
    use super::*;
    use crate::constants::signature_algorithm::RSA_SHA256;
    use crate::entity::{SignatureAction, SignatureConfig};
    use crate::tests::engine::parse_logout_request;

    const PRIVKEY: &str = include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
    const CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");

    fn signing_setting() -> EntitySetting {
        EntitySetting {
            private_key: Some(PRIVKEY.into()),
            signing_cert: Some(CERT.into()),
            request_signature_algorithm: RSA_SHA256.into(),
            ..Default::default()
        }
    }

    fn signed_sp(entity_id: &str) -> Result<sp::Engine, SamlError> {
        sp::Engine::from_config(
            &SpMetadataInput {
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
            attacker_sp.metadata.as_metadata(),
            idp.metadata.as_metadata(),
            Binding::Post,
            &LogoutUser::new("victim@example.com"),
            None,
            true,
        )?;
        let request = HttpRequest::post(vec![("SAMLRequest".into(), ctx.context)]);

        let result = parse_logout_request(
            &idp.setting,
            expected_sp.metadata.as_metadata(),
            Binding::Post,
            &request,
        );

        assert!(matches!(result, Err(SamlError::IssuerMismatch { .. })));
        Ok(())
    }

    #[test]
    fn signed_post_logout_response_rejects_signature_after_status(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut sender = idp()?;
        let target = sp()?;
        sender.setting = signing_setting();
        sender.setting.signature_config = Some(SignatureConfig {
            prefix: "ds".into(),
            reference: Some("/*[local-name(.)='LogoutResponse']/*[local-name(.)='Status']".into()),
            action: SignatureAction::After,
        });

        let result = create_logout_response(
            &sender.setting,
            sender.metadata.as_metadata(),
            target.metadata.as_metadata(),
            Binding::Post,
            Some("_req1"),
            None,
            true,
        );

        assert_protocol_profile_error(
            result,
            "LogoutResponse children must be Issuer, optional Signature, optional Extensions, and exactly one final Status",
        )
    }

    fn signed_idp() -> Result<idp::Engine, SamlError> {
        idp::Engine::from_config(
            &IdpMetadataInput {
                entity_id: "https://idp.example.com/metadata".into(),
                signing_certs: vec![CERT.into()],
                single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
                single_logout_service: vec![Endpoint::new(Binding::Post, "https://idp/slo")],
                ..Default::default()
            },
            signing_setting(),
        )
    }

    fn strict_sp() -> Result<sp::Engine, SamlError> {
        let mut service_provider = sp()?;
        service_provider.setting.xml_signatures = crate::config::XmlSignatureProfile::StrictRsaSha2;
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
            idp.metadata.as_metadata(),
            service_provider.metadata.as_metadata(),
            Binding::Post,
            &LogoutUser::new("user@example.com"),
            None,
            true,
        )?;
        let parsed = parse_logout_request(
            &service_provider.setting,
            idp.metadata.as_metadata(),
            Binding::Post,
            &post_logout_request(request.context),
        )?;
        assert_eq!(
            parsed.extract.get_str("issuer"),
            Some("https://idp.example.com/metadata")
        );

        let response = create_logout_response(
            &idp.setting,
            idp.metadata.as_metadata(),
            service_provider.metadata.as_metadata(),
            Binding::Post,
            Some("_req1"),
            None,
            true,
        )?;
        let parsed = parse_logout_response(
            &service_provider.setting,
            idp.metadata.as_metadata(),
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
        let compatible = sp()?;
        let strict = strict_sp()?;

        let request = create_logout_request(
            &idp.setting,
            idp.metadata.as_metadata(),
            strict.metadata.as_metadata(),
            Binding::Post,
            &LogoutUser::new("user@example.com"),
            None,
            true,
        )?;
        let request_message = post_logout_request(request.context);
        assert_eq!(
            parse_logout_request(
                &compatible.setting,
                idp.metadata.as_metadata(),
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
                idp.metadata.as_metadata(),
                Binding::Post,
                &request_message
            ),
            Err(SamlError::AlgorithmUnsupported)
        ));

        let response = create_logout_response(
            &idp.setting,
            idp.metadata.as_metadata(),
            strict.metadata.as_metadata(),
            Binding::Post,
            Some("_req1"),
            None,
            true,
        )?;
        let response_message = post_logout_response(response.context);
        assert_eq!(
            parse_logout_response(
                &compatible.setting,
                idp.metadata.as_metadata(),
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
                idp.metadata.as_metadata(),
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
        let compatible = sp()?;
        let strict = strict_sp()?;
        let request = create_logout_request(
            &idp.setting,
            idp.metadata.as_metadata(),
            strict.metadata.as_metadata(),
            Binding::Post,
            &LogoutUser::new("user@example.com"),
            None,
            true,
        )?;
        let message = post_logout_request(request.context);
        assert!(parse_logout_request(
            &compatible.setting,
            idp.metadata.as_metadata(),
            Binding::Post,
            &message,
        )
        .is_ok());
        assert!(matches!(
            parse_logout_request(
                &strict.setting,
                idp.metadata.as_metadata(),
                Binding::Post,
                &message
            ),
            Err(SamlError::AlgorithmUnsupported)
        ));
        Ok(())
    }
}

#[test]
fn logout_response_preserves_braces_in_the_destination() -> Result<(), Box<dyn std::error::Error>> {
    let sender = idp()?;
    let target = sp::Engine::from_config(
        &SpMetadataInput {
            entity_id: "https://sp.example.com/metadata".into(),
            single_logout_service: vec![Endpoint::new(
                Binding::Post,
                "https://sp/slo?next={InResponseTo}",
            )],
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
            ..Default::default()
        },
        EntitySetting::default(),
    )?;

    let context = create_logout_response(
        &sender.setting,
        sender.metadata.as_metadata(),
        target.metadata.as_metadata(),
        Binding::Post,
        Some("_req1"),
        None,
        false,
    )?;
    let xml = String::from_utf8(decode_base64(&context.context)?)?;

    assert!(xml.contains(r#"Destination="https://sp/slo?next={InResponseTo}""#));
    assert!(xml.contains(r#"InResponseTo="_req1""#));
    Ok(())
}

#[test]
fn logout_response_rejects_a_peer_slo_location_that_is_not_a_url(
) -> Result<(), Box<dyn std::error::Error>> {
    let sender = idp()?;
    for location in ["http://", "https://sp:70000/slo"] {
        let target = sp::Engine::from_config(
            &SpMetadataInput {
                entity_id: "https://sp.example.com/metadata".into(),
                single_logout_service: vec![Endpoint::new(Binding::Redirect, location)],
                assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
                ..Default::default()
            },
            EntitySetting::default(),
        )?;
        assert_protocol_profile_error(
            create_logout_response(
                &sender.setting,
                sender.metadata.as_metadata(),
                target.metadata.as_metadata(),
                Binding::Redirect,
                Some("_req1"),
                None,
                false,
            ),
            "LogoutResponse Destination must be",
        )?;
    }
    Ok(())
}

#[test]
fn logout_response_rejects_missing_issue_instant() {
    let result = parse_attested_soap_logout_response("");

    assert!(matches!(
        result,
        Err(SamlError::ProtocolProfile(message))
            if message.contains("LogoutResponse is missing required unqualified attribute IssueInstant")
    ));
}

#[test]
fn logout_response_rejects_malformed_issue_instant() {
    let result = parse_attested_soap_logout_response("IssueInstant=\"not-a-date\"");

    assert!(matches!(
        result,
        Err(SamlError::ProtocolProfile(message))
            if message.contains("LogoutResponse IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z")
    ));
}

#[test]
fn logout_response_rejects_non_utc_issue_instant() {
    let result = parse_attested_soap_logout_response("IssueInstant=\"2024-01-01T00:00:00+00:00\"");

    assert!(matches!(
        result,
        Err(SamlError::ProtocolProfile(message))
            if message.contains("LogoutResponse IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z")
    ));
}

#[test]
fn logout_response_rejects_qualified_issue_instant() {
    let result =
        parse_attested_soap_logout_response(r#"samlp:IssueInstant="2000-01-01T00:00:00Z""#);
    assert!(matches!(
        result,
        Err(SamlError::ProtocolProfile(message))
            if message.contains("attribute IssueInstant on LogoutResponse must be unqualified")
    ));
}

#[test]
fn logout_response_accepts_well_formed_utc_issue_instant_without_age_policy(
) -> Result<(), Box<dyn std::error::Error>> {
    let parsed = parse_attested_soap_logout_response("IssueInstant=\"2000-01-01T00:00:00Z\"")?;

    assert_eq!(
        parsed.extract.get_str("response.issueInstant"),
        Some("2000-01-01T00:00:00Z")
    );
    Ok(())
}

#[test]
fn logout_response_rejects_empty_request_id() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = (sp()?, idp()?);
    let ctx = create_logout_response(
        &idp.setting,
        idp.metadata.as_metadata(),
        sp.metadata.as_metadata(),
        Binding::Post,
        Some("_req1"),
        None,
        false,
    )?;
    let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);

    assert!(matches!(
        parse_logout_response(
            &sp.setting,
            idp.metadata.as_metadata(),
            Binding::Post,
            &request,
            ""
        ),
        Err(SamlError::InvalidInResponseTo)
    ));
    Ok(())
}

#[test]
fn default_logout_response_parsing_requires_signature() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = (sp()?, idp()?);
    let ctx = create_logout_response(
        &idp.setting,
        idp.metadata.as_metadata(),
        sp.metadata.as_metadata(),
        Binding::Post,
        Some("_req1"),
        None,
        false,
    )?;
    let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);

    let result = parse_logout_response(
        &sp.setting,
        idp.metadata.as_metadata(),
        Binding::Post,
        &request,
        "_req1",
    );

    #[cfg(crypto)]
    assert!(matches!(result, Err(SamlError::SignatureMissing)));

    #[cfg(not(crypto))]
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
    let target = sp::Engine::from_metadata(sp_xml, EntitySetting::default())?;
    let sender = idp()?;
    let response = create_logout_response(
        &sender.setting,
        sender.metadata.as_metadata(),
        target.metadata.as_metadata(),
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
        sender.metadata.as_metadata(),
        target.metadata.as_metadata(),
        Binding::Post,
        &LogoutUser::new("alice"),
        None,
        false,
    )?;
    assert_eq!(
        request.entity_endpoint,
        "https://sp.example.com/slo/request"
    );
    Ok(())
}
