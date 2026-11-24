use super::*;
use saml_rs::StatusMessage;

const DIAGNOSTIC: &str = "MFA provider unavailable";
const MESSAGE_XML: &str = "<samlp:StatusMessage>MFA provider unavailable</samlp:StatusMessage>";

fn with_diagnostic(xml: &str, diagnostic: &str) -> String {
    xml.replacen(
        "</samlp:Status>",
        &format!("{diagnostic}</samlp:Status>"),
        1,
    )
}

fn assert_diagnostic(
    result: Result<saml_rs::SsoSession, SamlError>,
    expected: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let Err(error @ SamlError::StatusNotSuccess { .. }) = result else {
        return Err(format!("expected StatusNotSuccess, got {result:?}").into());
    };
    assert!(!error.to_string().contains(DIAGNOSTIC));
    assert!(!format!("{error:?}").contains(DIAGNOSTIC));
    let SamlError::StatusNotSuccess {
        status,
        status_message,
    } = error
    else {
        return Err("expected StatusNotSuccess".into());
    };
    assert_eq!(status, auth_failed_status()?);
    assert_eq!(status_message.as_ref().map(StatusMessage::as_str), expected);
    Ok(())
}

#[test]
fn post_error_exposes_diagnostic_only_with_response_signature_and_matching_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = start_receive_respond_with(
        StartSso::post().relay_state(RelayState::try_new("pending-login")?),
        SsoOutcome::Failure(auth_failed_status()?),
        RespondSso::post(),
    )?;
    let base = strip_embedded_signatures(&response_xml_from_fields(&exchange.response_fields)?)?;
    let unsigned = with_diagnostic(&base, MESSAGE_XML);
    let signed = resign_response(&unsigned)?;
    let without_id = resign_response(&unsigned.replacen(
        &format!(
            " InResponseTo=\"{}\"",
            exchange.pending.request_id().as_str()
        ),
        "",
        1,
    ))?;
    let no_message = resign_response(&base)?;
    let request_id = exchange.pending.request_id().as_str();
    let padded_id = resign_response(&unsigned.replacen(
        &format!(" InResponseTo=\"{request_id}\""),
        &format!(" InResponseTo=\"&#10; {request_id}&#9;\""),
        1,
    ))?;
    assert_ne!(padded_id, signed);

    for (xml, relay_state, expected) in [
        (&signed, Some("pending-login"), Some(DIAGNOSTIC)),
        (&padded_id, Some("pending-login"), Some(DIAGNOSTIC)),
        (&no_message, Some("pending-login"), None),
        (&unsigned, Some("pending-login"), None),
        (&signed, Some("another-login"), None),
        (&signed, None, None),
        (&without_id, Some("pending-login"), None),
    ] {
        let mut fields = vec![FormField::new(
            "SAMLResponse",
            STANDARD.encode(xml.as_bytes()),
        )];
        if let Some(state) = relay_state {
            fields.push(FormField::new("RelayState", state));
        }
        assert_diagnostic(
            exchange.sp.finish_sso(
                &exchange.idp_descriptor,
                &exchange.pending,
                Inbound::post(fields),
                validation(),
            ),
            expected,
        )?;
    }
    for (xml, expected) in [(&signed, None), (&without_id, Some(DIAGNOSTIC))] {
        let input = Inbound::post(vec![FormField::new(
            "SAMLResponse",
            STANDARD.encode(xml.as_bytes()),
        )]);
        assert_diagnostic(
            exchange
                .sp
                .accept_unsolicited_sso(&exchange.idp_descriptor, input, validation()),
            expected,
        )?;
    }
    Ok(())
}

#[test]
fn simplesign_error_exposes_diagnostic_with_detached_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = start_receive_respond_with(
        StartSso::post().response_binding(SsoResponseBinding::SimpleSign),
        SsoOutcome::Failure(auth_failed_status()?),
        RespondSso::simple_sign(),
    )?;
    let xml = with_diagnostic(
        &strip_embedded_signatures(&response_xml_from_fields(&exchange.response_fields)?)?,
        MESSAGE_XML,
    );
    let key = read_private_key(PRIVKEY, None)?;
    let signature = sign_octet_string(
        &format!("SAMLResponse={xml}&SigAlg={RSA_SHA256}"),
        &key,
        RSA_SHA256,
    )?;
    let fields = vec![
        FormField::new("SAMLResponse", STANDARD.encode(xml.as_bytes())),
        FormField::new("SigAlg", RSA_SHA256),
        FormField::new("Signature", signature),
    ];
    assert_diagnostic(
        exchange.sp.finish_sso(
            &exchange.idp_descriptor,
            &exchange.pending,
            Inbound::simple_sign(fields),
            validation(),
        ),
        Some(DIAGNOSTIC),
    )
}

#[test]
fn signed_error_ignores_ambiguous_or_non_text_diagnostics() -> Result<(), Box<dyn std::error::Error>>
{
    let exchange = error_response_exchange()?;
    let base = response_xml_from_fields(&exchange.response_fields)?;
    for diagnostic in [
        r#"<other:StatusMessage xmlns:other="urn:example:other">Foreign</other:StatusMessage>"#,
        "<samlp:StatusDetail><samlp:StatusMessage>Nested</samlp:StatusMessage></samlp:StatusDetail>",
        "<samlp:StatusMessage>Text<Other/>continued</samlp:StatusMessage>",
        r#"<samlp:StatusMessage xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true">Marked nil</samlp:StatusMessage>"#,
        "<samlp:StatusMessage/><samlp:StatusMessage>Duplicate</samlp:StatusMessage>",
        "<samlp:StatusMessage/>",
    ] {
        let xml = resign_response(&with_diagnostic(&base, diagnostic))?;
        assert_diagnostic(finish_sso_with_response_xml(&exchange, &xml), None)?;
    }
    Ok(())
}

#[test]
fn assertion_signature_does_not_authenticate_error_diagnostic(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = start_receive_respond_with(
        StartSso::post(),
        SsoAssertion::new(principal()),
        RespondSso::post(),
    )?;
    let base = response_xml_from_fields(&exchange.response_fields)?;
    let status = format!(
        "<samlp:StatusCode Value=\"{}\"><samlp:StatusCode Value=\"{}\"/></samlp:StatusCode>",
        status_code::RESPONDER,
        status_code::AUTHN_FAILED,
    );
    let xml = with_diagnostic(
        &base.replacen(
            &format!("<samlp:StatusCode Value=\"{}\"/>", status_code::SUCCESS),
            &status,
            1,
        ),
        MESSAGE_XML,
    );
    assert_diagnostic(finish_sso_with_response_xml(&exchange, &xml), None)
}
