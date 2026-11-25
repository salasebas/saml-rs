use super::*;
use saml_rs::constants::{namespace, status_code};
use saml_rs::StatusMessage;

#[test]
fn signed_logout_error_carries_status_message_in_every_binding(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let message = "  Could not end the session <café & tea>.\r\nContact the operator.  ";
    let status = Status::responder()
        .with_subordinate(SubordinateStatusCode::try_new(status_code::REQUEST_DENIED)?);

    for binding in LOGOUT_BINDINGS_WITH_SOAP {
        for requester in LOCAL_SLO_ROLES {
            let start = start_slo_for_binding(binding);
            let respond = respond_slo_for_binding(binding).status_message(message);
            let (response, result) = match requester {
                LocalSloRole::Sp => {
                    let started = sp.start_slo(&idp_descriptor, subject()?, start)?;
                    let request = logout_request_input(&started.outbound, binding)?;
                    let received = idp.receive_slo(&sp_descriptor, request, validation())?;
                    let response = idp.respond_slo(&sp_descriptor, &received, &status, respond)?;
                    let input = logout_response_input(&response, binding)?;
                    let result =
                        sp.finish_slo(&idp_descriptor, &started.pending, input, validation());
                    (response, result)
                }
                LocalSloRole::Idp => {
                    let started = idp.start_slo(&sp_descriptor, subject()?, start)?;
                    let request = logout_request_input(&started.outbound, binding)?;
                    let received = sp.receive_slo(&idp_descriptor, request, validation())?;
                    let response = sp.respond_slo(&idp_descriptor, &received, &status, respond)?;
                    let input = logout_response_input(&response, binding)?;
                    let result =
                        idp.finish_slo(&sp_descriptor, &started.pending, input, validation());
                    (response, result)
                }
            };

            let xml = outbound_xml(&response, "SAMLResponse")?;
            let document = roxmltree::Document::parse(&xml)?;
            let response_status = document
                .root_element()
                .children()
                .find(|node| node.has_tag_name((namespace::PROTOCOL, "Status")))
                .ok_or("missing Status")?;
            let children: Vec<_> = response_status
                .children()
                .filter(roxmltree::Node::is_element)
                .collect();
            let [code, status_message] = children.as_slice() else {
                return Err(format!(
                    "expected StatusCode and StatusMessage for {requester:?} over {binding:?}"
                )
                .into());
            };
            assert!(code.has_tag_name((namespace::PROTOCOL, "StatusCode")));
            assert!(status_message.has_tag_name((namespace::PROTOCOL, "StatusMessage")));
            assert_eq!(status_message.text(), Some(message));
            let Err(error) = result else {
                return Err(format!(
                    "expected StatusNotSuccess for {requester:?} over {binding:?}"
                )
                .into());
            };
            assert!(!error.to_string().contains("Could not end the session"));
            assert!(!format!("{error:?}").contains("Could not end the session"));
            let SamlError::StatusNotSuccess {
                status: reported,
                status_message,
            } = error
            else {
                return Err(format!("expected StatusNotSuccess, got {error:?}").into());
            };
            assert_eq!(reported, status);
            assert_eq!(
                status_message.as_ref().map(StatusMessage::as_str),
                Some(message)
            );
        }
    }
    Ok(())
}

#[test]
fn successful_logout_exposes_diagnostic_without_printing_it(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = sp_started_exchange()?;
    let message = "Local session closed";
    let response = exchange.idp.respond_slo(
        &exchange.sp_descriptor,
        &exchange.received,
        &Status::success(),
        RespondSlo::post().status_message(message),
    )?;
    let completed = exchange.sp.finish_slo(
        &exchange.idp_descriptor,
        &exchange.pending,
        Inbound::post(post_fields(&response)?),
        validation(),
    )?;
    assert_eq!(completed.response().status(), &Status::success());
    assert_eq!(completed.response().status_message(), Some(message));
    assert!(!format!("{completed:?}").contains(message));
    Ok(())
}

#[test]
fn a_logout_status_message_needs_a_character_other_than_xml_whitespace(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = sp_started_exchange()?;
    let respond = |message: &str| {
        exchange.idp.respond_slo(
            &exchange.sp_descriptor,
            &exchange.received,
            &Status::responder(),
            RespondSlo::post().status_message(message),
        )
    };
    for message in [" ", "\r\n\t"] {
        let response = respond(message);
        assert!(
            matches!(response, Err(SamlError::Invalid(_))),
            "{message:?}: {response:?}"
        );
    }
    let no_break_space = "\u{a0}";
    let xml = outbound_xml(&respond(no_break_space)?, "SAMLResponse")?;
    assert!(
        xml.contains(&format!(
            "<samlp:StatusMessage>{no_break_space}</samlp:StatusMessage>"
        )),
        "{xml}"
    );
    let xml = outbound_xml(&respond("")?, "SAMLResponse")?;
    assert!(!xml.contains("StatusMessage"), "{xml}");
    Ok(())
}

#[test]
fn directly_authenticated_soap_logout_covers_diagnostic_without_xml_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::soap())?;
    let xml = logout_response_xml(
        "_soap_diagnostic",
        IDP_ENTITY_ID,
        started.pending.request_id().as_str(),
        None,
    )
    .replace(
        "</samlp:Status>",
        "<samlp:StatusMessage>Local session closed</samlp:StatusMessage></samlp:Status>",
    );
    let envelope = SoapResponse::try_new(&xml)?;
    let completed = sp.finish_slo(
        &idp_descriptor,
        &started.pending,
        Inbound::soap(
            envelope.envelope(),
            SoapChannel::mutually_authenticated_confidential(),
        ),
        validation(),
    )?;
    assert_eq!(
        completed.response().status_message(),
        Some("Local session closed")
    );
    Ok(())
}
