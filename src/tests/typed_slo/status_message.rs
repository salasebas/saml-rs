use super::*;
use saml_rs::constants::{namespace, status_code};

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
            let start = start_slo_for_binding(binding)?;
            let respond = respond_slo_for_binding(binding)?.with_status_message(message);
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
                .filter(|node| node.is_element())
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
            match result {
                Err(SamlError::StatusNotSuccess { status: reported }) => {
                    assert_eq!(reported, status)
                }
                other => {
                    return Err(format!(
                    "expected StatusNotSuccess for {requester:?} over {binding:?}, got {other:?}"
                )
                    .into())
                }
            }
        }
    }
    Ok(())
}
