use super::*;
use saml_rs::MessageId;

#[test]
fn finish_sso_reads_each_in_response_to_after_whitespace_collapse(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::default(), false)?;
    let request_id = exchange
        .pending
        .as_ref()
        .ok_or("expected a pending request")?
        .request_id()
        .as_str()
        .to_string();
    let xml = response_xml(&exchange.response_fields)?;
    let written = format!("InResponseTo=\"{request_id}\"");
    let padded = format!("InResponseTo=\"&#10; {request_id}&#9;\"");
    assert_eq!(xml.matches(&written).count(), 2);

    let response_padded = xml.replacen(&written, &padded, 1);
    let bearer_padded = replace_in_last_assertion(&xml, &written, &padded)?;
    for altered in [response_padded, bearer_padded] {
        let session = accept(&exchange, &resigned(&altered)?)?;
        assert_eq!(
            session.in_response_to().map(MessageId::as_str),
            Some(request_id.as_str())
        );
    }
    Ok(())
}

#[test]
fn an_unsolicited_session_ignores_a_namespace_prefix_named_in_response_to(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = exchange_for(SpValidationPolicy::default(), true)?;
    let xml = response_xml(&exchange.response_fields)?.replacen(
        "<samlp:Response ",
        "<samlp:Response xmlns:InResponseTo=\"urn:example:correlation\" ",
        1,
    );

    let session = accept(&exchange, &resigned(&xml)?)?;

    assert_eq!(session.in_response_to(), None);
    Ok(())
}
