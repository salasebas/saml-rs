use super::*;
use std::time::{Duration, SystemTime};

#[test]
fn confirmation_attributes_with_the_same_local_name_use_the_first_value(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = r#"<Response><Assertion><Subject>
        <SubjectConfirmation xmlns:extra="urn:extra"
            Method="urn:oasis:names:tc:SAML:2.0:cm:bearer" extra:Method="other">
            <SubjectConfirmationData
                NotBefore="2000-01-01T00:00:00Z" extra:NotBefore="2100-01-01T00:00:00Z"
                NotOnOrAfter="2100-01-01T00:00:00Z" extra:NotOnOrAfter="2000-01-01T00:00:00Z"
                Recipient="https://sp/acs" extra:Recipient="wrong"
                InResponseTo="_req1" extra:InResponseTo="wrong"/>
        </SubjectConfirmation>
    </Subject></Assertion></Response>"#;
    let opts = FlowOptions {
        now: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
        expected_in_response_to: Some("_req1"),
        ..FlowOptions::default()
    };
    accept_response_assertions(xml, &opts, Some("https://sp/acs"))?;

    let reversed = xml.replace(
        "Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\" extra:Method=\"other\"",
        "extra:Method=\"other\" Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"",
    );
    assert!(matches!(
        accept_response_assertions(&reversed, &opts, Some("https://sp/acs")),
        Err(SamlError::SubjectConfirmationInvalid {
            reason: SubjectConfirmationReason::InvalidMethod
        })
    ));
    Ok(())
}

#[test]
fn unsolicited_duplicate_data_uses_the_first_child_with_a_request_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = r#"<Response><Assertion><Subject>
        <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <SubjectConfirmationData/>
            <SubjectConfirmationData InResponseTo="_req1"/>
            <SubjectConfirmationData InResponseTo=""/>
        </SubjectConfirmation>
    </Subject></Assertion></Response>"#;
    for rule in [
        UnsolicitedInResponseTo::RejectPresent,
        UnsolicitedInResponseTo::RejectNonEmpty,
    ] {
        assert!(matches!(
            reject_unsolicited_bearer_in_response_to(xml, XmlLimits::default(), rule),
            Err(SamlError::InResponseToMismatch { actual, .. }) if actual.as_deref() == Some("_req1")
        ));
    }
    let empty_first = xml.replace("InResponseTo=\"_req1\"", "InResponseTo=\"\"");
    reject_unsolicited_bearer_in_response_to(
        &empty_first,
        XmlLimits::default(),
        UnsolicitedInResponseTo::RejectNonEmpty,
    )?;
    assert!(matches!(
        reject_unsolicited_bearer_in_response_to(
            &empty_first,
            XmlLimits::default(),
            UnsolicitedInResponseTo::RejectPresent,
        ),
        Err(SamlError::InResponseToMismatch { .. })
    ));
    Ok(())
}
