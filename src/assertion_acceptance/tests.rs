use super::*;
use crate::constants::{Binding, ParserType};
use std::time::{Duration, SystemTime};

#[test]
fn confirmation_checks_read_the_unqualified_attributes() -> Result<(), Box<dyn std::error::Error>> {
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
        ..FlowOptions::new(Binding::Post, ParserType::SamlResponse)
    };
    accept_response_assertions(xml, &opts, Some("https://sp/acs"))?;

    let reversed = xml.replace(
        "Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\" extra:Method=\"other\"",
        "extra:Method=\"other\" Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"",
    );
    accept_response_assertions(&reversed, &opts, Some("https://sp/acs"))?;
    Ok(())
}

#[test]
fn an_unsolicited_confirmation_with_a_request_id_in_a_second_data_child_is_unsatisfied(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = r#"<Response><Assertion><Subject>
        <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <SubjectConfirmationData NotOnOrAfter="2100-01-01T00:00:00Z" Recipient="https://sp/acs"/>
            <SubjectConfirmationData InResponseTo="_req1"/>
        </SubjectConfirmation>
    </Subject></Assertion></Response>"#;
    let opts = FlowOptions {
        now: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
        ..FlowOptions::new(Binding::Post, ParserType::SamlResponse)
    };
    assert!(matches!(
        accept_response_assertions(xml, &opts, Some("https://sp/acs")),
        Err(SamlError::SubjectConfirmationInvalid { .. })
    ));
    let single = xml.replace("<SubjectConfirmationData InResponseTo=\"_req1\"/>", "");
    accept_response_assertions(&single, &opts, Some("https://sp/acs"))?;
    Ok(())
}
