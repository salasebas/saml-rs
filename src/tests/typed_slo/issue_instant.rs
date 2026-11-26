use super::*;

#[test]
fn receive_slo_reads_a_logout_request_issued_in_a_leap_second(
) -> Result<(), Box<dyn std::error::Error>> {
    let leap_second = "2024-01-01T00:00:60Z";
    let xml = logout_request_xml(
        "_leap_second",
        SP_ENTITY_ID,
        Some(LocalSloRole::Idp.endpoint(LogoutBinding::Redirect)),
    )
    .replace(
        r#"IssueInstant="2000-01-01T00:00:00Z""#,
        &format!(r#"IssueInstant="{leap_second}""#),
    );

    let received = receive_crafted_logout_request(
        &xml,
        LogoutBinding::Redirect,
        LocalSloRole::Idp,
        RequestProtection::Signed,
        validation(),
    )?;
    assert_eq!(received.message().issue_instant().as_str(), leap_second);
    Ok(())
}
