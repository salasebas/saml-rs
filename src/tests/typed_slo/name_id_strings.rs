use super::*;

#[test]
fn service_provider_logout_request_needs_a_character_other_than_xml_whitespace(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;

    let non_xml_whitespace = NameId::new("\u{a0}")
        .with_name_qualifier("\u{2003}")
        .with_sp_name_qualifier("\u{a0}")
        .with_sp_provided_id("\u{2003}");
    sp.start_slo(
        &idp_descriptor,
        subject_for(non_xml_whitespace)?,
        StartSlo::post(),
    )?;

    for refused in [
        NameId::new(""),
        NameId::new(" \t\r\n"),
        NameId::new("alice").with_name_qualifier(""),
        NameId::new("alice").with_sp_name_qualifier(" "),
        NameId::new("alice").with_sp_provided_id("\t"),
    ] {
        let started = sp.start_slo(
            &idp_descriptor,
            subject_for(refused.clone())?,
            StartSlo::post(),
        );
        assert!(
            matches!(started, Err(SamlError::Invalid(_))),
            "{refused:?}: {started:?}"
        );
        let started = sp.start_async_slo(
            &idp_descriptor,
            subject_for(refused.clone())?,
            StartSlo::redirect(),
        );
        assert!(
            matches!(started, Err(SamlError::Invalid(_))),
            "asynchronous {refused:?}: {started:?}"
        );
    }
    Ok(())
}
