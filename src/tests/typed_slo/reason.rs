use super::*;

const REASON: &str = "https://example.com/logout?initiator=admin&scope=all";
const USER_REASON: &str = "urn:oasis:names:tc:SAML:2.0:logout:user";

#[test]
fn typed_slo_writes_reason_in_signed_requests_for_both_roles(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(sp_config()?);
    let idp = IdentityProvider::new(idp_config()?);
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    for binding in LOGOUT_BINDINGS_WITH_SOAP {
        let options = start_slo_for_binding(binding);
        let from_sp = sp.start_slo(
            &idp_descriptor,
            subject()?,
            options.clone().reason(USER_REASON),
        )?;
        let from_idp = idp.start_slo(&sp_descriptor, subject()?, options.reason(REASON))?;
        for (outbound, expected) in [
            (&from_sp.outbound, USER_REASON),
            (&from_idp.outbound, REASON),
        ] {
            let xml = outbound_xml(outbound, "SAMLRequest")?;
            let document = parse_document(&xml, saml_rs::XmlLimits::default())?;
            assert_eq!(document.root.attr("Reason"), Some(expected), "{binding:?}");
        }
        let received_by_idp = idp.receive_slo(
            &sp_descriptor,
            logout_request_input(&from_sp.outbound, binding)?,
            validation(),
        )?;
        assert_eq!(
            received_by_idp.message().reason(),
            Some(USER_REASON),
            "{binding:?}"
        );
        let received_by_sp = sp.receive_slo(
            &idp_descriptor,
            logout_request_input(&from_idp.outbound, binding)?,
            validation(),
        )?;
        assert_eq!(
            received_by_sp.message().reason(),
            Some(REASON),
            "{binding:?}"
        );
    }
    Ok(())
}

#[test]
fn typed_slo_returns_none_when_received_request_omits_reason(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    for binding in LOGOUT_BINDINGS_WITH_SOAP {
        let options = start_slo_for_binding(binding);
        let from_sp = sp.start_slo(&idp_descriptor, subject()?, options.clone())?;
        let from_idp = idp.start_slo(&sp_descriptor, subject()?, options)?;

        let received_by_idp = idp.receive_slo(
            &sp_descriptor,
            logout_request_input(&from_sp.outbound, binding)?,
            validation(),
        )?;
        assert_eq!(received_by_idp.message().reason(), None, "{binding:?}");

        let received_by_sp = sp.receive_slo(
            &idp_descriptor,
            logout_request_input(&from_idp.outbound, binding)?,
            validation(),
        )?;
        assert_eq!(received_by_sp.message().reason(), None, "{binding:?}");
    }
    Ok(())
}

fn logout_request_with_root_attrs(
    binding: LogoutBinding,
    receiver_role: LocalSloRole,
    extra_attrs: &str,
) -> String {
    logout_request_xml(
        "_reason_fixture",
        sender_entity_id(receiver_role),
        Some(receiver_role.endpoint(binding)),
    )
    .replace(
        r#"Version="2.0""#,
        &format!(r#"Version="2.0" {extra_attrs}"#),
    )
}

#[test]
fn typed_slo_preserves_received_reason_as_xml_string_for_both_roles(
) -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (r#"Reason="  custom  reason  ""#, Some("  custom  reason  ")),
        (
            r#"Reason="&#x9;urn:example:logout&#xA;""#,
            Some("\turn:example:logout\n"),
        ),
        (r#"Reason="""#, Some("")),
        (
            r#"Reason="urn:oasis:names:tc:SAML:2.0:logout:sp-timeout""#,
            Some("urn:oasis:names:tc:SAML:2.0:logout:sp-timeout"),
        ),
        (
            r#"xmlns:x="urn:example:foreign" x:Reason="urn:example:foreign""#,
            None,
        ),
        (
            r#"xmlns:x="urn:example:foreign" x:Reason="urn:example:foreign" Reason="urn:example:real""#,
            Some("urn:example:real"),
        ),
    ];

    for binding in [LogoutBinding::Redirect, LogoutBinding::Post] {
        for receiver_role in [LocalSloRole::Sp, LocalSloRole::Idp] {
            for (attrs, expected) in cases {
                let xml = logout_request_with_root_attrs(binding, receiver_role, attrs);
                let received = receive_crafted_logout_request(
                    &xml,
                    binding,
                    receiver_role,
                    RequestProtection::Signed,
                    validation(),
                )?;
                assert_eq!(
                    received.message().reason(),
                    expected,
                    "{binding:?} {receiver_role:?} {attrs}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn directly_authenticated_soap_logout_request_exposes_reason(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    for (receiver_role, expected) in [
        (LocalSloRole::Sp, "  idp  initiated  "),
        (LocalSloRole::Idp, "  sp  initiated  "),
    ] {
        let xml = logout_request_xml(
            "_soap_reason",
            sender_entity_id(receiver_role),
            Some(receiver_role.endpoint(LogoutBinding::Soap)),
        )
        .replace(
            r#"Version="2.0""#,
            &format!(r#"Version="2.0" Reason="{expected}""#),
        );
        let envelope = SoapResponse::try_new(&xml)?;
        let input = Inbound::soap(
            envelope.envelope(),
            SoapChannel::mutually_authenticated_confidential(),
        );
        let received = match receiver_role {
            LocalSloRole::Sp => sp.receive_slo(&idp_descriptor, input, validation())?,
            LocalSloRole::Idp => idp.receive_slo(&sp_descriptor, input, validation())?,
        };
        assert_eq!(received.message().reason(), Some(expected));
    }
    Ok(())
}

#[test]
fn typed_slo_rejects_invalid_reason_uris() -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(sp_config()?);
    let idp = IdentityProvider::new(idp_config()?);
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    for reason in ["logout/admin", " \t\n", "urn:example:bad%zz"] {
        let options = StartSlo::redirect().reason(reason);
        for result in [
            sp.start_slo(&idp_descriptor, subject()?, options.clone()),
            idp.start_slo(&sp_descriptor, subject()?, options),
        ] {
            assert!(matches!(result, Err(SamlError::Invalid(_))), "{result:?}");
        }
    }
    Ok(())
}

#[test]
fn typed_slo_omits_reason_by_default_and_collapses_supplied_whitespace(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    for (options, expected) in [
        (StartSlo::post(), None),
        (
            StartSlo::post().reason(format!(" \t{REASON}\n")),
            Some(REASON),
        ),
    ] {
        let started = sp.start_slo(&idp_descriptor, subject()?, options)?;
        let xml = outbound_xml(&started.outbound, "SAMLRequest")?;
        let document = parse_document(&xml, saml_rs::XmlLimits::default())?;
        assert_eq!(document.root.attr("Reason"), expected);
    }
    Ok(())
}

const SESSION_AUTHORITY_REASONS: [&str; 2] = [
    "urn:oasis:names:tc:SAML:2.0:logout:global-timeout",
    "urn:oasis:names:tc:SAML:2.0:logout:sp-timeout",
];

#[test]
fn service_provider_refuses_session_authority_reasons_on_ordinary_and_async_slo(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (_, idp_descriptor) = descriptors(&sp, &idp)?;
    let padded = format!(" {} ", SESSION_AUTHORITY_REASONS[0]);
    for reason in SESSION_AUTHORITY_REASONS
        .into_iter()
        .chain([padded.as_str()])
    {
        let options = StartSlo::redirect().reason(reason);
        let ordinary = sp.start_slo(&idp_descriptor, subject()?, options.clone());
        assert!(
            matches!(ordinary, Err(SamlError::Invalid(_))),
            "{reason:?} {ordinary:?}"
        );
        let asynchronous = sp.start_async_slo(&idp_descriptor, subject()?, options);
        assert!(
            matches!(asynchronous, Err(SamlError::Invalid(_))),
            "{reason:?} {asynchronous:?}"
        );
    }
    Ok(())
}

#[test]
fn identity_provider_sends_session_authority_reasons_that_the_service_provider_reads(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    for reason in SESSION_AUTHORITY_REASONS {
        let started = idp.start_slo(&sp_descriptor, subject()?, StartSlo::post().reason(reason))?;
        let received = sp.receive_slo(
            &idp_descriptor,
            logout_request_input(&started.outbound, LogoutBinding::Post)?,
            validation(),
        )?;
        assert_eq!(received.message().reason(), Some(reason));
    }
    Ok(())
}
