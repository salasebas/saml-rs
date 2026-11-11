use super::*;
use crate::constants::name_id_format;

const DESTINATION: &str = "https://sp.example.com/slo";
const ISSUER: &str = "https://idp.example.com/metadata";
const RESPONSE_ID: &str = "_response";

fn response_xml_with_attributes(
    id: &str,
    destination: Option<&str>,
    additional_attributes: &str,
    children: &str,
) -> String {
    let destination = destination
        .map(|value| format!(r#" Destination="{value}""#))
        .unwrap_or_default();
    format!(
        r#"<samlp:LogoutResponse xmlns:samlp="{protocol}" xmlns:saml="{assertion}" xmlns:ds="{dsig}" xmlns:x="urn:example:extension" ID="{id}" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"{destination}{additional_attributes}>{children}</samlp:LogoutResponse>"#,
        protocol = namespace::PROTOCOL,
        assertion = namespace::ASSERTION,
        dsig = namespace::DSIG,
    )
}

fn response_xml(id: &str, destination: Option<&str>, children: &str) -> String {
    response_xml_with_attributes(id, destination, "", children)
}

fn issuer(attributes: &str, value: &str) -> String {
    format!(r#"<saml:Issuer{attributes}>{value}</saml:Issuer>"#)
}

fn status(contents: &str) -> String {
    format!("<samlp:Status>{contents}</samlp:Status>")
}

fn success_status() -> String {
    status(&format!(
        r#"<samlp:StatusCode Value="{}"/>"#,
        status_code::SUCCESS
    ))
}

fn canonical_children() -> String {
    format!(
        r#"{issuer}<samlp:Extensions><x:Extension/></samlp:Extensions><samlp:Status><samlp:StatusCode Value="{success}"><samlp:StatusCode Value="urn:example:subordinate"/></samlp:StatusCode><samlp:StatusMessage>completed</samlp:StatusMessage><samlp:StatusDetail><x:Detail/></samlp:StatusDetail></samlp:Status>"#,
        issuer = issuer(&format!(r#" Format="{}""#, name_id_format::ENTITY), ISSUER),
        success = status_code::SUCCESS,
    )
}

fn validate(xml: &str, expected_id: &str, signed: bool) -> Result<Document, SamlError> {
    validate_with_in_response_to(xml, expected_id, None, signed)
}

fn validate_with_in_response_to(
    xml: &str,
    expected_id: &str,
    expected_in_response_to: Option<&str>,
    signed: bool,
) -> Result<Document, SamlError> {
    validate_with_issuer(xml, expected_id, ISSUER, expected_in_response_to, signed)
}

fn validate_with_issuer(
    xml: &str,
    expected_id: &str,
    expected_issuer: &str,
    expected_in_response_to: Option<&str>,
    signed: bool,
) -> Result<Document, SamlError> {
    validate_logout_response_outbound(
        xml,
        expected_id,
        Some(DESTINATION),
        expected_issuer,
        expected_in_response_to,
        OutboundLogoutValidation::BeforeSigning {
            destination_required: signed,
        },
    )
}

fn expect_profile_error(xml: &str) -> Result<(), Box<dyn std::error::Error>> {
    match validate(xml, RESPONSE_ID, false) {
        Err(SamlError::ProtocolProfile(_)) => Ok(()),
        other => Err(format!("expected ProtocolProfile error, got {other:?}").into()),
    }
}

#[test]
fn outbound_logout_response_accepts_canonical_schema_and_slo_profile(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = response_xml_with_attributes(
        RESPONSE_ID,
        Some(DESTINATION),
        r#" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" xmlns:opaque="urn:example:opaque""#,
        &canonical_children().replace(
            "<x:Extension/>",
            r#"<x:Extension opaque:attribute="value">opaque text<samlp:Nested/></x:Extension>"#,
        ),
    );
    let document = validate(&xml, RESPONSE_ID, true)?;

    assert_eq!(document.root.attr("ID"), Some(RESPONSE_ID));
    Ok(())
}

#[test]
fn outbound_logout_response_rejects_invalid_root_child_cardinality_and_order(
) -> Result<(), Box<dyn std::error::Error>> {
    let issuer = issuer("", ISSUER);
    let status = success_status();
    let cases = [
        issuer.clone(),
        format!("{issuer}{status}{status}"),
        format!("{status}{issuer}"),
        format!("{issuer}{status}<samlp:Extensions/>"),
    ];

    for children in cases {
        expect_profile_error(&response_xml(RESPONSE_ID, Some(DESTINATION), &children))?;
    }
    Ok(())
}

#[test]
fn outbound_logout_response_rejects_status_without_status_code(
) -> Result<(), Box<dyn std::error::Error>> {
    let children = format!("{}{}", issuer("", ISSUER), status(""));

    expect_profile_error(&response_xml(RESPONSE_ID, Some(DESTINATION), &children))
}

#[test]
fn outbound_logout_response_rejects_missing_or_qualified_status_code_value(
) -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        "<samlp:StatusCode/>",
        r#"<samlp:StatusCode x:Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>"#,
    ];

    for status_code in cases {
        let children = format!("{}{}", issuer("", ISSUER), status(status_code));
        expect_profile_error(&response_xml(RESPONSE_ID, Some(DESTINATION), &children))?;
    }
    Ok(())
}

#[test]
fn outbound_logout_response_rejects_invalid_status_child_cardinality_and_order(
) -> Result<(), Box<dyn std::error::Error>> {
    let code = format!(r#"<samlp:StatusCode Value="{}"/>"#, status_code::SUCCESS);
    let cases = [
            format!("{code}<samlp:StatusDetail/><samlp:StatusMessage>late</samlp:StatusMessage>"),
            format!(
                "{code}<samlp:StatusMessage>one</samlp:StatusMessage><samlp:StatusMessage>two</samlp:StatusMessage>"
            ),
            format!("{code}<samlp:StatusDetail/><samlp:StatusDetail/>"),
            format!("{code}<x:Unexpected/>"),
        ];

    for contents in cases {
        let children = format!("{}{}", issuer("", ISSUER), status(&contents));
        expect_profile_error(&response_xml(RESPONSE_ID, Some(DESTINATION), &children))?;
    }
    Ok(())
}

#[test]
fn outbound_logout_response_rejects_nonstandard_top_level_status_code(
) -> Result<(), Box<dyn std::error::Error>> {
    let children = format!(
        "{}{}",
        issuer("", ISSUER),
        status(r#"<samlp:StatusCode Value="urn:example:custom"/>"#)
    );

    expect_profile_error(&response_xml(RESPONSE_ID, Some(DESTINATION), &children))
}

#[test]
fn outbound_logout_response_rejects_duplicate_or_relative_subordinate_status_code(
) -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        format!(
            r#"<samlp:StatusCode Value="{success}"><samlp:StatusCode Value="urn:example:first"/><samlp:StatusCode Value="urn:example:second"/></samlp:StatusCode>"#,
            success = status_code::SUCCESS
        ),
        format!(
            r#"<samlp:StatusCode Value="{success}"><samlp:StatusCode Value="relative"/></samlp:StatusCode>"#,
            success = status_code::SUCCESS
        ),
        format!(
            r#"<samlp:StatusCode Value="{success}"><samlp:StatusCode/></samlp:StatusCode>"#,
            success = status_code::SUCCESS
        ),
    ];

    for status_code in cases {
        let children = format!("{}{}", issuer("", ISSUER), status(&status_code));
        expect_profile_error(&response_xml(RESPONSE_ID, Some(DESTINATION), &children))?;
    }
    Ok(())
}

#[test]
fn outbound_logout_response_rejects_missing_wrong_or_invalid_format_issuer(
) -> Result<(), Box<dyn std::error::Error>> {
    let status = success_status();
    expect_profile_error(&response_xml(RESPONSE_ID, Some(DESTINATION), &status))?;

    let invalid_format = format!(
        "{}{}",
        issuer(r#" Format="urn:example:format""#, ISSUER),
        status
    );
    expect_profile_error(&response_xml(
        RESPONSE_ID,
        Some(DESTINATION),
        &invalid_format,
    ))?;

    for qualifier in ["NameQualifier", "SPNameQualifier", "SPProvidedID"] {
        let qualified = format!(
            "{}{}",
            issuer(&format!(r#" {qualifier}="urn:example:qualifier""#), ISSUER),
            success_status()
        );
        expect_profile_error(&response_xml(RESPONSE_ID, Some(DESTINATION), &qualified))?;
    }

    let wrong = format!(
        "{}{}",
        issuer("", "https://attacker.example.com/metadata"),
        success_status()
    );
    match validate(
        &response_xml(RESPONSE_ID, Some(DESTINATION), &wrong),
        RESPONSE_ID,
        false,
    ) {
        Err(SamlError::IssuerMismatch { .. }) => Ok(()),
        other => Err(format!("expected IssuerMismatch, got {other:?}").into()),
    }
}

#[test]
fn outbound_logout_response_rejects_relative_entity_issuer(
) -> Result<(), Box<dyn std::error::Error>> {
    let relative_issuer = "relative/entity";
    let children = format!("{}{}", issuer("", relative_issuer), success_status());
    let xml = response_xml(RESPONSE_ID, Some(DESTINATION), &children);

    match validate_with_issuer(&xml, RESPONSE_ID, relative_issuer, None, false) {
        Err(SamlError::ProtocolProfile(message)) if message.contains("must be an absolute URI") => {
            Ok(())
        }
        other => Err(format!("expected invalid entity Issuer error, got {other:?}").into()),
    }
}

#[test]
fn outbound_logout_response_rejects_entity_issuer_longer_than_1024_characters(
) -> Result<(), Box<dyn std::error::Error>> {
    let long_issuer = format!("urn:{}", "a".repeat(1021));
    let children = format!("{}{}", issuer("", &long_issuer), success_status());
    let xml = response_xml(RESPONSE_ID, Some(DESTINATION), &children);

    match validate_with_issuer(&xml, RESPONSE_ID, &long_issuer, None, false) {
        Err(SamlError::ProtocolProfile(message))
            if message.contains("no longer than 1024 characters") =>
        {
            Ok(())
        }
        other => Err(format!("expected oversized entity Issuer error, got {other:?}").into()),
    }
}

#[test]
fn outbound_logout_response_accepts_entity_issuer_at_1024_character_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    let boundary_issuer = format!("urn:{}", "a".repeat(1020));
    let children = format!("{}{}", issuer("", &boundary_issuer), success_status());
    let xml = response_xml(RESPONSE_ID, Some(DESTINATION), &children);

    validate_with_issuer(&xml, RESPONSE_ID, &boundary_issuer, None, false)?;
    Ok(())
}

#[test]
fn outbound_logout_response_enforces_xs_id_lexical_form_and_local_id_invariant(
) -> Result<(), Box<dyn std::error::Error>> {
    let children = format!("{}{}", issuer("", ISSUER), success_status());
    for invalid_id in ["", "9response", "bad:id"] {
        expect_profile_error(&response_xml(invalid_id, Some(DESTINATION), &children))?;
    }

    match validate(
        &response_xml("_other", Some(DESTINATION), &children),
        RESPONSE_ID,
        false,
    ) {
        Err(SamlError::Invalid(message)) if message.contains("ID mismatch") => Ok(()),
        other => Err(format!("expected local ID invariant error, got {other:?}").into()),
    }
}

#[test]
fn outbound_logout_response_accepts_unicode_ncname_id() -> Result<(), Box<dyn std::error::Error>> {
    let children = format!("{}{}", issuer("", ISSUER), success_status());
    let xml = response_xml("Δresponse", Some(DESTINATION), &children);

    validate(&xml, "Δresponse", false)?;
    Ok(())
}

#[test]
fn outbound_logout_response_enforces_destination_when_present_or_signed(
) -> Result<(), Box<dyn std::error::Error>> {
    let children = format!("{}{}", issuer("", ISSUER), success_status());
    let wrong = response_xml(
        RESPONSE_ID,
        Some("https://attacker.example.com/slo"),
        &children,
    );
    match validate(&wrong, RESPONSE_ID, false) {
        Err(SamlError::DestinationMismatch { .. }) => {}
        other => return Err(format!("expected DestinationMismatch, got {other:?}").into()),
    }

    let omitted = response_xml(RESPONSE_ID, None, &children);
    match validate(&omitted, RESPONSE_ID, true) {
        Err(SamlError::DestinationMismatch { .. }) => {}
        other => return Err(format!("expected signed Destination error, got {other:?}").into()),
    }

    validate(&omitted, RESPONSE_ID, false)?;
    Ok(())
}

#[test]
fn outbound_logout_response_enforces_in_response_to_correlation_and_ncname(
) -> Result<(), Box<dyn std::error::Error>> {
    let children = format!("{}{}", issuer("", ISSUER), success_status());
    let matching = response_xml_with_attributes(
        RESPONSE_ID,
        Some(DESTINATION),
        r#" InResponseTo="_request""#,
        &children,
    );
    validate_with_in_response_to(&matching, RESPONSE_ID, Some("_request"), false)?;

    let cases = [
        (
            response_xml(RESPONSE_ID, Some(DESTINATION), &children),
            Some("_request"),
        ),
        (
            response_xml_with_attributes(
                RESPONSE_ID,
                Some(DESTINATION),
                r#" InResponseTo="_other""#,
                &children,
            ),
            Some("_request"),
        ),
        (
            response_xml_with_attributes(
                RESPONSE_ID,
                Some(DESTINATION),
                r#" InResponseTo="_request""#,
                &children,
            ),
            None,
        ),
    ];
    for (xml, expected) in cases {
        match validate_with_in_response_to(&xml, RESPONSE_ID, expected, false) {
            Err(SamlError::InResponseToMismatch { .. }) => {}
            other => {
                return Err(format!("expected InResponseToMismatch, got {other:?}").into());
            }
        }
    }

    for invalid in ["", "9request", "bad:request", "bad request"] {
        let xml = response_xml_with_attributes(
            RESPONSE_ID,
            Some(DESTINATION),
            &format!(r#" InResponseTo="{invalid}""#),
            &children,
        );
        match validate_with_in_response_to(&xml, RESPONSE_ID, Some(invalid), false) {
            Err(SamlError::ProtocolProfile(_)) => {}
            other => {
                return Err(format!("expected invalid NCName rejection, got {other:?}").into());
            }
        }
    }
    Ok(())
}

#[test]
fn outbound_logout_response_rejects_unexpected_known_element_attributes(
) -> Result<(), Box<dyn std::error::Error>> {
    let status_code = format!(r#"<samlp:StatusCode Value="{}"/>"#, status_code::SUCCESS);
    let cases = [
        response_xml_with_attributes(
            RESPONSE_ID,
            Some(DESTINATION),
            r#" Unexpected="value""#,
            &format!("{}{}", issuer("", ISSUER), status(&status_code)),
        ),
        response_xml_with_attributes(
            RESPONSE_ID,
            Some(DESTINATION),
            r#" x:Unexpected="value""#,
            &format!("{}{}", issuer("", ISSUER), status(&status_code)),
        ),
        response_xml_with_attributes(
            RESPONSE_ID,
            Some(DESTINATION),
            r#" x:ID="_qualified""#,
            &format!("{}{}", issuer("", ISSUER), status(&status_code)),
        ),
        response_xml(
            RESPONSE_ID,
            Some(DESTINATION),
            &format!(
                "{}{}",
                issuer(r#" Unexpected="value""#, ISSUER),
                status(&status_code)
            ),
        ),
        response_xml(
            RESPONSE_ID,
            Some(DESTINATION),
            &format!(
                "{}{}",
                issuer("", ISSUER),
                r#"<samlp:Status Unexpected="value"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>"#
            ),
        ),
        response_xml(
            RESPONSE_ID,
            Some(DESTINATION),
            &format!(
                "{}{}",
                issuer("", ISSUER),
                status(
                    r#"<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" Unexpected="value"/>"#
                )
            ),
        ),
        response_xml(
            RESPONSE_ID,
            Some(DESTINATION),
            &format!(
                "{}{}",
                issuer("", ISSUER),
                status(&format!(
                    r#"{status_code}<samlp:StatusMessage Unexpected="value">message</samlp:StatusMessage>"#
                ))
            ),
        ),
        response_xml(
            RESPONSE_ID,
            Some(DESTINATION),
            &format!(
                "{}{}",
                issuer("", ISSUER),
                status(&format!(
                    r#"{status_code}<samlp:StatusDetail Unexpected="value"/>"#
                ))
            ),
        ),
        response_xml(
            RESPONSE_ID,
            Some(DESTINATION),
            &format!(
                r#"{}<samlp:Extensions Unexpected="value"><x:Extension/></samlp:Extensions>{}"#,
                issuer("", ISSUER),
                success_status()
            ),
        ),
    ];

    for xml in cases {
        expect_profile_error(&xml)?;
    }
    Ok(())
}

#[test]
fn outbound_logout_response_rejects_invalid_destination_or_consent_uri(
) -> Result<(), Box<dyn std::error::Error>> {
    let children = format!("{}{}", issuer("", ISSUER), success_status());
    expect_profile_error(&response_xml(RESPONSE_ID, Some("relative/path"), &children))?;
    for consent in ["relative consent", "urn:example:%zz"] {
        expect_profile_error(&response_xml_with_attributes(
            RESPONSE_ID,
            Some(DESTINATION),
            &format!(r#" Consent="{consent}""#),
            &children,
        ))?;
    }
    Ok(())
}

#[test]
fn outbound_logout_response_enforces_extensions_boundary() -> Result<(), Box<dyn std::error::Error>>
{
    let issuer = issuer("", ISSUER);
    let status = success_status();
    let cases = [
        format!("{issuer}<samlp:Extensions/>{status}"),
        format!("{issuer}<samlp:Extensions>text</samlp:Extensions>{status}"),
        format!("{issuer}<samlp:Extensions><Extension/></samlp:Extensions>{status}"),
        format!("{issuer}<samlp:Extensions><samlp:Extension/></samlp:Extensions>{status}"),
        format!("{issuer}<samlp:Extensions><saml:Extension/></samlp:Extensions>{status}"),
    ];
    for children in cases {
        expect_profile_error(&response_xml(RESPONSE_ID, Some(DESTINATION), &children))?;
    }
    Ok(())
}

#[test]
fn outbound_logout_response_keeps_status_detail_open_but_element_only(
) -> Result<(), Box<dyn std::error::Error>> {
    let issuer = issuer("", ISSUER);
    let code = format!(r#"<samlp:StatusCode Value="{}"/>"#, status_code::SUCCESS);
    for detail in [
        "<samlp:StatusDetail/>",
        r#"<samlp:StatusDetail><Arbitrary attr="value">opaque</Arbitrary></samlp:StatusDetail>"#,
    ] {
        let xml = response_xml(
            RESPONSE_ID,
            Some(DESTINATION),
            &format!("{issuer}{}", status(&format!("{code}{detail}"))),
        );
        validate(&xml, RESPONSE_ID, false)?;
    }

    let invalid = response_xml(
        RESPONSE_ID,
        Some(DESTINATION),
        &format!(
            "{issuer}{}",
            status(&format!(
                "{code}<samlp:StatusDetail>text</samlp:StatusDetail>"
            ))
        ),
    );
    expect_profile_error(&invalid)
}

#[test]
fn outbound_logout_response_rejects_root_signature_before_library_signing(
) -> Result<(), Box<dyn std::error::Error>> {
    let children = format!(
        "{}<ds:Signature><ds:SignedInfo/></ds:Signature>{}",
        issuer("", ISSUER),
        success_status()
    );

    expect_profile_error(&response_xml(RESPONSE_ID, Some(DESTINATION), &children))
}
