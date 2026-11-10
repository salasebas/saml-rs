//! Service-provider acceptance of every assertion in a login `Response`.
//!
//! An unrecognized `<Conditions>` child is rejected. `<OneTimeUse>` and
//! `<ProxyRestriction>` stay valid. The assertions must share one issuer and
//! one principal. One successful bearer confirmation confirms that assertion.

use crate::constants::namespace;
use crate::error::{SamlError, SubjectConfirmationReason, TimeWindowField};
use crate::flow::FlowOptions;
use crate::model::{authn_statement_not_on_or_after_values, earliest_authn_session_expiration};
use crate::util::Value;
use crate::validator::{conditions_time_bounds, verify_time_at};
use crate::xml::dom::{self, Node};
use crate::xml::{extract_with_limits, fields, ExtractorField, XmlLimits};
use quick_xml::events::Event;
use quick_xml::reader::NsReader;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

const BEARER_SUBJECT_CONFIRMATION_METHOD: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

#[derive(Clone, Copy, PartialEq, Eq)]
enum ElementNamespace {
    Protocol,
    Assertion,
    Other,
}

#[derive(Debug, PartialEq, Eq)]
struct Principal {
    name_id: String,
    format: String,
    name_qualifier: Option<String>,
    sp_name_qualifier: Option<String>,
}

/// Evaluate every direct `<Assertion>` in a login response.
///
/// # Errors
///
/// Returns [`SamlError`] when an assertion is not understood, its bearer
/// confirmation, audience, or time window fails, or the assertions do not share
/// one issuer and one principal.
pub(crate) fn accept_response_assertions(
    response_xml: &str,
    opts: &FlowOptions<'_>,
    expected_recipient: Option<&str>,
) -> Result<(), SamlError> {
    reject_unrecognized_conditions(response_xml, opts.xml_limits)?;
    let document = dom::parse_with_limits(response_xml, opts.xml_limits)?;
    let assertions = direct_assertions(&document.root);
    if assertions.is_empty() {
        return Err(SamlError::Xml("ERR_EMPTY_ASSERTION".into()));
    }

    let mut saw_bearer = false;
    let mut confirmation_error = None;
    let mut shared_issuer: Option<Option<String>> = None;
    let mut shared_principal: Option<Principal> = None;
    let several = assertions.len() > 1;
    for assertion in assertions {
        let assertion_xml = &response_xml[assertion.start..assertion.end];
        if several {
            remember_same_issuer(opts.from_issuer, assertion, &mut shared_issuer)?;
            remember_same_principal(assertion, &mut shared_principal)?;
        }
        let extracted = extract_with_limits(
            assertion_xml,
            &fields::login_response_fields(assertion_xml),
            opts.xml_limits,
        )?;
        if extracted_has_bearer(&extracted, opts.xml_limits)? {
            saw_bearer = true;
            validate_subject_confirmation(&extracted, opts, expected_recipient)?;
            validate_audience(assertion_xml, opts)?;
            validate_assertion_time(&extracted, opts)?;
        } else if confirmation_error.is_none() && !subject_confirmation_xmls(&extracted).is_empty()
        {
            if let Err(error) = validate_subject_confirmation(&extracted, opts, expected_recipient)
            {
                confirmation_error = Some(error);
            }
        }
    }
    if !saw_bearer {
        return Err(
            confirmation_error.unwrap_or(SamlError::SubjectConfirmationInvalid {
                reason: SubjectConfirmationReason::MissingBearerConfirmation,
            }),
        );
    }
    Ok(())
}

/// Reject an unsolicited response whose bearer confirmation names a request.
///
/// # Errors
///
/// Returns [`SamlError::InResponseToMismatch`] when any bearer confirmation in
/// any direct assertion carries `InResponseTo`.
pub(crate) fn reject_unsolicited_bearer_in_response_to(
    response_xml: &str,
    limits: XmlLimits,
) -> Result<(), SamlError> {
    let document = dom::parse_with_limits(response_xml, limits)?;
    let fields = [
        ExtractorField::new("subjectConfirmation", &["SubjectConfirmation"]).attrs(&["Method"]),
        ExtractorField::new(
            "subjectConfirmationData",
            &["SubjectConfirmation", "SubjectConfirmationData"],
        )
        .attrs(&["InResponseTo"]),
    ];
    for assertion in direct_assertions(&document.root) {
        let assertion_xml = &response_xml[assertion.start..assertion.end];
        let extracted = extract_with_limits(
            assertion_xml,
            &fields::login_response_fields(assertion_xml),
            limits,
        )?;
        for confirmation_xml in subject_confirmation_xmls(&extracted) {
            let confirmation = extract_with_limits(confirmation_xml, &fields, limits)?;
            let is_bearer = confirmation.get_str("subjectConfirmation")
                == Some(BEARER_SUBJECT_CONFIRMATION_METHOD);
            let request_id = confirmation
                .get_str("subjectConfirmationData")
                .filter(|actual| !actual.is_empty());
            if is_bearer && request_id.is_some() {
                return Err(SamlError::in_response_to_mismatch(None, request_id));
            }
        }
    }
    Ok(())
}

/// Source of the first bearer `<Assertion>`, or the first `<Assertion>`.
///
/// # Errors
///
/// Returns [`SamlError`] when `xml` cannot be parsed under `limits`.
pub(crate) fn first_login_assertion_xml(
    xml: &str,
    limits: XmlLimits,
) -> Result<Option<String>, SamlError> {
    let document = dom::parse_with_limits(xml, limits)?;
    let assertions = direct_assertions(&document.root);
    let Some(chosen) = assertions
        .iter()
        .find(|assertion| node_has_bearer(assertion))
        .copied()
        .or_else(|| assertions.first().copied())
    else {
        return Ok(None);
    };
    Ok(Some(xml[chosen.start..chosen.end].to_string()))
}

/// Replay identity of one direct assertion in an already accepted response.
pub(crate) struct AssertionReplayId {
    /// Assertion `ID`.
    pub id: String,
    /// Bearer `SubjectConfirmationData@NotOnOrAfter`, when that confirmation has one.
    pub bearer_not_on_or_after: Option<String>,
}

/// Direct assertion identifiers in an already accepted response.
///
/// # Errors
///
/// Returns [`SamlError`] when `xml` cannot be parsed.
pub(crate) fn assertion_replays(xml: &str) -> Result<Vec<AssertionReplayId>, SamlError> {
    let document = dom::parse_with_limits(xml, XmlLimits::unbounded())?;
    let nodes = if document.root.local_name == "Assertion" {
        vec![&document.root]
    } else {
        direct_assertions(&document.root)
    };
    Ok(nodes
        .into_iter()
        .filter_map(|assertion| {
            Some(AssertionReplayId {
                id: assertion.attr("ID")?.to_string(),
                bearer_not_on_or_after: latest_bearer_not_on_or_after(assertion),
            })
        })
        .collect())
}

/// Assertion `ID` values in document order.
///
/// # Errors
///
/// Returns [`SamlError`] when `xml` cannot be parsed.
pub(crate) fn assertion_ids(xml: &str) -> Result<Vec<String>, SamlError> {
    Ok(assertion_replays(xml)?
        .into_iter()
        .map(|replay| replay.id)
        .collect())
}

fn node_has_bearer(assertion: &Node) -> bool {
    assertion
        .children
        .iter()
        .filter(|child| child.local_name == "Subject")
        .flat_map(|subject| subject.children.iter())
        .filter(|child| child.local_name == "SubjectConfirmation")
        .any(|confirmation| confirmation.attr("Method") == Some(BEARER_SUBJECT_CONFIRMATION_METHOD))
}

fn latest_bearer_not_on_or_after(assertion: &Node) -> Option<String> {
    let mut latest: Option<(OffsetDateTime, String)> = None;
    let mut unparsed = None;
    for confirmation in assertion
        .children
        .iter()
        .filter(|child| child.local_name == "Subject")
        .flat_map(|subject| subject.children.iter())
        .filter(|child| child.local_name == "SubjectConfirmation")
    {
        if confirmation.attr("Method") != Some(BEARER_SUBJECT_CONFIRMATION_METHOD) {
            continue;
        }
        let Some(value) = confirmation
            .children
            .iter()
            .find(|child| child.local_name == "SubjectConfirmationData")
            .and_then(|data| data.attr("NotOnOrAfter"))
        else {
            continue;
        };
        match OffsetDateTime::parse(value, &Rfc3339) {
            Ok(instant) => {
                let replace = latest
                    .as_ref()
                    .is_none_or(|(current, _)| *current < instant);
                if replace {
                    latest = Some((instant, value.to_string()));
                }
            }
            Err(_) => unparsed = Some(value.to_string()),
        }
    }
    latest.map(|(_, value)| value).or(unparsed)
}

fn direct_assertions(root: &Node) -> Vec<&Node> {
    root.children
        .iter()
        .filter(|child| child.local_name == "Assertion")
        .collect()
}

fn issuer_text(assertion: &Node) -> Option<&str> {
    assertion
        .children
        .iter()
        .find(|child| child.local_name == "Issuer")
        .map(|issuer| issuer.text.as_str())
}

fn remember_same_issuer(
    expected_issuer: Option<&str>,
    assertion: &Node,
    shared_issuer: &mut Option<Option<String>>,
) -> Result<(), SamlError> {
    let actual = issuer_text(assertion);
    if let Some(expected) = expected_issuer {
        if actual != Some(expected) {
            return Err(SamlError::issuer_mismatch(expected, actual));
        }
    }
    match shared_issuer {
        None => *shared_issuer = Some(actual.map(str::to_string)),
        Some(previous) if previous.as_deref() != actual => {
            let expected = previous.as_deref().unwrap_or("");
            return Err(SamlError::issuer_mismatch(expected, actual));
        }
        Some(_) => {}
    }
    Ok(())
}

fn remember_same_principal(
    assertion: &Node,
    shared_principal: &mut Option<Principal>,
) -> Result<(), SamlError> {
    let principal = principal_of(assertion)?;
    match shared_principal {
        None => *shared_principal = Some(principal),
        Some(previous) if previous != &principal => return Err(SamlError::PrincipalMismatch),
        Some(_) => {}
    }
    Ok(())
}

fn principal_of(assertion: &Node) -> Result<Principal, SamlError> {
    let Some(subject) = assertion
        .children
        .iter()
        .find(|child| child.local_name == "Subject")
    else {
        return Err(SamlError::PrincipalMismatch);
    };
    let name_ids: Vec<_> = subject
        .children
        .iter()
        .filter(|child| child.local_name == "NameID")
        .collect();
    let [name_id] = name_ids.as_slice() else {
        return Err(SamlError::PrincipalMismatch);
    };
    Ok(Principal {
        name_id: name_id.text.clone(),
        format: name_id
            .attr("Format")
            .map(str::to_string)
            .unwrap_or_else(|| crate::constants::name_id_format::UNSPECIFIED.to_string()),
        name_qualifier: name_id.attr("NameQualifier").map(str::to_string),
        sp_name_qualifier: name_id.attr("SPNameQualifier").map(str::to_string),
    })
}

fn reject_unrecognized_conditions(response_xml: &str, limits: XmlLimits) -> Result<(), SamlError> {
    if let Some(element) = unrecognized_condition_name(response_xml, limits)? {
        return Err(SamlError::UnrecognizedCondition { element });
    }
    Ok(())
}

fn unrecognized_condition_name(
    response_xml: &str,
    limits: XmlLimits,
) -> Result<Option<String>, SamlError> {
    limits.check_input_bytes(response_xml.len())?;
    let mut reader = NsReader::from_str(response_xml);
    reader
        .resolver_mut()
        .set_max_namespace_bindings(limits.max_attributes_per_element);
    let mut stack = Vec::new();
    loop {
        let (resolved, event) = reader
            .read_resolved_event()
            .map_err(|error| SamlError::Xml(error.to_string()))?;
        let namespace = element_namespace(resolved);
        match event {
            Event::Start(element) => {
                let local = element_local_name(&element);
                if let Some(element) = unknown_condition_child(&stack, namespace, &local) {
                    return Ok(Some(element));
                }
                stack.push((namespace, local));
            }
            Event::Empty(element) => {
                let local = element_local_name(&element);
                if let Some(element) = unknown_condition_child(&stack, namespace, &local) {
                    return Ok(Some(element));
                }
            }
            Event::End(_) => {
                stack.pop();
            }
            Event::Eof => break,
            Event::Decl(_)
            | Event::Text(_)
            | Event::CData(_)
            | Event::Comment(_)
            | Event::PI(_)
            | Event::DocType(_)
            | Event::GeneralRef(_) => {}
        }
    }
    Ok(None)
}

fn element_namespace(resolved: quick_xml::name::ResolveResult<'_>) -> ElementNamespace {
    match resolved {
        quick_xml::name::ResolveResult::Bound(bound)
            if bound.into_inner() == namespace::PROTOCOL =>
        {
            ElementNamespace::Protocol
        }
        quick_xml::name::ResolveResult::Bound(bound)
            if bound.into_inner() == namespace::ASSERTION =>
        {
            ElementNamespace::Assertion
        }
        _ => ElementNamespace::Other,
    }
}

fn element_local_name(element: &quick_xml::events::BytesStart<'_>) -> String {
    String::from_utf8_lossy(element.local_name().into_inner().as_bytes()).into_owned()
}

fn unknown_condition_child(
    stack: &[(ElementNamespace, String)],
    namespace: ElementNamespace,
    local: &str,
) -> Option<String> {
    let (conditions_namespace, conditions_local) = stack.last()?;
    if *conditions_namespace != ElementNamespace::Assertion || conditions_local != "Conditions" {
        return None;
    }
    let [.., (response_namespace, response_local), (assertion_namespace, assertion_local), _] =
        stack
    else {
        return None;
    };
    if *response_namespace != ElementNamespace::Protocol
        || response_local != "Response"
        || *assertion_namespace != ElementNamespace::Assertion
        || assertion_local != "Assertion"
    {
        return None;
    }
    if namespace == ElementNamespace::Assertion && understood_condition(local) {
        return None;
    }
    Some(local.to_string())
}

fn understood_condition(local: &str) -> bool {
    matches!(
        local,
        "AudienceRestriction" | "OneTimeUse" | "ProxyRestriction"
    )
}

fn extracted_has_bearer(extracted: &Value, limits: XmlLimits) -> Result<bool, SamlError> {
    for confirmation_xml in subject_confirmation_xmls(extracted) {
        let fields = [
            ExtractorField::new("subjectConfirmation", &["SubjectConfirmation"]).attrs(&["Method"]),
        ];
        let confirmation = extract_with_limits(confirmation_xml, &fields, limits)?;
        if confirmation.get_str("subjectConfirmation") == Some(BEARER_SUBJECT_CONFIRMATION_METHOD) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn audience_restriction_contains(
    audience_restriction: &str,
    expected: &str,
    limits: XmlLimits,
) -> Result<bool, SamlError> {
    let field = ExtractorField::new("audience", &["AudienceRestriction", "Audience"]);
    let extracted =
        extract_with_limits(audience_restriction, std::slice::from_ref(&field), limits)?;
    Ok(match extracted.get("audience") {
        Some(Value::Str(audience)) => audience == expected,
        Some(Value::Array(audiences)) => audiences
            .iter()
            .any(|audience| audience.as_str() == Some(expected)),
        _ => false,
    })
}

enum AudienceCheck {
    Satisfied,
    Absent,
    Rejected,
}

fn audience_restrictions_contain(
    assertion: &str,
    expected: &str,
    limits: XmlLimits,
) -> Result<AudienceCheck, SamlError> {
    let field = ExtractorField::new(
        "audienceRestriction",
        &["Assertion", "Conditions", "AudienceRestriction"],
    )
    .with_context();
    let extracted = extract_with_limits(assertion, std::slice::from_ref(&field), limits)?;

    match extracted.get("audienceRestriction") {
        Some(Value::Str(audience_restriction)) => {
            if audience_restriction_contains(audience_restriction, expected, limits)? {
                Ok(AudienceCheck::Satisfied)
            } else {
                Ok(AudienceCheck::Rejected)
            }
        }
        Some(Value::Array(audience_restrictions)) if !audience_restrictions.is_empty() => {
            for audience_restriction in audience_restrictions {
                let Some(audience_restriction) = audience_restriction.as_str() else {
                    return Ok(AudienceCheck::Rejected);
                };
                if !audience_restriction_contains(audience_restriction, expected, limits)? {
                    return Ok(AudienceCheck::Rejected);
                }
            }
            Ok(AudienceCheck::Satisfied)
        }
        _ => Ok(AudienceCheck::Absent),
    }
}

fn validate_audience(assertion_xml: &str, opts: &FlowOptions<'_>) -> Result<(), SamlError> {
    let Some(expected) = opts.expected_audience else {
        return Ok(());
    };
    match audience_restrictions_contain(assertion_xml, expected, opts.xml_limits)? {
        AudienceCheck::Satisfied => Ok(()),
        AudienceCheck::Absent if !opts.require_audience_restriction => Ok(()),
        AudienceCheck::Absent | AudienceCheck::Rejected => Err(SamlError::AudienceMismatch {
            expected: expected.to_string(),
        }),
    }
}

fn subject_confirmation_xmls(extracted: &Value) -> Vec<&str> {
    match extracted.get("subjectConfirmation") {
        Some(Value::Str(xml)) => vec![xml.as_str()],
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubjectConfirmationCheck {
    Valid,
    Invalid(SubjectConfirmationReason),
}

fn check_bearer_subject_confirmation(
    xml: &str,
    opts: &FlowOptions<'_>,
    expected_recipient: Option<&str>,
) -> Result<SubjectConfirmationCheck, SamlError> {
    let fields = [
        ExtractorField::new("subjectConfirmation", &["SubjectConfirmation"]).attrs(&["Method"]),
        ExtractorField::new(
            "subjectConfirmationData",
            &["SubjectConfirmation", "SubjectConfirmationData"],
        )
        .attrs(&["NotBefore", "NotOnOrAfter", "Recipient", "InResponseTo"]),
    ];
    let extracted = extract_with_limits(xml, &fields, opts.xml_limits)?;

    if extracted.get_str("subjectConfirmation") != Some(BEARER_SUBJECT_CONFIRMATION_METHOD) {
        return Ok(SubjectConfirmationCheck::Invalid(
            SubjectConfirmationReason::InvalidMethod,
        ));
    }

    let Some(not_on_or_after) = extracted.get_str("subjectConfirmationData.notOnOrAfter") else {
        return Ok(SubjectConfirmationCheck::Invalid(
            SubjectConfirmationReason::MissingNotOnOrAfter,
        ));
    };
    if !verify_time_at(
        extracted.get_str("subjectConfirmationData.notBefore"),
        Some(not_on_or_after),
        opts.clock_drifts,
        opts.validation_now()?,
    ) {
        return Ok(SubjectConfirmationCheck::Invalid(
            SubjectConfirmationReason::TimeWindowInvalid,
        ));
    }

    if let Some(expected) = expected_recipient {
        if extracted.get_str("subjectConfirmationData.recipient") != Some(expected) {
            return Ok(SubjectConfirmationCheck::Invalid(
                SubjectConfirmationReason::RecipientMismatch,
            ));
        }
    }

    if let Some(expected) = opts.expected_in_response_to {
        if extracted.get_str("subjectConfirmationData.inResponseTo") != Some(expected) {
            return Ok(SubjectConfirmationCheck::Invalid(
                SubjectConfirmationReason::InResponseToMismatch,
            ));
        }
    }

    Ok(SubjectConfirmationCheck::Valid)
}

fn validate_subject_confirmation(
    extracted: &Value,
    opts: &FlowOptions<'_>,
    expected_recipient: Option<&str>,
) -> Result<(), SamlError> {
    let mut reason = None;
    for xml in subject_confirmation_xmls(extracted) {
        match check_bearer_subject_confirmation(xml, opts, expected_recipient)? {
            SubjectConfirmationCheck::Valid => return Ok(()),
            SubjectConfirmationCheck::Invalid(current) => reason = Some(current),
        }
    }
    Err(SamlError::SubjectConfirmationInvalid {
        reason: reason.unwrap_or(SubjectConfirmationReason::MissingBearerConfirmation),
    })
}

fn validate_assertion_time(extracted: &Value, opts: &FlowOptions<'_>) -> Result<(), SamlError> {
    let now = opts.validation_now()?;
    let session_bounds = authn_statement_not_on_or_after_values(extracted)?;
    if let Some(raw_expiration) =
        earliest_authn_session_expiration(session_bounds, TimeWindowField::SessionNotOnOrAfter)?
    {
        let expiration = raw_expiration
            .checked_add(Duration::milliseconds(opts.clock_drifts.1))
            .ok_or(SamlError::TimeWindowInvalid {
                field: TimeWindowField::SessionNotOnOrAfter,
            })?;
        if now >= expiration {
            return Err(SamlError::TimeWindowInvalid {
                field: TimeWindowField::SessionNotOnOrAfter,
            });
        }
    }
    let (not_before, not_on_or_after) = conditions_time_bounds(extracted)?;
    if !verify_time_at(not_before, not_on_or_after, opts.clock_drifts, now) {
        return Err(SamlError::TimeWindowInvalid {
            field: TimeWindowField::Conditions,
        });
    }
    Ok(())
}
