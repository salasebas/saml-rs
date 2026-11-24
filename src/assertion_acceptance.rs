use crate::constants::namespace;
use crate::error::{SamlError, SubjectConfirmationReason, TimeWindowField};
use crate::flow::FlowOptions;
use crate::model::{authn_statement_not_on_or_after_values, earliest_authn_session_expiration};
use crate::util::Value;
use crate::validator::{conditions_time_window, TimeWindow};
use crate::xml::any_uri::collapse_whitespace;
use crate::xml::dom::{self, reader_err, Node};
use crate::xml::{extract_with_limits, fields, parse_saml_utc_instant, XmlLimits};
use quick_xml::events::Event;
use quick_xml::reader::NsReader;
use time::{Duration, OffsetDateTime};

const BEARER_SUBJECT_CONFIRMATION_METHOD: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

#[cfg(test)]
mod tests;

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

pub(crate) fn accept_response_assertions(
    response_xml: &str,
    opts: &FlowOptions<'_>,
    expected_recipient: Option<&str>,
) -> Result<(), SamlError> {
    reject_unrecognized_conditions(response_xml, opts.xml_limits)?;
    let document = dom::parse_document(response_xml, opts.xml_limits)?;
    let assertions: Vec<_> = document.root.children_named("Assertion").collect();
    let [first, ..] = assertions.as_slice() else {
        return Err(SamlError::AssertionMissing);
    };
    let first_issuer = issuer_text(first);

    let mut saw_bearer = false;
    let mut confirmation_error = None;
    let mut shared_principal: Option<Principal> = None;
    let several = assertions.len() > 1;
    for assertion in &assertions {
        let assertion_xml = &response_xml[assertion.start..assertion.end];
        if several {
            require_shared_issuer(opts.from_issuer, first_issuer, assertion)?;
            remember_same_principal(assertion, &mut shared_principal)?;
        }
        let extracted = extract_with_limits(
            assertion_xml,
            &fields::login_response_fields(assertion_xml),
            opts.xml_limits,
        )?;
        if node_has_bearer(assertion) {
            saw_bearer = true;
            validate_subject_confirmation(assertion, opts, expected_recipient)?;
            validate_audience(assertion, opts)?;
            validate_assertion_time(&extracted, opts)?;
        } else if confirmation_error.is_none() && subject_confirmations(assertion).next().is_some()
        {
            if let Err(error) = validate_subject_confirmation(assertion, opts, expected_recipient) {
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

pub(crate) fn reject_unsolicited_bearer_in_response_to(
    response_xml: &str,
    limits: XmlLimits,
) -> Result<(), SamlError> {
    let document = dom::parse_document(response_xml, limits)?;
    for assertion in document.root.children_named("Assertion") {
        for confirmation in subject_confirmations(assertion) {
            let request_id = confirmation
                .children
                .iter()
                .filter(|child| child.local_name == "SubjectConfirmationData")
                .find_map(|data| data.attr("InResponseTo"));
            if request_id.is_some() && is_bearer_confirmation(confirmation) {
                return Err(SamlError::in_response_to_mismatch(None, request_id));
            }
        }
    }
    Ok(())
}

pub(crate) fn first_login_assertion_xml(
    xml: &str,
    limits: XmlLimits,
) -> Result<Option<String>, SamlError> {
    let document = dom::parse_document(xml, limits)?;
    Ok(consumed_assertion(&document.root).map(|chosen| xml[chosen.start..chosen.end].to_string()))
}

pub(crate) fn consumed_assertion(response: &Node) -> Option<&Node> {
    let mut assertions = response.children_named("Assertion").peekable();
    let first = assertions.peek().copied()?;
    let mut first_bearer = None;
    for assertion in assertions.filter(|assertion| node_has_bearer(assertion)) {
        if assertion.child_named("AuthnStatement").is_some() {
            return Some(assertion);
        }
        first_bearer.get_or_insert(assertion);
    }
    first_bearer.or(Some(first))
}

pub(crate) struct AssertionReplayId {
    pub id: String,
    pub bearer_not_on_or_after: Option<String>,
}

pub(crate) fn assertion_replays(
    xml: &str,
    limits: XmlLimits,
) -> Result<Vec<AssertionReplayId>, SamlError> {
    let document = dom::parse_fragment_with_limits(xml, limits)?;
    let nodes = if document.root.local_name == "Assertion" {
        vec![&document.root]
    } else {
        document.root.children_named("Assertion").collect()
    };
    Ok(nodes
        .into_iter()
        .filter_map(|assertion| {
            Some(AssertionReplayId {
                id: assertion.attr("ID")?.to_string(),
                bearer_not_on_or_after: latest_bearer_not_on_or_after(subject_confirmations(
                    assertion,
                )),
            })
        })
        .collect())
}

fn subject_confirmations(assertion: &Node) -> impl Iterator<Item = &Node> {
    assertion
        .children
        .iter()
        .filter(|child| child.local_name == "Subject")
        .flat_map(|subject| subject.children.iter())
        .filter(|child| child.local_name == "SubjectConfirmation")
}

fn node_has_bearer(assertion: &Node) -> bool {
    subject_confirmations(assertion).any(is_bearer_confirmation)
}

fn is_bearer_confirmation(confirmation: &Node) -> bool {
    confirmation
        .attr("Method")
        .is_some_and(|method| collapse_whitespace(method) == BEARER_SUBJECT_CONFIRMATION_METHOD)
}

pub(crate) fn latest_bearer_not_on_or_after<'a>(
    confirmations: impl IntoIterator<Item = &'a Node>,
) -> Option<String> {
    let mut latest: Option<(OffsetDateTime, String)> = None;
    let mut unparsed = None;
    for confirmation in confirmations {
        if !is_bearer_confirmation(confirmation) {
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
        match parse_saml_utc_instant(value) {
            Some(instant) => {
                let replace = latest
                    .as_ref()
                    .is_none_or(|(current, _)| *current < instant);
                if replace {
                    latest = Some((instant, value.to_string()));
                }
            }
            None => unparsed = Some(value.to_string()),
        }
    }
    latest.map(|(_, value)| value).or(unparsed)
}

fn issuer_text(assertion: &Node) -> Option<&str> {
    assertion
        .children
        .iter()
        .find(|child| child.local_name == "Issuer")
        .map(|issuer| issuer.text.as_str())
}

fn require_shared_issuer(
    expected_issuer: Option<&str>,
    first_issuer: Option<&str>,
    assertion: &Node,
) -> Result<(), SamlError> {
    let actual = issuer_text(assertion);
    if let Some(expected) = expected_issuer {
        if actual != Some(expected) {
            return Err(SamlError::issuer_mismatch(expected, actual));
        }
    }
    if actual != first_issuer {
        return Err(SamlError::issuer_mismatch(
            first_issuer.unwrap_or(""),
            actual,
        ));
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
        let (resolved, event) = reader.read_resolved_event().map_err(reader_err)?;
        let namespace = element_namespace(&resolved);
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

fn element_namespace(resolved: &quick_xml::name::ResolveResult<'_>) -> ElementNamespace {
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

enum AudienceCheck {
    Satisfied,
    Absent,
    Rejected,
}

fn audience_restrictions_contain(assertion: &Node, expected: &str) -> AudienceCheck {
    let restrictions: Vec<&Node> = assertion
        .children_named("Conditions")
        .flat_map(|conditions| conditions.children_named("AudienceRestriction"))
        .collect();
    let names_expected = |restriction: &Node| {
        restriction
            .children_named("Audience")
            .any(|audience| collapse_whitespace(&audience.text) == expected)
    };
    if restrictions.is_empty() {
        AudienceCheck::Absent
    } else if restrictions.into_iter().all(names_expected) {
        AudienceCheck::Satisfied
    } else {
        AudienceCheck::Rejected
    }
}

fn validate_audience(assertion: &Node, opts: &FlowOptions<'_>) -> Result<(), SamlError> {
    let Some(expected) = opts.expected_audience else {
        return Ok(());
    };
    match audience_restrictions_contain(assertion, expected) {
        AudienceCheck::Satisfied => Ok(()),
        AudienceCheck::Absent if !opts.require_audience_restriction => Ok(()),
        AudienceCheck::Absent | AudienceCheck::Rejected => Err(SamlError::AudienceMismatch {
            expected: expected.to_string(),
        }),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubjectConfirmationCheck {
    Valid,
    Invalid(SubjectConfirmationReason),
}

fn check_bearer_subject_confirmation(
    confirmation: &Node,
    opts: &FlowOptions<'_>,
    expected_recipient: Option<&str>,
) -> Result<SubjectConfirmationCheck, SamlError> {
    if !is_bearer_confirmation(confirmation) {
        return Ok(SubjectConfirmationCheck::Invalid(
            SubjectConfirmationReason::InvalidMethod,
        ));
    }

    let data: Vec<&Node> = confirmation
        .children_named("SubjectConfirmationData")
        .collect();
    let [data] = data[..] else {
        return Ok(SubjectConfirmationCheck::Invalid(
            SubjectConfirmationReason::MissingNotOnOrAfter,
        ));
    };
    let Some(not_on_or_after) = data.attr("NotOnOrAfter") else {
        return Ok(SubjectConfirmationCheck::Invalid(
            SubjectConfirmationReason::MissingNotOnOrAfter,
        ));
    };
    let window = TimeWindow {
        not_before: data.attr("NotBefore"),
        not_on_or_after: Some(not_on_or_after),
    };
    if !window.contains(opts.validation_now()?, opts.clock_skew) {
        return Ok(SubjectConfirmationCheck::Invalid(
            SubjectConfirmationReason::TimeWindowInvalid,
        ));
    }

    if let Some(expected) = expected_recipient {
        if data.attr("Recipient").map(collapse_whitespace).as_deref() != Some(expected) {
            return Ok(SubjectConfirmationCheck::Invalid(
                SubjectConfirmationReason::RecipientMismatch,
            ));
        }
    }

    if let Some(expected) = opts.expected_in_response_to {
        if data.attr("InResponseTo") != Some(expected) {
            return Ok(SubjectConfirmationCheck::Invalid(
                SubjectConfirmationReason::InResponseToMismatch,
            ));
        }
    }

    Ok(SubjectConfirmationCheck::Valid)
}

fn validate_subject_confirmation(
    assertion: &Node,
    opts: &FlowOptions<'_>,
    expected_recipient: Option<&str>,
) -> Result<(), SamlError> {
    let mut reason = None;
    for confirmation in subject_confirmations(assertion) {
        match check_bearer_subject_confirmation(confirmation, opts, expected_recipient)? {
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
            .checked_add(Duration::milliseconds(
                opts.clock_skew.not_on_or_after_millis(),
            ))
            .ok_or(SamlError::TimeWindowInvalid {
                field: TimeWindowField::SessionNotOnOrAfter,
            })?;
        if now >= expiration {
            return Err(SamlError::TimeWindowInvalid {
                field: TimeWindowField::SessionNotOnOrAfter,
            });
        }
    }
    if !conditions_time_window(extracted)?.contains(now, opts.clock_skew) {
        return Err(SamlError::TimeWindowInvalid {
            field: TimeWindowField::Conditions,
        });
    }
    Ok(())
}
