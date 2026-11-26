use crate::constants::namespace;
use crate::error::{xml_err, SamlError, SubjectConfirmationReason, TimeWindowField};
use crate::flow::FlowOptions;
use crate::model::{authn_statement_not_on_or_after_values, earliest_authn_session_expiration};
use crate::util::Value;
use crate::validator::{conditions_time_window, TimeWindow};
use crate::xml::any_uri::collapse_whitespace;
use crate::xml::dom::{self, reader_err, Node};
use crate::xml::{extract_with_limits, fields, parse_saml_utc_instant, utf8_bom_len, XmlLimits};
use quick_xml::escape::unescape;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::{NamespaceResolver, ResolveResult};
use quick_xml::reader::NsReader;
use std::collections::HashSet;
use time::{Duration, OffsetDateTime};

const BEARER_SUBJECT_CONFIRMATION_METHOD: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const XML_SCHEMA_INSTANCE_NAMESPACE: &str = "http://www.w3.org/2001/XMLSchema-instance";

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ElementNamespace {
    Protocol,
    Assertion,
    Other,
}

pub(crate) fn accept_response_assertions(
    response_xml: &str,
    opts: &FlowOptions<'_>,
    expected_recipient: Option<&str>,
) -> Result<(), SamlError> {
    let document = dom::parse_document(response_xml, opts.xml_limits)?;
    if opts.expected_in_response_to.is_none() {
        if let Some(actual) = document.root.unqualified_attr("InResponseTo") {
            return Err(SamlError::in_response_to_mismatch(None, Some(actual)));
        }
    }
    let assertions: Vec<_> = document.root.children_named("Assertion").collect();
    let Some(selected) = consumed_assertion(&document.root) else {
        return Err(SamlError::AssertionMissing);
    };
    require_understood_conditions(response_xml, selected, opts.xml_limits)?;
    require_text_only_values(selected)?;
    if let [first, _, ..] = assertions.as_slice() {
        let mut ids = HashSet::new();
        if assertions
            .iter()
            .filter_map(|assertion| assertion.unqualified_attr("ID"))
            .any(|id| !ids.insert(collapse_whitespace(id)))
        {
            return Err(SamlError::PotentialWrappingAttack);
        }
        let first_issuer = issuer_text(first);
        for assertion in &assertions {
            require_shared_issuer(opts.from_issuer, first_issuer, assertion)?;
        }
    }
    if !node_has_bearer(selected) {
        return Err(missing_bearer_error(&assertions, opts, expected_recipient));
    }
    if selected.child_named("AuthnStatement").is_none() {
        return Err(SamlError::ProtocolProfile(
            "no bearer assertion has an AuthnStatement".into(),
        ));
    }
    let assertion_xml = &response_xml[selected.start..selected.end];
    let extracted = extract_with_limits(
        assertion_xml,
        &fields::login_response_fields(assertion_xml),
        opts.xml_limits,
    )?;
    validate_subject_confirmation(selected, opts, expected_recipient)?;
    validate_audience(selected, opts)?;
    validate_assertion_time(&extracted, opts)
}

fn missing_bearer_error(
    assertions: &[&Node],
    opts: &FlowOptions<'_>,
    expected_recipient: Option<&str>,
) -> SamlError {
    assertions
        .iter()
        .filter(|assertion| subject_confirmations(assertion).next().is_some())
        .find_map(|assertion| {
            validate_subject_confirmation(assertion, opts, expected_recipient).err()
        })
        .unwrap_or(SamlError::SubjectConfirmationInvalid {
            reason: SubjectConfirmationReason::MissingBearerConfirmation,
        })
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
                id: assertion.unqualified_attr("ID")?.to_string(),
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

pub(crate) fn is_bearer_confirmation(confirmation: &Node) -> bool {
    confirmation
        .unqualified_attr("Method")
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
            .and_then(|data| data.unqualified_attr("NotOnOrAfter"))
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

struct OpenElement {
    namespace: ElementNamespace,
    local: String,
    start: usize,
}

fn require_understood_conditions(
    response_xml: &str,
    assertion: &Node,
    limits: XmlLimits,
) -> Result<(), SamlError> {
    limits.check_input_bytes(response_xml.len())?;
    let mut reader = NsReader::from_str(response_xml);
    reader
        .resolver_mut()
        .set_max_namespace_bindings(limits.max_attributes_per_element);
    let bom_len = utf8_bom_len(response_xml);
    let mut stack = Vec::new();
    loop {
        let start = bom_len + reader.buffer_position() as usize;
        let (resolved, event) = reader.read_resolved_event().map_err(reader_err)?;
        let namespace = element_namespace(&resolved);
        match event {
            Event::Start(element) => {
                let local = element_local_name(&element);
                require_understood_element(
                    &stack,
                    assertion,
                    namespace,
                    &local,
                    &element,
                    reader.resolver(),
                )?;
                stack.push(OpenElement {
                    namespace,
                    local,
                    start,
                });
            }
            Event::Empty(element) => {
                let local = element_local_name(&element);
                require_understood_element(
                    &stack,
                    assertion,
                    namespace,
                    &local,
                    &element,
                    reader.resolver(),
                )?;
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
    Ok(())
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

fn element_local_name(element: &BytesStart<'_>) -> String {
    String::from_utf8_lossy(element.local_name().into_inner().as_bytes()).into_owned()
}

fn is_selected_assertion(response: &OpenElement, open: &OpenElement, assertion: &Node) -> bool {
    response.namespace == ElementNamespace::Protocol
        && response.local == "Response"
        && open.namespace == ElementNamespace::Assertion
        && open.local == "Assertion"
        && open.start == assertion.start
}

fn require_understood_element(
    stack: &[OpenElement],
    assertion: &Node,
    namespace: ElementNamespace,
    local: &str,
    element: &BytesStart<'_>,
    resolver: &NamespaceResolver,
) -> Result<(), SamlError> {
    let declared: &[&str] = match stack {
        [.., response, open_assertion]
            if is_selected_assertion(response, open_assertion, assertion)
                && namespace == ElementNamespace::Assertion
                && local == "Conditions" =>
        {
            &["NotBefore", "NotOnOrAfter"]
        }
        [.., response, open_assertion, conditions]
            if is_selected_assertion(response, open_assertion, assertion)
                && conditions.namespace == ElementNamespace::Assertion
                && conditions.local == "Conditions" =>
        {
            match (namespace, local) {
                (ElementNamespace::Assertion, "AudienceRestriction" | "OneTimeUse") => &[],
                (ElementNamespace::Assertion, "ProxyRestriction") => &["Count"],
                (
                    ElementNamespace::Assertion
                    | ElementNamespace::Protocol
                    | ElementNamespace::Other,
                    _,
                ) => {
                    return Err(SamlError::UnrecognizedCondition {
                        element: local.to_string(),
                        attribute: None,
                    });
                }
            }
        }
        _ => return Ok(()),
    };
    match undeclared_attribute(element, declared, resolver)? {
        Some(attribute) => Err(SamlError::UnrecognizedCondition {
            element: local.to_string(),
            attribute: Some(attribute),
        }),
        None => Ok(()),
    }
}

fn undeclared_attribute(
    element: &BytesStart<'_>,
    declared: &[&str],
    resolver: &NamespaceResolver,
) -> Result<Option<String>, SamlError> {
    for attribute in element.attributes() {
        let key = attribute.map_err(xml_err)?.key;
        if key.as_namespace_binding().is_some() {
            continue;
        }
        let understood = match resolver.resolve_attribute(key) {
            (ResolveResult::Unbound, local) => declared.contains(&local.into_inner()),
            (ResolveResult::Bound(namespace), _) => {
                unescape(namespace.into_inner()).map_err(xml_err)? == XML_SCHEMA_INSTANCE_NAMESPACE
            }
            (ResolveResult::Unknown(_), _) => false,
        };
        if !understood {
            return Ok(Some(key.into_inner().to_owned()));
        }
    }
    Ok(None)
}

fn require_text_only_values(assertion: &Node) -> Result<(), SamlError> {
    let issuers = assertion.children_named("Issuer");
    let name_ids = assertion
        .children_named("Subject")
        .flat_map(|subject| subject.children_named("NameID"));
    let audiences = assertion
        .children_named("Conditions")
        .flat_map(|conditions| conditions.children_named("AudienceRestriction"))
        .flat_map(|restriction| restriction.children_named("Audience"));
    match issuers
        .chain(name_ids)
        .chain(audiences)
        .find(|value| !value.children.is_empty())
    {
        Some(value) => Err(SamlError::ProtocolProfile(format!(
            "{} must hold text without child elements",
            value.local_name
        ))),
        None => Ok(()),
    }
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
    let Some(not_on_or_after) = data.unqualified_attr("NotOnOrAfter") else {
        return Ok(SubjectConfirmationCheck::Invalid(
            SubjectConfirmationReason::MissingNotOnOrAfter,
        ));
    };
    let window = TimeWindow {
        not_before: data.unqualified_attr("NotBefore"),
        not_on_or_after: Some(not_on_or_after),
    };
    if !window.contains(opts.validation_now()?, opts.clock_skew) {
        return Ok(SubjectConfirmationCheck::Invalid(
            SubjectConfirmationReason::TimeWindowInvalid,
        ));
    }

    if let Some(expected) = expected_recipient {
        if data
            .unqualified_attr("Recipient")
            .map(collapse_whitespace)
            .as_deref()
            != Some(expected)
        {
            return Ok(SubjectConfirmationCheck::Invalid(
                SubjectConfirmationReason::RecipientMismatch,
            ));
        }
    }

    if data
        .unqualified_attr("InResponseTo")
        .map(collapse_whitespace)
        .as_deref()
        != opts.expected_in_response_to
    {
        return Ok(SubjectConfirmationCheck::Invalid(
            SubjectConfirmationReason::InResponseToMismatch,
        ));
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
