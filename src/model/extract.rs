use std::collections::HashMap;

use super::attributes::{Attribute, AttributeValue, Attributes};
use super::audience_restriction::AudienceRestriction;
use super::authn_statement::AuthnStatement;
use super::endpoint::EndpointUrl;
use super::identifiers::{MessageId, SamlInstant, SessionIndex};
use super::subject::{NameId, NameIdPolicy, SubjectConfirmation};
use crate::config::{EntityId, NameIdFormat};
use crate::constants::attribute_name_format;
use crate::error::{SamlError, TimeWindowField};
use crate::util::Value;
use crate::validator::conditions_time_window;
use crate::xml::any_uri::collapse_whitespace;
use crate::xml::fields::{attribute, authn_request, authn_statement, login_response, name_id};
use crate::xml::{dom, xs_boolean, xs_unsigned_short, XmlLimits};

pub(super) fn required_str<'a>(extract: &'a Value, path: &str) -> Result<&'a str, SamlError> {
    extract
        .get_str(path)
        .ok_or_else(|| SamlError::Invalid(format!("missing extracted field {path}")))
}

pub(super) fn required_saml_utc_instant(
    value: Option<&str>,
    element: &str,
    attribute: &str,
) -> Result<SamlInstant, SamlError> {
    let value = value.ok_or_else(|| {
        SamlError::ProtocolProfile(format!(
            "{element} is missing required unqualified attribute {attribute}"
        ))
    })?;
    saml_utc_instant(value, element, attribute)
}

pub(super) fn saml_utc_instant(
    value: &str,
    element: &str,
    attribute: &str,
) -> Result<SamlInstant, SamlError> {
    SamlInstant::parse_utc(value).ok_or_else(|| {
        SamlError::ProtocolProfile(format!(
            "{element} {attribute} must use the SAML-conformant UTC xs:dateTime form ending in Z"
        ))
    })
}

pub(super) fn optional_request_id(
    extract: &Value,
    path: &str,
) -> Result<Option<MessageId>, SamlError> {
    extract
        .get_str(path)
        .map(collapse_whitespace)
        .filter(|value| !value.is_empty())
        .map(MessageId::try_new)
        .transpose()
}

pub(super) fn optional_endpoint(
    extract: &Value,
    path: &str,
) -> Result<Option<EndpointUrl>, SamlError> {
    extract
        .get_str(path)
        .map(|value| EndpointUrl::try_new(collapse_whitespace(value)))
        .transpose()
}

pub(super) fn optional_u16(extract: &Value, path: &str) -> Result<Option<u16>, SamlError> {
    extract
        .get_str(path)
        .map(|value| {
            xs_unsigned_short(value).ok_or_else(|| {
                SamlError::Invalid(format!("{path} must be an unsigned 16-bit integer"))
            })
        })
        .transpose()
}

fn checked_time_bound(value: &str, field: TimeWindowField) -> Result<SamlInstant, SamlError> {
    SamlInstant::parse_utc(value).ok_or(SamlError::TimeWindowInvalid { field })
}

pub(super) fn conditions_instants(
    extract: &Value,
) -> Result<(Option<SamlInstant>, Option<SamlInstant>), SamlError> {
    let window = conditions_time_window(extract)?;
    let bound = |value| checked_time_bound(value, TimeWindowField::Conditions);
    Ok((
        window.not_before.map(bound).transpose()?,
        window.not_on_or_after.map(bound).transpose()?,
    ))
}

pub(super) fn name_id_from_extract(extract: &Value, value: &str) -> NameId {
    let qualifier = |field| extract.get_str(field).map(str::to_owned);
    NameId::received(
        value,
        extract
            .get_str(name_id::FORMAT)
            .map(|format| NameIdFormat::from_uri(&collapse_whitespace(format))),
        qualifier(name_id::NAME_QUALIFIER),
        qualifier(name_id::SP_NAME_QUALIFIER),
        qualifier(name_id::SP_PROVIDED_ID),
    )
}

pub(super) fn name_id_policy_from_extract(
    extract: &Value,
) -> Result<Option<NameIdPolicy>, SamlError> {
    let format = extract
        .get_str(authn_request::NAME_ID_POLICY_FORMAT)
        .map(|format| NameIdFormat::from_uri(&collapse_whitespace(format)));
    let sp_name_qualifier = extract
        .get_str(authn_request::NAME_ID_POLICY_SP_NAME_QUALIFIER)
        .map(str::to_string);
    let allow_create = extract
        .get_str(authn_request::NAME_ID_POLICY_ALLOW_CREATE)
        .map(parse_bool)
        .transpose()?;
    Ok(NameIdPolicy::from_parsed(
        format,
        sp_name_qualifier,
        allow_create,
    ))
}

fn parse_bool(value: &str) -> Result<bool, SamlError> {
    xs_boolean(Some(value))
        .ok_or_else(|| SamlError::Invalid("NameIDPolicy AllowCreate must be a boolean".into()))
}

fn value_strings(value: &Value) -> Vec<String> {
    match value {
        Value::Str(value) => vec![value.clone()],
        Value::Array(values) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        Value::Null | Value::Object(_) => Vec::new(),
    }
}

pub(super) fn attributes_from_extract(extract: &Value) -> Result<Attributes, SamlError> {
    let elements: Vec<&Value> = match extract.get(login_response::ATTRIBUTE_ELEMENTS) {
        Some(Value::Array(elements)) => elements.iter().collect(),
        Some(element @ Value::Object(_)) => vec![element],
        Some(Value::Null | Value::Str(_)) | None => Vec::new(),
    };
    if elements.is_empty()
        && matches!(extract.get(login_response::ATTRIBUTES), Some(Value::Object(entries)) if !entries.is_empty())
    {
        return Err(SamlError::Invalid(
            "extracted attributes are missing attributeNameFormats".into(),
        ));
    }
    let mut attributes: Vec<Attribute> = Vec::new();
    let mut positions: HashMap<(&str, String), usize> = HashMap::new();
    for element in elements {
        let name = element.get_str(attribute::NAME).ok_or_else(|| {
            SamlError::ProtocolProfile(
                "Attribute is missing required unqualified attribute Name".into(),
            )
        })?;
        let name_format = element
            .get_str(attribute::NAME_FORMAT)
            .map(collapse_whitespace);
        let friendly_name = element.get_str(attribute::FRIENDLY_NAME);
        let values = element
            .get(attribute::VALUES)
            .map(value_strings)
            .ok_or_else(|| {
                SamlError::Invalid("extracted Attribute is missing attributeValue".into())
            })?
            .into_iter()
            .map(AttributeValue::new);
        let identity = (
            name,
            name_format
                .clone()
                .unwrap_or_else(|| attribute_name_format::UNSPECIFIED.to_string()),
        );
        match positions.get(&identity) {
            Some(&position) => attributes[position].extend_values(values),
            None => {
                positions.insert(identity, attributes.len());
                attributes.push(Attribute::received(
                    name,
                    name_format.as_deref(),
                    friendly_name,
                    values.collect(),
                ));
            }
        }
    }
    Ok(Attributes::new(attributes))
}

pub(super) fn subject_confirmations_from_extract(extract: &Value) -> Vec<SubjectConfirmation> {
    subject_confirmations_at(extract, login_response::SUBJECT_CONFIRMATION)
}

pub(super) fn subject_confirmations_at(extract: &Value, path: &str) -> Vec<SubjectConfirmation> {
    match extract.get(path) {
        Some(Value::Str(xml)) => vec![SubjectConfirmation::from_raw_xml(xml.clone())],
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(SubjectConfirmation::from_raw_xml)
            .collect(),
        Some(Value::Null | Value::Object(_)) | None => Vec::new(),
    }
}

fn authn_statement_values(extract: &Value) -> Result<Vec<&Value>, SamlError> {
    match extract.get(login_response::AUTHN_STATEMENTS) {
        Some(value @ Value::Object(_)) => Ok(vec![value]),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| match value {
                Value::Object(_) => Ok(value),
                Value::Null | Value::Str(_) | Value::Array(_) => Err(SamlError::Invalid(
                    "extracted AuthnStatement array must contain only objects".into(),
                )),
            })
            .collect(),
        Some(Value::Str(_)) => Err(SamlError::Invalid(
            "extracted AuthnStatement must be an object or array of objects".into(),
        )),
        Some(Value::Null) | None => Ok(Vec::new()),
    }
}

fn optional_authn_statement_str<'a>(
    statement: &'a Value,
    field: &str,
) -> Result<Option<&'a str>, SamlError> {
    match statement.get(field) {
        Some(Value::Str(value)) => Ok(Some(value)),
        Some(Value::Null) | None => Ok(None),
        Some(Value::Array(_) | Value::Object(_)) => Err(SamlError::Invalid(format!(
            "extracted AuthnStatement {field} must be a string"
        ))),
    }
}

pub(crate) fn authn_statement_not_on_or_after_values(
    extract: &Value,
) -> Result<Vec<&str>, SamlError> {
    authn_statement_values(extract)?
        .into_iter()
        .map(|statement| {
            optional_authn_statement_str(statement, authn_statement::SESSION_NOT_ON_OR_AFTER)
        })
        .filter_map(Result::transpose)
        .collect()
}

pub(super) fn authn_statements_from_extract(
    extract: &Value,
    saml_content: &str,
) -> Result<Vec<AuthnStatement>, SamlError> {
    let statements = authn_statement_values(extract)?;
    if statements.is_empty() {
        return Ok(Vec::new());
    }
    let children = super::authn_details::statement_children(extract, saml_content)?;
    if statements.len() != children.len() {
        return Err(SamlError::Invalid(
            "extracted AuthnStatement count does not match the assertion".into(),
        ));
    }
    statements
        .into_iter()
        .zip(children)
        .map(|(statement, children)| {
            let session_index =
                optional_authn_statement_str(statement, authn_statement::SESSION_INDEX)?
                    .map(SessionIndex::try_new)
                    .transpose()?;
            let authn_instant = required_saml_utc_instant(
                optional_authn_statement_str(statement, authn_statement::AUTHN_INSTANT)?,
                "AuthnStatement",
                "AuthnInstant",
            )?;
            let not_on_or_after =
                optional_authn_statement_str(statement, authn_statement::SESSION_NOT_ON_OR_AFTER)?
                    .map(|value| checked_time_bound(value, TimeWindowField::SessionNotOnOrAfter))
                    .transpose()?;
            Ok(AuthnStatement::new(
                session_index,
                authn_instant,
                not_on_or_after,
                children,
            ))
        })
        .collect()
}

pub(super) fn audience_restrictions_from_extract(
    extract: &Value,
) -> Result<Vec<AudienceRestriction>, SamlError> {
    let Some(value) = extract.get(login_response::AUDIENCE_RESTRICTION) else {
        return Ok(Vec::new());
    };
    value_strings(value)
        .iter()
        .map(|xml| {
            let restriction = dom::parse_fragment_with_limits(xml, XmlLimits::unbounded())?;
            restriction
                .root
                .children_named("Audience")
                .map(|audience| EntityId::try_new(collapse_whitespace(&audience.text)))
                .collect::<Result<Vec<_>, _>>()
                .map(AudienceRestriction::new)
        })
        .collect()
}

pub(super) fn session_indexes_from_value(
    value: Option<&Value>,
) -> Result<Vec<SessionIndex>, SamlError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    value_strings(value)
        .into_iter()
        .map(SessionIndex::try_new)
        .collect()
}
