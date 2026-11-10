use std::collections::HashMap;

use super::attributes::{Attribute, AttributeValue, Attributes};
use super::endpoint::EndpointUrl;
use super::identifiers::{MessageId, SamlInstant, SessionIndex};
use super::session::AuthnSession;
use super::subject::{NameIdPolicy, SubjectConfirmation};
use crate::config::{EntityId, NameIdFormat};
use crate::constants::{attribute_name_format, name_id_format};
use crate::error::SamlError;
use crate::util::Value;
use crate::validator::conditions_time_bounds;
use crate::xml::{xs_boolean, xs_unsigned_short};

pub(super) fn required_str<'a>(extract: &'a Value, path: &str) -> Result<&'a str, SamlError> {
    extract
        .get_str(path)
        .ok_or_else(|| SamlError::Invalid(format!("missing extracted field {path}")))
}

pub(super) fn optional_request_id(
    extract: &Value,
    path: &str,
) -> Result<Option<MessageId>, SamlError> {
    extract
        .get_str(path)
        .filter(|value| !value.is_empty())
        .map(MessageId::try_new)
        .transpose()
}

pub(super) fn optional_endpoint(
    extract: &Value,
    path: &str,
) -> Result<Option<EndpointUrl>, SamlError> {
    extract.get_str(path).map(EndpointUrl::try_new).transpose()
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

pub(super) fn conditions_instants(
    extract: &Value,
) -> Result<(Option<SamlInstant>, Option<SamlInstant>), SamlError> {
    let (not_before, not_on_or_after) = conditions_time_bounds(extract)?;
    Ok((
        not_before.map(SamlInstant::try_new).transpose()?,
        not_on_or_after.map(SamlInstant::try_new).transpose()?,
    ))
}

pub(super) fn name_id_policy_from_extract(
    extract: &Value,
) -> Result<Option<NameIdPolicy>, SamlError> {
    let format = extract
        .get_str("nameIDPolicy.format")
        .map(name_id_format_from_uri);
    let sp_name_qualifier = extract
        .get_str("nameIDPolicy.spNameQualifier")
        .map(str::to_string);
    let allow_create = extract
        .get_str("nameIDPolicy.allowCreate")
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

pub(crate) fn name_id_format_from_uri(uri: &str) -> NameIdFormat {
    match uri {
        name_id_format::EMAIL_ADDRESS => NameIdFormat::EmailAddress,
        name_id_format::PERSISTENT => NameIdFormat::Persistent,
        name_id_format::TRANSIENT => NameIdFormat::Transient,
        name_id_format::ENTITY => NameIdFormat::Entity,
        name_id_format::UNSPECIFIED => NameIdFormat::Unspecified,
        name_id_format::KERBEROS => NameIdFormat::Kerberos,
        name_id_format::WINDOWS_DOMAIN_QUALIFIED_NAME => NameIdFormat::WindowsDomainQualifiedName,
        name_id_format::X509_SUBJECT_NAME => NameIdFormat::X509SubjectName,
        _ => NameIdFormat::Custom(uri.to_string()),
    }
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
    let elements: Vec<&Value> = match extract.get("attributeNameFormats") {
        Some(Value::Array(elements)) => elements.iter().collect(),
        Some(element @ Value::Object(_)) => vec![element],
        Some(Value::Null | Value::Str(_)) | None => Vec::new(),
    };
    if elements.is_empty()
        && matches!(extract.get("attributes"), Some(Value::Object(entries)) if !entries.is_empty())
    {
        return Err(SamlError::Invalid(
            "extracted attributes are missing attributeNameFormats".into(),
        ));
    }
    let mut attributes: Vec<(&str, Option<&str>, Vec<AttributeValue>)> = Vec::new();
    let mut positions: HashMap<(&str, &str), usize> = HashMap::new();
    for element in elements {
        let name = element.get_str("name").unwrap_or_default();
        let name_format = element.get_str("nameFormat");
        let values = element
            .get("attributeValue")
            .map(value_strings)
            .ok_or_else(|| {
                SamlError::Invalid("extracted Attribute is missing attributeValue".into())
            })?
            .into_iter()
            .map(AttributeValue::new);
        let identity = (
            name,
            name_format.unwrap_or(attribute_name_format::UNSPECIFIED),
        );
        match positions.get(&identity) {
            Some(&position) => attributes[position].2.extend(values),
            None => {
                positions.insert(identity, attributes.len());
                attributes.push((name, name_format, values.collect()));
            }
        }
    }
    Ok(Attributes::new(
        attributes
            .into_iter()
            .map(|(name, name_format, values)| {
                Attribute::new(name, name_format.map(str::to_string), values)
            })
            .collect(),
    ))
}

pub(super) fn subject_confirmations_from_extract(extract: &Value) -> Vec<SubjectConfirmation> {
    subject_confirmations_at(extract, "subjectConfirmation")
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
    match extract.get("sessionIndex") {
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
        .map(|statement| optional_authn_statement_str(statement, "sessionNotOnOrAfter"))
        .filter_map(Result::transpose)
        .collect()
}

pub(super) fn authn_sessions_from_extract(extract: &Value) -> Result<Vec<AuthnSession>, SamlError> {
    authn_statement_values(extract)?
        .into_iter()
        .map(|statement| {
            let session_index = optional_authn_statement_str(statement, "sessionIndex")?
                .map(SessionIndex::try_new)
                .transpose()?;
            let authn_instant = optional_authn_statement_str(statement, "authnInstant")?
                .map(SamlInstant::try_new)
                .transpose()?;
            let not_on_or_after = optional_authn_statement_str(statement, "sessionNotOnOrAfter")?
                .map(SamlInstant::try_new)
                .transpose()?;
            Ok(AuthnSession::new(
                session_index,
                authn_instant,
                not_on_or_after,
            ))
        })
        .collect()
}

pub(super) fn entity_ids_from_value(value: Option<&Value>) -> Result<Vec<EntityId>, SamlError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    value_strings(value)
        .into_iter()
        .map(EntityId::from_peer)
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
