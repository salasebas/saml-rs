use super::LoginResponseXml;
use crate::error::SamlError;
use crate::template::{
    apply_tag_prefixes, attr_tag, build_attribute_statement, login_response_attribute_value,
    replace_tags_by_optional_value, ATTRIBUTE_STATEMENT_TEMPLATE, ATTRIBUTE_TEMPLATE,
};

pub(super) fn render(template: &str, response: &LoginResponseXml<'_>) -> Result<String, SamlError> {
    let attributes = if response.attributes.is_empty() {
        String::new()
    } else {
        build_attribute_statement(
            response.attributes,
            ATTRIBUTE_TEMPLATE,
            ATTRIBUTE_STATEMENT_TEMPLATE,
        )
    };
    let template = apply_tag_prefixes(
        &template.replacen("{AttributeStatement}", &attributes, 1),
        response.protocol_prefix,
        response.assertion_prefix,
    );
    let mut tags = vec![
        ("ID", Some(response.response_id.to_owned())),
        ("AssertionID", Some(response.assertion_id.to_owned())),
        ("Destination", Some(response.destination.to_owned())),
        (
            "SubjectRecipient",
            Some(response.subject_recipient.to_owned()),
        ),
        (
            "AssertionConsumerServiceURL",
            Some(response.destination.to_owned()),
        ),
        ("Audience", Some(response.audience.to_owned())),
        ("Issuer", Some(response.issuer.to_owned())),
        ("IssueInstant", Some(response.issue_instant.to_owned())),
        (
            "StatusCode",
            Some(response.status.top_level().as_uri().to_owned()),
        ),
        (
            "ConditionsNotBefore",
            Some(response.conditions_not_before.to_owned()),
        ),
        (
            "ConditionsNotOnOrAfter",
            Some(response.conditions_not_on_or_after.to_owned()),
        ),
        (
            "SubjectConfirmationDataNotOnOrAfter",
            Some(response.subject_confirmation_not_on_or_after.to_owned()),
        ),
        ("NameID", Some(response.name_id.to_owned())),
        ("AuthnStatement", Some(String::new())),
        ("NameIDFormat", response.name_id_format.map(str::to_owned)),
        ("InResponseTo", response.in_response_to.map(str::to_owned)),
    ];
    let values = response
        .attributes
        .iter()
        .map(|attr| {
            Ok((
                attr_tag(&attr.value_tag),
                login_response_attribute_value(attr, response.user_attributes)?.to_owned(),
            ))
        })
        .collect::<Result<Vec<_>, SamlError>>()?;
    tags.extend(
        values
            .iter()
            .map(|(tag, value)| (tag.as_str(), Some(value.clone()))),
    );
    Ok(replace_tags_by_optional_value(&template, &tags))
}
