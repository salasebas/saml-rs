use super::AuthnRequestXml;
use crate::template::replace_tags_by_optional_value;

pub(super) fn render(template: &str, request: &AuthnRequestXml<'_>) -> String {
    replace_tags_by_optional_value(
        template,
        &[
            ("ID", Some(request.id.to_owned())),
            ("IssueInstant", Some(request.issue_instant.to_owned())),
            ("Destination", Some(request.destination.to_owned())),
            (
                "ForceAuthn",
                request.force_authn.map(|value| value.to_string()),
            ),
            (
                "ProtocolBinding",
                request.protocol_binding.map(str::to_owned),
            ),
            (
                "AssertionConsumerServiceURL",
                request.assertion_consumer_service_url.map(str::to_owned),
            ),
            (
                "AssertionConsumerServiceIndex",
                request
                    .assertion_consumer_service_index
                    .map(|value| value.to_string()),
            ),
            ("Issuer", Some(request.issuer.to_owned())),
            ("NameIDFormat", request.name_id_format.map(str::to_owned)),
            ("AllowCreate", Some(request.allow_create.to_string())),
        ],
    )
}
