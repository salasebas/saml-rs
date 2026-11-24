use crate::browser::SsoResponseBinding;
use crate::constants::Binding;
use crate::metadata::SpMetadata;
use crate::model::AuthnRequest;

use super::{SamlError, SsoOutcome};

pub(super) fn resolve_response_acs(
    metadata: &SpMetadata,
    request: Option<&AuthnRequest>,
    binding: SsoResponseBinding,
    outcome: &SsoOutcome,
) -> Result<String, SamlError> {
    let acs_url = request.and_then(AuthnRequest::acs_url);
    let acs_index = request.and_then(AuthnRequest::acs_index);
    if acs_url.is_some() && acs_index.is_some() {
        return Err(SamlError::Invalid(
            "AuthnRequest must not specify both ACS URL and ACS index".into(),
        ));
    }
    let protocol_binding = request.and_then(AuthnRequest::protocol_binding);
    if protocol_binding.is_some_and(|requested| requested != binding) {
        return Err(SamlError::Invalid(
            "response binding conflicts with AuthnRequest ProtocolBinding".into(),
        ));
    }

    if let Some(url) = acs_url {
        if !metadata.has_assertion_consumer_service(Binding::from(binding), url.as_str()) {
            return Err(SamlError::destination_mismatch(
                url.as_str(),
                metadata
                    .assertion_consumer_location(Binding::from(binding))
                    .as_deref(),
            ));
        }
        return Ok(url.as_str().to_string());
    }

    if let Some(index) = acs_index {
        if let Some(endpoint) = metadata.assertion_consumer_service_by_index(index)? {
            if SsoResponseBinding::try_from(endpoint.binding)? != binding {
                return Err(SamlError::Invalid(
                    "response binding conflicts with AuthnRequest ACS index".into(),
                ));
            }
            return Ok(endpoint.location);
        }
        if protocol_binding.is_some() || !matches!(outcome, SsoOutcome::Failure(_)) {
            return Err(SamlError::MissingMetadata(
                "AssertionConsumerService".into(),
            ));
        }
    }

    let endpoint = if protocol_binding.is_some() {
        metadata.assertion_consumer_service_endpoint(Binding::from(binding))
    } else {
        metadata.default_assertion_consumer_service_endpoint()?
    }
    .ok_or_else(|| SamlError::MissingMetadata("AssertionConsumerService".into()))?;

    if endpoint.binding != Binding::from(binding) {
        return Err(SamlError::Invalid(
            "response binding conflicts with default AssertionConsumerService".into(),
        ));
    }
    Ok(endpoint.location)
}
