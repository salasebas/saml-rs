use crate::browser::SsoResponseBinding;
use crate::constants::Binding;
use crate::metadata::SpMetadata;
use crate::model::AuthnRequest;

use super::SamlError;

pub(super) fn resolve_response_acs(
    metadata: &SpMetadata,
    request: Option<&AuthnRequest>,
    binding: SsoResponseBinding,
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

    let endpoint = if let Some(index) = acs_index {
        metadata.assertion_consumer_service_by_index(index)?
    } else if protocol_binding.is_some() {
        metadata.assertion_consumer_service_endpoint(Binding::from(binding))
    } else {
        metadata.default_assertion_consumer_service_endpoint()?
    }
    .ok_or_else(|| SamlError::MissingMetadata("AssertionConsumerService".into()))?;

    if acs_index.is_some() {
        let indexed_binding = SsoResponseBinding::try_from(endpoint.binding)?;
        if indexed_binding != binding {
            return Err(SamlError::Invalid(
                "response binding conflicts with AuthnRequest ACS index".into(),
            ));
        }
    } else if endpoint.binding != Binding::from(binding) {
        return Err(SamlError::Invalid(
            "response binding conflicts with default AssertionConsumerService".into(),
        ));
    }
    Ok(endpoint.location)
}
