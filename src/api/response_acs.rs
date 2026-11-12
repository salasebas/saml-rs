use crate::browser::SsoResponseBinding;
use crate::metadata::SpMetadata;
use crate::model::AuthnRequest;

use super::SamlError;

pub(super) enum ResponseAcsBindings {
    Browser(SsoResponseBinding),
    Paos,
}

pub(super) fn resolve_response_acs(
    metadata: &SpMetadata,
    request: Option<&AuthnRequest>,
    bindings: ResponseAcsBindings,
) -> Result<String, SamlError> {
    let acs_url = request.and_then(AuthnRequest::acs_url);
    let acs_index = request.and_then(AuthnRequest::acs_index);
    if acs_url.is_some() && acs_index.is_some() {
        return Err(SamlError::Invalid(
            match bindings {
                ResponseAcsBindings::Browser(_) => {
                    "AuthnRequest must not specify both ACS URL and ACS index"
                }
                ResponseAcsBindings::Paos => {
                    "AuthnRequest must not specify both an assertion consumer URL and an index"
                }
            }
            .into(),
        ));
    }
    let protocol_binding = request.and_then(AuthnRequest::protocol_binding);
    if let ResponseAcsBindings::Browser(selected) = bindings {
        if protocol_binding.is_some_and(|binding| binding != selected) {
            return Err(SamlError::Invalid(
                "response binding conflicts with AuthnRequest ProtocolBinding".into(),
            ));
        }
    }

    if let Some(url) = acs_url {
        match bindings {
            ResponseAcsBindings::Browser(binding) => {
                if !metadata.has_assertion_consumer_service(binding.as_binding(), url.as_str()) {
                    return Err(SamlError::destination_mismatch(
                        url.as_str(),
                        metadata
                            .get_assertion_consumer_service(binding.as_binding())
                            .as_deref(),
                    ));
                }
            }
            ResponseAcsBindings::Paos => {
                if !metadata
                    .assertion_consumer_locations()
                    .iter()
                    .any(|location| location == url.as_str())
                {
                    return Err(SamlError::Invalid(
                        "AuthnRequest AssertionConsumerServiceURL is not published for HTTP-POST or HTTP-POST-SimpleSign in service provider metadata"
                            .into(),
                    ));
                }
            }
        }
        return Ok(url.as_str().to_string());
    }

    let endpoint = if let Some(index) = acs_index {
        metadata.get_assertion_consumer_service_by_index(index)?
    } else if let (ResponseAcsBindings::Browser(binding), Some(_)) = (&bindings, protocol_binding) {
        metadata.get_assertion_consumer_service_endpoint(binding.as_binding())
    } else {
        metadata.get_default_assertion_consumer_service_endpoint()?
    }
    .ok_or_else(|| SamlError::MissingMetadata("AssertionConsumerService".into()))?;

    match bindings {
        ResponseAcsBindings::Browser(binding) => {
            if acs_index.is_some() {
                let indexed_binding = SsoResponseBinding::try_from(endpoint.binding)?;
                if indexed_binding != binding {
                    return Err(SamlError::Invalid(
                        "response binding conflicts with AuthnRequest ACS index".into(),
                    ));
                }
            } else if endpoint.binding != binding.as_binding() {
                return Err(SamlError::Invalid(
                    "response binding conflicts with default AssertionConsumerService".into(),
                ));
            }
        }
        ResponseAcsBindings::Paos => {
            if !endpoint.accepts_posted_response() {
                return Err(SamlError::Invalid(
                    "AuthnRequest AssertionConsumerServiceIndex, or the default assertion consumer when the request names none, is not HTTP-POST or HTTP-POST-SimpleSign in service provider metadata"
                        .into(),
                ));
            }
        }
    }
    Ok(endpoint.location)
}
