use crate::browser::{
    field_value, parse_form_fields, AcsEndpoint, Inbound, SsoResponseBinding, Transport,
};
use crate::config::{EntityId, HmacSecret, IdpDescriptor, SpDescriptor};
use crate::constants::{url_params, Binding};
use crate::idp;
use crate::metadata::{DefaultMarking, Metadata};
use crate::model::RelayState;
use crate::sp;
use std::time::SystemTime;

use super::SamlError;

pub(super) fn idp_engine_at(
    idp: &IdpDescriptor,
    now: SystemTime,
) -> Result<&idp::Engine, SamlError> {
    idp.ensure_valid_at(now)?;
    Ok(idp.provider())
}

pub(super) fn sp_engine_at(sp: &SpDescriptor, now: SystemTime) -> Result<&sp::Engine, SamlError> {
    sp.ensure_valid_at(now)?;
    Ok(sp.provider())
}

#[derive(Clone, Copy)]
pub(super) struct Peer<'a> {
    pub(super) entity_id: &'a EntityId,
    pub(super) metadata: &'a Metadata,
    pub(super) hmac_secret: Option<&'a HmacSecret>,
}

impl<'a> Peer<'a> {
    pub(super) fn from_idp(idp: &'a IdpDescriptor, now: SystemTime) -> Result<Self, SamlError> {
        let engine = idp_engine_at(idp, now)?;
        Ok(Self {
            entity_id: idp.entity_id(),
            metadata: engine.metadata.as_metadata(),
            hmac_secret: engine.setting.hmac_secret.as_ref(),
        })
    }

    pub(super) fn from_sp(sp: &'a SpDescriptor, now: SystemTime) -> Result<Self, SamlError> {
        let engine = sp_engine_at(sp, now)?;
        Ok(Self {
            entity_id: sp.entity_id(),
            metadata: engine.metadata.as_metadata(),
            hmac_secret: engine.setting.hmac_secret.as_ref(),
        })
    }
}

pub(super) fn selected_acs(
    sp: &sp::Engine,
    requested_binding: Option<SsoResponseBinding>,
    index: Option<u16>,
) -> Result<AcsEndpoint, SamlError> {
    if let Some(index) = index {
        let endpoint = sp
            .metadata
            .assertion_consumer_service_by_index(index)?
            .ok_or_else(|| SamlError::MissingMetadata("AssertionConsumerService".into()))?;
        let binding = SsoResponseBinding::try_from(endpoint.binding)?;
        if let Some(requested_binding) = requested_binding {
            if requested_binding != binding {
                return Err(SamlError::Invalid(
                    "AssertionConsumerServiceIndex binding does not match response_binding".into(),
                ));
            }
        }
        let acs = AcsEndpoint::new(
            binding,
            crate::model::EndpointUrl::try_new(endpoint.location)?,
        )
        .with_index(index);
        return Ok(marked_default(acs, endpoint.is_default));
    }

    let binding = requested_binding.unwrap_or(SsoResponseBinding::Post);
    let endpoint = sp
        .metadata
        .assertion_consumer_service_endpoint(Binding::from(binding))
        .ok_or_else(|| SamlError::MissingMetadata("AssertionConsumerService".into()))?;
    let acs = AcsEndpoint::new(
        binding,
        crate::model::EndpointUrl::try_new(endpoint.location)?,
    );
    Ok(marked_default(acs, endpoint.is_default))
}

fn marked_default(acs: AcsEndpoint, is_default: DefaultMarking) -> AcsEndpoint {
    match is_default {
        DefaultMarking::Default => acs.with_default(),
        DefaultMarking::Unmarked | DefaultMarking::NotDefault => acs,
    }
}

pub(super) fn relay_state_from_input<Message>(
    input: &Inbound<Message>,
) -> Result<Option<RelayState>, SamlError> {
    let received = |value: Option<&str>| {
        value
            .map(|value| RelayState::received(value.to_string()))
            .transpose()
    };
    match &input.transport {
        Transport::Redirect { raw_query } => {
            let params = parse_form_fields(raw_query.trim_start_matches('?'));
            received(field_value(&params, url_params::RELAY_STATE)?)
        }
        Transport::Post { fields } | Transport::SimpleSign { fields } => {
            received(field_value(fields, url_params::RELAY_STATE)?)
        }
        Transport::Artifact { delivered, .. } => Ok(delivered.relay_state().cloned()),
        Transport::Soap { .. } => Ok(None),
    }
}

pub(super) fn ensure_relay_state(
    expected: Option<&RelayState>,
    actual: Option<&RelayState>,
) -> Result<(), SamlError> {
    if expected.is_none() || expected == actual {
        return Ok(());
    }
    Err(SamlError::RelayStateMismatch {
        expected: expected.cloned(),
        actual: actual.cloned(),
    })
}

pub(super) fn ensure_entity_id(expected: &EntityId, actual: &EntityId) -> Result<(), SamlError> {
    if expected == actual {
        return Ok(());
    }
    Err(SamlError::issuer_mismatch(
        expected.as_str(),
        Some(actual.as_str()),
    ))
}

pub(super) fn ensure_https_endpoint(
    endpoint: &str,
    profile: &str,
    service: &str,
) -> Result<(), SamlError> {
    let url = url::Url::parse(endpoint)
        .map_err(|error| SamlError::Invalid(format!("{service} location is not a URL: {error}")))?;
    if url.scheme() == "https" {
        return Ok(());
    }
    Err(SamlError::ProtocolProfile(format!(
        "{profile} sends the user agent to an https {service} unless allow_http is selected"
    )))
}

pub(super) fn ensure_sso_response_binding(
    actual: Binding,
    expected: SsoResponseBinding,
) -> Result<(), SamlError> {
    if actual == Binding::from(expected) {
        return Ok(());
    }
    Err(SamlError::UnsupportedBinding { binding: actual })
}
