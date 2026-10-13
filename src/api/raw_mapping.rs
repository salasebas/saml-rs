use crate::browser::{AcsEndpoint, BrowserInput, SsoResponseBinding};
use crate::config::{
    AuthnRequestSigningPolicy, AuthnRequestValidationPolicy, CertificatePem, EntityId, IdpConfig,
    IdpDescriptor, NameIdFormat, SpConfig, SpDescriptor,
};
use crate::constants::Binding;
use crate::entity::EntitySetting;
use crate::error::SamlError as Error;
use crate::idp::IdentityProvider;
use crate::metadata::{
    ArtifactResolutionEndpoint, IdpMetadataConfig as RawIdpMetadataConfig,
    SpMetadataConfig as RawSpMetadataConfig,
};
use crate::model::{AuthnRequest, RelayStateParam};
use crate::sp::ServiceProvider;

use super::SamlError;

pub(super) fn raw_sp_metadata_config(config: &SpConfig) -> RawSpMetadataConfig {
    RawSpMetadataConfig {
        entity_id: config.entity_id.as_str().to_string(),
        signing_certs: certificates(&config.credentials.signing_certificate),
        encrypt_certs: certificates(&config.credentials.encryption_certificate),
        authn_requests_signed: matches!(
            config.validation.authn_requests,
            AuthnRequestSigningPolicy::Sign
        ),
        want_assertions_signed: matches!(
            config.validation.assertions,
            crate::config::AssertionSignaturePolicy::RequireSigned
        ),
        name_id_format: name_id_format_uris(&config.metadata.name_id_format),
        single_logout_service: config
            .metadata
            .single_logout_service
            .iter()
            .map(|endpoint| endpoint.to_raw())
            .collect(),
        assertion_consumer_service: config
            .metadata
            .assertion_consumer_service
            .iter()
            .map(|endpoint| endpoint.to_raw())
            .collect(),
        elements_order: config.metadata.elements_order.clone(),
    }
}

pub(super) fn raw_idp_metadata_config(config: &IdpConfig) -> RawIdpMetadataConfig {
    RawIdpMetadataConfig {
        entity_id: config.entity_id.as_str().to_string(),
        signing_certs: certificates(&config.credentials.signing_certificate),
        encrypt_certs: certificates(&config.credentials.encryption_certificate),
        want_authn_requests_signed: matches!(
            config.validation.authn_requests,
            AuthnRequestValidationPolicy::RequireSigned
        ),
        name_id_format: name_id_format_uris(&config.metadata.name_id_format),
        single_sign_on_service: config
            .metadata
            .single_sign_on_service
            .iter()
            .map(|endpoint| endpoint.to_raw())
            .collect(),
        single_logout_service: config
            .metadata
            .single_logout_service
            .iter()
            .map(|endpoint| endpoint.to_raw())
            .collect(),
        artifact_resolution_service: config
            .metadata
            .artifact_resolution_service
            .iter()
            .map(|service| ArtifactResolutionEndpoint {
                index: service.index(),
                location: service.location().as_str().to_string(),
            })
            .collect(),
        elements_order: config.metadata.elements_order.clone(),
    }
}

fn certificates(certificate: &Option<CertificatePem>) -> Vec<String> {
    certificate
        .as_ref()
        .map(|certificate| vec![certificate.as_str().to_string()])
        .unwrap_or_default()
}

fn name_id_format_uris(formats: &[NameIdFormat]) -> Vec<String> {
    formats
        .iter()
        .map(|format| format.as_uri().to_string())
        .collect()
}

pub(super) fn raw_idp_descriptor(idp: &IdpDescriptor) -> Result<IdentityProvider, SamlError> {
    IdentityProvider::from_metadata(idp.metadata_xml(), EntitySetting::default())
}

pub(super) fn raw_sp_descriptor(sp: &SpDescriptor) -> Result<ServiceProvider, SamlError> {
    ServiceProvider::from_metadata(sp.metadata_xml(), EntitySetting::default())
}

pub(super) fn selected_acs(
    sp: &ServiceProvider,
    requested_binding: Option<SsoResponseBinding>,
    index: Option<u16>,
) -> Result<AcsEndpoint, SamlError> {
    if let Some(index) = index {
        let endpoint = sp
            .metadata
            .get_assertion_consumer_service_by_index(index)?
            .ok_or_else(|| Error::MissingMetadata("AssertionConsumerService".into()))?;
        let binding = SsoResponseBinding::try_from(endpoint.binding)?;
        if let Some(requested_binding) = requested_binding {
            if requested_binding != binding {
                return Err(Error::Invalid(
                    "AssertionConsumerServiceIndex binding does not match response_binding".into(),
                ));
            }
        }
        return Ok(AcsEndpoint::new(
            binding,
            crate::model::EndpointUrl::try_new(endpoint.location)?,
        )
        .with_index(index)
        .with_default_flag(endpoint.is_default));
    }

    let binding = requested_binding.unwrap_or(SsoResponseBinding::Post);
    let endpoint = sp
        .metadata
        .get_assertion_consumer_service_endpoint(binding.as_binding())
        .ok_or_else(|| Error::MissingMetadata("AssertionConsumerService".into()))?;
    Ok(AcsEndpoint::new(
        binding,
        crate::model::EndpointUrl::try_new(endpoint.location)?,
    )
    .with_default_flag(endpoint.is_default))
}

pub(super) fn response_target(
    sp: &ServiceProvider,
    request: &AuthnRequest,
    selected_binding: SsoResponseBinding,
) -> Result<(SsoResponseBinding, Option<String>), SamlError> {
    if request.acs_url().is_some() && request.acs_index().is_some() {
        return Err(Error::Invalid(
            "AuthnRequest must not specify both ACS URL and ACS index".into(),
        ));
    }
    if let Some(protocol_binding) = request.protocol_binding() {
        if protocol_binding != selected_binding {
            return Err(Error::Invalid(
                "response binding conflicts with AuthnRequest ProtocolBinding".into(),
            ));
        }
    }
    let binding = request.protocol_binding().unwrap_or(selected_binding);

    if let Some(acs_url) = request.acs_url() {
        if !sp
            .metadata
            .has_assertion_consumer_service(binding.as_binding(), acs_url.as_str())
        {
            return Err(Error::destination_mismatch(
                acs_url.as_str(),
                sp.metadata
                    .get_assertion_consumer_service(binding.as_binding())
                    .as_deref(),
            ));
        }
        return Ok((binding, Some(acs_url.as_str().to_string())));
    }

    if let Some(index) = request.acs_index() {
        let endpoint = sp
            .metadata
            .get_assertion_consumer_service_by_index(index)?
            .ok_or_else(|| Error::MissingMetadata("AssertionConsumerService".into()))?;
        let indexed_binding = SsoResponseBinding::try_from(endpoint.binding)?;
        if indexed_binding != binding {
            return Err(Error::Invalid(
                "response binding conflicts with AuthnRequest ACS index".into(),
            ));
        }
        return Ok((binding, Some(endpoint.location)));
    }

    if request.protocol_binding().is_none() {
        return default_response_target(sp, binding);
    }

    Ok((binding, None))
}

pub(super) fn default_response_target(
    sp: &ServiceProvider,
    selected_binding: SsoResponseBinding,
) -> Result<(SsoResponseBinding, Option<String>), SamlError> {
    let endpoint = sp
        .metadata
        .get_default_assertion_consumer_service_endpoint()?
        .ok_or_else(|| Error::MissingMetadata("AssertionConsumerService".into()))?;
    if endpoint.binding != selected_binding.as_binding() {
        return Err(Error::Invalid(
            "response binding conflicts with default AssertionConsumerService".into(),
        ));
    }
    Ok((selected_binding, Some(endpoint.location)))
}

pub(super) fn input_binding<Message>(input: &BrowserInput<Message>) -> Binding {
    match input {
        BrowserInput::Redirect { .. } => Binding::Redirect,
        BrowserInput::Post { .. } => Binding::Post,
        BrowserInput::SimpleSignPost { .. } => Binding::SimpleSign,
    }
}

pub(super) fn relay_state_from_input<Message>(
    input: &BrowserInput<Message>,
) -> Result<RelayStateParam, SamlError> {
    match input {
        BrowserInput::Redirect { raw_query, .. } => {
            let value = url::form_urlencoded::parse(raw_query.trim_start_matches('?').as_bytes())
                .find(|(name, _)| name == "RelayState")
                .map(|(_, value)| value.into_owned());
            RelayStateParam::try_from_option(value)
        }
        BrowserInput::Post { fields, .. } | BrowserInput::SimpleSignPost { fields, .. } => {
            let value = fields
                .iter()
                .find(|field| field.name() == "RelayState")
                .map(|field| field.value().to_string());
            RelayStateParam::try_from_option(value)
        }
    }
}

pub(super) fn ensure_relay_state(
    expected: &RelayStateParam,
    actual: &RelayStateParam,
) -> Result<(), SamlError> {
    if expected == actual {
        return Ok(());
    }
    Err(Error::RelayStateMismatch {
        expected: expected.clone(),
        actual: actual.clone(),
    })
}

pub(super) fn ensure_entity_id(expected: &EntityId, actual: &EntityId) -> Result<(), SamlError> {
    if expected == actual {
        return Ok(());
    }
    Err(Error::issuer_mismatch(
        expected.as_str(),
        Some(actual.as_str()),
    ))
}

pub(super) fn ensure_sso_response_binding(
    actual: Binding,
    expected: SsoResponseBinding,
) -> Result<(), SamlError> {
    if actual == expected.as_binding() {
        return Ok(());
    }
    Err(Error::UnsupportedBinding { binding: actual })
}
