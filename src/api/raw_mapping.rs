use crate::browser::{
    field_value, parse_form_fields, AcsEndpoint, BrowserInput, SsoResponseBinding,
};
use crate::config::{
    name_id_format_uris, AuthnRequestSigningPolicy, AuthnRequestValidationPolicy, Credentials,
    EntityId, HmacSecret, IdpConfig, IdpDescriptor, ManageNameIdService, SpConfig, SpDescriptor,
};
use crate::constants::{url_params, Binding};
use crate::entity::User;
use crate::error::SamlError as Error;
use crate::idp::IdentityProvider;
use crate::metadata::{
    ArtifactResolutionEndpoint, IdpMetadataConfig as RawIdpMetadataConfig, Metadata,
    SpMetadataConfig as RawSpMetadataConfig,
};
use crate::model::{RelayStateParam, Subject};
use crate::sp::ServiceProvider;
use std::time::SystemTime;

use super::SamlError;

pub(super) fn raw_sp_metadata_config(config: &SpConfig) -> RawSpMetadataConfig {
    RawSpMetadataConfig {
        entity_id: config.entity_id.as_str().to_string(),
        signing_certs: signing_certificates(&config.credentials),
        encrypt_certs: encryption_certificates(&config.credentials),
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
        manage_name_id_service: config
            .metadata
            .manage_name_id_service
            .iter()
            .map(ManageNameIdService::to_raw)
            .collect(),
        elements_order: config.metadata.elements_order.clone(),
        lifetime: config.metadata.lifetime,
    }
}

pub(super) fn raw_idp_metadata_config(config: &IdpConfig) -> RawIdpMetadataConfig {
    RawIdpMetadataConfig {
        entity_id: config.entity_id.as_str().to_string(),
        signing_certs: signing_certificates(&config.credentials),
        encrypt_certs: encryption_certificates(&config.credentials),
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
        manage_name_id_service: config
            .metadata
            .manage_name_id_service
            .iter()
            .map(ManageNameIdService::to_raw)
            .collect(),
        elements_order: config.metadata.elements_order.clone(),
        lifetime: config.metadata.lifetime,
    }
}

fn signing_certificates(credentials: &Credentials) -> Vec<String> {
    credentials
        .signing_certificate
        .iter()
        .chain(&credentials.additional_signing_certificates)
        .map(|certificate| certificate.as_str().to_string())
        .collect()
}

fn encryption_certificates(credentials: &Credentials) -> Vec<String> {
    credentials
        .encryption_certificate
        .iter()
        .chain(
            credentials
                .additional_decryption_keys
                .iter()
                .map(|credential| &credential.certificate),
        )
        .map(|certificate| certificate.as_str().to_string())
        .collect()
}

pub(super) fn raw_idp_descriptor(
    idp: &IdpDescriptor,
    now: SystemTime,
) -> Result<&IdentityProvider, SamlError> {
    idp.ensure_valid_at(now)?;
    Ok(idp.provider())
}

pub(super) fn raw_sp_descriptor(
    sp: &SpDescriptor,
    now: SystemTime,
) -> Result<&ServiceProvider, SamlError> {
    sp.ensure_valid_at(now)?;
    Ok(sp.provider())
}

#[derive(Clone, Copy)]
pub(super) struct RawPeer<'a> {
    pub(super) entity_id: &'a EntityId,
    pub(super) metadata: &'a Metadata,
    pub(super) hmac_secret: Option<&'a HmacSecret>,
}

impl<'a> RawPeer<'a> {
    pub(super) fn from_idp(idp: &'a IdpDescriptor, now: SystemTime) -> Result<Self, SamlError> {
        let raw = raw_idp_descriptor(idp, now)?;
        Ok(Self {
            entity_id: idp.entity_id(),
            metadata: &raw.metadata,
            hmac_secret: raw.setting.hmac_secret.as_ref(),
        })
    }

    pub(super) fn from_sp(sp: &'a SpDescriptor, now: SystemTime) -> Result<Self, SamlError> {
        let raw = raw_sp_descriptor(sp, now)?;
        Ok(Self {
            entity_id: sp.entity_id(),
            metadata: &raw.metadata,
            hmac_secret: raw.setting.hmac_secret.as_ref(),
        })
    }
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

pub(super) fn input_binding<Message>(input: &BrowserInput<Message>) -> Binding {
    match input {
        BrowserInput::Redirect { .. } => Binding::Redirect,
        BrowserInput::Post { .. } => Binding::Post,
        BrowserInput::SimpleSignPost { .. } => Binding::SimpleSign,
        BrowserInput::Artifact { .. } => Binding::Artifact,
        BrowserInput::Soap { .. } => Binding::Soap,
    }
}

pub(super) fn relay_state_from_input<Message>(
    input: &BrowserInput<Message>,
) -> Result<RelayStateParam, SamlError> {
    match input {
        BrowserInput::Redirect { raw_query, .. } => {
            let params = parse_form_fields(raw_query.trim_start_matches('?'));
            RelayStateParam::received(
                field_value(&params, url_params::RELAY_STATE)?.map(str::to_string),
            )
        }
        BrowserInput::Post { fields, .. } | BrowserInput::SimpleSignPost { fields, .. } => {
            RelayStateParam::received(
                field_value(fields, url_params::RELAY_STATE)?.map(str::to_string),
            )
        }
        BrowserInput::Artifact { delivered, .. } => Ok(delivered.relay_state().clone()),
        BrowserInput::Soap { .. } => Ok(RelayStateParam::absent()),
    }
}

pub(super) fn ensure_relay_state(
    expected: &RelayStateParam,
    actual: &RelayStateParam,
) -> Result<(), SamlError> {
    if *expected == RelayStateParam::Absent || expected == actual {
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

pub(super) fn ensure_https_endpoint(
    endpoint: &str,
    profile: &str,
    service: &str,
    policy_option: &str,
) -> Result<(), SamlError> {
    let url = url::Url::parse(endpoint)
        .map_err(|error| Error::Invalid(format!("{service} location is not a URL: {error}")))?;
    if url.scheme() == "https" {
        return Ok(());
    }
    Err(Error::ProtocolProfile(format!(
        "{profile} sends the user agent to an https {service} unless {policy_option} is selected"
    )))
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

pub(super) fn user_from_subject(subject: &Subject) -> Result<User, SamlError> {
    if !subject.confirmations().is_empty() {
        return Err(Error::Unsupported(
            "an issued assertion takes no caller-supplied SubjectConfirmation; the identity provider writes its own bearer confirmation".into(),
        ));
    }
    Ok(User::new(subject.name_id().value()))
}
