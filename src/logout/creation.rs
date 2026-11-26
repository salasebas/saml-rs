use crate::binding::sign_message;
use crate::config::IdentifierEncryptionPolicy;
use crate::constants::{Binding, ParserType};
use crate::entity::{generate_id, now_iso8601, BindingContext, EntitySetting};
use crate::error::SamlError;
use crate::metadata::Metadata;
use crate::model::{validate_issued_name_id, validate_name_id_format, Status};
use crate::xml::any_uri::{collapse_whitespace, is_absolute_uri_reference};
use crate::xml::dom::is_xml_whitespace_char;
use crate::xml::{
    validate_logout_request_outbound, validate_logout_response_outbound, OutboundLogoutExpiration,
    OutboundLogoutRequestExpectation, OutboundLogoutRequestValidation, OutboundLogoutValidation,
};

use super::encrypted_id::encrypt_name_id_for_peer;
use super::rendering::{
    issuer_of, render_logout_request, render_logout_response, LogoutRequestAttributes,
    LogoutRequestSubject, LogoutResponseAttributes,
};

const SESSION_AUTHORITY_REASONS: [&str; 2] = [
    "urn:oasis:names:tc:SAML:2.0:logout:global-timeout",
    "urn:oasis:names:tc:SAML:2.0:logout:sp-timeout",
];

pub(crate) struct CreatedLogoutRequest {
    pub(crate) context: BindingContext,
    pub(crate) not_on_or_after: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum LogoutRequestValidation {
    SessionParticipant,
    SessionAuthority,
}

pub(crate) struct LogoutRequestInput<'a> {
    pub(crate) init_setting: &'a EntitySetting,
    pub(crate) init_meta: &'a Metadata,
    pub(crate) target_meta: &'a Metadata,
    pub(crate) target_role: usize,
    pub(crate) binding: Binding,
    pub(crate) destination: &'a str,
    pub(crate) subject: &'a LogoutRequestSubject<'a>,
    pub(crate) relay_state: Option<&'a str>,
    pub(crate) name_id_format: Option<&'a str>,
    pub(crate) issue_instant: &'a str,
    pub(crate) not_on_or_after: Option<&'a str>,
    pub(crate) reason: Option<&'a str>,
    pub(crate) asynchronous: bool,
    pub(crate) validation: LogoutRequestValidation,
    pub(crate) name_id_encryption: IdentifierEncryptionPolicy,
}

pub(crate) fn create_logout_request_for_subject_inner(
    input: &LogoutRequestInput<'_>,
) -> Result<CreatedLogoutRequest, SamlError> {
    let LogoutRequestInput {
        init_setting,
        init_meta,
        target_meta,
        target_role,
        binding,
        destination,
        subject,
        relay_state,
        name_id_format,
        issue_instant,
        not_on_or_after,
        reason,
        asynchronous,
        validation,
        name_id_encryption,
    } = *input;

    reject_soap_relay_state(binding, relay_state)?;
    validate_name_id_format(name_id_format)?;
    match validation {
        LogoutRequestValidation::SessionAuthority => {
            validate_issued_name_id(name_id_format, subject.name_id, subject.qualifiers)?;
        }
        LogoutRequestValidation::SessionParticipant => {}
    }
    if reason.is_some_and(|value| !is_absolute_uri_reference(value)) {
        return Err(SamlError::Invalid(
            "a LogoutRequest reason must be an absolute URI reference".into(),
        ));
    }
    let reason = reason.map(collapse_whitespace);
    let reason = reason.as_deref();
    if let (LogoutRequestValidation::SessionParticipant, Some(reason)) = (validation, reason) {
        if SESSION_AUTHORITY_REASONS.contains(&reason) {
            return Err(SamlError::Invalid(format!(
                "a session participant LogoutRequest cannot use the session authority reason {reason}"
            )));
        }
    }
    if matches!(validation, LogoutRequestValidation::SessionParticipant)
        && subject.session_indexes.is_empty()
    {
        return Err(SamlError::ProtocolProfile(
            "a session participant LogoutRequest must include at least one SessionIndex".into(),
        ));
    }
    let id = generate_id();
    let issuer = issuer_of(init_setting, init_meta);
    let xml = render_logout_request(
        init_setting,
        &issuer,
        &LogoutRequestAttributes {
            id: &id,
            destination,
            issue_instant,
            not_on_or_after,
            reason,
            asynchronous,
        },
        subject,
        name_id_format,
    )?;
    let session_indexes = subject.session_indexes.as_slice();
    let expiration = match validation {
        LogoutRequestValidation::SessionParticipant => OutboundLogoutExpiration::Optional,
        LogoutRequestValidation::SessionAuthority => {
            OutboundLogoutExpiration::Required(not_on_or_after.ok_or_else(|| {
                SamlError::Invalid(
                    "Session Authority LogoutRequest is missing its generated expiration".into(),
                )
            })?)
        }
    };
    let expectation = OutboundLogoutRequestExpectation {
        id: &id,
        issue_instant,
        destination,
        issuer: &issuer,
        expiration,
        reason,
        name_id: subject.name_id,
        name_id_format,
        name_id_qualifiers: subject.qualifiers,
        session_indexes,
    };
    validate_logout_request_outbound(
        &xml,
        &expectation,
        OutboundLogoutRequestValidation::BeforeSigning,
    )?;
    let xml = encrypt_name_id_for_peer(
        xml,
        name_id_encryption,
        init_setting,
        target_meta,
        target_role,
    )?;
    let signed = sign_message(
        init_setting,
        binding,
        &xml,
        destination,
        relay_state,
        ParserType::LogoutRequest,
    )?;
    if let Some(signed_xml) = embedded_signed_xml(binding, &signed.content)? {
        validate_logout_request_outbound(
            &signed_xml,
            &expectation,
            OutboundLogoutRequestValidation::AfterEmbeddedSigning(name_id_encryption),
        )?;
    }
    Ok(CreatedLogoutRequest {
        context: signed.bind(id, destination.to_owned(), relay_state),
        not_on_or_after: not_on_or_after.map(str::to_string),
    })
}

pub(crate) struct LogoutResponseInput<'a> {
    pub(crate) init_setting: &'a EntitySetting,
    pub(crate) init_meta: &'a Metadata,
    pub(crate) binding: Binding,
    pub(crate) destination: Option<&'a str>,
    pub(crate) in_response_to: Option<&'a str>,
    pub(crate) relay_state: Option<&'a str>,
    pub(crate) status: &'a Status,
    pub(crate) status_message: Option<&'a str>,
}

pub(crate) struct RenderedLogoutResponse {
    pub(crate) id: String,
    pub(crate) xml: String,
    pub(crate) destination: Option<String>,
    issuer: String,
}

impl LogoutResponseInput<'_> {
    pub(crate) fn render(&self) -> Result<RenderedLogoutResponse, SamlError> {
        let Self {
            init_setting,
            init_meta,
            binding,
            destination,
            in_response_to,
            relay_state,
            status,
            status_message,
        } = *self;
        if binding == Binding::Artifact {
            return Err(SamlError::UnsupportedBinding { binding });
        }
        reject_soap_relay_state(binding, relay_state)?;
        if status_message.is_some_and(|message| message.chars().all(is_xml_whitespace_char)) {
            return Err(SamlError::Invalid(
                "logout status message must contain a non-whitespace character".into(),
            ));
        }
        let id = generate_id();
        let issue_instant = now_iso8601();
        let issuer = issuer_of(init_setting, init_meta);
        let xml = render_logout_response(
            init_setting,
            &LogoutResponseAttributes {
                id: &id,
                issue_instant: &issue_instant,
                destination,
                in_response_to,
            },
            &issuer,
            status,
            status_message,
        )?;
        validate_logout_response_outbound(
            &xml,
            &id,
            destination,
            &issuer,
            in_response_to,
            status.top_level().as_uri(),
            OutboundLogoutValidation::BeforeSigning,
        )?;
        Ok(RenderedLogoutResponse {
            id,
            xml,
            destination: destination.map(str::to_owned),
            issuer,
        })
    }
}

pub(crate) fn create_logout_response_inner(
    input: &LogoutResponseInput<'_>,
) -> Result<BindingContext, SamlError> {
    let RenderedLogoutResponse {
        id,
        xml,
        destination,
        issuer,
    } = input.render()?;
    let endpoint = destination.as_deref().unwrap_or_default();
    let signed = sign_message(
        input.init_setting,
        input.binding,
        &xml,
        endpoint,
        input.relay_state,
        ParserType::LogoutResponse,
    )?;
    if let Some(signed_xml) = embedded_signed_xml(input.binding, &signed.content)? {
        validate_logout_response_outbound(
            &signed_xml,
            &id,
            destination.as_deref(),
            &issuer,
            input.in_response_to,
            input.status.top_level().as_uri(),
            OutboundLogoutValidation::AfterEmbeddedSigning,
        )?;
    }
    Ok(signed.bind(id, destination.unwrap_or_default(), input.relay_state))
}

fn embedded_signed_xml(binding: Binding, context: &str) -> Result<Option<String>, SamlError> {
    match binding {
        Binding::Post => crate::xml::decode_utf8(crate::binding::decode_base64(context)?).map(Some),
        Binding::Soap => Ok(Some(context.to_string())),
        Binding::Redirect | Binding::SimpleSign | Binding::Artifact => Ok(None),
    }
}

pub(crate) fn reject_soap_relay_state(
    binding: Binding,
    relay_state: Option<&str>,
) -> Result<(), SamlError> {
    if binding == Binding::Soap && relay_state.is_some() {
        return Err(SamlError::ProtocolProfile(
            "the SOAP binding does not carry RelayState".into(),
        ));
    }
    Ok(())
}
