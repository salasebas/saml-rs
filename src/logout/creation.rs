use crate::binding::sign_message;
use crate::config::IdentifierEncryptionPolicy;
use crate::constants::{Binding, ParserType};
use crate::entity::{generate_id, now_iso8601, BindingContext, EntitySetting};
use crate::error::{utf8_err, SamlError};
use crate::metadata::Metadata;
use crate::model::{validate_name_id_format, Status};
use crate::template::render_template;
use crate::xml::any_uri::{collapse_whitespace, is_absolute_uri_reference};
use crate::xml::write::Prefixes;
use crate::xml::{
    validate_logout_request_outbound, validate_logout_response_outbound, OutboundLogoutExpiration,
    OutboundLogoutRequestExpectation, OutboundLogoutRequestValidation, OutboundLogoutValidation,
};

use super::encrypted_id::encrypt_name_id_for_peer;
use super::rendering::{
    issuer_of, render_default_logout_response, render_logout_request, LogoutRequestAttributes,
    LogoutRequestSubject,
};

pub(crate) struct CreatedLogoutRequest {
    pub(crate) context: BindingContext,
    pub(crate) not_on_or_after: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum LogoutRequestValidation {
    /// Session participant producer rules. `NotOnOrAfter` stays optional.
    SessionParticipant,
    SessionAuthority,
}

pub(crate) struct LogoutRequestInput<'a> {
    pub(crate) init_setting: &'a EntitySetting,
    pub(crate) init_meta: &'a Metadata,
    pub(crate) target_meta: &'a Metadata,
    pub(crate) binding: Binding,
    pub(crate) subject: &'a LogoutRequestSubject<'a>,
    pub(crate) relay_state: Option<&'a str>,
    /// `<NameID>` `Format`. `None` omits the attribute.
    pub(crate) name_id_format: Option<&'a str>,
    pub(crate) issue_instant: &'a str,
    pub(crate) not_on_or_after: Option<&'a str>,
    pub(crate) reason: Option<&'a str>,
    pub(crate) validation: LogoutRequestValidation,
    /// `EncryptIdentifiers` sends the `<NameID>` as an `<EncryptedID>` for the
    /// peer's encryption key.
    pub(crate) name_id_encryption: IdentifierEncryptionPolicy,
}

pub(crate) fn create_logout_request_for_subject_inner(
    input: LogoutRequestInput<'_>,
) -> Result<CreatedLogoutRequest, SamlError> {
    let LogoutRequestInput {
        init_setting,
        init_meta,
        target_meta,
        binding,
        subject,
        relay_state,
        name_id_format,
        issue_instant,
        not_on_or_after,
        reason,
        validation,
        name_id_encryption,
    } = input;

    reject_soap_relay_state(binding, relay_state)?;
    validate_name_id_format(name_id_format)?;
    if reason.is_some_and(|value| !is_absolute_uri_reference(value)) {
        return Err(SamlError::Invalid(
            "a LogoutRequest reason must be an absolute URI reference".into(),
        ));
    }
    let reason = reason.map(collapse_whitespace);
    let reason = reason.as_deref();
    if matches!(validation, LogoutRequestValidation::SessionParticipant)
        && subject.session_indexes.is_empty()
    {
        return Err(SamlError::ProtocolProfile(
            "a session participant LogoutRequest must include at least one SessionIndex".into(),
        ));
    }
    let destination = target_meta
        .single_logout_location(binding)
        .ok_or_else(|| SamlError::MissingMetadata("SingleLogoutService".into()))?;
    let id = generate_id();
    let issuer = issuer_of(init_setting, init_meta);
    let xml = render_logout_request(
        init_setting,
        &issuer,
        LogoutRequestAttributes {
            id: &id,
            destination: &destination,
            issue_instant,
            not_on_or_after,
            reason,
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
        destination: &destination,
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
    let xml = encrypt_name_id_for_peer(xml, name_id_encryption, init_setting, target_meta)?;
    let signed = sign_message(
        init_setting,
        binding,
        &xml,
        &destination,
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
        context: signed.bind(id, destination, relay_state),
        not_on_or_after: not_on_or_after.map(str::to_string),
    })
}

pub(crate) struct LogoutResponseInput<'a> {
    pub(crate) init_setting: &'a EntitySetting,
    pub(crate) init_meta: &'a Metadata,
    pub(crate) target_meta: &'a Metadata,
    pub(crate) binding: Binding,
    pub(crate) in_response_to: Option<&'a str>,
    pub(crate) relay_state: Option<&'a str>,
    pub(crate) status: &'a Status,
    pub(crate) template: Option<&'a str>,
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
            target_meta,
            binding,
            in_response_to,
            relay_state,
            status,
            template,
        } = *self;
        reject_soap_relay_state(binding, relay_state)?;
        // A SOAP response returns on the requester's own HTTP exchange, so it has
        // no Destination.
        let destination = match binding {
            Binding::Soap => None,
            Binding::Artifact => return Err(SamlError::UnsupportedBinding { binding }),
            Binding::Redirect | Binding::Post | Binding::SimpleSign => Some(
                target_meta
                    .single_logout_response_location(binding)
                    .ok_or_else(|| SamlError::MissingMetadata("SingleLogoutService".into()))?,
            ),
        };
        let id = generate_id();
        let issue_instant = now_iso8601();
        let issuer = issuer_of(init_setting, init_meta);
        let xml = if let Some(template) = template {
            if status.subordinate().is_some() {
                return Err(SamlError::Invalid(
                    "LogoutResponse template StatusCode placeholder cannot carry a subordinate status code"
                        .into(),
                ));
            }
            render_template(
                template,
                Prefixes::of(init_setting)?,
                &[
                    ("ID", Some(id.clone())),
                    ("IssueInstant", Some(issue_instant)),
                    ("Destination", destination.clone()),
                    ("Issuer", Some(issuer.clone())),
                    ("StatusCode", Some(status.top_level().as_uri().to_string())),
                    ("InResponseTo", in_response_to.map(str::to_string)),
                ],
            )?
        } else {
            render_default_logout_response(
                init_setting,
                &id,
                &issue_instant,
                destination.as_deref(),
                in_response_to,
                &issuer,
                status,
            )?
        };
        validate_logout_response_outbound(
            &xml,
            &id,
            destination.as_deref(),
            &issuer,
            in_response_to,
            status.top_level().as_uri(),
            OutboundLogoutValidation::BeforeSigning,
        )?;
        Ok(RenderedLogoutResponse {
            id,
            xml,
            destination,
            issuer,
        })
    }
}

pub(crate) fn create_logout_response_inner(
    input: LogoutResponseInput<'_>,
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

/// The signed XML an embedded-signature binding carries.
fn embedded_signed_xml(binding: Binding, context: &str) -> Result<Option<String>, SamlError> {
    match binding {
        Binding::Post => String::from_utf8(crate::binding::decode_base64(context)?)
            .map(Some)
            .map_err(utf8_err),
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
