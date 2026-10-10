use crate::constants::{Binding, ParserType};
use crate::entity::{generate_id, now_iso8601, BindingContext, EntitySetting, User};
use crate::error::SamlError;
use crate::metadata::Metadata;
use crate::model::Status;
use crate::template::{
    apply_tag_prefixes, replace_tags_by_optional_value, replace_tags_by_value, validate_tag_prefix,
};
use crate::xml::{
    validate_logout_request_outbound, validate_logout_response_outbound, OutboundLogoutExpiration,
    OutboundLogoutRequestExpectation, OutboundLogoutRequestValidation, OutboundLogoutValidation,
};

use super::bindings::unsigned_context;
use super::rendering::{
    issuer_of, render_default_logout_request, render_default_logout_response, LogoutRequestSubject,
    LogoutRequestTimeAttributes,
};
use super::signing::sign_logout;

fn logout_name_id_format<'a>(
    subject_format: Option<&'a str>,
    init_setting: &'a EntitySetting,
) -> &'a str {
    subject_format.unwrap_or_else(|| {
        init_setting
            .name_id_format
            .first()
            .map(String::as_str)
            .unwrap_or("")
    })
}

/// Build a `<LogoutRequest>` from `init` to `target`.
///
/// `user` supplies the `<NameID>` and optional `<samlp:SessionIndex>`.
///
/// # Errors
///
/// Returns an error if `target_meta` has no SLO endpoint for `binding`,
/// `binding` is unsupported, the configured logout template cannot represent
/// the supplied subject, configured XML tag prefixes are invalid, default XML
/// rendering fails, or Redirect DEFLATE encoding fails. When `want_signed` is
/// true, missing or invalid signing keys/certificates, unavailable crypto
/// support, XML signature construction, and detached-signature construction
/// errors are propagated.
pub fn create_logout_request(
    init_setting: &EntitySetting,
    init_meta: &Metadata,
    target_meta: &Metadata,
    binding: Binding,
    user: &User,
    relay_state: Option<&str>,
    want_signed: bool,
) -> Result<BindingContext, SamlError> {
    create_logout_request_with_id(
        init_setting,
        init_meta,
        target_meta,
        binding,
        user,
        relay_state,
        want_signed,
        None,
    )
}

/// Like [`create_logout_request`] but uses `message_id` when provided.
///
/// # Errors
///
/// Returns the same errors as [`create_logout_request`]. Empty `message_id`
/// values are ignored and replaced with a generated ID.
#[allow(clippy::too_many_arguments)] // public API adds optional `message_id`
pub fn create_logout_request_with_id(
    init_setting: &EntitySetting,
    init_meta: &Metadata,
    target_meta: &Metadata,
    binding: Binding,
    user: &User,
    relay_state: Option<&str>,
    want_signed: bool,
    message_id: Option<&str>,
) -> Result<BindingContext, SamlError> {
    let name_id_format = logout_name_id_format(None, init_setting).to_string();
    let issue_instant = now_iso8601();
    let subject = LogoutRequestSubject::from_user(user);
    Ok(create_logout_request_for_subject_inner(LogoutRequestInput {
        init_setting,
        init_meta,
        target_meta,
        binding,
        subject: &subject,
        relay_state,
        want_signed,
        message_id,
        name_id_format: &name_id_format,
        issue_instant: &issue_instant,
        not_on_or_after: None,
        validation: LogoutRequestValidation::Compatibility,
    })?
    .context)
}

pub(crate) struct CreatedLogoutRequest {
    pub(crate) context: BindingContext,
    pub(crate) issue_instant: String,
    pub(crate) not_on_or_after: Option<String>,
}

pub(crate) struct LogoutRequestSessionIndexes<'a> {
    pub(crate) init_setting: &'a EntitySetting,
    pub(crate) init_meta: &'a Metadata,
    pub(crate) target_meta: &'a Metadata,
    pub(crate) binding: Binding,
    pub(crate) name_id: &'a str,
    pub(crate) name_id_format: Option<&'a str>,
    pub(crate) name_qualifier: Option<&'a str>,
    pub(crate) sp_name_qualifier: Option<&'a str>,
    pub(crate) sp_provided_id: Option<&'a str>,
    pub(crate) session_indexes: &'a [String],
    pub(crate) relay_state: Option<&'a str>,
    pub(crate) want_signed: bool,
    pub(crate) issue_instant: &'a str,
    pub(crate) not_on_or_after: Option<&'a str>,
    pub(crate) validation: LogoutRequestValidation,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum LogoutRequestValidation {
    Compatibility,
    /// Session participant producer rules. `NotOnOrAfter` stays optional.
    SessionParticipant,
    SessionAuthority,
}

pub(crate) fn create_logout_request_with_session_indexes(
    input: LogoutRequestSessionIndexes<'_>,
) -> Result<CreatedLogoutRequest, SamlError> {
    let LogoutRequestSessionIndexes {
        init_setting,
        init_meta,
        target_meta,
        binding,
        name_id,
        name_id_format,
        name_qualifier,
        sp_name_qualifier,
        sp_provided_id,
        session_indexes,
        relay_state,
        want_signed,
        issue_instant,
        not_on_or_after,
        validation,
    } = input;

    let name_id_format = logout_name_id_format(name_id_format, init_setting);
    let subject = LogoutRequestSubject {
        name_id,
        session_indexes: session_indexes.iter().map(String::as_str).collect(),
        name_qualifier,
        sp_name_qualifier,
        sp_provided_id,
    };
    create_logout_request_for_subject_inner(LogoutRequestInput {
        init_setting,
        init_meta,
        target_meta,
        binding,
        subject: &subject,
        relay_state,
        want_signed,
        message_id: None,
        name_id_format,
        issue_instant,
        not_on_or_after,
        validation,
    })
}

struct LogoutRequestInput<'a> {
    init_setting: &'a EntitySetting,
    init_meta: &'a Metadata,
    target_meta: &'a Metadata,
    binding: Binding,
    subject: &'a LogoutRequestSubject<'a>,
    relay_state: Option<&'a str>,
    want_signed: bool,
    message_id: Option<&'a str>,
    name_id_format: &'a str,
    issue_instant: &'a str,
    not_on_or_after: Option<&'a str>,
    validation: LogoutRequestValidation,
}

fn create_logout_request_for_subject_inner(
    input: LogoutRequestInput<'_>,
) -> Result<CreatedLogoutRequest, SamlError> {
    let LogoutRequestInput {
        init_setting,
        init_meta,
        target_meta,
        binding,
        subject,
        relay_state,
        want_signed,
        message_id,
        name_id_format,
        issue_instant,
        not_on_or_after,
        validation,
    } = input;

    if matches!(validation, LogoutRequestValidation::SessionParticipant)
        && subject.session_indexes.is_empty()
    {
        return Err(SamlError::ProtocolProfile(
            "a session participant LogoutRequest must include at least one SessionIndex".into(),
        ));
    }
    let destination = target_meta
        .get_single_logout_service(binding)
        .ok_or_else(|| SamlError::MissingMetadata("SingleLogoutService".into()))?;
    let id = message_id
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(generate_id);
    let issuer = issuer_of(init_setting, init_meta);
    let xml = if let Some(template) = init_setting.logout_request_template.as_deref() {
        if subject.session_indexes.len() > 1 {
            return Err(SamlError::Unsupported(
                "custom LogoutRequest templates cannot render multiple SessionIndex values".into(),
            ));
        }
        validate_tag_prefix("protocol", &init_setting.tag_prefix_protocol)?;
        validate_tag_prefix("assertion", &init_setting.tag_prefix_assertion)?;
        let template = apply_tag_prefixes(
            template,
            &init_setting.tag_prefix_protocol,
            &init_setting.tag_prefix_assertion,
        );
        let mut replacements = vec![
            ("ID", Some(id.clone())),
            ("IssueInstant", Some(issue_instant.to_string())),
            ("Destination", Some(destination.clone())),
            ("Issuer", Some(issuer.clone())),
            ("NameIDFormat", Some(name_id_format.to_string())),
            ("NameID", Some(subject.name_id.to_string())),
            ("NameQualifier", subject.name_qualifier.map(str::to_string)),
            (
                "SPNameQualifier",
                subject.sp_name_qualifier.map(str::to_string),
            ),
            ("SPProvidedID", subject.sp_provided_id.map(str::to_string)),
            (
                "SessionIndex",
                subject
                    .session_indexes
                    .first()
                    .map(|value| (*value).to_string()),
            ),
        ];
        if matches!(validation, LogoutRequestValidation::SessionAuthority) {
            replacements.push(("NotOnOrAfter", not_on_or_after.map(str::to_string)));
        }
        replace_tags_by_optional_value(&template, &replacements)
    } else {
        render_default_logout_request(
            init_setting,
            init_meta,
            &id,
            LogoutRequestTimeAttributes {
                issue_instant,
                not_on_or_after,
            },
            &destination,
            subject,
            name_id_format,
        )?
    };
    let session_indexes = subject.session_indexes.as_slice();
    // `None` skips outbound checks. `Optional` checks a participant request
    // and leaves `NotOnOrAfter` optional. `Required` checks the
    // session-authority instant.
    let expiration = match validation {
        LogoutRequestValidation::Compatibility => None,
        LogoutRequestValidation::SessionParticipant => Some(OutboundLogoutExpiration::Optional),
        LogoutRequestValidation::SessionAuthority => Some(OutboundLogoutExpiration::Required(
            not_on_or_after.ok_or_else(|| {
                SamlError::Invalid(
                    "Session Authority LogoutRequest is missing its generated expiration".into(),
                )
            })?,
        )),
    };
    let expectation = expiration.map(|expiration| OutboundLogoutRequestExpectation {
        id: &id,
        issue_instant,
        destination: &destination,
        issuer: &issuer,
        expiration,
        name_id: subject.name_id,
        name_id_format,
        name_qualifier: subject.name_qualifier,
        sp_name_qualifier: subject.sp_name_qualifier,
        sp_provided_id: subject.sp_provided_id,
        session_indexes,
    });
    if let Some(expectation) = expectation.as_ref() {
        validate_logout_request_outbound(
            &xml,
            expectation,
            OutboundLogoutRequestValidation::BeforeSigning,
        )?;
    }
    let (context, signature, sig_alg) = if want_signed {
        sign_logout(
            init_setting,
            binding,
            &xml,
            &destination,
            relay_state,
            ParserType::LogoutRequest,
        )?
    } else {
        (
            unsigned_context(
                binding,
                &xml,
                &destination,
                ParserType::LogoutRequest,
                relay_state,
            )?,
            None,
            None,
        )
    };
    if let Some(expectation) = expectation
        .as_ref()
        .filter(|_| want_signed && matches!(binding, Binding::Post))
    {
        let signed_xml = String::from_utf8(crate::binding::base64_decode(&context)?)
            .map_err(|error| SamlError::Xml(error.to_string()))?;
        validate_logout_request_outbound(
            &signed_xml,
            expectation,
            OutboundLogoutRequestValidation::AfterPostSigning,
        )?;
    }
    Ok(CreatedLogoutRequest {
        context: BindingContext {
            id,
            context,
            relay_state: relay_state.map(str::to_string),
            entity_endpoint: destination,
            binding,
            request_type: "SAMLRequest",
            signature,
            sig_alg,
        },
        issue_instant: issue_instant.to_string(),
        not_on_or_after: not_on_or_after.map(str::to_string),
    })
}

/// Build a `<LogoutResponse>` from `init` to `target`.
///
/// `Destination` is the peer `SingleLogoutService` `ResponseLocation` for
/// `binding` when that attribute is present, and `Location` otherwise.
///
/// # Errors
///
/// Returns an error if `binding` is unsupported, `target_meta` has no SLO
/// endpoint for `binding`, configured XML tag prefixes are invalid, the final
/// outbound XML violates the enforced LogoutResponse schema structure,
/// correlation, or SLO-profile requirements, default XML rendering fails, or
/// Redirect DEFLATE encoding fails. A custom template must not contain a root
/// XML signature before library signing. When `want_signed` is true, missing
/// or invalid signing keys/certificates, unavailable crypto support, XML
/// signature construction, detached-signature construction, and invalid
/// post-signing placement errors are propagated.
pub fn create_logout_response(
    init_setting: &EntitySetting,
    init_meta: &Metadata,
    target_meta: &Metadata,
    binding: Binding,
    in_response_to: Option<&str>,
    relay_state: Option<&str>,
    want_signed: bool,
) -> Result<BindingContext, SamlError> {
    create_logout_response_with_id(
        init_setting,
        init_meta,
        target_meta,
        binding,
        in_response_to,
        relay_state,
        want_signed,
        None,
    )
}

struct LogoutResponseInput<'a> {
    init_setting: &'a EntitySetting,
    init_meta: &'a Metadata,
    target_meta: &'a Metadata,
    binding: Binding,
    in_response_to: Option<&'a str>,
    relay_state: Option<&'a str>,
    want_signed: bool,
    message_id: Option<&'a str>,
    status: &'a Status,
}

/// Like [`create_logout_response`] but uses `message_id` when provided.
///
/// # Errors
///
/// Returns the same errors as [`create_logout_response`]. Empty `message_id`
/// values are ignored and replaced with a generated ID.
#[allow(clippy::too_many_arguments)] // public API adds optional `message_id`
pub fn create_logout_response_with_id(
    init_setting: &EntitySetting,
    init_meta: &Metadata,
    target_meta: &Metadata,
    binding: Binding,
    in_response_to: Option<&str>,
    relay_state: Option<&str>,
    want_signed: bool,
    message_id: Option<&str>,
) -> Result<BindingContext, SamlError> {
    let status = Status::success();
    create_logout_response_with_status(
        init_setting,
        init_meta,
        target_meta,
        binding,
        in_response_to,
        relay_state,
        want_signed,
        message_id,
        &status,
    )
}

/// Like [`create_logout_response_with_id`], with the caller-supplied status.
///
/// # Errors
///
/// Returns the same errors as [`create_logout_response`]. A logout-response
/// template rejects a subordinate code.
#[allow(clippy::too_many_arguments)] // internal path adds the caller-supplied status
pub(crate) fn create_logout_response_with_status(
    init_setting: &EntitySetting,
    init_meta: &Metadata,
    target_meta: &Metadata,
    binding: Binding,
    in_response_to: Option<&str>,
    relay_state: Option<&str>,
    want_signed: bool,
    message_id: Option<&str>,
    status: &Status,
) -> Result<BindingContext, SamlError> {
    create_logout_response_inner(LogoutResponseInput {
        init_setting,
        init_meta,
        target_meta,
        binding,
        in_response_to,
        relay_state,
        want_signed,
        message_id,
        status,
    })
}

fn create_logout_response_inner(
    input: LogoutResponseInput<'_>,
) -> Result<BindingContext, SamlError> {
    let LogoutResponseInput {
        init_setting,
        init_meta,
        target_meta,
        binding,
        in_response_to,
        relay_state,
        want_signed,
        message_id,
        status,
    } = input;

    if matches!(binding, Binding::Artifact) {
        return Err(SamlError::UnsupportedBinding {
            binding: Binding::Artifact,
        });
    }
    let destination = target_meta
        .get_single_logout_response_service(binding)
        .ok_or_else(|| SamlError::MissingMetadata("SingleLogoutService".into()))?;
    let id = message_id
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(generate_id);
    let issue_instant = now_iso8601();
    let issuer = issuer_of(init_setting, init_meta);
    let xml = if let Some(template) = init_setting.logout_response_template.as_deref() {
        if status.subordinate().is_some() {
            return Err(SamlError::Invalid(
                "LogoutResponse template StatusCode placeholder cannot carry a subordinate status code"
                    .into(),
            ));
        }
        validate_tag_prefix("protocol", &init_setting.tag_prefix_protocol)?;
        validate_tag_prefix("assertion", &init_setting.tag_prefix_assertion)?;
        let template = apply_tag_prefixes(
            template,
            &init_setting.tag_prefix_protocol,
            &init_setting.tag_prefix_assertion,
        );
        let xml = replace_tags_by_value(
            &template,
            &[
                ("ID", id.clone()),
                ("IssueInstant", issue_instant),
                ("Destination", destination.clone()),
                ("Issuer", issuer.clone()),
                ("StatusCode", status.top_level().as_uri().to_string()),
            ],
        );
        let xml = replace_tags_by_optional_value(
            &xml,
            &[("InResponseTo", in_response_to.map(str::to_string))],
        );
        if let Ok(extracted) =
            crate::xml::extract(&xml, &crate::xml::fields::logout_response_status_fields())
        {
            if extracted.get_str("top") != Some(status.top_level().as_uri()) {
                return Err(SamlError::Invalid(
                    "LogoutResponse template did not carry the supplied top-level status code"
                        .into(),
                ));
            }
        }
        xml
    } else {
        render_default_logout_response(
            init_setting,
            &id,
            &issue_instant,
            &destination,
            in_response_to,
            &issuer,
            status,
        )?
    };
    validate_logout_response_outbound(
        &xml,
        &id,
        &destination,
        &issuer,
        in_response_to,
        OutboundLogoutValidation::BeforeSigning {
            destination_required: want_signed,
        },
    )?;
    let (context, signature, sig_alg) = if want_signed {
        sign_logout(
            init_setting,
            binding,
            &xml,
            &destination,
            relay_state,
            ParserType::LogoutResponse,
        )?
    } else {
        (
            unsigned_context(
                binding,
                &xml,
                &destination,
                ParserType::LogoutResponse,
                relay_state,
            )?,
            None,
            None,
        )
    };
    if want_signed && matches!(binding, Binding::Post) {
        let signed_xml = String::from_utf8(crate::binding::base64_decode(&context)?)
            .map_err(|error| SamlError::Xml(error.to_string()))?;
        validate_logout_response_outbound(
            &signed_xml,
            &id,
            &destination,
            &issuer,
            in_response_to,
            OutboundLogoutValidation::AfterPostSigning,
        )?;
    }
    Ok(BindingContext {
        id,
        context,
        relay_state: relay_state.map(str::to_string),
        entity_endpoint: destination,
        binding,
        request_type: "SAMLResponse",
        signature,
        sig_alg,
    })
}
