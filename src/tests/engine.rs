//! Message-level entry points into the protocol engine for tests that build
//! or receive arbitrary messages without the typed facade.
#![cfg_attr(not(crypto), allow(dead_code))]

use std::time::SystemTime;

use crate::config::IdentifierEncryptionPolicy;
use crate::constants::Binding;
use crate::entity::{now_iso8601, BindingContext, EntitySetting, User};
use crate::error::SamlError;
use crate::flow::{flow_with_authentication, FlowOptions, FlowResult, HttpRequest};
use crate::idp::{self, LoginResponseOptions, LoginResponseOverrides};
use crate::logout::{
    create_logout_request_for_subject_inner, create_logout_response_inner, parse_logout_request_at,
    parse_logout_response_at, LogoutFlowValidation, LogoutReceipt, LogoutRequestInput,
    LogoutRequestSubject, LogoutRequestValidation, LogoutResponseInput,
};
use crate::metadata::Metadata;
use crate::model::{ClockSkew, Status};
use crate::sp::{
    self, AuthnRequestPreferences, LoginRequestOptions, LoginResponseParseOptions,
    WebBrowserSsoProducer,
};
use crate::template::{
    apply_tag_prefixes, build_attribute_statement, replace_tags_by_optional_value,
    LoginResponseTemplate, ATTRIBUTE_STATEMENT_TEMPLATE, ATTRIBUTE_TEMPLATE,
    LOGIN_REQUEST_TEMPLATE, LOGIN_RESPONSE_TEMPLATE,
};

/// The subject of a `<LogoutRequest>`.
#[derive(Debug, Clone, Default)]
pub(crate) struct LogoutUser {
    /// `<NameID>` value.
    pub(crate) name_id: String,
    /// `<samlp:SessionIndex>` value.
    pub(crate) session_index: Option<String>,
}

impl LogoutUser {
    /// A subject with just a NameID.
    pub(crate) fn new(name_id: impl Into<String>) -> Self {
        Self {
            name_id: name_id.into(),
            session_index: None,
        }
    }
}

fn clock_skew(setting: &EntitySetting) -> ClockSkew {
    let (not_before_ms, not_on_or_after_ms) = setting.clock_drifts;
    ClockSkew::from_millis(not_before_ms, not_on_or_after_ms)
}

/// Service provider messages without the typed facade.
pub(crate) trait SpMessages {
    /// `<AuthnRequest>` to `idp` over `binding`.
    fn create_login_request(
        &self,
        idp: &idp::Engine,
        binding: Binding,
        options: &LoginRequestOptions<'_>,
    ) -> Result<BindingContext, SamlError>;

    /// Login `<Response>` whose `InResponseTo` must be `request_id`.
    fn parse_login_response_with_request_id(
        &self,
        idp: &idp::Engine,
        binding: Binding,
        request: &HttpRequest,
        request_id: &str,
    ) -> Result<FlowResult, SamlError>;

    /// Login `<Response>` that answers no request.
    fn parse_unsolicited_login_response(
        &self,
        idp: &idp::Engine,
        binding: Binding,
        request: &HttpRequest,
    ) -> Result<FlowResult, SamlError>;

    /// `<AuthnRequest>` whose XML `render` writes from the request template,
    /// signed and bound like [`Self::create_login_request`] output. `render`
    /// returns the request `ID` and the XML.
    fn create_rendered_login_request(
        &self,
        idp: &idp::Engine,
        binding: Binding,
        options: &LoginRequestOptions<'_>,
        render: &dyn Fn(&str) -> (String, String),
    ) -> Result<BindingContext, SamlError>;
}

impl SpMessages for sp::Engine {
    fn create_login_request(
        &self,
        idp: &idp::Engine,
        binding: Binding,
        options: &LoginRequestOptions<'_>,
    ) -> Result<BindingContext, SamlError> {
        self.create_typed_login_request(
            idp,
            binding,
            options,
            WebBrowserSsoProducer::Legacy,
            &AuthnRequestPreferences::default(),
        )
    }

    fn parse_login_response_with_request_id(
        &self,
        idp: &idp::Engine,
        binding: Binding,
        request: &HttpRequest,
        request_id: &str,
    ) -> Result<FlowResult, SamlError> {
        Ok(self
            .parse_login_response_with_request_id_at(
                idp,
                binding,
                request,
                request_id,
                LoginResponseParseOptions::at(SystemTime::now(), clock_skew(&self.setting)),
            )?
            .into_parts()
            .0)
    }

    fn parse_unsolicited_login_response(
        &self,
        idp: &idp::Engine,
        binding: Binding,
        request: &HttpRequest,
    ) -> Result<FlowResult, SamlError> {
        Ok(self
            .parse_unsolicited_login_response_at(
                idp,
                binding,
                request,
                LoginResponseParseOptions::at(SystemTime::now(), clock_skew(&self.setting)),
            )?
            .into_parts()
            .0)
    }

    fn create_rendered_login_request(
        &self,
        idp: &idp::Engine,
        binding: Binding,
        options: &LoginRequestOptions<'_>,
        render: &dyn Fn(&str) -> (String, String),
    ) -> Result<BindingContext, SamlError> {
        let template = self
            .setting
            .login_request_template
            .as_deref()
            .unwrap_or(LOGIN_REQUEST_TEMPLATE);
        let (id, xml) = render(template);
        let mut sp = self.clone();
        sp.setting.login_request_template = Some(xml);
        let mut context = sp.create_login_request(idp, binding, options)?;
        context.id = id;
        Ok(context)
    }
}

/// Identity provider messages without the typed facade.
pub(crate) trait IdpMessages {
    /// Login `<Response>` for `user` to `sp` over `binding`.
    fn create_login_response(
        &self,
        sp: &sp::Engine,
        binding: Binding,
        user: &User,
        options: &LoginResponseOptions<'_>,
    ) -> Result<BindingContext, SamlError>;

    /// Login `<Response>` whose XML `render` writes, signed and bound like
    /// [`Self::create_login_response`] output. `render` gets the response
    /// template with its `<AttributeStatement>` and tag prefixes applied, and
    /// returns the response `ID` and the XML, which is not prefixed again.
    fn create_rendered_login_response(
        &self,
        sp: &sp::Engine,
        binding: Binding,
        user: &User,
        options: &LoginResponseOptions<'_>,
        render: &dyn Fn(&str) -> (String, String),
    ) -> Result<BindingContext, SamlError>;

    /// `<AuthnRequest>` from `sp`.
    fn parse_login_request(
        &self,
        sp: &sp::Engine,
        binding: Binding,
        request: &HttpRequest,
    ) -> Result<FlowResult, SamlError>;
}

impl IdpMessages for idp::Engine {
    fn create_login_response(
        &self,
        sp: &sp::Engine,
        binding: Binding,
        user: &User,
        options: &LoginResponseOptions<'_>,
    ) -> Result<BindingContext, SamlError> {
        Ok(self
            .create_login_response_with_overrides(
                sp,
                binding,
                user,
                options,
                LoginResponseOverrides::default(),
            )?
            .context)
    }

    fn create_rendered_login_response(
        &self,
        sp: &sp::Engine,
        binding: Binding,
        user: &User,
        options: &LoginResponseOptions<'_>,
        render: &dyn Fn(&str) -> (String, String),
    ) -> Result<BindingContext, SamlError> {
        let configured = self.setting.login_response_template.as_ref();
        let attributes = configured.map_or(&[][..], |template| template.attributes.as_slice());
        let attribute_statement = if attributes.is_empty() {
            String::new()
        } else {
            build_attribute_statement(attributes, ATTRIBUTE_TEMPLATE, ATTRIBUTE_STATEMENT_TEMPLATE)
        };
        let template = configured
            .and_then(|template| template.context.as_deref())
            .unwrap_or(LOGIN_RESPONSE_TEMPLATE)
            .replacen("{AttributeStatement}", &attribute_statement, 1);
        let template = apply_tag_prefixes(
            &template,
            &self.setting.tag_prefix_protocol,
            &self.setting.tag_prefix_assertion,
        );
        let (id, xml) = render(&template);
        let mut idp = self.clone();
        idp.setting.login_response_template = Some(LoginResponseTemplate {
            context: Some(xml),
            attributes: Vec::new(),
        });
        idp.setting.tag_prefix_protocol = "samlp".into();
        idp.setting.tag_prefix_assertion = "saml".into();
        let mut context = idp.create_login_response(sp, binding, user, options)?;
        context.id = id;
        Ok(context)
    }

    fn parse_login_request(
        &self,
        sp: &sp::Engine,
        binding: Binding,
        request: &HttpRequest,
    ) -> Result<FlowResult, SamlError> {
        Ok(self
            .parse_login_request_at(
                sp,
                binding,
                request,
                SystemTime::now(),
                clock_skew(&self.setting),
            )?
            .0)
    }
}

/// `<LogoutRequest>` for `user` from `init` to `target` over `binding`.
pub(crate) fn create_logout_request(
    init_setting: &EntitySetting,
    init_meta: &Metadata,
    target_meta: &Metadata,
    binding: Binding,
    user: &LogoutUser,
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

/// Like [`create_logout_request`], with `message_id` as the request `ID`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn create_logout_request_with_id(
    init_setting: &EntitySetting,
    init_meta: &Metadata,
    target_meta: &Metadata,
    binding: Binding,
    user: &LogoutUser,
    relay_state: Option<&str>,
    want_signed: bool,
    message_id: Option<&str>,
) -> Result<BindingContext, SamlError> {
    let issue_instant = now_iso8601();
    let subject = LogoutRequestSubject {
        name_id: &user.name_id,
        qualifiers: Default::default(),
        session_indexes: user.session_index.as_deref().into_iter().collect(),
    };
    Ok(create_logout_request_for_subject_inner(LogoutRequestInput {
        init_setting,
        init_meta,
        target_meta,
        binding,
        subject: &subject,
        relay_state,
        want_signed,
        message_id,
        name_id_format: init_setting.default_name_id_format(),
        issue_instant: &issue_instant,
        not_on_or_after: None,
        validation: LogoutRequestValidation::SkipProducerChecks,
        name_id_encryption: IdentifierEncryptionPolicy::PlaintextIdentifiers,
    })?
    .context)
}

/// Successful `<LogoutResponse>` from `init` to `target` over `binding`.
pub(crate) fn create_logout_response(
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

/// Like [`create_logout_response`], with `message_id` as the response `ID`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn create_logout_response_with_id(
    init_setting: &EntitySetting,
    init_meta: &Metadata,
    target_meta: &Metadata,
    binding: Binding,
    in_response_to: Option<&str>,
    relay_state: Option<&str>,
    want_signed: bool,
    message_id: Option<&str>,
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
        status: &Status::success(),
    })
}

/// `<LogoutRequest>` from the peer described by `from_meta`.
pub(crate) fn parse_logout_request(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    binding: Binding,
    request: &HttpRequest,
) -> Result<FlowResult, SamlError> {
    Ok(parse_logout_request_at(
        self_setting,
        from_meta,
        LogoutReceipt::of_binding(binding),
        request,
        LogoutFlowValidation::typed(None, SystemTime::now(), clock_skew(self_setting), None),
    )?
    .0)
}

/// `<LogoutResponse>` from the peer described by `from_meta` that answers
/// `request_id`.
pub(crate) fn parse_logout_response(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    binding: Binding,
    request: &HttpRequest,
    request_id: &str,
) -> Result<FlowResult, SamlError> {
    parse_logout_response_at(
        self_setting,
        from_meta,
        LogoutReceipt::of_binding(binding),
        request,
        request_id,
        LogoutFlowValidation::typed(None, SystemTime::now(), clock_skew(self_setting), None),
    )
}

/// Run the receive flow that `opts` describes against `request`.
pub(crate) fn flow(opts: &FlowOptions<'_>, request: &HttpRequest) -> Result<FlowResult, SamlError> {
    Ok(flow_with_authentication(opts, request)?.0)
}

/// `raw_xml` with each `{key}` placeholder of `tags` filled.
pub(crate) fn fill_template(raw_xml: &str, tags: &[(&str, String)]) -> String {
    let tags: Vec<(&str, Option<String>)> = tags
        .iter()
        .map(|(key, value)| (*key, Some(value.clone())))
        .collect();
    replace_tags_by_optional_value(raw_xml, &tags)
}

/// HTTP-Redirect request from decoded query pairs.
pub(crate) fn redirect_query(query: Vec<(String, String)>) -> HttpRequest {
    HttpRequest {
        query,
        ..HttpRequest::default()
    }
}
