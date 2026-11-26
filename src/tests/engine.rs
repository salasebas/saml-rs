#![cfg_attr(not(crypto), allow(dead_code))]

use std::time::SystemTime;

use crate::binding::sign_message;
use crate::constants::{Binding, ParserType};
use crate::entity::{generate_id, now_iso8601, BindingContext, EntitySetting, User};
use crate::error::SamlError;
use crate::flow::{flow_with_authentication, FlowOptions, FlowResult, HttpRequest};
use crate::idp::{self, LoginResponseOptions, LoginResponseOverrides, ResponseMessageSignature};
use crate::logout::{
    create_logout_response_inner, issuer_of, parse_logout_request_at, parse_logout_response_at,
    reject_soap_relay_state, render_logout_request, LogoutFlowValidation, LogoutReceipt,
    LogoutRequestAttributes, LogoutRequestSubject, LogoutResponseInput,
};
use crate::metadata::Metadata;
use crate::model::{validate_name_id_format, ClockSkew, Status};
use crate::sp::{self, AuthnRequestPreferences, LoginRequestOptions, LoginResponseParseOptions};
use crate::tests::template::LOGIN_RESPONSE_TEMPLATE;

#[derive(Debug, Clone, Default)]
pub(crate) struct LogoutUser {
    pub(crate) name_id: String,
    pub(crate) session_index: Option<String>,
}

impl LogoutUser {
    pub(crate) fn new(name_id: impl Into<String>) -> Self {
        Self {
            name_id: name_id.into(),
            session_index: None,
        }
    }
}

pub(crate) trait SpMessages {
    fn create_login_request(
        &self,
        idp: &idp::Engine,
        binding: Binding,
        options: &LoginRequestOptions<'_>,
    ) -> Result<BindingContext, SamlError>;

    fn parse_login_response_with_request_id(
        &self,
        idp: &idp::Engine,
        binding: Binding,
        request: &HttpRequest,
        request_id: &str,
    ) -> Result<FlowResult, SamlError>;

    fn parse_unsolicited_login_response(
        &self,
        idp: &idp::Engine,
        binding: Binding,
        request: &HttpRequest,
    ) -> Result<FlowResult, SamlError>;
}

impl SpMessages for sp::Engine {
    fn create_login_request(
        &self,
        idp: &idp::Engine,
        binding: Binding,
        options: &LoginRequestOptions<'_>,
    ) -> Result<BindingContext, SamlError> {
        self.create_typed_login_request(idp, binding, options, &AuthnRequestPreferences::default())
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
                self.decode_login_response(binding, request)?,
                request_id,
                LoginResponseParseOptions::at(SystemTime::now(), ClockSkew::strict()),
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
                self.decode_login_response(binding, request)?,
                LoginResponseParseOptions::at(SystemTime::now(), ClockSkew::strict()),
            )?
            .into_parts()
            .0)
    }
}

pub(crate) trait IdpMessages {
    fn create_login_response(
        &self,
        sp: &sp::Engine,
        binding: Binding,
        user: &User,
        options: &LoginResponseOptions<'_>,
    ) -> Result<BindingContext, SamlError>;

    fn create_rendered_login_response(
        &self,
        sp: &sp::Engine,
        binding: Binding,
        render: &dyn Fn(&str) -> RenderedLoginResponse,
    ) -> Result<BindingContext, SamlError>;

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
                LoginResponseOverrides {
                    authn_instant: Some(SystemTime::now()),
                    ..LoginResponseOverrides::default()
                },
            )?
            .context)
    }

    fn create_rendered_login_response(
        &self,
        sp: &sp::Engine,
        binding: Binding,
        render: &dyn Fn(&str) -> RenderedLoginResponse,
    ) -> Result<BindingContext, SamlError> {
        let acs = sp
            .metadata
            .assertion_consumer_service_endpoint(binding)
            .ok_or_else(|| SamlError::MissingMetadata("AssertionConsumerService".into()))?;
        let (id, xml) = render(LOGIN_RESPONSE_TEMPLATE)?;
        let signed = self.finalize_login_response(
            sp,
            &acs,
            binding,
            &xml,
            ResponseMessageSignature::requested_by(sp),
            &sp.setting.transformation_algorithms,
        )?;
        let (context, signature, sig_alg) =
            self.bind_response(binding, &signed, &acs.location, None)?;
        Ok(BindingContext {
            id,
            context,
            signature,
            sig_alg,
            entity_endpoint: acs.location,
            binding,
            relay_state: None,
            request_type: "SAMLResponse",
        })
    }

    fn parse_login_request(
        &self,
        sp: &sp::Engine,
        binding: Binding,
        request: &HttpRequest,
    ) -> Result<FlowResult, SamlError> {
        Ok(self
            .parse_login_request_at(sp, binding, request, SystemTime::now(), ClockSkew::strict())?
            .into_flow_result())
    }
}

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
    reject_soap_relay_state(binding, relay_state)?;
    let name_id_format = init_setting.default_name_id_format();
    validate_name_id_format(name_id_format)?;
    let destination = target_meta
        .single_logout_location(binding)
        .ok_or_else(|| SamlError::MissingMetadata("SingleLogoutService".into()))?;
    let id = message_id
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(generate_id);
    let xml = render_logout_request(
        init_setting,
        &issuer_of(init_setting, init_meta),
        &LogoutRequestAttributes {
            id: &id,
            destination: &destination,
            issue_instant: &issue_instant,
            not_on_or_after: None,
            reason: None,
            asynchronous: false,
        },
        &subject,
        name_id_format,
    )?;
    let kind = ParserType::LogoutRequest;
    if want_signed {
        return Ok(
            sign_message(init_setting, binding, &xml, &destination, relay_state, kind)?.bind(
                id,
                destination,
                relay_state,
            ),
        );
    }
    Ok(BindingContext {
        id,
        context: unsigned_context(binding, &xml, &destination, kind, relay_state)?,
        signature: None,
        sig_alg: None,
        binding,
        entity_endpoint: destination,
        relay_state: relay_state.map(str::to_owned),
        request_type: kind.query_param(),
    })
}

pub(crate) fn create_logout_response(
    init_setting: &EntitySetting,
    init_meta: &Metadata,
    target_meta: &Metadata,
    binding: Binding,
    in_response_to: Option<&str>,
    relay_state: Option<&str>,
    want_signed: bool,
) -> Result<BindingContext, SamlError> {
    let status = Status::success();
    let destination = match binding {
        Binding::Soap | Binding::Artifact => None,
        Binding::Redirect | Binding::Post | Binding::SimpleSign => Some(
            target_meta
                .single_logout_response_location(binding)
                .ok_or_else(|| SamlError::MissingMetadata("SingleLogoutService".into()))?,
        ),
    };
    let input = LogoutResponseInput {
        init_setting,
        init_meta,
        binding,
        destination: destination.as_deref(),
        in_response_to,
        relay_state,
        status: &status,
        status_message: None,
    };
    if want_signed {
        return create_logout_response_inner(&input);
    }
    let rendered = input.render()?;
    let endpoint = rendered.destination.unwrap_or_default();
    let context = unsigned_context(
        binding,
        &rendered.xml,
        &endpoint,
        ParserType::LogoutResponse,
        relay_state,
    )?;
    Ok(BindingContext {
        id: rendered.id,
        context,
        entity_endpoint: endpoint,
        binding,
        request_type: "SAMLResponse",
        relay_state: relay_state.map(str::to_owned),
        signature: None,
        sig_alg: None,
    })
}

pub(crate) fn parse_logout_request(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    binding: Binding,
    request: &HttpRequest,
) -> Result<FlowResult, SamlError> {
    parse_logout_request_at(
        self_setting,
        from_meta,
        LogoutReceipt::browser(binding),
        request,
        LogoutFlowValidation::typed(None, SystemTime::now(), ClockSkew::strict(), None),
    )
}

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
        LogoutReceipt::browser(binding),
        request,
        request_id,
        LogoutFlowValidation::typed(None, SystemTime::now(), ClockSkew::strict(), None),
        None,
    )
    .map(|parsed| parsed.flow)
}

pub(crate) type RenderedLoginResponse = Result<(String, String), SamlError>;

pub(crate) fn flow(opts: &FlowOptions<'_>, request: &HttpRequest) -> Result<FlowResult, SamlError> {
    Ok(flow_with_authentication(opts, request)?.into_flow_result())
}

pub(crate) fn redirect_query(query: Vec<(String, String)>) -> HttpRequest {
    HttpRequest {
        query,
        ..HttpRequest::default()
    }
}

fn unsigned_context(
    binding: Binding,
    xml: &str,
    destination: &str,
    parser_type: ParserType,
    relay: Option<&str>,
) -> Result<String, SamlError> {
    match binding {
        Binding::Redirect => {
            crate::binding::build_redirect_url(destination, parser_type, xml, relay)
        }
        Binding::Post | Binding::SimpleSign => Ok(crate::binding::encode_base64(xml.as_bytes())),
        Binding::Soap => Ok(xml.to_string()),
        Binding::Artifact => Err(SamlError::UnsupportedBinding {
            binding: Binding::Artifact,
        }),
    }
}
