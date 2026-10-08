use core::marker::PhantomData;

use super::artifact::ArtifactEncoding;
use super::forms::{FormField, PostForm};
use crate::artifact::Artifact;
use crate::binding::append_redirect_query;
use crate::constants::url_params;
use crate::constants::Binding;
use crate::entity::BindingContext;
use crate::error::SamlError;
use crate::model::{
    AuthnRequest, EndpointUrl, LogoutRequest, LogoutResponse, MessageId, RelayState, SsoResponse,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutboundKind {
    Redirect,
    Post,
    SimpleSignPost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageField {
    Request,
    Response,
}

impl MessageField {
    fn param_name(self) -> &'static str {
        match self {
            Self::Request => url_params::SAML_REQUEST,
            Self::Response => url_params::SAML_RESPONSE,
        }
    }

    fn opposite_param_name(self) -> &'static str {
        match self {
            Self::Request => url_params::SAML_RESPONSE,
            Self::Response => url_params::SAML_REQUEST,
        }
    }
}

/// Typed outbound browser action.
///
/// # Examples
///
/// ```
/// use saml_rs::{AuthnRequest, Outbound};
/// # use saml_rs::raw::{Binding, BindingContext};
/// #
/// # fn redirect_context() -> BindingContext {
/// #     BindingContext {
/// #         id: "_request123".to_string(),
/// #         context: "https://idp.example.com/sso?SAMLRequest=abc".to_string(),
/// #         relay_state: None,
/// #         entity_endpoint: "https://idp.example.com/sso".to_string(),
/// #         binding: Binding::Redirect,
/// #         request_type: "SAMLRequest",
/// #         signature: None,
/// #         sig_alg: None,
/// #     }
/// # }
/// # fn post_context() -> BindingContext {
/// #     BindingContext {
/// #         id: "_request456".to_string(),
/// #         context: "PHNhbWxwOkF1dGhuUmVxdWVzdA==".to_string(),
/// #         relay_state: None,
/// #         entity_endpoint: "https://idp.example.com/sso".to_string(),
/// #         binding: Binding::Post,
/// #         request_type: "SAMLRequest",
/// #         signature: None,
/// #         sig_alg: None,
/// #     }
/// # }
///
/// let redirect = Outbound::<AuthnRequest>::try_from(redirect_context())?;
/// assert!(redirect.redirect_url()?.contains("SAMLRequest="));
///
/// let post = Outbound::<AuthnRequest>::try_from(post_context())?;
/// assert_eq!(post.post_form()?.action().as_str(), "https://idp.example.com/sso");
/// # Ok::<(), saml_rs::SamlError>(())
/// ```
#[derive(Debug, Clone)]
pub struct Outbound<Message> {
    id: MessageId,
    relay_state: Option<RelayState>,
    kind: OutboundKind,
    redirect_url: Option<String>,
    post_form: Option<PostForm>,
    raw_context: BindingContext,
    _message: PhantomData<Message>,
}

impl<Message> Outbound<Message> {
    /// Message ID.
    pub fn id(&self) -> &MessageId {
        &self.id
    }

    /// RelayState parameter, when present.
    pub fn relay_state(&self) -> Option<&RelayState> {
        self.relay_state.as_ref()
    }

    /// Redirect URL for Redirect actions, and for an artifact delivered in a
    /// redirect.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::UndefinedBinding`] when this action is not Redirect.
    pub fn redirect_url(&self) -> Result<&str, SamlError> {
        if self.kind == OutboundKind::Redirect {
            return self
                .redirect_url
                .as_deref()
                .ok_or_else(|| SamlError::Invalid("missing redirect URL".into()));
        }
        Err(SamlError::UndefinedBinding)
    }

    /// POST form for POST and SimpleSign actions, and for an artifact
    /// delivered in a form.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::UndefinedBinding`] when this action is a redirect.
    pub fn post_form(&self) -> Result<&PostForm, SamlError> {
        if matches!(self.kind, OutboundKind::Post | OutboundKind::SimpleSignPost) {
            return self
                .post_form
                .as_ref()
                .ok_or_else(|| SamlError::Invalid("missing POST form".into()));
        }
        Err(SamlError::UndefinedBinding)
    }

    /// Raw compatibility context used to build this typed action.
    pub fn raw_context(&self) -> &BindingContext {
        &self.raw_context
    }

    /// Consume the typed action and return the raw compatibility context.
    pub fn into_raw_context(self) -> BindingContext {
        self.raw_context
    }
}

impl Outbound<SsoResponse> {
    /// Browser action that delivers `artifact` to the assertion consumer `acs`.
    ///
    /// `id` is the ID of the stored `<Response>`.
    pub(crate) fn artifact(
        id: String,
        relay_state: Option<String>,
        acs: &str,
        artifact: &Artifact,
        encoding: ArtifactEncoding,
    ) -> Result<Self, SamlError> {
        let raw_context = BindingContext {
            id,
            context: artifact.as_str().to_string(),
            relay_state,
            entity_endpoint: acs.to_string(),
            binding: Binding::Artifact,
            request_type: url_params::SAML_ART,
            signature: None,
            sig_alg: None,
        };
        let id = MessageId::try_new(raw_context.id.clone())?;
        let relay_state = raw_context
            .relay_state
            .clone()
            .map(RelayState::try_new)
            .transpose()?;
        let (kind, redirect_url, post_form) = match encoding {
            ArtifactEncoding::Url => {
                let query = crate::binding::redirect_binding_query(
                    url_params::SAML_ART,
                    artifact.as_str(),
                    raw_context.relay_state.as_deref(),
                );
                let url = append_redirect_query(acs, &query);
                EndpointUrl::try_new(url.clone())?;
                (OutboundKind::Redirect, Some(url), None)
            }
            ArtifactEncoding::Form => (
                OutboundKind::Post,
                None,
                Some(post_form_from_context(&raw_context, false)?),
            ),
        };
        Ok(Self {
            id,
            relay_state,
            kind,
            redirect_url,
            post_form,
            raw_context,
            _message: PhantomData,
        })
    }
}

impl TryFrom<BindingContext> for Outbound<AuthnRequest> {
    type Error = SamlError;

    fn try_from(raw_context: BindingContext) -> Result<Self, Self::Error> {
        outbound_from_context(raw_context, true, MessageField::Request)
    }
}

impl TryFrom<BindingContext> for Outbound<SsoResponse> {
    type Error = SamlError;

    fn try_from(raw_context: BindingContext) -> Result<Self, Self::Error> {
        outbound_from_context(raw_context, false, MessageField::Response)
    }
}

impl TryFrom<BindingContext> for Outbound<LogoutRequest> {
    type Error = SamlError;

    fn try_from(raw_context: BindingContext) -> Result<Self, Self::Error> {
        outbound_from_context(raw_context, true, MessageField::Request)
    }
}

impl TryFrom<BindingContext> for Outbound<LogoutResponse> {
    type Error = SamlError;

    fn try_from(raw_context: BindingContext) -> Result<Self, Self::Error> {
        outbound_from_context(raw_context, true, MessageField::Response)
    }
}

fn outbound_from_context<Message>(
    raw_context: BindingContext,
    allow_redirect: bool,
    expected_message: MessageField,
) -> Result<Outbound<Message>, SamlError> {
    validate_context_message_kind(&raw_context, expected_message)?;
    let id = MessageId::try_new(raw_context.id.clone())?;
    let relay_state = raw_context
        .relay_state
        .clone()
        .map(RelayState::try_new)
        .transpose()?;
    match raw_context.binding {
        Binding::Redirect => {
            if !allow_redirect {
                return Err(SamlError::UndefinedBinding);
            }
            EndpointUrl::try_new(raw_context.context.clone())?;
            validate_redirect_message_kind(&raw_context.context, expected_message)?;
            Ok(Outbound {
                id,
                relay_state,
                kind: OutboundKind::Redirect,
                redirect_url: Some(raw_context.context.clone()),
                post_form: None,
                raw_context,
                _message: PhantomData,
            })
        }
        Binding::Post => {
            reject_detached_signature_for_post(&raw_context)?;
            let form = post_form_from_context(&raw_context, false)?;
            Ok(Outbound {
                id,
                relay_state,
                kind: OutboundKind::Post,
                redirect_url: None,
                post_form: Some(form),
                raw_context,
                _message: PhantomData,
            })
        }
        Binding::SimpleSign => {
            require_complete_detached_signature(&raw_context)?;
            let form = post_form_from_context(&raw_context, true)?;
            Ok(Outbound {
                id,
                relay_state,
                kind: OutboundKind::SimpleSignPost,
                redirect_url: None,
                post_form: Some(form),
                raw_context,
                _message: PhantomData,
            })
        }
        Binding::Artifact => Err(SamlError::UndefinedBinding),
    }
}

fn validate_context_message_kind(
    context: &BindingContext,
    expected_message: MessageField,
) -> Result<(), SamlError> {
    let expected_name = expected_message.param_name();
    if context.request_type == expected_name {
        return Ok(());
    }
    Err(SamlError::Invalid(format!(
        "outbound context request_type must be {expected_name}"
    )))
}

fn validate_redirect_message_kind(
    raw_url: &str,
    expected_message: MessageField,
) -> Result<(), SamlError> {
    let expected_name = expected_message.param_name();
    let opposite_name = expected_message.opposite_param_name();
    let parsed = url::Url::parse(raw_url).map_err(|err| SamlError::Invalid(err.to_string()))?;
    let (expected_count, opposite_count) =
        parsed
            .query_pairs()
            .fold((0usize, 0usize), |(expected, opposite), (name, _)| {
                if name == expected_name {
                    (expected + 1, opposite)
                } else if name == opposite_name {
                    (expected, opposite + 1)
                } else {
                    (expected, opposite)
                }
            });

    match (expected_count, opposite_count) {
        (1, 0) => Ok(()),
        (0, 0) => Err(SamlError::Invalid(format!(
            "missing Redirect field {expected_name}"
        ))),
        (count, 0) if count > 1 => Err(SamlError::Invalid(format!(
            "ambiguous Redirect field {expected_name}"
        ))),
        (_, _) => Err(SamlError::Invalid(format!(
            "expected Redirect field {expected_name}, found {opposite_name}"
        ))),
    }
}

fn reject_partial_detached_signature(context: &BindingContext) -> Result<(), SamlError> {
    if context.sig_alg.is_some() != context.signature.is_some() {
        return Err(SamlError::Invalid(
            "partial detached signature state is invalid".into(),
        ));
    }
    Ok(())
}

fn reject_detached_signature_for_post(context: &BindingContext) -> Result<(), SamlError> {
    if context.sig_alg.is_some() || context.signature.is_some() {
        return Err(SamlError::Invalid(
            "POST outbound must not carry detached signature fields".into(),
        ));
    }
    Ok(())
}

fn require_complete_detached_signature(context: &BindingContext) -> Result<(), SamlError> {
    reject_partial_detached_signature(context)?;
    match (&context.sig_alg, &context.signature) {
        (Some(_), Some(_)) => Ok(()),
        _ => Err(SamlError::Invalid(
            "SimpleSign requires SigAlg and Signature".into(),
        )),
    }
}

fn post_form_from_context(
    context: &BindingContext,
    include_signature: bool,
) -> Result<PostForm, SamlError> {
    let action = EndpointUrl::try_new(context.entity_endpoint.clone())?;
    context.try_post_form()?;
    let mut fields = vec![FormField::new(
        context.request_type,
        context.context.clone(),
    )];
    if let Some(relay_state) = &context.relay_state {
        fields.push(FormField::new("RelayState", relay_state.clone()));
    }
    if include_signature {
        fields.push(FormField::new(
            "SigAlg",
            context.sig_alg.clone().unwrap_or_default(),
        ));
        fields.push(FormField::new(
            "Signature",
            context.signature.clone().unwrap_or_default(),
        ));
    }
    Ok(PostForm::new(action, fields))
}
