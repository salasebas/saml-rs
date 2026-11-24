use super::sso_flow_document::set_authn_statements;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::constants::Binding;
use saml_rs::entity::BindingContext;
use saml_rs::entity::EntitySetting;
use saml_rs::flow::FlowResult;
use saml_rs::idp;
use saml_rs::metadata::{Endpoint, IdpMetadataInput, SpMetadataInput};
use saml_rs::sp;
use saml_rs::sp::LoginRequestOptions;
use saml_rs::tests::engine::{IdpMessages, SpMessages};
use saml_rs::util::Value;
use saml_rs::XmlLimits;
#[cfg(crypto)]
use saml_rs::{entity::User, idp::LoginResponseOptions};
use saml_rs::{
    AuthnRequest, EndpointUrl, FormField, Inbound, LogoutRequest, LogoutResponse, MessageId,
    NameIdCreationRequest, NameIdFormat, NameIdPolicy, Outbound, RelayState, SamlError,
    SamlInstant, SsoResponse, SsoResponseBinding, SsoSession, Status,
};

#[cfg(crypto)]
const IDP_PRIVATE_KEY: &str =
    include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
#[cfg(crypto)]
const IDP_CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");

#[test]
fn typed_models_empty_request_ids_fail() {
    assert!(matches!(MessageId::try_new(""), Err(SamlError::Invalid(_))));
}

#[test]
fn typed_models_endpoint_url_accepts_absolute_http_urls() -> Result<(), Box<dyn std::error::Error>>
{
    assert_eq!(
        EndpointUrl::try_new("https://sp.example.com/acs")?.as_str(),
        "https://sp.example.com/acs"
    );
    assert_eq!(
        EndpointUrl::try_new("http://localhost:3000/sso")?.as_str(),
        "http://localhost:3000/sso"
    );
    Ok(())
}

#[test]
fn typed_models_endpoint_url_rejects_relative_urls() {
    assert!(matches!(
        EndpointUrl::try_new("/acs"),
        Err(SamlError::Invalid(_))
    ));
}

#[test]
fn typed_models_relay_state_rejects_overlong_values() {
    let result = RelayState::try_new("a".repeat(81));

    assert!(matches!(result, Err(SamlError::Invalid(_))));
}

fn binding_context(binding: Binding) -> BindingContext {
    BindingContext {
        id: "_request123".to_string(),
        context: match binding {
            Binding::Redirect => "https://idp.example.com/sso?SAMLRequest=abc".to_string(),
            Binding::Post | Binding::SimpleSign => "PHNhbWxwOkF1dGhuUmVxdWVzdC8+".to_string(),
            Binding::Artifact => "artifact".to_string(),
            Binding::Soap => "<samlp:LogoutRequest/>".to_string(),
        },
        relay_state: Some("relay".to_string()),
        entity_endpoint: "https://idp.example.com/sso".to_string(),
        binding,
        request_type: "SAMLRequest",
        signature: None,
        sig_alg: None,
    }
}

fn response_binding_context(binding: Binding) -> BindingContext {
    BindingContext {
        id: "_response123".to_string(),
        context: match binding {
            Binding::Redirect => "https://sp.example.com/acs?SAMLResponse=abc".to_string(),
            Binding::Post | Binding::SimpleSign => "PHNhbWxwOlJlc3BvbnNlLz4=".to_string(),
            Binding::Artifact => "artifact".to_string(),
            Binding::Soap => "<samlp:LogoutRequest/>".to_string(),
        },
        relay_state: Some("relay".to_string()),
        entity_endpoint: "https://sp.example.com/acs".to_string(),
        binding,
        request_type: "SAMLResponse",
        signature: None,
        sig_alg: None,
    }
}

fn signed_binding_context(binding: Binding) -> BindingContext {
    let mut context = binding_context(binding);
    context.sig_alg = Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".to_string());
    context.signature = Some("signature-value".to_string());
    context
}

fn signed_response_binding_context(binding: Binding) -> BindingContext {
    let mut context = response_binding_context(binding);
    context.sig_alg = Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".to_string());
    context.signature = Some("signature-value".to_string());
    context
}

trait IntoHttpRequest {
    fn into_request(self) -> Result<saml_rs::flow::HttpRequest, SamlError>;
}

impl IntoHttpRequest for Inbound<AuthnRequest> {
    fn into_request(self) -> Result<saml_rs::flow::HttpRequest, SamlError> {
        self.into_http_request(XmlLimits::default())
            .map(|(_, request)| request)
    }
}

impl IntoHttpRequest for Inbound<SsoResponse> {
    fn into_request(self) -> Result<saml_rs::flow::HttpRequest, SamlError> {
        self.into_http_request(XmlLimits::default())
    }
}

impl IntoHttpRequest for Inbound<LogoutRequest> {
    fn into_request(self) -> Result<saml_rs::flow::HttpRequest, SamlError> {
        self.into_http_request(XmlLimits::default(), None)
    }
}

impl IntoHttpRequest for Inbound<LogoutResponse> {
    fn into_request(self) -> Result<saml_rs::flow::HttpRequest, SamlError> {
        self.into_http_request(XmlLimits::default(), None)
    }
}

fn assert_browser_input_invalid<Message>(input: Inbound<Message>)
where
    Inbound<Message>: IntoHttpRequest,
{
    let result = input.into_request();

    assert!(matches!(result, Err(SamlError::Invalid(_))));
}

fn browser_input_error<Message>(input: Inbound<Message>) -> Option<SamlError>
where
    Inbound<Message>: IntoHttpRequest,
{
    input.into_request().err()
}

#[test]
fn typed_models_redirect_outbound_exposes_only_redirect_url(
) -> Result<(), Box<dyn std::error::Error>> {
    let outbound = Outbound::<AuthnRequest>::from_context(binding_context(Binding::Redirect))?;

    assert_eq!(outbound.id().as_str(), "_request123");
    assert_eq!(
        outbound.redirect_url()?,
        "https://idp.example.com/sso?SAMLRequest=abc"
    );
    assert!(matches!(
        outbound.post_form(),
        Err(SamlError::OutboundDeliveryMismatch {
            actual: Binding::Redirect,
            ..
        })
    ));
    assert_eq!(
        outbound.relay_state().map(RelayState::as_str),
        Some("relay")
    );
    Ok(())
}

#[test]
fn typed_models_post_outbound_exposes_post_form() -> Result<(), Box<dyn std::error::Error>> {
    let action = "https://idp.example.com/sso?tenant=a&region=b";
    let outbound = Outbound::<AuthnRequest>::from_context(BindingContext {
        entity_endpoint: action.into(),
        ..binding_context(Binding::Post)
    })?;
    let form = outbound.post_form()?;

    assert_eq!(form.action().as_str(), action);
    assert_eq!(
        form.fields(),
        [
            FormField::new("SAMLRequest", "PHNhbWxwOkF1dGhuUmVxdWVzdC8+"),
            FormField::new("RelayState", "relay"),
        ]
    );
    assert!(matches!(
        outbound.redirect_url(),
        Err(SamlError::OutboundDeliveryMismatch {
            actual: Binding::Post,
            ..
        })
    ));
    Ok(())
}

#[test]
fn typed_models_post_outbound_rejects_non_http_and_relative_actions() {
    for action in ["ftp://idp.example.org/sso", "/sso"] {
        let context = BindingContext {
            entity_endpoint: action.into(),
            ..binding_context(Binding::Post)
        };
        let result = Outbound::<AuthnRequest>::from_context(context);
        assert!(
            matches!(result, Err(SamlError::Invalid(_))),
            "unexpected result for {action}: {result:?}"
        );
    }
}

#[test]
fn typed_models_post_outbound_distinguishes_absent_and_empty_relay_state(
) -> Result<(), Box<dyn std::error::Error>> {
    for state in [None, Some("")] {
        let context = BindingContext {
            relay_state: state.map(str::to_owned),
            ..binding_context(Binding::Post)
        };
        let outbound = Outbound::<AuthnRequest>::from_context(context)?;
        assert_eq!(outbound.post_form()?.value("RelayState"), state);
        assert_eq!(outbound.relay_state().map(RelayState::as_str), state);
    }
    Ok(())
}

#[test]
fn typed_models_post_outbound_rejects_detached_signature_fields() {
    for (sig_alg, signature) in [
        (Some("alg"), None),
        (None, Some("AA==")),
        (Some("alg"), Some("AA==")),
    ] {
        let context = BindingContext {
            sig_alg: sig_alg.map(str::to_owned),
            signature: signature.map(str::to_owned),
            ..binding_context(Binding::Post)
        };
        let result = Outbound::<AuthnRequest>::from_context(context);
        assert!(
            matches!(&result, Err(SamlError::Invalid(message)) if message == "POST and SOAP outbound must not carry detached signature fields"),
            "unexpected result for {sig_alg:?} and {signature:?}: {result:?}"
        );
    }
}

#[test]
fn typed_models_simplesign_outbound_preserves_signature_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let state = "relay=&<>\"'";
    let context = BindingContext {
        relay_state: Some(state.into()),
        ..signed_binding_context(Binding::SimpleSign)
    };

    let outbound = Outbound::<AuthnRequest>::from_context(context)?;
    let form = outbound.post_form()?;

    assert_eq!(
        form.fields(),
        [
            FormField::new("SAMLRequest", "PHNhbWxwOkF1dGhuUmVxdWVzdC8+"),
            FormField::new("RelayState", state),
            FormField::new(
                "SigAlg",
                saml_rs::constants::signature_algorithm::RSA_SHA256
            ),
            FormField::new("Signature", "signature-value"),
        ]
    );
    Ok(())
}

#[test]
fn typed_models_simplesign_outbound_requires_both_detached_signature_fields() {
    let partial_signature = "partial detached signature state is invalid";
    for (sig_alg, signature, expected) in [
        (None, None, "SimpleSign requires SigAlg and Signature"),
        (Some("alg"), None, partial_signature),
        (None, Some("AA=="), partial_signature),
    ] {
        let context = BindingContext {
            sig_alg: sig_alg.map(str::to_owned),
            signature: signature.map(str::to_owned),
            ..binding_context(Binding::SimpleSign)
        };
        let result = Outbound::<AuthnRequest>::from_context(context);
        assert!(
            matches!(&result, Err(SamlError::Invalid(message)) if message == expected),
            "unexpected result for {sig_alg:?} and {signature:?}: {result:?}"
        );
    }
}

#[test]
fn typed_models_artifact_outbound_is_rejected() {
    let result = Outbound::<AuthnRequest>::from_context(binding_context(Binding::Artifact));

    assert!(matches!(
        result,
        Err(SamlError::UnsupportedBinding {
            binding: Binding::Artifact,
            ..
        })
    ));
}

#[test]
fn typed_models_sso_response_outbound_rejects_redirect() {
    let result = Outbound::<SsoResponse>::echoing_received_relay_state(response_binding_context(
        Binding::Redirect,
    ));

    assert!(matches!(
        result,
        Err(SamlError::UnsupportedBinding {
            binding: Binding::Redirect,
            ..
        })
    ));
}

#[test]
fn typed_models_sso_response_outbound_accepts_post_and_simplesign(
) -> Result<(), Box<dyn std::error::Error>> {
    let post = Outbound::<SsoResponse>::echoing_received_relay_state(response_binding_context(
        Binding::Post,
    ))?;
    let simple_sign = Outbound::<SsoResponse>::echoing_received_relay_state(
        signed_response_binding_context(Binding::SimpleSign),
    )?;

    assert_eq!(
        post.post_form()?.value("SAMLResponse"),
        Some("PHNhbWxwOlJlc3BvbnNlLz4=")
    );
    assert_eq!(
        simple_sign.post_form()?.value("SAMLResponse"),
        Some("PHNhbWxwOlJlc3BvbnNlLz4=")
    );
    Ok(())
}

#[test]
fn typed_models_outbound_rejects_marker_message_field_mismatch() {
    let mut authn_context = binding_context(Binding::Post);
    authn_context.request_type = "SAMLResponse";
    let mut logout_request_context = binding_context(Binding::Post);
    logout_request_context.request_type = "SAMLResponse";
    let mut sso_response_context = response_binding_context(Binding::Post);
    sso_response_context.request_type = "SAMLRequest";
    let mut logout_response_context = response_binding_context(Binding::Post);
    logout_response_context.request_type = "SAMLRequest";

    assert!(matches!(
        Outbound::<AuthnRequest>::from_context(authn_context),
        Err(SamlError::Invalid(_))
    ));
    assert!(matches!(
        Outbound::<LogoutRequest>::from_context(logout_request_context),
        Err(SamlError::Invalid(_))
    ));
    assert!(matches!(
        Outbound::<SsoResponse>::echoing_received_relay_state(sso_response_context),
        Err(SamlError::Invalid(_))
    ));
    assert!(matches!(
        Outbound::<LogoutResponse>::echoing_received_relay_state(logout_response_context),
        Err(SamlError::Invalid(_))
    ));
}

#[test]
fn typed_models_outbound_redirect_rejects_marker_url_field_mismatch() {
    let mut logout_response_context = response_binding_context(Binding::Redirect);
    logout_response_context.context = "https://sp.example.com/acs?SAMLRequest=abc".to_string();
    let mut logout_request_context = binding_context(Binding::Redirect);
    logout_request_context.context = "https://idp.example.com/slo?SAMLResponse=abc".to_string();

    assert!(matches!(
        Outbound::<LogoutResponse>::echoing_received_relay_state(logout_response_context),
        Err(SamlError::Invalid(_))
    ));
    assert!(matches!(
        Outbound::<LogoutRequest>::from_context(logout_request_context),
        Err(SamlError::Invalid(_))
    ));
}

#[test]
fn typed_models_outbound_redirect_rejects_a_missing_or_duplicate_message_field() {
    let mut duplicate = binding_context(Binding::Redirect);
    duplicate.context = "https://idp.example.com/sso?SAMLRequest=abc&SAMLRequest=def".to_string();
    let mut missing = binding_context(Binding::Redirect);
    missing.context = "https://idp.example.com/sso?RelayState=relay".to_string();

    assert!(matches!(
        Outbound::<LogoutRequest>::from_context(duplicate),
        Err(SamlError::DuplicateBindingParameter {
            name: "SAMLRequest",
            ..
        })
    ));
    assert!(matches!(
        Outbound::<LogoutRequest>::from_context(missing),
        Err(SamlError::MissingBindingParameter {
            name: "SAMLRequest",
            ..
        })
    ));
}

#[test]
fn typed_models_authn_request_outbound_accepts_browser_dispatch_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    let redirect = Outbound::<AuthnRequest>::from_context(binding_context(Binding::Redirect))?;
    let post = Outbound::<AuthnRequest>::from_context(binding_context(Binding::Post))?;
    let simple_sign =
        Outbound::<AuthnRequest>::from_context(signed_binding_context(Binding::SimpleSign))?;

    assert!(redirect.redirect_url().is_ok());
    assert!(post.post_form().is_ok());
    assert!(simple_sign.post_form().is_ok());
    Ok(())
}

#[test]
fn typed_models_slo_outbound_accepts_logout_bindings() -> Result<(), Box<dyn std::error::Error>> {
    for binding in [Binding::Redirect, Binding::Post, Binding::SimpleSign] {
        let request_context = match binding {
            Binding::SimpleSign => signed_binding_context(binding),
            _ => binding_context(binding),
        };
        let response_context = match binding {
            Binding::SimpleSign => signed_response_binding_context(binding),
            _ => response_binding_context(binding),
        };

        let request = Outbound::<LogoutRequest>::from_context(request_context)?;
        let response = Outbound::<LogoutResponse>::echoing_received_relay_state(response_context)?;

        assert!(
            matches!(
                request.soap_request(),
                Err(SamlError::OutboundDeliveryMismatch { actual, .. }) if actual == binding
            ),
            "{binding:?}"
        );
        assert!(
            matches!(
                response.soap_response(),
                Err(SamlError::OutboundDeliveryMismatch { actual, .. }) if actual == binding
            ),
            "{binding:?}"
        );
    }
    Ok(())
}

#[test]
fn typed_models_logout_response_outbound_rejects_saml_request_context() {
    let result =
        Outbound::<LogoutResponse>::echoing_received_relay_state(binding_context(Binding::Post));

    assert!(matches!(result, Err(SamlError::Invalid(_))));
}

#[test]
fn typed_models_redirect_browser_input_converts_to_http_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let input = Inbound::<AuthnRequest>::redirect(
        "?SAMLRequest=abc&RelayState=relay&SigAlg=alg&Signature=sig",
    );

    let request = input.into_request()?;

    assert_eq!(
        request.query,
        vec![
            ("SAMLRequest".to_string(), "abc".to_string()),
            ("RelayState".to_string(), "relay".to_string()),
            ("SigAlg".to_string(), "alg".to_string()),
            ("Signature".to_string(), "sig".to_string()),
        ]
    );
    assert_eq!(
        request.octet_string.as_deref(),
        Some("SAMLRequest=abc&RelayState=relay&SigAlg=alg")
    );
    Ok(())
}

#[test]
fn typed_models_redirect_browser_input_rejects_marker_field_mismatch() {
    assert_browser_input_invalid(Inbound::<AuthnRequest>::redirect("SAMLResponse=abc"));
    assert_browser_input_invalid(Inbound::<LogoutResponse>::redirect("SAMLRequest=abc"));
}

#[test]
fn typed_models_redirect_browser_input_uses_canonical_signed_octets_with_extra_params(
) -> Result<(), Box<dyn std::error::Error>> {
    let input = Inbound::<AuthnRequest>::redirect(
        "?ignored=before&Signature=sig&SAMLRequest=abc%2Bdef&RelayState=relay%20state&extra=after&SigAlg=http%3A%2F%2Fexample.com%2Falg",
    );

    let request = input.into_request()?;

    assert_eq!(
        request.octet_string.as_deref(),
        Some(
            "SAMLRequest=abc%2Bdef&RelayState=relay%20state&SigAlg=http%3A%2F%2Fexample.com%2Falg"
        )
    );
    Ok(())
}

#[test]
fn typed_models_redirect_browser_input_rejects_duplicate_signed_fields() {
    for (name, raw_query) in [
        (
            "SAMLRequest",
            "SAMLRequest=abc&SAMLRequest=def&SigAlg=alg&Signature=sig",
        ),
        (
            "SAMLResponse",
            "SAMLResponse=abc&SAMLResponse=def&SigAlg=alg&Signature=sig",
        ),
        (
            "RelayState",
            "SAMLRequest=abc&RelayState=one&RelayState=two&SigAlg=alg&Signature=sig",
        ),
        (
            "SigAlg",
            "SAMLRequest=abc&SigAlg=one&SigAlg=two&Signature=sig",
        ),
        (
            "Signature",
            "SAMLRequest=abc&SigAlg=alg&Signature=one&Signature=two",
        ),
    ] {
        let input = Inbound::<AuthnRequest>::redirect(raw_query);

        let result = input.into_request();

        assert!(
            matches!(
                result,
                Err(SamlError::DuplicateBindingParameter { name: duplicate, .. }) if duplicate == name
            ),
            "expected duplicate {name} to fail, got {result:?}"
        );
    }
}

#[test]
fn typed_models_redirect_browser_input_rejects_missing_or_both_message_fields() {
    assert!(matches!(
        browser_input_error(Inbound::<AuthnRequest>::redirect(
            "RelayState=relay&SigAlg=alg&Signature=sig",
        )),
        Some(SamlError::MissingBindingParameter {
            name: "SAMLRequest",
            ..
        })
    ));
    assert_browser_input_invalid(Inbound::<AuthnRequest>::redirect(
        "SAMLRequest=abc&SAMLResponse=def&SigAlg=alg&Signature=sig",
    ));
}

#[test]
fn typed_models_post_browser_input_preserves_fields() -> Result<(), Box<dyn std::error::Error>> {
    let input = Inbound::<AuthnRequest>::post(vec![
        FormField::new("SAMLRequest", "abc"),
        FormField::new("RelayState", ""),
    ]);

    let request = input.into_request()?;

    assert_eq!(
        request.body,
        vec![
            ("SAMLRequest".to_string(), "abc".to_string()),
            ("RelayState".to_string(), String::new()),
        ]
    );
    assert_eq!(request.octet_string, None);
    Ok(())
}

#[test]
fn typed_models_post_browser_input_accepts_response_markers(
) -> Result<(), Box<dyn std::error::Error>> {
    let sso = Inbound::<SsoResponse>::post(vec![
        FormField::new("SAMLResponse", "abc"),
        FormField::new("RelayState", "relay"),
    ]);
    let logout = Inbound::<LogoutResponse>::post(vec![FormField::new("SAMLResponse", "def")]);

    let sso_request = sso.into_request()?;
    let logout_request = logout.into_request()?;

    assert_eq!(
        sso_request.body,
        vec![
            ("SAMLResponse".to_string(), "abc".to_string()),
            ("RelayState".to_string(), "relay".to_string()),
        ]
    );
    assert_eq!(
        logout_request.body,
        vec![("SAMLResponse".to_string(), "def".to_string())]
    );
    Ok(())
}

#[test]
fn typed_models_post_browser_input_rejects_marker_field_mismatch() {
    assert_browser_input_invalid(Inbound::<AuthnRequest>::post(vec![FormField::new(
        "SAMLResponse",
        "abc",
    )]));
    assert_browser_input_invalid(Inbound::<LogoutRequest>::post(vec![FormField::new(
        "SAMLResponse",
        "abc",
    )]));
    assert_browser_input_invalid(Inbound::<SsoResponse>::post(vec![FormField::new(
        "SAMLRequest",
        "abc",
    )]));
    assert_browser_input_invalid(Inbound::<LogoutResponse>::post(vec![FormField::new(
        "SAMLRequest",
        "abc",
    )]));
}

#[test]
fn typed_models_post_browser_input_rejects_missing_duplicate_or_both_message_fields() {
    assert!(matches!(
        browser_input_error(Inbound::<AuthnRequest>::post(vec![FormField::new(
            "RelayState",
            "relay",
        )])),
        Some(SamlError::MissingBindingParameter {
            name: "SAMLRequest",
            ..
        })
    ));
    assert!(matches!(
        browser_input_error(Inbound::<AuthnRequest>::post(vec![
            FormField::new("SAMLRequest", "abc"),
            FormField::new("SAMLRequest", "def"),
        ])),
        Some(SamlError::DuplicateBindingParameter {
            name: "SAMLRequest",
            ..
        })
    ));
    assert_browser_input_invalid(Inbound::<AuthnRequest>::post(vec![
        FormField::new("SAMLRequest", "abc"),
        FormField::new("SAMLResponse", "def"),
    ]));
}

#[test]
fn typed_models_simplesign_browser_input_derives_signed_octets(
) -> Result<(), Box<dyn std::error::Error>> {
    let input = Inbound::<AuthnRequest>::simple_sign(vec![
        FormField::new("SAMLRequest", "PHNhbWxwOkF1dGhuUmVxdWVzdC8+"),
        FormField::new("RelayState", "relay"),
        FormField::new("SigAlg", "alg"),
        FormField::new("Signature", "sig"),
    ]);

    let request = input.into_request()?;

    assert_eq!(
        request.octet_string.as_deref(),
        Some("SAMLRequest=<samlp:AuthnRequest/>&RelayState=relay&SigAlg=alg")
    );
    Ok(())
}

#[test]
fn typed_models_simplesign_browser_input_accepts_response_markers(
) -> Result<(), Box<dyn std::error::Error>> {
    let sso_xml = "<samlp:Response/>";
    let logout_xml = "<samlp:LogoutResponse/>";
    let sso = Inbound::<SsoResponse>::simple_sign(vec![
        FormField::new("SAMLResponse", STANDARD.encode(sso_xml.as_bytes())),
        FormField::new("RelayState", "relay"),
        FormField::new("SigAlg", "alg"),
        FormField::new("Signature", "sig"),
    ]);
    let logout = Inbound::<LogoutResponse>::simple_sign(vec![
        FormField::new("SAMLResponse", STANDARD.encode(logout_xml.as_bytes())),
        FormField::new("SigAlg", "alg"),
        FormField::new("Signature", "sig"),
    ]);

    let sso_request = sso.into_request()?;
    let logout_request = logout.into_request()?;

    assert_eq!(
        sso_request.octet_string.as_deref(),
        Some("SAMLResponse=<samlp:Response/>&RelayState=relay&SigAlg=alg")
    );
    assert_eq!(
        logout_request.octet_string.as_deref(),
        Some("SAMLResponse=<samlp:LogoutResponse/>&SigAlg=alg")
    );
    Ok(())
}

#[test]
fn typed_models_simplesign_browser_input_rejects_marker_field_mismatch() {
    assert_browser_input_invalid(Inbound::<AuthnRequest>::simple_sign(vec![
        FormField::new("SAMLResponse", STANDARD.encode(b"<samlp:Response/>")),
        FormField::new("SigAlg", "alg"),
        FormField::new("Signature", "sig"),
    ]));
    assert_browser_input_invalid(Inbound::<LogoutRequest>::simple_sign(vec![
        FormField::new("SAMLResponse", STANDARD.encode(b"<samlp:LogoutResponse/>")),
        FormField::new("SigAlg", "alg"),
        FormField::new("Signature", "sig"),
    ]));
    assert_browser_input_invalid(Inbound::<SsoResponse>::simple_sign(vec![
        FormField::new("SAMLRequest", STANDARD.encode(b"<samlp:AuthnRequest/>")),
        FormField::new("SigAlg", "alg"),
        FormField::new("Signature", "sig"),
    ]));
    assert_browser_input_invalid(Inbound::<LogoutResponse>::simple_sign(vec![
        FormField::new("SAMLRequest", STANDARD.encode(b"<samlp:LogoutRequest/>")),
        FormField::new("SigAlg", "alg"),
        FormField::new("Signature", "sig"),
    ]));
}

#[test]
fn typed_models_simplesign_browser_input_rejects_missing_duplicate_or_both_message_fields() {
    assert!(matches!(
        browser_input_error(Inbound::<AuthnRequest>::simple_sign(vec![
            FormField::new("SigAlg", "alg"),
            FormField::new("Signature", "sig"),
        ])),
        Some(SamlError::MissingBindingParameter {
            name: "SAMLRequest",
            ..
        })
    ));
    assert!(matches!(
        browser_input_error(Inbound::<AuthnRequest>::simple_sign(vec![
            FormField::new("SAMLRequest", STANDARD.encode(b"<samlp:AuthnRequest/>")),
            FormField::new("SAMLRequest", STANDARD.encode(b"<samlp:AuthnRequest/>")),
            FormField::new("SigAlg", "alg"),
            FormField::new("Signature", "sig"),
        ])),
        Some(SamlError::DuplicateBindingParameter {
            name: "SAMLRequest",
            ..
        })
    ));
    assert_browser_input_invalid(Inbound::<AuthnRequest>::simple_sign(vec![
        FormField::new("SAMLRequest", STANDARD.encode(b"<samlp:AuthnRequest/>")),
        FormField::new("SAMLResponse", STANDARD.encode(b"<samlp:Response/>")),
        FormField::new("SigAlg", "alg"),
        FormField::new("Signature", "sig"),
    ]));
}

#[test]
fn typed_models_simplesign_browser_input_signs_decoded_field_values(
) -> Result<(), Box<dyn std::error::Error>> {
    let input = Inbound::<AuthnRequest>::simple_sign(vec![
        FormField::new("SAMLRequest", "PHNhbWxwOkF1dGhuUmVxdWVzdC8+"),
        FormField::new("RelayState", "relay"),
        FormField::new("SigAlg", "alg"),
        FormField::new("Signature", "sig"),
    ]);

    let request = input.into_request()?;

    assert_eq!(
        request.body,
        vec![
            (
                "SAMLRequest".to_string(),
                "PHNhbWxwOkF1dGhuUmVxdWVzdC8+".to_string()
            ),
            ("RelayState".to_string(), "relay".to_string()),
            ("SigAlg".to_string(), "alg".to_string()),
            ("Signature".to_string(), "sig".to_string()),
        ]
    );
    assert_eq!(
        request.octet_string.as_deref(),
        Some("SAMLRequest=<samlp:AuthnRequest/>&RelayState=relay&SigAlg=alg")
    );
    Ok(())
}

#[test]
fn typed_models_logout_browser_input_preserves_detached_signature_octets(
) -> Result<(), Box<dyn std::error::Error>> {
    let redirect = Inbound::<LogoutRequest>::redirect(
        "?SAMLRequest=abc&RelayState=relay&SigAlg=alg&Signature=sig",
    );
    let simple_sign = Inbound::<LogoutResponse>::simple_sign(vec![
        FormField::new("SAMLResponse", "PHNhbWxwOkxvZ291dFJlc3BvbnNlLz4="),
        FormField::new("RelayState", "relay"),
        FormField::new("SigAlg", "alg"),
        FormField::new("Signature", "sig"),
    ]);

    let redirect_request = redirect.into_request()?;
    let simple_sign_request = simple_sign.into_request()?;

    assert_eq!(
        redirect_request.octet_string.as_deref(),
        Some("SAMLRequest=abc&RelayState=relay&SigAlg=alg")
    );
    assert_eq!(
        simple_sign_request.octet_string.as_deref(),
        Some("SAMLResponse=<samlp:LogoutResponse/>&RelayState=relay&SigAlg=alg")
    );
    Ok(())
}

#[test]
fn typed_models_simplesign_browser_input_bounds_decoded_xml() {
    let too_large = vec![b'a'; XmlLimits::default().max_bytes + 1];
    let input = Inbound::<AuthnRequest>::simple_sign(vec![
        FormField::new("SAMLRequest", STANDARD.encode(&too_large)),
        FormField::new("SigAlg", "alg"),
        FormField::new("Signature", "sig"),
    ]);

    assert!(matches!(
        input.into_request(),
        Err(SamlError::LimitExceeded {
            limit: saml_rs::ResourceLimit::Base64DecodedBytes,
            ..
        })
    ));
}

fn value_object(entries: Vec<(&str, Value)>) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    )
}

fn value_str(value: &str) -> Value {
    Value::Str(value.to_string())
}

fn minimal_sso_flow(authn_statements: Option<Value>) -> FlowResult {
    minimal_sso_flow_with_issue_instants(
        Some("2024-01-01T00:00:00Z"),
        Some("2024-01-01T00:00:01Z"),
        authn_statements,
    )
}

fn minimal_sso_flow_with_issue_instants(
    response_issue_instant: Option<&str>,
    assertion_issue_instant: Option<&str>,
    authn_statements: Option<Value>,
) -> FlowResult {
    let mut response = vec![("id", value_str("_response123"))];
    if let Some(issue_instant) = response_issue_instant {
        response.push(("issueInstant", value_str(issue_instant)));
    }
    let mut assertion = vec![("id", value_str("_assertion123"))];
    if let Some(issue_instant) = assertion_issue_instant {
        assertion.push(("issueInstant", value_str(issue_instant)));
    }
    let mut flow = FlowResult {
        saml_content: "<samlp:Response/>".to_string(),
        sig_alg: None,
        extract: value_object(vec![
            ("response", value_object(response)),
            ("assertion", value_object(assertion)),
            ("issuer", value_str("https://idp.example.com/metadata")),
            ("nameID", value_str("alice@example.com")),
        ]),
    };
    if let Some(authn_statements) = authn_statements {
        set_authn_statements(&mut flow, authn_statements);
    }
    flow
}

#[test]
fn typed_models_authn_request_from_flow_result_exposes_typed_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let flow = FlowResult {
        saml_content: "<samlp:AuthnRequest/>".to_string(),
        sig_alg: None,
        extract: value_object(vec![
            (
                "request",
                value_object(vec![
                    ("id", value_str("_request123")),
                    ("issueInstant", value_str(" \t\n2024-01-01T00:00:00Z\r ")),
                    ("destination", value_str("https://idp.example.com/sso")),
                    (
                        "assertionConsumerServiceUrl",
                        value_str("https://sp.example.com/acs"),
                    ),
                    (
                        "protocolBinding",
                        value_str("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"),
                    ),
                    ("assertionConsumerServiceIndex", value_str("3")),
                ]),
            ),
            ("issuer", value_str("https://sp.example.com/metadata")),
            (
                "nameIDPolicy",
                value_object(vec![
                    (
                        "format",
                        value_str("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
                    ),
                    ("allowCreate", value_str("true")),
                ]),
            ),
        ]),
    };

    let request = AuthnRequest::from_flow(&flow)?;

    assert_eq!(request.id().as_str(), "_request123");
    assert_eq!(request.issue_instant().as_str(), "2024-01-01T00:00:00Z");
    assert_eq!(request.issuer().as_str(), "https://sp.example.com/metadata");
    assert_eq!(
        request.destination().map(EndpointUrl::as_str),
        Some("https://idp.example.com/sso")
    );
    assert_eq!(
        request.acs_url().map(EndpointUrl::as_str),
        Some("https://sp.example.com/acs")
    );
    assert_eq!(request.protocol_binding(), Some(SsoResponseBinding::Post));
    assert_eq!(request.acs_index(), Some(3));
    assert_eq!(
        request.name_id_policy().map(NameIdPolicy::creation_request),
        Some(NameIdCreationRequest::AllowCreate)
    );
    assert_eq!(request.force_authn(), None);
    assert_eq!(request.passive(), None);
    assert_eq!(request.requested_subject(), None);
    Ok(())
}

#[test]
fn typed_models_authn_request_rejects_invalid_name_id_policy_allow_create() {
    let flow = FlowResult {
        saml_content: "<samlp:AuthnRequest/>".to_string(),
        sig_alg: None,
        extract: value_object(vec![
            (
                "request",
                value_object(vec![
                    ("id", value_str("_request123")),
                    ("issueInstant", value_str("2024-01-01T00:00:00Z")),
                ]),
            ),
            ("issuer", value_str("https://sp.example.com/metadata")),
            (
                "nameIDPolicy",
                value_object(vec![("allowCreate", value_str("maybe"))]),
            ),
        ]),
    };

    assert!(matches!(
        AuthnRequest::from_flow(&flow),
        Err(SamlError::Invalid(_))
    ));
}

#[test]
fn typed_models_authn_request_rejects_missing_issue_instant_with_profile_context() {
    let flow = FlowResult {
        saml_content: "<samlp:AuthnRequest/>".to_string(),
        sig_alg: None,
        extract: value_object(vec![
            (
                "request",
                value_object(vec![("id", value_str("_request123"))]),
            ),
            ("issuer", value_str("https://sp.example.com/metadata")),
        ]),
    };

    assert!(matches!(
        AuthnRequest::from_flow(&flow),
        Err(SamlError::ProtocolProfile(message))
            if message.contains("missing required unqualified attribute IssueInstant")
    ));
}

#[test]
fn typed_models_authn_request_rejects_malformed_issue_instant_with_profile_context() {
    let flow = FlowResult {
        saml_content: "<samlp:AuthnRequest/>".to_string(),
        sig_alg: None,
        extract: value_object(vec![
            (
                "request",
                value_object(vec![
                    ("id", value_str("_request123")),
                    ("issueInstant", value_str("not-an-instant")),
                ]),
            ),
            ("issuer", value_str("https://sp.example.com/metadata")),
        ]),
    };

    assert!(matches!(
        AuthnRequest::from_flow(&flow),
        Err(SamlError::ProtocolProfile(message))
            if message.contains(
                "IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z"
            )
    ));
}

#[test]
fn typed_models_authn_request_name_id_policy_without_allow_create_is_unspecified(
) -> Result<(), Box<dyn std::error::Error>> {
    let flow = FlowResult {
        saml_content: "<samlp:AuthnRequest/>".to_string(),
        sig_alg: None,
        extract: value_object(vec![
            (
                "request",
                value_object(vec![
                    ("id", value_str("_request123")),
                    ("issueInstant", value_str("2024-01-01T00:00:00Z")),
                ]),
            ),
            ("issuer", value_str("https://sp.example.com/metadata")),
            (
                "nameIDPolicy",
                value_object(vec![(
                    "format",
                    value_str("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
                )]),
            ),
        ]),
    };

    let request = AuthnRequest::from_flow(&flow)?;

    assert_eq!(
        request.name_id_policy().map(NameIdPolicy::creation_request),
        Some(NameIdCreationRequest::Unspecified)
    );
    Ok(())
}

#[test]
fn typed_models_authn_request_without_name_id_policy_stays_absent(
) -> Result<(), Box<dyn std::error::Error>> {
    let flow = FlowResult {
        saml_content: "<samlp:AuthnRequest/>".to_string(),
        sig_alg: None,
        extract: value_object(vec![
            (
                "request",
                value_object(vec![
                    ("id", value_str("_request123")),
                    ("issueInstant", value_str("2024-01-01T00:00:00Z")),
                ]),
            ),
            ("issuer", value_str("https://sp.example.com/metadata")),
        ]),
    };

    let request = AuthnRequest::from_flow(&flow)?;

    assert_eq!(request.name_id_policy(), None);
    Ok(())
}

#[test]
fn typed_models_sso_session_rejects_missing_response_issue_instant_with_profile_context() {
    let result = SsoSession::try_from_with_verified_xml_signatures(
        minimal_sso_flow_with_issue_instants(None, Some("2024-01-01T00:00:01Z"), None),
        Vec::new(),
        None,
    );

    assert!(matches!(
        result,
        Err(SamlError::ProtocolProfile(message))
            if message.contains("Response is missing required unqualified attribute IssueInstant")
    ));
}

#[test]
fn typed_models_sso_session_rejects_malformed_response_issue_instant_with_profile_context() {
    let result = SsoSession::try_from_with_verified_xml_signatures(
        minimal_sso_flow_with_issue_instants(
            Some("2024-01-01T00:00:00+00:00"),
            Some("2024-01-01T00:00:01Z"),
            None,
        ),
        Vec::new(),
        None,
    );

    assert!(matches!(
        result,
        Err(SamlError::ProtocolProfile(message))
            if message.contains(
                "Response IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z"
            )
    ));
}

#[test]
fn typed_models_sso_session_rejects_missing_assertion_issue_instant_with_profile_context() {
    let result = SsoSession::try_from_with_verified_xml_signatures(
        minimal_sso_flow_with_issue_instants(Some("2024-01-01T00:00:00Z"), None, None),
        Vec::new(),
        None,
    );

    assert!(matches!(
        result,
        Err(SamlError::ProtocolProfile(message))
            if message.contains("Assertion is missing required unqualified attribute IssueInstant")
    ));
}

#[test]
fn typed_models_sso_session_rejects_malformed_assertion_issue_instant_with_profile_context() {
    let result = SsoSession::try_from_with_verified_xml_signatures(
        minimal_sso_flow_with_issue_instants(
            Some("2024-01-01T00:00:00Z"),
            Some("not-an-instant"),
            None,
        ),
        Vec::new(),
        None,
    );

    assert!(matches!(
        result,
        Err(SamlError::ProtocolProfile(message))
            if message.contains(
                "Assertion IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z"
            )
    ));
}

#[test]
fn typed_models_sso_session_rejects_attributes_without_their_elements() {
    let mut without_elements = minimal_sso_flow(None);
    without_elements.extract.insert(
        "attributes",
        value_object(vec![("mail", value_str("a@example.com"))]),
    );
    let mut without_values = minimal_sso_flow(None);
    without_values.extract.insert(
        "attributeNameFormats",
        value_object(vec![("name", value_str("mail"))]),
    );

    let mut null_elements = minimal_sso_flow(None);
    null_elements.extract.insert(
        "attributes",
        value_object(vec![("mail", value_str("a@example.com"))]),
    );
    null_elements
        .extract
        .insert("attributeNameFormats", Value::Null);

    for (flow, missing) in [
        (without_elements, "attributeNameFormats"),
        (without_values, "attributeValue"),
        (null_elements, "attributeNameFormats"),
    ] {
        assert!(
            matches!(
                SsoSession::try_from_with_verified_xml_signatures(flow, Vec::new(), None),
                Err(SamlError::Invalid(ref message)) if message.contains(missing)
            ),
            "{missing}"
        );
    }

    let mut no_attributes = minimal_sso_flow(None);
    no_attributes
        .extract
        .insert("attributes", value_object(Vec::new()));
    assert!(matches!(
        SsoSession::try_from_with_verified_xml_signatures(no_attributes, Vec::new(), None)
            .map(|session| session.attributes().as_slice().is_empty()),
        Ok(true)
    ));
}

#[test]
fn typed_models_sso_session_from_flow_result_preserves_multi_valued_attributes(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut flow = FlowResult {
        saml_content: "<samlp:Response/>".to_string(),
        sig_alg: Some("sig-alg".to_string()),
        extract: value_object(vec![
            (
                "response",
                value_object(vec![
                    ("id", value_str("_response123")),
                    ("issueInstant", value_str(" \t\n2024-01-01T00:00:00Z\r ")),
                    ("inResponseTo", value_str("_request123")),
                ]),
            ),
            (
                "assertion",
                value_object(vec![
                    ("id", value_str("_assertion123")),
                    ("issueInstant", value_str(" \t\n2024-01-01T00:00:01Z\r ")),
                ]),
            ),
            ("issuer", value_str("https://idp.example.com/metadata")),
            ("nameID", value_str("alice@example.com")),
            (
                "nameIDFormat",
                value_str("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"),
            ),
            (
                "attributes",
                value_object(vec![(
                    "eduPersonAffiliation",
                    Value::Array(vec![value_str("users"), value_str("examplerole1")]),
                )]),
            ),
            (
                "attributeNameFormats",
                value_object(vec![
                    ("name", value_str("eduPersonAffiliation")),
                    (
                        "attributeValue",
                        Value::Array(vec![value_str("users"), value_str("examplerole1")]),
                    ),
                ]),
            ),
            (
                "conditions",
                value_object(vec![
                    ("notBefore", value_str("2026-07-04T11:59:00Z")),
                    ("notOnOrAfter", value_str("2026-07-04T13:00:00Z")),
                ]),
            ),
            ("audience", value_str("https://sp.example.com/metadata")),
            (
                "subjectConfirmation",
                value_str("<saml:SubjectConfirmation/>"),
            ),
        ]),
    };
    set_authn_statements(
        &mut flow,
        value_object(vec![
            ("sessionIndex", value_str("_session123")),
            ("authnInstant", value_str("2026-07-04T12:00:00Z")),
            ("sessionNotOnOrAfter", value_str("2026-07-04T13:00:00Z")),
        ]),
    );

    let session = SsoSession::try_from_with_verified_xml_signatures(flow, Vec::new(), None)?;
    let affiliation = session
        .attributes()
        .get("eduPersonAffiliation")
        .ok_or("missing affiliation")?;

    assert_eq!(session.response_id().as_str(), "_response123");
    assert_eq!(
        session.response_issue_instant().as_str(),
        "2024-01-01T00:00:00Z"
    );
    assert_eq!(session.assertion_id().as_str(), "_assertion123");
    assert_eq!(
        session.assertion_issue_instant().as_str(),
        "2024-01-01T00:00:01Z"
    );
    assert_eq!(session.name_id().value(), "alice@example.com");
    assert_eq!(session.name_id().format(), Some(&NameIdFormat::Persistent));
    assert_eq!(
        affiliation
            .values()
            .iter()
            .map(saml_rs::AttributeValue::as_str)
            .collect::<Vec<_>>(),
        vec!["users", "examplerole1"]
    );
    assert_eq!(
        session
            .authn_statements()
            .iter()
            .map(|statement| statement.session_index().map(saml_rs::SessionIndex::as_str))
            .collect::<Vec<_>>(),
        [Some("_session123")]
    );
    assert_eq!(session.binding_signature_algorithm_uri(), Some("sig-alg"));
    Ok(())
}

#[test]
fn typed_models_sso_session_preserves_repeated_authn_statements_in_order(
) -> Result<(), Box<dyn std::error::Error>> {
    let flow = minimal_sso_flow(Some(Value::Array(vec![
        value_object(vec![
            ("sessionIndex", value_str("_session1")),
            ("authnInstant", value_str("2026-07-04T12:00:00Z")),
            ("sessionNotOnOrAfter", value_str("2026-07-04T13:00:00Z")),
        ]),
        value_object(vec![
            ("sessionIndex", value_str("_session2")),
            ("authnInstant", value_str("2026-07-04T12:05:00Z")),
            ("sessionNotOnOrAfter", value_str("2026-07-04T12:30:00Z")),
        ]),
    ])));

    let session = SsoSession::try_from_with_verified_xml_signatures(flow, Vec::new(), None)?;
    let tuples = session
        .authn_statements()
        .iter()
        .map(|authn| {
            (
                authn.session_index().map(saml_rs::SessionIndex::as_str),
                authn.authn_instant().as_str(),
                authn.session_not_on_or_after().map(SamlInstant::as_str),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(
        tuples,
        vec![
            (
                Some("_session1"),
                "2026-07-04T12:00:00Z",
                Some("2026-07-04T13:00:00Z")
            ),
            (
                Some("_session2"),
                "2026-07-04T12:05:00Z",
                Some("2026-07-04T12:30:00Z")
            ),
        ]
    );
    Ok(())
}

#[test]
fn typed_models_sso_session_without_authn_statements_lists_none(
) -> Result<(), Box<dyn std::error::Error>> {
    let missing = SsoSession::try_from_with_verified_xml_signatures(
        minimal_sso_flow(None),
        Vec::new(),
        None,
    )?;
    let empty_array = SsoSession::try_from_with_verified_xml_signatures(
        minimal_sso_flow(Some(Value::Array(Vec::new()))),
        Vec::new(),
        None,
    )?;

    assert!(missing.authn_statements().is_empty());
    assert!(empty_array.authn_statements().is_empty());
    Ok(())
}

#[test]
fn typed_models_sso_session_rejects_non_object_authn_statement_member() {
    let flow = minimal_sso_flow(Some(Value::Array(vec![
        value_object(vec![("sessionIndex", value_str("_session1"))]),
        value_str("not-an-object"),
    ])));

    assert!(matches!(
        SsoSession::try_from_with_verified_xml_signatures(flow, Vec::new(), None),
        Err(SamlError::Invalid(_))
    ));
}

#[test]
fn typed_models_sso_session_rejects_scalar_authn_statement_shape() {
    let flow = minimal_sso_flow(Some(value_str("not-an-object")));

    assert!(matches!(
        SsoSession::try_from_with_verified_xml_signatures(flow, Vec::new(), None),
        Err(SamlError::Invalid(_))
    ));
}

#[test]
fn typed_models_sso_session_without_assertion_id_fails_closed() {
    let flow = FlowResult {
        saml_content: "<samlp:Response/>".to_string(),
        sig_alg: None,
        extract: value_object(vec![
            (
                "response",
                value_object(vec![
                    ("id", value_str("_response123")),
                    ("issueInstant", value_str("2024-01-01T00:00:00Z")),
                ]),
            ),
            ("issuer", value_str("https://idp.example.com/metadata")),
            ("nameID", value_str("alice@example.com")),
        ]),
    };

    assert!(matches!(
        SsoSession::try_from_with_verified_xml_signatures(flow, Vec::new(), None),
        Err(SamlError::Invalid(_))
    ));
}

#[test]
fn typed_models_sso_session_rejects_repeated_conditions_shape() {
    let condition = || value_object(vec![("notOnOrAfter", value_str("2026-07-04T13:00:00Z"))]);
    let flow = FlowResult {
        saml_content: "<samlp:Response/>".to_string(),
        sig_alg: None,
        extract: value_object(vec![
            (
                "response",
                value_object(vec![
                    ("id", value_str("_response123")),
                    ("issueInstant", value_str("2024-01-01T00:00:00Z")),
                ]),
            ),
            (
                "assertion",
                value_object(vec![
                    ("id", value_str("_assertion123")),
                    ("issueInstant", value_str("2024-01-01T00:00:01Z")),
                ]),
            ),
            ("issuer", value_str("https://idp.example.com/metadata")),
            ("nameID", value_str("alice@example.com")),
            ("conditions", Value::Array(vec![condition(), condition()])),
        ]),
    };

    assert!(matches!(
        SsoSession::try_from_with_verified_xml_signatures(flow, Vec::new(), None),
        Err(SamlError::Invalid(message)) if message.contains("Conditions")
    ));
}

#[test]
fn typed_models_sso_session_rejects_malformed_assertion_id() {
    let flow = FlowResult {
        saml_content: "<samlp:Response/>".to_string(),
        sig_alg: None,
        extract: value_object(vec![
            (
                "response",
                value_object(vec![
                    ("id", value_str("_response123")),
                    ("issueInstant", value_str("2024-01-01T00:00:00Z")),
                ]),
            ),
            (
                "assertion",
                value_object(vec![
                    ("id", value_str("  ")),
                    ("issueInstant", value_str("2024-01-01T00:00:01Z")),
                ]),
            ),
            ("issuer", value_str("https://idp.example.com/metadata")),
            ("nameID", value_str("alice@example.com")),
        ]),
    };

    assert!(matches!(
        SsoSession::try_from_with_verified_xml_signatures(flow, Vec::new(), None),
        Err(SamlError::Invalid(_))
    ));
}

#[test]
fn typed_models_logout_request_from_flow_result_exposes_session_indexes(
) -> Result<(), Box<dyn std::error::Error>> {
    let flow = FlowResult {
        saml_content: "<samlp:LogoutRequest/>".to_string(),
        sig_alg: None,
        extract: value_object(vec![
            (
                "request",
                value_object(vec![
                    ("id", value_str("_logout123")),
                    ("issueInstant", value_str(" \t\n2024-01-01T00:00:00Z\r ")),
                    ("notOnOrAfter", value_str(" \t\n2024-01-01T00:05:00Z\r ")),
                    ("destination", value_str("https://idp.example.com/slo")),
                ]),
            ),
            ("issuer", value_str("https://sp.example.com/metadata")),
            ("nameID", value_str("alice@example.com")),
            (
                "sessionIndex",
                Value::Array(vec![value_str("_session1"), value_str("_session2")]),
            ),
        ]),
    };

    let request = LogoutRequest::from_flow(flow, None)?;

    assert_eq!(request.id().as_str(), "_logout123");
    assert_eq!(request.issue_instant().as_str(), "2024-01-01T00:00:00Z");
    assert_eq!(
        request.not_on_or_after().map(SamlInstant::as_str),
        Some("2024-01-01T00:05:00Z")
    );
    assert_eq!(request.issuer().as_str(), "https://sp.example.com/metadata");
    assert_eq!(
        request
            .session_indexes()
            .iter()
            .map(saml_rs::SessionIndex::as_str)
            .collect::<Vec<_>>(),
        vec!["_session1", "_session2"]
    );
    assert_eq!(
        request.destination().map(EndpointUrl::as_str),
        Some("https://idp.example.com/slo")
    );
    Ok(())
}

#[test]
fn typed_models_logout_response_from_flow_result_exposes_correlation(
) -> Result<(), Box<dyn std::error::Error>> {
    let response = LogoutResponse::from_flow(
        &logout_response_flow(Some(" \t\n2024-01-01T00:00:00Z\r ")),
        Status::success(),
        None,
    )?;

    assert_eq!(response.id().as_str(), "_logout_response123");
    assert_eq!(response.issue_instant().as_str(), "2024-01-01T00:00:00Z");
    assert_eq!(
        response.in_response_to().map(MessageId::as_str),
        Some("_logout123")
    );
    assert_eq!(
        response.destination().map(EndpointUrl::as_str),
        Some("https://sp.example.com/slo")
    );
    Ok(())
}

fn logout_response_flow(issue_instant: Option<&str>) -> FlowResult {
    let mut response = vec![
        ("id", value_str("_logout_response123")),
        ("inResponseTo", value_str("_logout123")),
        ("destination", value_str("https://sp.example.com/slo")),
    ];
    if let Some(issue_instant) = issue_instant {
        response.push(("issueInstant", value_str(issue_instant)));
    }
    FlowResult {
        saml_content: "<samlp:LogoutResponse/>".to_string(),
        sig_alg: None,
        extract: value_object(vec![
            ("response", value_object(response)),
            ("issuer", value_str("https://idp.example.com/metadata")),
        ]),
    }
}

#[test]
fn typed_models_logout_response_rejects_missing_issue_instant_with_profile_context() {
    assert!(matches!(
        LogoutResponse::from_flow(&logout_response_flow(None), Status::success(), None),
        Err(SamlError::ProtocolProfile(message))
            if message.contains("LogoutResponse is missing required unqualified attribute IssueInstant")
    ));
}

#[test]
fn typed_models_logout_response_rejects_malformed_issue_instant_with_profile_context() {
    assert!(matches!(
        LogoutResponse::from_flow(
            &logout_response_flow(Some("not-an-instant")),
            Status::success(),
            None,
        ),
        Err(SamlError::ProtocolProfile(message))
            if message.contains("LogoutResponse IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z")
    ));
}

fn sp(setting: EntitySetting) -> Result<sp::Engine, SamlError> {
    let config = SpMetadataInput {
        entity_id: "https://sp.example.com/metadata".into(),
        single_logout_service: vec![Endpoint::new(Binding::Post, "https://sp.example.com/slo")],
        assertion_consumer_service: vec![
            Endpoint::new(Binding::Post, "https://sp.example.com/acs"),
            Endpoint::new(Binding::SimpleSign, "https://sp.example.com/acs-simple"),
        ],
        ..SpMetadataInput::default()
    };
    sp::Engine::from_config(&config, setting)
}

fn idp(setting: EntitySetting) -> Result<idp::Engine, SamlError> {
    let mut config = IdpMetadataInput {
        entity_id: "https://idp.example.com/metadata".into(),
        signing_certs: setting
            .signing_cert
            .clone()
            .map(|cert| vec![cert])
            .unwrap_or_default(),
        single_sign_on_service: vec![
            Endpoint::new(Binding::Post, "https://idp.example.com/sso"),
            Endpoint::new(Binding::Redirect, "https://idp.example.com/sso"),
            Endpoint::new(Binding::SimpleSign, "https://idp.example.com/sso"),
        ],
        ..IdpMetadataInput::default()
    };
    config.single_logout_service =
        vec![Endpoint::new(Binding::Post, "https://idp.example.com/slo")];
    idp::Engine::from_config(&config, setting)
}

#[cfg(crypto)]
fn signing_setting() -> EntitySetting {
    EntitySetting {
        private_key: Some(IDP_PRIVATE_KEY.to_string()),
        signing_cert: Some(IDP_CERT.to_string()),
        ..EntitySetting::default()
    }
}

#[test]
fn typed_models_existing_authn_request_flow_converts_to_typed_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp(EntitySetting::default())?;
    let idp = idp(EntitySetting::default())?;
    let context = sp.create_login_request(&idp, Binding::Post, &LoginRequestOptions::default())?;
    let request = saml_rs::flow::HttpRequest::post(vec![(
        "SAMLRequest".to_string(),
        context.context.clone(),
    )]);

    let parsed = idp.parse_login_request(&sp, Binding::Post, &request)?;
    let typed = AuthnRequest::from_flow(&parsed)?;

    assert_eq!(typed.id().as_str(), context.id.as_str());
    assert_eq!(typed.issuer().as_str(), "https://sp.example.com/metadata");
    Ok(())
}

#[cfg(crypto)]
#[test]
fn typed_models_existing_login_response_flow_converts_to_typed_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp(EntitySetting::default())?;
    let idp = idp(signing_setting())?;
    let context = idp.create_login_response(
        &sp,
        Binding::Post,
        &User::new("alice@example.com"),
        &LoginResponseOptions {
            in_response_to: Some("_request123"),
            ..Default::default()
        },
    )?;
    let request =
        saml_rs::flow::HttpRequest::post(vec![("SAMLResponse".to_string(), context.context)]);

    let parsed =
        sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, "_request123")?;
    let raw_assertion_id = parsed
        .extract
        .get_str("assertion.id")
        .ok_or("missing assertion ID")?
        .to_string();
    let session = SsoSession::try_from_with_verified_xml_signatures(parsed, Vec::new(), None)?;

    assert_eq!(session.name_id().value(), "alice@example.com");
    assert_eq!(
        session.in_response_to().map(MessageId::as_str),
        Some("_request123")
    );
    assert_eq!(session.assertion_id().as_str(), raw_assertion_id.as_str());
    Ok(())
}

#[cfg(crypto)]
#[test]
fn typed_models_existing_login_response_flow_preserves_multi_value_attributes(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp(EntitySetting::default())?;
    let idp = idp(signing_setting())?;
    let attributes = [
        saml_rs::Attribute::new("mail", [saml_rs::AttributeValue::new("alice@example.com")]),
        saml_rs::Attribute::new(
            "eduPersonAffiliation",
            [saml_rs::AttributeValue::new("users")],
        ),
        saml_rs::Attribute::new(
            "eduPersonAffiliation",
            [saml_rs::AttributeValue::new("examplerole1")],
        ),
    ];
    let context = idp
        .create_login_response_with_overrides(
            &sp,
            Binding::Post,
            &User::new("alice@example.com"),
            &LoginResponseOptions {
                in_response_to: Some("_request123"),
                ..Default::default()
            },
            crate::idp::LoginResponseOverrides {
                typed_attributes: &attributes,
                ..Default::default()
            },
        )?
        .context;
    let request =
        saml_rs::flow::HttpRequest::post(vec![("SAMLResponse".to_string(), context.context)]);

    let parsed =
        sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, "_request123")?;
    let raw_values = parsed
        .extract
        .get("attributes.eduPersonAffiliation")
        .cloned();
    let session = SsoSession::try_from_with_verified_xml_signatures(parsed, Vec::new(), None)?;
    let affiliation = session
        .attributes()
        .get("eduPersonAffiliation")
        .ok_or("missing affiliation")?;

    assert_eq!(
        raw_values,
        Some(Value::Array(vec![
            value_str("users"),
            value_str("examplerole1")
        ]))
    );
    assert_eq!(
        affiliation
            .values()
            .iter()
            .map(saml_rs::AttributeValue::as_str)
            .collect::<Vec<_>>(),
        vec!["users", "examplerole1"]
    );
    Ok(())
}

#[test]
fn typed_models_simplesign_browser_input_error_does_not_keep_the_message_bytes(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![b'a'; 4096];
    bytes.push(0xff);
    let error = browser_input_error(Inbound::<AuthnRequest>::simple_sign(vec![
        FormField::new("SAMLRequest", STANDARD.encode(&bytes)),
        FormField::new("SigAlg", "alg"),
        FormField::new("Signature", "sig"),
    ]))
    .ok_or("non-UTF-8 input was accepted")?;

    assert!(
        matches!(
            error,
            SamlError::Xml {
                source: Some(_),
                ..
            }
        ),
        "{error}"
    );
    let debug = format!("{error:?}");
    assert!(debug.len() < 512, "the error kept the input: {debug:.200}");
    Ok(())
}
