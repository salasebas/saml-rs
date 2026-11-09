use saml_rs::binding::base64_encode;
use saml_rs::constants::Binding;
use saml_rs::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
use saml_rs::raw::{BindingContext, FlowResult};
use saml_rs::util::Value;
use saml_rs::xml::XmlLimits;
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
use saml_rs::{
    raw::LoginResponseOptions,
    raw::User,
    template::{LoginResponseAttribute, LoginResponseTemplate},
};
use saml_rs::{
    AcsEndpoint, AuthnRequest, BrowserInput, EndpointUrl, EntityId, EntitySetting, FormField,
    IdentityProvider, LogoutCompleted, LogoutRequest, LogoutResponse, MessageId,
    NameIdCreationRequest, NameIdFormat, NameIdPolicy, Outbound, PendingAuthnRequest, RelayState,
    RelayStateParam, SamlError, SamlInstant, ServiceProvider, SsoRequestBinding, SsoResponse,
    SsoResponseBinding, SsoSession,
};

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
const IDP_PRIVATE_KEY: &str = include_str!("fixtures/key/sp_privkey.pem");
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
const IDP_CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");

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
fn typed_models_relay_state_preserves_tri_state() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(RelayStateParam::absent(), RelayStateParam::Absent);
    assert_eq!(
        RelayStateParam::present_empty(),
        RelayStateParam::PresentEmpty
    );
    assert_eq!(
        RelayStateParam::try_from_option(Some("state".to_string()))?,
        RelayStateParam::PresentValue(RelayState::try_new("state")?)
    );
    Ok(())
}

#[test]
fn typed_models_relay_state_try_from_option_rejects_overlong_values() {
    let result = RelayStateParam::try_from_option(Some("a".repeat(81)));

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

fn assert_browser_input_invalid<Message>(input: BrowserInput<Message>)
where
    saml_rs::raw::HttpRequest: TryFrom<BrowserInput<Message>, Error = SamlError>,
{
    let result = saml_rs::raw::HttpRequest::try_from(input);

    assert!(matches!(result, Err(SamlError::Invalid(_))));
}

#[test]
fn typed_models_redirect_outbound_exposes_only_redirect_url(
) -> Result<(), Box<dyn std::error::Error>> {
    let outbound: Outbound<AuthnRequest> = binding_context(Binding::Redirect).try_into()?;

    assert_eq!(outbound.id().as_str(), "_request123");
    assert_eq!(
        outbound.redirect_url()?,
        "https://idp.example.com/sso?SAMLRequest=abc"
    );
    assert!(matches!(
        outbound.post_form(),
        Err(SamlError::UndefinedBinding)
    ));
    assert_eq!(
        outbound.relay_state().map(RelayState::as_str),
        Some("relay")
    );
    Ok(())
}

#[test]
fn typed_models_post_outbound_exposes_post_form() -> Result<(), Box<dyn std::error::Error>> {
    let outbound: Outbound<AuthnRequest> = binding_context(Binding::Post).try_into()?;
    let form = outbound.post_form()?;

    assert_eq!(form.action().as_str(), "https://idp.example.com/sso");
    assert_eq!(
        form.value("SAMLRequest"),
        Some("PHNhbWxwOkF1dGhuUmVxdWVzdC8+")
    );
    assert!(matches!(
        outbound.redirect_url(),
        Err(SamlError::UndefinedBinding)
    ));
    Ok(())
}

#[test]
fn typed_models_post_outbound_rejects_detached_signature_fields() {
    let mut context = binding_context(Binding::Post);
    context.sig_alg = Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".to_string());
    context.signature = Some("signature-value".to_string());

    let result = Outbound::<AuthnRequest>::try_from(context);

    assert!(matches!(result, Err(SamlError::Invalid(_))));
}

#[test]
fn typed_models_simplesign_outbound_preserves_signature_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut context = binding_context(Binding::SimpleSign);
    context.sig_alg = Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".to_string());
    context.signature = Some("signature-value".to_string());

    let outbound: Outbound<AuthnRequest> = context.try_into()?;
    let form = outbound.post_form()?;

    assert_eq!(
        form.value("SigAlg"),
        Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
    );
    assert_eq!(form.value("Signature"), Some("signature-value"));
    Ok(())
}

#[test]
fn typed_models_simplesign_outbound_rejects_partial_signature_state() {
    let mut context = binding_context(Binding::SimpleSign);
    context.sig_alg = Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".to_string());

    let result = Outbound::<AuthnRequest>::try_from(context);

    assert!(matches!(result, Err(SamlError::Invalid(_))));
}

#[test]
fn typed_models_artifact_outbound_is_rejected() {
    let result = Outbound::<AuthnRequest>::try_from(binding_context(Binding::Artifact));

    assert!(matches!(result, Err(SamlError::UndefinedBinding)));
}

#[test]
fn typed_models_sso_response_outbound_rejects_redirect() {
    let result = Outbound::<SsoResponse>::try_from(response_binding_context(Binding::Redirect));

    assert!(matches!(result, Err(SamlError::UndefinedBinding)));
}

#[test]
fn typed_models_sso_response_outbound_accepts_post_and_simplesign(
) -> Result<(), Box<dyn std::error::Error>> {
    let post = Outbound::<SsoResponse>::try_from(response_binding_context(Binding::Post))?;
    let simple_sign =
        Outbound::<SsoResponse>::try_from(signed_response_binding_context(Binding::SimpleSign))?;

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
        Outbound::<AuthnRequest>::try_from(authn_context),
        Err(SamlError::Invalid(_))
    ));
    assert!(matches!(
        Outbound::<LogoutRequest>::try_from(logout_request_context),
        Err(SamlError::Invalid(_))
    ));
    assert!(matches!(
        Outbound::<SsoResponse>::try_from(sso_response_context),
        Err(SamlError::Invalid(_))
    ));
    assert!(matches!(
        Outbound::<LogoutResponse>::try_from(logout_response_context),
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
        Outbound::<LogoutResponse>::try_from(logout_response_context),
        Err(SamlError::Invalid(_))
    ));
    assert!(matches!(
        Outbound::<LogoutRequest>::try_from(logout_request_context),
        Err(SamlError::Invalid(_))
    ));
}

#[test]
fn typed_models_outbound_redirect_rejects_duplicate_message_field() {
    let mut context = binding_context(Binding::Redirect);
    context.context = "https://idp.example.com/sso?SAMLRequest=abc&SAMLRequest=def".to_string();

    assert!(matches!(
        Outbound::<LogoutRequest>::try_from(context),
        Err(SamlError::Invalid(_))
    ));
}

#[test]
fn typed_models_authn_request_outbound_accepts_browser_dispatch_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    let redirect = Outbound::<AuthnRequest>::try_from(binding_context(Binding::Redirect))?;
    let post = Outbound::<AuthnRequest>::try_from(binding_context(Binding::Post))?;
    let simple_sign =
        Outbound::<AuthnRequest>::try_from(signed_binding_context(Binding::SimpleSign))?;

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
            Binding::Redirect | Binding::Post | Binding::Artifact | Binding::Soap => {
                binding_context(binding)
            }
        };
        let response_context = match binding {
            Binding::SimpleSign => signed_response_binding_context(binding),
            Binding::Redirect | Binding::Post | Binding::Artifact | Binding::Soap => {
                response_binding_context(binding)
            }
        };

        let request = Outbound::<LogoutRequest>::try_from(request_context)?;
        let response = Outbound::<LogoutResponse>::try_from(response_context)?;

        assert_eq!(request.raw_context().binding, binding);
        assert_eq!(response.raw_context().binding, binding);
    }
    Ok(())
}

#[test]
fn typed_models_logout_response_outbound_rejects_saml_request_context() {
    let result = Outbound::<LogoutResponse>::try_from(binding_context(Binding::Post));

    assert!(matches!(result, Err(SamlError::Invalid(_))));
}

#[test]
fn typed_models_redirect_browser_input_converts_to_http_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let input = BrowserInput::<AuthnRequest>::redirect(
        "?SAMLRequest=abc&RelayState=relay&SigAlg=alg&Signature=sig",
    );

    let request = saml_rs::raw::HttpRequest::try_from(input)?;

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
fn typed_models_sso_response_browser_input_rejects_redirect() {
    let input = BrowserInput::<SsoResponse>::Redirect {
        raw_query: "?SAMLResponse=abc&SigAlg=alg&Signature=sig".to_string(),
        _message: std::marker::PhantomData,
    };

    let result = saml_rs::raw::HttpRequest::try_from(input);

    assert!(matches!(result, Err(SamlError::UndefinedBinding)));
}

#[test]
fn typed_models_redirect_browser_input_rejects_marker_field_mismatch() {
    assert_browser_input_invalid(BrowserInput::<AuthnRequest>::redirect("SAMLResponse=abc"));
    assert_browser_input_invalid(BrowserInput::<LogoutResponse>::redirect("SAMLRequest=abc"));
}

#[test]
fn typed_models_redirect_browser_input_uses_canonical_signed_octets_with_extra_params(
) -> Result<(), Box<dyn std::error::Error>> {
    let input = BrowserInput::<AuthnRequest>::redirect(
        "?ignored=before&Signature=sig&SAMLRequest=abc%2Bdef&RelayState=relay%20state&extra=after&SigAlg=http%3A%2F%2Fexample.com%2Falg",
    );

    let request = saml_rs::raw::HttpRequest::try_from(input)?;

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
        let input = BrowserInput::<AuthnRequest>::redirect(raw_query);

        let result = saml_rs::raw::HttpRequest::try_from(input);

        assert!(
            matches!(result, Err(SamlError::Invalid(_))),
            "expected duplicate {name} to fail"
        );
    }
}

#[test]
fn typed_models_redirect_browser_input_rejects_missing_or_both_message_fields() {
    assert_browser_input_invalid(BrowserInput::<AuthnRequest>::redirect(
        "RelayState=relay&SigAlg=alg&Signature=sig",
    ));
    assert_browser_input_invalid(BrowserInput::<AuthnRequest>::redirect(
        "SAMLRequest=abc&SAMLResponse=def&SigAlg=alg&Signature=sig",
    ));
}

#[test]
fn typed_models_post_browser_input_preserves_fields() -> Result<(), Box<dyn std::error::Error>> {
    let input = BrowserInput::<AuthnRequest>::post(vec![
        FormField::new("SAMLRequest", "abc"),
        FormField::new("RelayState", ""),
    ]);

    let request = saml_rs::raw::HttpRequest::try_from(input)?;

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
    let sso = BrowserInput::<SsoResponse>::post(vec![
        FormField::new("SAMLResponse", "abc"),
        FormField::new("RelayState", "relay"),
    ]);
    let logout = BrowserInput::<LogoutResponse>::post(vec![FormField::new("SAMLResponse", "def")]);

    let sso_request = saml_rs::raw::HttpRequest::try_from(sso)?;
    let logout_request = saml_rs::raw::HttpRequest::try_from(logout)?;

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
    assert_browser_input_invalid(BrowserInput::<AuthnRequest>::post(vec![FormField::new(
        "SAMLResponse",
        "abc",
    )]));
    assert_browser_input_invalid(BrowserInput::<LogoutRequest>::post(vec![FormField::new(
        "SAMLResponse",
        "abc",
    )]));
    assert_browser_input_invalid(BrowserInput::<SsoResponse>::post(vec![FormField::new(
        "SAMLRequest",
        "abc",
    )]));
    assert_browser_input_invalid(BrowserInput::<LogoutResponse>::post(vec![FormField::new(
        "SAMLRequest",
        "abc",
    )]));
}

#[test]
fn typed_models_post_browser_input_rejects_missing_duplicate_or_both_message_fields() {
    assert_browser_input_invalid(BrowserInput::<AuthnRequest>::post(vec![FormField::new(
        "RelayState",
        "relay",
    )]));
    assert_browser_input_invalid(BrowserInput::<AuthnRequest>::post(vec![
        FormField::new("SAMLRequest", "abc"),
        FormField::new("SAMLRequest", "def"),
    ]));
    assert_browser_input_invalid(BrowserInput::<AuthnRequest>::post(vec![
        FormField::new("SAMLRequest", "abc"),
        FormField::new("SAMLResponse", "def"),
    ]));
}

#[test]
fn typed_models_simplesign_browser_input_derives_signed_octets(
) -> Result<(), Box<dyn std::error::Error>> {
    let input = BrowserInput::<AuthnRequest>::simple_sign(vec![
        FormField::new("SAMLRequest", "PHNhbWxwOkF1dGhuUmVxdWVzdC8+"),
        FormField::new("RelayState", "relay"),
        FormField::new("SigAlg", "alg"),
        FormField::new("Signature", "sig"),
    ]);

    let request = saml_rs::raw::HttpRequest::try_from(input)?;

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
    let sso = BrowserInput::<SsoResponse>::simple_sign(vec![
        FormField::new("SAMLResponse", base64_encode(sso_xml.as_bytes())),
        FormField::new("RelayState", "relay"),
        FormField::new("SigAlg", "alg"),
        FormField::new("Signature", "sig"),
    ]);
    let logout = BrowserInput::<LogoutResponse>::simple_sign(vec![
        FormField::new("SAMLResponse", base64_encode(logout_xml.as_bytes())),
        FormField::new("SigAlg", "alg"),
        FormField::new("Signature", "sig"),
    ]);

    let sso_request = saml_rs::raw::HttpRequest::try_from(sso)?;
    let logout_request = saml_rs::raw::HttpRequest::try_from(logout)?;

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
    assert_browser_input_invalid(BrowserInput::<AuthnRequest>::simple_sign(vec![
        FormField::new("SAMLResponse", base64_encode(b"<samlp:Response/>")),
        FormField::new("SigAlg", "alg"),
        FormField::new("Signature", "sig"),
    ]));
    assert_browser_input_invalid(BrowserInput::<LogoutRequest>::simple_sign(vec![
        FormField::new("SAMLResponse", base64_encode(b"<samlp:LogoutResponse/>")),
        FormField::new("SigAlg", "alg"),
        FormField::new("Signature", "sig"),
    ]));
    assert_browser_input_invalid(BrowserInput::<SsoResponse>::simple_sign(vec![
        FormField::new("SAMLRequest", base64_encode(b"<samlp:AuthnRequest/>")),
        FormField::new("SigAlg", "alg"),
        FormField::new("Signature", "sig"),
    ]));
    assert_browser_input_invalid(BrowserInput::<LogoutResponse>::simple_sign(vec![
        FormField::new("SAMLRequest", base64_encode(b"<samlp:LogoutRequest/>")),
        FormField::new("SigAlg", "alg"),
        FormField::new("Signature", "sig"),
    ]));
}

#[test]
fn typed_models_simplesign_browser_input_rejects_missing_duplicate_or_both_message_fields() {
    assert_browser_input_invalid(BrowserInput::<AuthnRequest>::simple_sign(vec![
        FormField::new("SigAlg", "alg"),
        FormField::new("Signature", "sig"),
    ]));
    assert_browser_input_invalid(BrowserInput::<AuthnRequest>::simple_sign(vec![
        FormField::new("SAMLRequest", base64_encode(b"<samlp:AuthnRequest/>")),
        FormField::new("SAMLRequest", base64_encode(b"<samlp:AuthnRequest/>")),
        FormField::new("SigAlg", "alg"),
        FormField::new("Signature", "sig"),
    ]));
    assert_browser_input_invalid(BrowserInput::<AuthnRequest>::simple_sign(vec![
        FormField::new("SAMLRequest", base64_encode(b"<samlp:AuthnRequest/>")),
        FormField::new("SAMLResponse", base64_encode(b"<samlp:Response/>")),
        FormField::new("SigAlg", "alg"),
        FormField::new("Signature", "sig"),
    ]));
}

#[test]
fn typed_models_simplesign_browser_input_accepts_raw_body_only(
) -> Result<(), Box<dyn std::error::Error>> {
    let input = BrowserInput::<AuthnRequest>::simple_sign_body(
        "SAMLRequest=PHNhbWxwOkF1dGhuUmVxdWVzdC8%2B&RelayState=relay&SigAlg=alg&Signature=sig",
    );

    let request = saml_rs::raw::HttpRequest::try_from(input)?;

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
    let redirect = BrowserInput::<LogoutRequest>::redirect(
        "?SAMLRequest=abc&RelayState=relay&SigAlg=alg&Signature=sig",
    );
    let simple_sign = BrowserInput::<LogoutResponse>::simple_sign(vec![
        FormField::new("SAMLResponse", "PHNhbWxwOkxvZ291dFJlc3BvbnNlLz4="),
        FormField::new("RelayState", "relay"),
        FormField::new("SigAlg", "alg"),
        FormField::new("Signature", "sig"),
    ]);

    let redirect_request = saml_rs::raw::HttpRequest::try_from(redirect)?;
    let simple_sign_request = saml_rs::raw::HttpRequest::try_from(simple_sign)?;

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
    let input = BrowserInput::<AuthnRequest>::simple_sign(vec![
        FormField::new("SAMLRequest", base64_encode(&too_large)),
        FormField::new("SigAlg", "alg"),
        FormField::new("Signature", "sig"),
    ]);

    assert!(matches!(
        saml_rs::raw::HttpRequest::try_from(input),
        Err(SamlError::Invalid(_))
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
    let mut extract = value_object(vec![
        ("response", value_object(response)),
        ("assertion", value_object(assertion)),
        ("issuer", value_str("https://idp.example.com/metadata")),
        ("nameID", value_str("alice@example.com")),
    ]);
    if let Some(authn_statements) = authn_statements {
        extract.insert("sessionIndex", authn_statements);
    }
    FlowResult {
        saml_content: "<samlp:Response/>".to_string(),
        sig_alg: None,
        extract,
    }
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

    let request = AuthnRequest::try_from(flow)?;

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
        request
            .name_id_policy()
            .and_then(saml_rs::NameIdPolicy::allow_create),
        Some(true)
    );
    assert_eq!(request.force_authn(), None);
    assert_eq!(request.is_passive(), None);
    assert_eq!(request.requested_subject(), None);
    assert_eq!(request.raw_flow().saml_content, "<samlp:AuthnRequest/>");
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
        AuthnRequest::try_from(flow),
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
        AuthnRequest::try_from(flow),
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
        AuthnRequest::try_from(flow),
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

    let request = AuthnRequest::try_from(flow)?;

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

    let request = AuthnRequest::try_from(flow)?;

    assert_eq!(request.name_id_policy(), None);
    Ok(())
}

#[test]
fn typed_models_name_id_policy_constructors_use_typed_creation_request() {
    let unspecified = NameIdPolicy::unspecified(None);
    let allow = NameIdPolicy::allow_creation(None);
    let disallow = NameIdPolicy::disallow_creation(None);

    assert_eq!(
        unspecified.creation_request(),
        NameIdCreationRequest::Unspecified
    );
    assert_eq!(unspecified.allow_create(), None);
    assert_eq!(allow.creation_request(), NameIdCreationRequest::AllowCreate);
    assert_eq!(allow.allow_create(), Some(true));
    assert_eq!(
        disallow.creation_request(),
        NameIdCreationRequest::DoNotAllowCreate
    );
    assert_eq!(disallow.allow_create(), Some(false));
}

#[test]
fn typed_models_sso_response_from_flow_result_normalizes_issue_instant(
) -> Result<(), Box<dyn std::error::Error>> {
    let response = SsoResponse::try_from(minimal_sso_flow_with_issue_instants(
        Some(" \t\n2024-01-01T00:00:00Z\r "),
        Some("2024-01-01T00:00:01Z"),
        None,
    ))?;

    assert_eq!(response.response_id().as_str(), "_response123");
    assert_eq!(response.issue_instant().as_str(), "2024-01-01T00:00:00Z");
    Ok(())
}

#[test]
fn typed_models_sso_response_rejects_missing_issue_instant_with_profile_context() {
    let result = SsoResponse::try_from(minimal_sso_flow_with_issue_instants(
        None,
        Some("2024-01-01T00:00:01Z"),
        None,
    ));

    assert!(matches!(
        result,
        Err(SamlError::ProtocolProfile(message))
            if message.contains("Response is missing required unqualified attribute IssueInstant")
    ));
}

#[test]
fn typed_models_sso_response_rejects_malformed_issue_instant_with_profile_context() {
    let result = SsoResponse::try_from(minimal_sso_flow_with_issue_instants(
        Some("not-an-instant"),
        Some("2024-01-01T00:00:01Z"),
        None,
    ));

    assert!(matches!(
        result,
        Err(SamlError::ProtocolProfile(message))
            if message.contains(
                "Response IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z"
            )
    ));
}

#[test]
fn typed_models_sso_session_rejects_missing_response_issue_instant_with_profile_context() {
    let result = SsoSession::try_from(minimal_sso_flow_with_issue_instants(
        None,
        Some("2024-01-01T00:00:01Z"),
        None,
    ));

    assert!(matches!(
        result,
        Err(SamlError::ProtocolProfile(message))
            if message.contains("Response is missing required unqualified attribute IssueInstant")
    ));
}

#[test]
fn typed_models_sso_session_rejects_malformed_response_issue_instant_with_profile_context() {
    let result = SsoSession::try_from(minimal_sso_flow_with_issue_instants(
        Some("2024-01-01T00:00:00+00:00"),
        Some("2024-01-01T00:00:01Z"),
        None,
    ));

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
    let result = SsoSession::try_from(minimal_sso_flow_with_issue_instants(
        Some("2024-01-01T00:00:00Z"),
        None,
        None,
    ));

    assert!(matches!(
        result,
        Err(SamlError::ProtocolProfile(message))
            if message.contains("Assertion is missing required unqualified attribute IssueInstant")
    ));
}

#[test]
fn typed_models_sso_session_rejects_malformed_assertion_issue_instant_with_profile_context() {
    let result = SsoSession::try_from(minimal_sso_flow_with_issue_instants(
        Some("2024-01-01T00:00:00Z"),
        Some("not-an-instant"),
        None,
    ));

    assert!(matches!(
        result,
        Err(SamlError::ProtocolProfile(message))
            if message.contains(
                "Assertion IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z"
            )
    ));
}

#[test]
fn typed_models_sso_session_from_flow_result_preserves_multi_valued_attributes(
) -> Result<(), Box<dyn std::error::Error>> {
    let flow = FlowResult {
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
                "sessionIndex",
                value_object(vec![
                    ("sessionIndex", value_str("_session123")),
                    ("authnInstant", value_str("2026-07-04T12:00:00Z")),
                    ("sessionNotOnOrAfter", value_str("2026-07-04T13:00:00Z")),
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

    let session = SsoSession::try_from(flow)?;
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
    assert_eq!(
        session.assertion().id().map(saml_rs::AssertionId::as_str),
        Some("_assertion123")
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
            .authn_session()
            .session_index()
            .map(|id| id.as_str()),
        Some("_session123")
    );
    assert_eq!(session.sig_alg(), Some("sig-alg"));
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

    let session = SsoSession::try_from(flow)?;
    let tuples = session
        .authn_sessions()
        .iter()
        .map(|authn| {
            (
                authn.session_index().map(|value| value.as_str()),
                authn.authn_instant().map(SamlInstant::as_str),
                authn.not_on_or_after().map(SamlInstant::as_str),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(
        tuples,
        vec![
            (
                Some("_session1"),
                Some("2026-07-04T12:00:00Z"),
                Some("2026-07-04T13:00:00Z")
            ),
            (
                Some("_session2"),
                Some("2026-07-04T12:05:00Z"),
                Some("2026-07-04T12:30:00Z")
            ),
        ]
    );
    assert_eq!(
        session
            .authn_session()
            .session_index()
            .map(|value| value.as_str()),
        Some("_session1")
    );
    Ok(())
}

#[test]
fn typed_models_sso_session_without_authn_statements_has_empty_views(
) -> Result<(), Box<dyn std::error::Error>> {
    let missing = SsoSession::try_from(minimal_sso_flow(None))?;
    let empty_array = SsoSession::try_from(minimal_sso_flow(Some(Value::Array(Vec::new()))))?;

    assert!(missing.authn_sessions().is_empty());
    assert!(missing.authn_session().session_index().is_none());
    assert!(missing.authn_session().authn_instant().is_none());
    assert!(missing.authn_session().not_on_or_after().is_none());
    assert!(empty_array.authn_sessions().is_empty());
    assert!(empty_array.authn_session().session_index().is_none());
    Ok(())
}

#[test]
fn typed_models_sso_session_rejects_non_object_authn_statement_member() {
    let flow = minimal_sso_flow(Some(Value::Array(vec![
        value_object(vec![("sessionIndex", value_str("_session1"))]),
        value_str("not-an-object"),
    ])));

    assert!(matches!(
        SsoSession::try_from(flow),
        Err(SamlError::Invalid(_))
    ));
}

#[test]
fn typed_models_sso_session_rejects_scalar_authn_statement_shape() {
    let flow = minimal_sso_flow(Some(value_str("not-an-object")));

    assert!(matches!(
        SsoSession::try_from(flow),
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
        SsoSession::try_from(flow),
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
        SsoSession::try_from(flow),
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
        SsoSession::try_from(flow),
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

    let request = LogoutRequest::try_from(flow)?;

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
            .map(|index| index.as_str())
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
    let response =
        LogoutResponse::try_from(logout_response_flow(Some(" \t\n2024-01-01T00:00:00Z\r ")))?;

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
        LogoutResponse::try_from(logout_response_flow(None)),
        Err(SamlError::ProtocolProfile(message))
            if message.contains("LogoutResponse is missing required unqualified attribute IssueInstant")
    ));
}

#[test]
fn typed_models_logout_response_rejects_malformed_issue_instant_with_profile_context() {
    assert!(matches!(
        LogoutResponse::try_from(logout_response_flow(Some("not-an-instant"))),
        Err(SamlError::ProtocolProfile(message))
            if message.contains("LogoutResponse IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z")
    ));
}

#[test]
fn typed_models_logout_completed_equality_uses_peer_entity_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let first = LogoutCompleted::new(EntityId::try_new("https://idp.example.com/metadata")?);
    let second = LogoutCompleted::new(EntityId::try_new("https://idp.example.com/metadata")?);
    let other = LogoutCompleted::new(EntityId::try_new("https://other.example.com/metadata")?);

    assert_eq!(first, second);
    assert_ne!(first, other);
    Ok(())
}

fn sp(setting: EntitySetting) -> Result<ServiceProvider, SamlError> {
    ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            single_logout_service: vec![Endpoint::new(Binding::Post, "https://sp.example.com/slo")],
            assertion_consumer_service: vec![
                Endpoint::new(Binding::Post, "https://sp.example.com/acs"),
                Endpoint::new(Binding::SimpleSign, "https://sp.example.com/acs-simple"),
            ],
            ..Default::default()
        },
        setting,
    )
}

fn idp(setting: EntitySetting) -> Result<IdentityProvider, SamlError> {
    IdentityProvider::from_config(
        &IdpMetadataConfig {
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
            single_logout_service: vec![Endpoint::new(
                Binding::Post,
                "https://idp.example.com/slo",
            )],
            ..Default::default()
        },
        setting,
    )
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn signing_setting() -> EntitySetting {
    let mut setting = EntitySetting::default();
    setting.private_key = Some(IDP_PRIVATE_KEY.to_string());
    setting.signing_cert = Some(IDP_CERT.to_string());
    setting
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn attribute(name: &str, tag: &str) -> LoginResponseAttribute {
    LoginResponseAttribute {
        name: name.to_string(),
        name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".to_string(),
        value_xsi_type: "xs:string".to_string(),
        value_tag: tag.to_string(),
        value_xmlns_xs: None,
        value_xmlns_xsi: None,
    }
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn idp_with_attribute_template() -> Result<IdentityProvider, SamlError> {
    let mut setting = signing_setting();
    setting.login_response_template = Some(LoginResponseTemplate {
        context: None,
        attributes: vec![
            attribute("mail", "mail"),
            attribute("eduPersonAffiliation", "affiliation.primary"),
            attribute("eduPersonAffiliation", "affiliation.secondary"),
        ],
    });
    idp(setting)
}

#[test]
fn typed_models_existing_authn_request_flow_converts_to_typed_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp(EntitySetting::default())?;
    let idp = idp(EntitySetting::default())?;
    let context = sp.create_login_request(&idp, Binding::Post, None)?;
    let request =
        saml_rs::raw::HttpRequest::post(vec![("SAMLRequest".to_string(), context.context.clone())]);

    let parsed = idp.parse_login_request(&sp, Binding::Post, &request)?;
    let typed = AuthnRequest::try_from(parsed)?;

    assert_eq!(typed.id().as_str(), context.id.as_str());
    assert_eq!(typed.issuer().as_str(), "https://sp.example.com/metadata");
    Ok(())
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
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
        saml_rs::raw::HttpRequest::post(vec![("SAMLResponse".to_string(), context.context)]);

    let parsed =
        sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, "_request123")?;
    let raw_assertion_id = parsed
        .extract
        .get_str("assertion.id")
        .ok_or("missing assertion ID")?
        .to_string();
    let session = SsoSession::try_from(parsed)?;

    assert_eq!(session.name_id().value(), "alice@example.com");
    assert_eq!(
        session.in_response_to().map(MessageId::as_str),
        Some("_request123")
    );
    assert_eq!(session.assertion_id().as_str(), raw_assertion_id.as_str());
    Ok(())
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
#[test]
fn typed_models_existing_login_response_flow_preserves_multi_value_attributes(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp(EntitySetting::default())?;
    let idp = idp_with_attribute_template()?;
    let user = User {
        name_id: "alice@example.com".to_string(),
        attributes: vec![
            ("mail".to_string(), "alice@example.com".to_string()),
            ("affiliation.primary".to_string(), "users".to_string()),
            (
                "affiliation.secondary".to_string(),
                "examplerole1".to_string(),
            ),
        ],
        session_index: None,
    };
    let context = idp.create_login_response(
        &sp,
        Binding::Post,
        &user,
        &LoginResponseOptions {
            in_response_to: Some("_request123"),
            ..Default::default()
        },
    )?;
    let request =
        saml_rs::raw::HttpRequest::post(vec![("SAMLResponse".to_string(), context.context)]);

    let parsed =
        sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, "_request123")?;
    let raw_values = parsed
        .extract
        .get("attributes.eduPersonAffiliation")
        .cloned();
    let session = SsoSession::try_from(parsed)?;
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
fn typed_models_pending_snapshot_round_trips_without_raw_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let pending = PendingAuthnRequest::try_new(
        MessageId::try_new("_request123")?,
        RelayStateParam::try_from_option(Some("relay".to_string()))?,
        AcsEndpoint::post("https://sp.example.com/acs")?.with_index(3),
        SsoResponseBinding::Post,
        saml_rs::EntityId::try_new("https://idp.example.com/metadata")?,
    )?
    .with_request_binding(SsoRequestBinding::Redirect)
    .with_issue_instant(SamlInstant::try_new("2026-07-04T12:00:00Z")?)
    .with_expiration(SamlInstant::try_new("2026-07-04T12:05:00Z")?);

    let snapshot = pending.snapshot();
    let snapshot_debug = format!("{snapshot:?}");
    let restored = PendingAuthnRequest::from_snapshot(snapshot)?;

    assert_eq!(restored.id().as_str(), "_request123");
    assert_eq!(
        restored.relay_state(),
        &RelayStateParam::PresentValue(RelayState::try_new("relay")?)
    );
    assert_eq!(
        restored.request_binding(),
        Some(SsoRequestBinding::Redirect)
    );
    assert_eq!(restored.response_binding(), SsoResponseBinding::Post);
    assert_eq!(restored.acs().index(), Some(3));
    assert_eq!(
        restored.peer_entity_id().as_str(),
        "https://idp.example.com/metadata"
    );
    assert_eq!(
        restored.issued_at().map(SamlInstant::as_str),
        Some("2026-07-04T12:00:00Z")
    );
    assert_eq!(
        restored.expires_at().map(SamlInstant::as_str),
        Some("2026-07-04T12:05:00Z")
    );
    assert!(!snapshot_debug.contains("PRIVATE KEY"));
    assert!(!snapshot_debug.contains("<EntityDescriptor"));
    Ok(())
}

#[test]
fn typed_models_pending_snapshot_validates_expiration_requires_issue_instant(
) -> Result<(), Box<dyn std::error::Error>> {
    let pending = PendingAuthnRequest::try_new(
        MessageId::try_new("_request123")?,
        RelayStateParam::Absent,
        AcsEndpoint::post("https://sp.example.com/acs")?,
        SsoResponseBinding::Post,
        saml_rs::EntityId::try_new("https://idp.example.com/metadata")?,
    )?;
    let mut snapshot = pending.snapshot();
    snapshot.expires_at = Some(SamlInstant::try_new("2026-07-04T12:05:00Z")?);

    assert!(matches!(
        PendingAuthnRequest::from_snapshot(snapshot),
        Err(SamlError::Invalid(_))
    ));
    Ok(())
}
