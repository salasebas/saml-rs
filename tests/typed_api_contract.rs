use saml_rs::{
    AcsEndpoint, AuthnRequest, EndpointUrl, Idp, LogoutBinding, MessageId, NameIdCreationRequest,
    PendingAuthnRequest, PendingAuthnRequestSnapshot, PendingLogoutRequest,
    PendingLogoutRequestSnapshot, RelayState, Saml, SamlError, SamlInstant, SloEndpoint, Sp,
    SsoEndpoint, SsoRequestBinding, SsoResponseBinding, VerifiedXmlSignature,
    VerifiedXmlSignatureCoverage,
};

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn typed_api_contract_exposes_role_markers() {
    assert_send_sync::<Saml<Sp>>();
    assert_send_sync::<Saml<Idp>>();
    let _: Option<SamlError> = None;
}

#[test]
fn typed_api_contract_reexports_raw_flow_types() {
    let _ = std::any::type_name::<saml_rs::raw::Binding>();
    let _ = std::any::type_name::<saml_rs::raw::FlowResult>();
    let _ = std::any::type_name::<saml_rs::raw::BindingContext>();
    let _ = std::any::type_name::<saml_rs::raw::HttpRequest>();
}

#[test]
fn typed_api_contract_reexports_config_builders() {
    let _ = std::any::type_name::<saml_rs::SpConfigBuilder>();
    let _ = std::any::type_name::<saml_rs::IdpConfigBuilder>();
    let _ = std::any::type_name::<saml_rs::AuthnRequestSigningPolicy>();
    let _ = std::any::type_name::<saml_rs::AuthnRequestValidationPolicy>();
}

#[test]
fn typed_api_contract_reexports_typed_binding_building_blocks(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_send_sync::<SsoRequestBinding>();
    assert_send_sync::<SsoResponseBinding>();
    assert_send_sync::<LogoutBinding>();
    assert_send_sync::<EndpointUrl>();
    assert_send_sync::<SsoEndpoint>();
    assert_send_sync::<AcsEndpoint>();
    assert_send_sync::<SloEndpoint>();
    assert_send_sync::<MessageId>();
    assert_send_sync::<RelayState>();
    assert_send_sync::<SamlInstant>();
    assert_send_sync::<PendingAuthnRequest>();
    assert_send_sync::<PendingAuthnRequestSnapshot>();
    assert_send_sync::<PendingLogoutRequest>();
    assert_send_sync::<PendingLogoutRequestSnapshot>();
    assert_send_sync::<NameIdCreationRequest>();

    let pending = PendingAuthnRequest::from_snapshot(PendingAuthnRequestSnapshot {
        id: "_request123".to_string(),
        relay_state: Some("relay".to_string()),
        peer_entity_id: "https://idp.example.com/metadata".to_string(),
        acs_binding: "post".to_string(),
        acs_url: "https://sp.example.com/acs".to_string(),
        acs_index: None,
        acs_is_default: false,
    })?;
    let _: &AcsEndpoint = pending.acs();
    let _: SsoResponseBinding = pending.acs().binding();
    let logout_pending = PendingLogoutRequest::from_snapshot(PendingLogoutRequestSnapshot {
        id: "_logout123".to_string(),
        relay_state: Some(String::new()),
        peer_entity_id: "https://idp.example.com/metadata".to_string(),
        binding: "redirect".to_string(),
        issued_at: None,
        expires_at: None,
    })?;
    let _: LogoutBinding = logout_pending.binding();
    let _ = SsoEndpoint::redirect("https://idp.example.com/sso")?;
    let _ = SloEndpoint::new(
        LogoutBinding::Redirect,
        EndpointUrl::try_new("https://idp.example.com/slo")?,
    );
    let _ = SsoRequestBinding::Redirect;
    Ok(())
}

#[test]
fn typed_api_contract_reexports_browser_and_model_types() {
    let _: for<'a> fn(&'a AuthnRequest) -> &'a SamlInstant = AuthnRequest::issue_instant;
    let _: fn(&AuthnRequest) -> Option<saml_rs::ForceAuthn> = AuthnRequest::force_authn;
    let _: fn(&AuthnRequest) -> Option<saml_rs::IsPassive> = AuthnRequest::is_passive;
    let _: for<'a> fn(&'a AuthnRequest) -> Option<&'a saml_rs::RequestedSubject> =
        AuthnRequest::requested_subject;
    let _: for<'a> fn(&'a saml_rs::NameId) -> Option<&'a str> = saml_rs::NameId::name_qualifier;
    let _: for<'a> fn(&'a saml_rs::NameId) -> Option<&'a str> = saml_rs::NameId::sp_name_qualifier;
    let _: for<'a> fn(&'a saml_rs::NameId) -> Option<&'a str> = saml_rs::NameId::sp_provided_id;
    let _: for<'a> fn(&'a saml_rs::SsoResponse) -> &'a SamlInstant =
        saml_rs::SsoResponse::issue_instant;
    let _: for<'a> fn(&'a saml_rs::SsoSession) -> &'a SamlInstant =
        saml_rs::SsoSession::response_issue_instant;
    let _: for<'a> fn(&'a saml_rs::SsoSession) -> &'a SamlInstant =
        saml_rs::SsoSession::assertion_issue_instant;
    let _: for<'a> fn(&'a saml_rs::SsoSession) -> &'a [VerifiedXmlSignature] =
        saml_rs::SsoSession::verified_xml_signatures;
    let _: for<'a> fn(&'a VerifiedXmlSignature) -> &'a str = VerifiedXmlSignature::algorithm_uri;
    let _: fn(&VerifiedXmlSignature) -> VerifiedXmlSignatureCoverage =
        VerifiedXmlSignature::coverage;
    let _ = std::any::type_name::<saml_rs::BrowserInput<saml_rs::AuthnRequest>>();
    let _ = std::any::type_name::<saml_rs::FormField>();
    let _ = std::any::type_name::<saml_rs::Outbound<saml_rs::AuthnRequest>>();
    let _ = std::any::type_name::<saml_rs::Pending<saml_rs::AuthnRequest>>();
    let _ = std::any::type_name::<saml_rs::PostForm>();
    let _ = std::any::type_name::<saml_rs::Started<saml_rs::AuthnRequest>>();
    let _ = std::any::type_name::<saml_rs::Assertion>();
    let _ = std::any::type_name::<saml_rs::AssertionId>();
    let _ = std::any::type_name::<saml_rs::Attribute>();
    let _ = std::any::type_name::<saml_rs::AttributeValue>();
    let _ = std::any::type_name::<saml_rs::Attributes>();
    let _ = std::any::type_name::<saml_rs::AuthnSession>();
    let _ = std::any::type_name::<saml_rs::LogoutCompleted>();
    let _ = std::any::type_name::<saml_rs::LogoutRequest>();
    let _ = std::any::type_name::<saml_rs::LogoutResponse>();
    let _ = std::any::type_name::<saml_rs::OutstandingLogout>();
    let _ = std::any::type_name::<saml_rs::NameId>();
    let _ = std::any::type_name::<saml_rs::NameIdPolicy>();
    let _ = std::any::type_name::<saml_rs::Received<saml_rs::SsoResponse>>();
    let _ = std::any::type_name::<saml_rs::RelayState>();
    let _ = saml_rs::MAX_RELAY_STATE_BYTES;
    let _ = std::any::type_name::<saml_rs::SessionIndex>();
    let _ = std::any::type_name::<saml_rs::SsoResponse>();
    let _ = std::any::type_name::<saml_rs::SsoSession>();
    let _ = std::any::type_name::<VerifiedXmlSignature>();
    let _ = std::any::type_name::<VerifiedXmlSignatureCoverage>();
    let _ = std::any::type_name::<saml_rs::RequestedSubject>();
    let _ = std::any::type_name::<saml_rs::RequestedSubjectIdentifier>();
    let _ = std::any::type_name::<saml_rs::Subject>();
    let _ = std::any::type_name::<saml_rs::SubjectConfirmation>();
    let _ = std::any::type_name::<saml_rs::IsPassive>();
    let _ = std::any::type_name::<saml_rs::Status>();
    let _ = std::any::type_name::<saml_rs::SubordinateStatusCode>();
    let _ = std::any::type_name::<saml_rs::TopLevelStatusCode>();
}
