use saml_rs::constants::Binding;
use saml_rs::metadata::Endpoint;
use saml_rs::SamlError;
use saml_rs::{
    AcsEndpoint, AuthnRequest, EntityId, LogoutBinding, MessageId, PendingAuthnRequest,
    PendingLogoutRequest, PendingSnapshot, RelayState, RelayStateParam, SamlInstant, SloEndpoint,
    SsoEndpoint, SsoRequestBinding, SsoResponseBinding, MAX_RELAY_STATE_BYTES,
};

#[test]
fn typed_bindings_sso_request_binding_accepts_browser_request_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        SsoRequestBinding::try_from(Binding::Redirect)?,
        SsoRequestBinding::Redirect
    );
    assert_eq!(
        SsoRequestBinding::try_from(Binding::Post)?,
        SsoRequestBinding::Post
    );
    assert_eq!(
        SsoRequestBinding::try_from(Binding::SimpleSign)?,
        SsoRequestBinding::SimpleSign
    );
    Ok(())
}

#[test]
fn typed_bindings_sso_request_binding_uses_undefined_binding_until_artifact_is_supported() {
    assert!(matches!(
        SsoRequestBinding::try_from(Binding::Artifact),
        Err(SamlError::UndefinedBinding)
    ));
}

#[test]
fn typed_bindings_sso_response_binding_accepts_post_simplesign_and_artifact(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        SsoResponseBinding::try_from(Binding::Post)?,
        SsoResponseBinding::Post
    );
    assert_eq!(
        SsoResponseBinding::try_from(Binding::SimpleSign)?,
        SsoResponseBinding::SimpleSign
    );
    assert_eq!(
        SsoResponseBinding::try_from(Binding::Artifact)?,
        SsoResponseBinding::Artifact
    );
    assert_eq!(SsoResponseBinding::Artifact.as_binding(), Binding::Artifact);
    Ok(())
}

#[test]
fn typed_bindings_sso_response_binding_uses_undefined_binding_for_redirect() {
    assert!(matches!(
        SsoResponseBinding::try_from(Binding::Redirect),
        Err(SamlError::UndefinedBinding)
    ));
}

#[test]
fn typed_bindings_logout_binding_accepts_supported_logout_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        LogoutBinding::try_from(Binding::Redirect)?,
        LogoutBinding::Redirect
    );
    assert_eq!(LogoutBinding::try_from(Binding::Post)?, LogoutBinding::Post);
    assert_eq!(
        LogoutBinding::try_from(Binding::SimpleSign)?,
        LogoutBinding::SimpleSign
    );
    Ok(())
}

#[test]
fn typed_bindings_logout_binding_uses_undefined_binding_until_artifact_is_supported() {
    assert!(matches!(
        LogoutBinding::try_from(Binding::Artifact),
        Err(SamlError::UndefinedBinding)
    ));
}

#[test]
fn typed_bindings_post_acs_endpoint_converts_to_raw_metadata_endpoint(
) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = AcsEndpoint::post("https://sp.example.com/acs")?
        .mark_default()
        .with_index(7);

    let raw = endpoint.to_raw();

    assert_eq!(raw.binding, Binding::Post);
    assert_eq!(raw.location, "https://sp.example.com/acs");
    assert!(raw.is_default);
    assert_eq!(endpoint.index(), Some(7));
    Ok(())
}

#[test]
fn typed_bindings_simplesign_acs_endpoint_converts_to_raw_metadata_endpoint(
) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = AcsEndpoint::simple_sign("https://sp.example.com/acs/simple")?;

    let raw = endpoint.to_raw();

    assert_eq!(raw.binding, Binding::SimpleSign);
    assert_eq!(raw.location, "https://sp.example.com/acs/simple");
    assert!(!raw.is_default);
    Ok(())
}

#[test]
fn typed_bindings_redirect_acs_endpoint_narrowing_fails() {
    let raw = Endpoint::new(Binding::Redirect, "https://sp.example.com/acs");

    assert!(matches!(
        AcsEndpoint::try_from_raw(raw),
        Err(SamlError::UndefinedBinding)
    ));
}

#[test]
fn typed_bindings_artifact_acs_endpoint_narrows_successfully(
) -> Result<(), Box<dyn std::error::Error>> {
    let raw = Endpoint::new(Binding::Artifact, "https://sp.example.com/acs");

    let endpoint = AcsEndpoint::try_from_raw(raw)?;
    assert_eq!(endpoint.binding(), SsoResponseBinding::Artifact);
    assert_eq!(
        endpoint,
        AcsEndpoint::artifact("https://sp.example.com/acs")?
    );
    assert_eq!(endpoint.to_raw().binding, Binding::Artifact);
    Ok(())
}

#[test]
fn typed_bindings_redirect_sso_endpoint_narrows_successfully(
) -> Result<(), Box<dyn std::error::Error>> {
    let raw = Endpoint::new(Binding::Redirect, "https://idp.example.com/sso");

    let endpoint = SsoEndpoint::try_from_raw(raw)?;

    assert_eq!(endpoint.binding(), SsoRequestBinding::Redirect);
    assert_eq!(endpoint.location().as_str(), "https://idp.example.com/sso");
    Ok(())
}

#[test]
fn typed_bindings_sso_endpoint_rejects_artifact_until_artifact_is_supported() {
    let raw = Endpoint::new(Binding::Artifact, "https://idp.example.com/sso");

    assert!(matches!(
        SsoEndpoint::try_from_raw(raw),
        Err(SamlError::UndefinedBinding)
    ));
}

#[test]
fn typed_bindings_slo_endpoint_rejects_artifact_until_artifact_is_supported() {
    let raw = Endpoint::new(Binding::Artifact, "https://idp.example.com/slo");

    assert!(matches!(
        SloEndpoint::try_from_raw(raw),
        Err(SamlError::UndefinedBinding)
    ));
}

#[test]
fn typed_bindings_sso_and_slo_endpoints_do_not_emit_acs_flags(
) -> Result<(), Box<dyn std::error::Error>> {
    let sso = SsoEndpoint::post("https://idp.example.com/sso")?;
    let slo = SloEndpoint::redirect("https://idp.example.com/slo")?;

    assert!(!sso.to_raw().is_default);
    assert!(!slo.to_raw().is_default);
    Ok(())
}

#[test]
fn typed_bindings_endpoint_url_rejects_non_http_urls() {
    assert!(matches!(
        SsoEndpoint::redirect("mailto:idp@example.com"),
        Err(SamlError::Invalid(_))
    ));
    assert!(matches!(
        AcsEndpoint::post("/acs"),
        Err(SamlError::Invalid(_))
    ));
}

#[test]
fn typed_bindings_relay_state_preserves_absent_empty_and_present_values(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(RelayStateParam::absent(), RelayStateParam::Absent);
    assert_eq!(
        RelayStateParam::present_empty(),
        RelayStateParam::PresentEmpty
    );
    assert_eq!(
        RelayStateParam::try_from_option(Some("state-123".to_string()))?,
        RelayStateParam::PresentValue(RelayState::try_new("state-123")?)
    );
    Ok(())
}

#[test]
fn typed_bindings_relay_state_enforces_saml_bindings_byte_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        RelayState::try_new("a".repeat(MAX_RELAY_STATE_BYTES))?
            .as_str()
            .len(),
        MAX_RELAY_STATE_BYTES
    );
    assert!(RelayState::try_new("a".repeat(MAX_RELAY_STATE_BYTES + 1)).is_err());

    let eighty_utf8_bytes = "é".repeat(40);
    let eighty_two_utf8_bytes = "é".repeat(41);
    assert_eq!(
        RelayState::try_new(eighty_utf8_bytes)?.as_str().len(),
        MAX_RELAY_STATE_BYTES
    );
    assert!(RelayState::try_new(eighty_two_utf8_bytes).is_err());
    assert!(RelayStateParam::try_from_option(Some("a".repeat(MAX_RELAY_STATE_BYTES + 1))).is_err());
    Ok(())
}

#[test]
fn typed_bindings_pending_authn_request_snapshot_round_trips_without_raw_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let acs = AcsEndpoint::post("https://sp.example.com/acs")?
        .with_index(2)
        .mark_default();
    let pending = PendingAuthnRequest::try_new(
        MessageId::try_new("_request123")?,
        RelayStateParam::try_from_option(Some("relay".to_string()))?,
        acs,
        SsoResponseBinding::Post,
        saml_rs::EntityId::try_new("https://idp.example.com/metadata")?,
    )?
    .with_issue_instant(SamlInstant::try_new("2026-07-04T12:00:00Z")?)
    .with_expiration(SamlInstant::try_new("2026-07-04T12:05:00Z")?);

    let snapshot = pending.snapshot();
    let snapshot_debug = format!("{snapshot:?}");
    let restored = PendingAuthnRequest::from_snapshot(snapshot)?;

    assert_eq!(restored.request_id().as_str(), "_request123");
    assert_eq!(
        restored.relay_state(),
        &RelayStateParam::PresentValue(RelayState::try_new("relay")?)
    );
    assert_eq!(restored.acs().binding(), SsoResponseBinding::Post);
    assert_eq!(
        restored.acs().location().as_str(),
        "https://sp.example.com/acs"
    );
    assert_eq!(restored.acs().index(), Some(2));
    assert!(restored.acs().is_default());
    assert_eq!(restored.response_binding(), SsoResponseBinding::Post);
    assert_eq!(
        restored.idp_entity_id().as_str(),
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
fn typed_bindings_pending_logout_request_snapshot_round_trips_supported_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in [
        LogoutBinding::Redirect,
        LogoutBinding::Post,
        LogoutBinding::SimpleSign,
    ] {
        let pending = PendingLogoutRequest::try_new(
            MessageId::try_new(format!("_logout_{binding:?}"))?,
            RelayStateParam::try_from_option(Some("relay".to_string()))?,
            binding,
            EntityId::try_new("https://idp.example.com/metadata")?,
        )?
        .with_issue_instant(SamlInstant::try_new("2026-07-04T12:00:00Z")?)
        .with_expiration(SamlInstant::try_new("2026-07-04T12:05:00Z")?);

        let restored = PendingLogoutRequest::from_snapshot(pending.snapshot())?;

        assert_eq!(restored.request_binding(), binding);
        assert_eq!(restored.response_binding(), binding);
        assert_eq!(
            restored.relay_state(),
            &RelayStateParam::PresentValue(RelayState::try_new("relay")?)
        );
        assert_eq!(
            restored.peer_entity_id().as_str(),
            "https://idp.example.com/metadata"
        );
        assert_eq!(
            restored.expires_at().map(SamlInstant::as_str),
            Some("2026-07-04T12:05:00Z")
        );
    }
    Ok(())
}

#[test]
fn typed_bindings_pending_authn_request_rejects_mismatched_acs_and_response_binding(
) -> Result<(), Box<dyn std::error::Error>> {
    let acs = AcsEndpoint::simple_sign("https://sp.example.com/acs/simple")?;

    let result = PendingAuthnRequest::try_new(
        MessageId::try_new("_request123")?,
        RelayStateParam::Absent,
        acs,
        SsoResponseBinding::Post,
        saml_rs::EntityId::try_new("https://idp.example.com/metadata")?,
    );

    assert!(matches!(result, Err(SamlError::Invalid(_))));
    Ok(())
}

fn valid_authn_snapshot() -> PendingSnapshot<AuthnRequest> {
    PendingSnapshot::authn_request(
        "_request123",
        RelayStateParam::Absent,
        "https://idp.example.com/metadata",
        Binding::Post.short_name(),
        "https://sp.example.com/acs",
        Binding::Post.short_name(),
    )
}

fn valid_logout_snapshot() -> PendingSnapshot<saml_rs::LogoutRequest> {
    PendingSnapshot::logout_request(
        "_logout123",
        RelayStateParam::Absent,
        "https://idp.example.com/metadata",
        LogoutBinding::Post,
    )
}

#[test]
fn typed_bindings_pending_snapshot_validates_request_id() {
    let mut snapshot = valid_authn_snapshot();
    snapshot.id.clear();

    assert!(matches!(
        PendingAuthnRequest::from_snapshot(snapshot),
        Err(SamlError::Invalid(_))
    ));
}

#[test]
fn typed_bindings_pending_snapshot_accepts_present_empty_relay_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut snapshot = valid_authn_snapshot();
    snapshot.relay_state = RelayStateParam::present_empty();

    let pending = PendingAuthnRequest::from_snapshot(snapshot)?;

    assert_eq!(pending.relay_state(), &RelayStateParam::PresentEmpty);
    Ok(())
}

#[test]
fn typed_bindings_pending_snapshot_validates_peer_entity_id() {
    let mut snapshot = valid_authn_snapshot();
    snapshot.peer_entity_id.clear();

    assert!(matches!(
        PendingAuthnRequest::from_snapshot(snapshot),
        Err(SamlError::Invalid(_))
    ));
}

#[test]
fn typed_bindings_pending_snapshot_validates_expected_binding() {
    let mut snapshot = valid_authn_snapshot();
    snapshot.expected_binding = Binding::Redirect.short_name().to_string();

    assert!(matches!(
        PendingAuthnRequest::from_snapshot(snapshot),
        Err(SamlError::UndefinedBinding)
    ));
}

#[test]
fn typed_bindings_pending_snapshot_validates_acs_url() {
    let mut snapshot = valid_authn_snapshot();
    snapshot.acs_url = "/acs".to_string();

    assert!(matches!(
        PendingAuthnRequest::from_snapshot(snapshot),
        Err(SamlError::Invalid(_))
    ));
}

#[test]
fn typed_bindings_pending_snapshot_rejects_missing_acs_fields() {
    let mut snapshot = valid_authn_snapshot();
    snapshot.acs_url.clear();
    snapshot.acs_binding.clear();

    assert!(matches!(
        PendingAuthnRequest::from_snapshot(snapshot),
        Err(SamlError::Invalid(_) | SamlError::UndefinedBinding)
    ));
}

#[test]
fn typed_bindings_pending_snapshot_validates_acs_binding() {
    let mut snapshot = valid_authn_snapshot();
    snapshot.acs_binding = Binding::Redirect.short_name().to_string();

    assert!(matches!(
        PendingAuthnRequest::from_snapshot(snapshot),
        Err(SamlError::UndefinedBinding)
    ));
}

#[test]
fn typed_bindings_pending_snapshot_validates_acs_expected_binding_match() {
    let mut snapshot = valid_authn_snapshot();
    snapshot.acs_binding = Binding::SimpleSign.short_name().to_string();

    assert!(matches!(
        PendingAuthnRequest::from_snapshot(snapshot),
        Err(SamlError::Invalid(_))
    ));
}

#[test]
fn typed_bindings_pending_snapshot_validates_expiration_requires_issue_instant(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut snapshot = valid_authn_snapshot();
    snapshot.expires_at = Some(SamlInstant::try_new("2026-07-04T12:05:00Z")?);

    assert!(matches!(
        PendingAuthnRequest::from_snapshot(snapshot),
        Err(SamlError::Invalid(_))
    ));
    Ok(())
}

#[test]
fn typed_bindings_pending_logout_snapshot_ignores_authn_only_acs_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut snapshot = valid_logout_snapshot();
    snapshot.acs_url = "https://evil.example.com/acs".to_string();
    snapshot.acs_binding = Binding::Redirect.short_name().to_string();
    snapshot.acs_index = Some(99);
    snapshot.acs_is_default = true;

    let pending = PendingLogoutRequest::from_snapshot(snapshot)?;

    assert_eq!(pending.request_binding(), LogoutBinding::Post);
    assert_eq!(pending.response_binding(), LogoutBinding::Post);
    Ok(())
}

#[test]
fn typed_bindings_pending_logout_snapshot_rejects_mismatched_request_binding() {
    let mut snapshot = valid_logout_snapshot();
    snapshot.request_binding = Some(Binding::Redirect.short_name().to_string());

    assert!(matches!(
        PendingLogoutRequest::from_snapshot(snapshot),
        Err(SamlError::Invalid(_))
    ));
}
