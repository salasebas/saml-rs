use saml_rs::constants::Binding;
use saml_rs::metadata::Endpoint;
use saml_rs::SamlError;
use saml_rs::{
    AcsEndpoint, AuthnContextReference, LogoutBinding, NameIdManagementBinding,
    PendingAuthnRequest, PendingAuthnRequestSnapshot, PendingLogoutRequest,
    PendingLogoutRequestSnapshot, RelayState, SamlInstant, SloEndpoint, SsoEndpoint,
    SsoRequestBinding, SsoResponseBinding, MAX_RELAY_STATE_BYTES,
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
fn typed_bindings_sso_request_binding_rejects_artifact() {
    assert!(matches!(
        SsoRequestBinding::try_from(Binding::Artifact),
        Err(SamlError::UnsupportedBinding {
            binding: Binding::Artifact,
            ..
        })
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
    assert_eq!(
        Binding::from(SsoResponseBinding::Artifact),
        Binding::Artifact
    );
    Ok(())
}

#[test]
fn typed_bindings_sso_response_binding_rejects_redirect() {
    assert!(matches!(
        SsoResponseBinding::try_from(Binding::Redirect),
        Err(SamlError::UnsupportedBinding {
            binding: Binding::Redirect,
            ..
        })
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
fn typed_bindings_logout_binding_rejects_artifact() {
    assert!(matches!(
        LogoutBinding::try_from(Binding::Artifact),
        Err(SamlError::UnsupportedBinding {
            binding: Binding::Artifact,
            ..
        })
    ));
}

#[test]
fn typed_bindings_name_id_management_binding_accepts_redirect_and_soap(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in [
        NameIdManagementBinding::Redirect,
        NameIdManagementBinding::Soap,
    ] {
        assert_eq!(
            NameIdManagementBinding::try_from(Binding::from(binding))?,
            binding
        );
    }
    for binding in [Binding::Post, Binding::SimpleSign, Binding::Artifact] {
        assert!(matches!(
            NameIdManagementBinding::try_from(binding),
            Err(SamlError::UnsupportedBinding { binding: rejected, .. }) if rejected == binding
        ));
    }
    Ok(())
}

#[test]
fn typed_bindings_post_acs_endpoint_converts_to_raw_metadata_endpoint(
) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = AcsEndpoint::post("https://sp.example.com/acs")?
        .with_default()
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
        Err(SamlError::UnsupportedBinding {
            binding: Binding::Redirect,
            ..
        })
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
        Err(SamlError::UnsupportedBinding {
            binding: Binding::Artifact,
            ..
        })
    ));
}

#[test]
fn typed_bindings_slo_endpoint_rejects_artifact_until_artifact_is_supported() {
    let raw = Endpoint::new(Binding::Artifact, "https://idp.example.com/slo");

    assert!(matches!(
        SloEndpoint::try_from_raw(raw),
        Err(SamlError::UnsupportedBinding {
            binding: Binding::Artifact,
            ..
        })
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
    Ok(())
}

fn valid_authn_snapshot() -> PendingAuthnRequestSnapshot {
    PendingAuthnRequestSnapshot::new(
        "_request123",
        "https://idp.example.com/metadata",
        Binding::Post.short_name(),
        "https://sp.example.com/acs",
    )
}

fn valid_logout_snapshot() -> PendingLogoutRequestSnapshot {
    PendingLogoutRequestSnapshot::new(
        "_logout123",
        "https://idp.example.com/metadata",
        Binding::Post.short_name(),
    )
}

#[test]
fn typed_bindings_pending_authn_request_snapshot_round_trips(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut snapshot = valid_authn_snapshot();
    snapshot.relay_state = Some("relay".to_string());
    snapshot.acs_index = Some(2);
    snapshot.acs_is_default = true;

    let restored = PendingAuthnRequest::from_snapshot(snapshot.clone())?;

    assert_eq!(restored.request_id().as_str(), "_request123");
    assert_eq!(restored.relay_state(), Some(&RelayState::try_new("relay")?));
    assert_eq!(
        restored.acs(),
        &AcsEndpoint::post("https://sp.example.com/acs")?
            .with_index(2)
            .with_default()
    );
    assert_eq!(
        restored.idp_entity_id().as_str(),
        "https://idp.example.com/metadata"
    );
    assert_eq!(restored.required_authn_context(), None);
    assert_eq!(restored.snapshot(), snapshot);
    let mut snapshot_with_other_index = snapshot;
    snapshot_with_other_index.acs_index = Some(3);
    assert_ne!(
        restored,
        PendingAuthnRequest::from_snapshot(snapshot_with_other_index)?
    );
    Ok(())
}

#[test]
fn typed_bindings_pending_authn_request_snapshot_round_trips_required_authn_context(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut class_snapshot = valid_authn_snapshot();
    class_snapshot.required_authn_context_class_refs = vec![
        "https://refeds.org/profile/mfa".to_string(),
        "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken".to_string(),
    ];
    let class_pending = PendingAuthnRequest::from_snapshot(class_snapshot.clone())?;
    assert_eq!(
        class_pending.required_authn_context(),
        Some(
            &[
                AuthnContextReference::class("https://refeds.org/profile/mfa")?,
                AuthnContextReference::class(
                    "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"
                )?,
            ][..]
        )
    );
    assert_eq!(class_pending.snapshot(), class_snapshot);

    let mut decl_snapshot = valid_authn_snapshot();
    decl_snapshot.required_authn_context_decl_refs =
        vec!["https://idp.example.com/context/mfa".to_string()];
    let decl_pending = PendingAuthnRequest::from_snapshot(decl_snapshot.clone())?;
    assert_eq!(
        decl_pending.required_authn_context(),
        Some(
            &[AuthnContextReference::declaration(
                "https://idp.example.com/context/mfa"
            )?][..]
        )
    );
    assert_eq!(decl_pending.snapshot(), decl_snapshot);
    assert_ne!(class_pending, decl_pending);

    let mut mixed_snapshot = valid_authn_snapshot();
    mixed_snapshot.required_authn_context_class_refs =
        vec!["https://refeds.org/profile/mfa".to_string()];
    mixed_snapshot.required_authn_context_decl_refs =
        vec!["https://idp.example.com/context/mfa".to_string()];
    assert!(matches!(
        PendingAuthnRequest::from_snapshot(mixed_snapshot),
        Err(SamlError::Invalid(_))
    ));

    let mut relative_snapshot = valid_authn_snapshot();
    relative_snapshot.required_authn_context_class_refs = vec!["relative-context".to_string()];
    assert!(matches!(
        PendingAuthnRequest::from_snapshot(relative_snapshot),
        Err(SamlError::Invalid(_))
    ));
    Ok(())
}

#[test]
fn typed_bindings_pending_snapshot_reads_a_binding_urn() -> Result<(), Box<dyn std::error::Error>> {
    let mut snapshot = valid_authn_snapshot();
    snapshot.acs_binding = Binding::SimpleSign.urn().to_string();

    let restored = PendingAuthnRequest::from_snapshot(snapshot)?;

    assert_eq!(restored.acs().binding(), SsoResponseBinding::SimpleSign);
    assert_eq!(restored.snapshot().acs_binding, "simpleSign");
    Ok(())
}

#[test]
fn typed_bindings_pending_logout_request_snapshot_round_trips_supported_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    for (binding, relay_state) in [
        (LogoutBinding::Redirect, Some("relay")),
        (LogoutBinding::Post, Some("relay")),
        (LogoutBinding::SimpleSign, Some("")),
        (LogoutBinding::Soap, None),
    ] {
        let mut snapshot = valid_logout_snapshot();
        snapshot.relay_state = relay_state.map(str::to_string);
        snapshot.request_binding = Binding::from(binding).short_name().to_string();
        snapshot.not_on_or_after = Some("2026-07-04T12:05:00Z".to_string());

        let restored = PendingLogoutRequest::from_snapshot(snapshot.clone())?;

        assert_eq!(restored.request_binding(), binding);
        assert_eq!(restored.relay_state().map(RelayState::as_str), relay_state);
        assert_eq!(
            restored.not_on_or_after().map(SamlInstant::as_str),
            Some("2026-07-04T12:05:00Z")
        );
        assert_eq!(restored.snapshot(), snapshot);
    }
    Ok(())
}

#[test]
fn typed_bindings_pending_snapshot_validates_request_id() {
    let mut snapshot = valid_authn_snapshot();
    snapshot.request_id.clear();

    assert!(matches!(
        PendingAuthnRequest::from_snapshot(snapshot),
        Err(SamlError::Invalid(_))
    ));
}

#[test]
fn typed_bindings_pending_snapshot_accepts_present_empty_relay_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut snapshot = valid_authn_snapshot();
    snapshot.relay_state = Some(String::new());

    let pending = PendingAuthnRequest::from_snapshot(snapshot)?;

    assert_eq!(pending.relay_state(), Some(&RelayState::try_new("")?));
    Ok(())
}

#[test]
fn typed_bindings_pending_snapshot_rejects_an_overlong_relay_state() {
    let mut snapshot = valid_authn_snapshot();
    snapshot.relay_state = Some("a".repeat(MAX_RELAY_STATE_BYTES + 1));

    assert!(matches!(
        PendingAuthnRequest::from_snapshot(snapshot),
        Err(SamlError::Invalid(_))
    ));
}

#[test]
fn typed_bindings_pending_snapshot_validates_idp_entity_id() {
    let mut snapshot = valid_authn_snapshot();
    snapshot.idp_entity_id.clear();

    assert!(matches!(
        PendingAuthnRequest::from_snapshot(snapshot),
        Err(SamlError::Invalid(_))
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
        Err(SamlError::Invalid(_))
    ));
}

#[test]
fn typed_bindings_pending_snapshot_validates_acs_binding() {
    let mut snapshot = valid_authn_snapshot();
    snapshot.acs_binding = Binding::Redirect.short_name().to_string();

    assert!(matches!(
        PendingAuthnRequest::from_snapshot(snapshot),
        Err(SamlError::UnsupportedBinding {
            binding: Binding::Redirect,
            ..
        })
    ));
}

#[test]
fn typed_bindings_pending_logout_snapshot_validates_binding() {
    let mut snapshot = valid_logout_snapshot();
    snapshot.request_binding = Binding::Artifact.short_name().to_string();

    assert!(matches!(
        PendingLogoutRequest::from_snapshot(snapshot),
        Err(SamlError::UnsupportedBinding {
            binding: Binding::Artifact,
            ..
        })
    ));
}

#[test]
fn typed_bindings_pending_logout_snapshot_rejects_relay_state_on_soap() {
    let mut snapshot = valid_logout_snapshot();
    snapshot.relay_state = Some(String::new());
    snapshot.request_binding = Binding::Soap.short_name().to_string();

    assert!(matches!(
        PendingLogoutRequest::from_snapshot(snapshot),
        Err(SamlError::ProtocolProfile(_))
    ));
}
