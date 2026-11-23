#![cfg(feature = "serde")]

use std::error::Error;

use saml_rs::{
    PendingAuthnRequest, PendingAuthnRequestSnapshot, PendingLogoutRequest,
    PendingLogoutRequestSnapshot, PendingManageNameIdRequest, PendingManageNameIdRequestSnapshot,
};
use serde_json::Value;

const AUTHN_REQUEST_JSON: &str = r#"{
  "request_id": "_request123",
  "relay_state": "return-to-cart",
  "idp_entity_id": "https://idp.example.com/metadata",
  "acs_binding": "post",
  "acs_url": "https://sp.example.com/acs",
  "acs_index": null,
  "acs_is_default": false
}"#;

const LOGOUT_REQUEST_JSON: &str = r#"{
  "request_id": "_logout123",
  "relay_state": null,
  "peer_entity_id": "https://idp.example.com/metadata",
  "request_binding": "redirect",
  "not_on_or_after": "2026-01-01T00:05:00Z"
}"#;

const MANAGE_NAME_ID_REQUEST_JSON: &str = r#"{
  "request_id": "_manage123",
  "relay_state": null,
  "peer_entity_id": "https://idp.example.com/metadata"
}"#;

fn with_unknown_field(json: &str) -> Result<String, Box<dyn Error>> {
    let mut value: Value = serde_json::from_str(json)?;
    value
        .as_object_mut()
        .ok_or("snapshot JSON is not an object")?
        .insert("added_by_a_later_release".to_string(), Value::Bool(true));
    Ok(serde_json::to_string(&value)?)
}

fn without_field(json: &str, field: &str) -> Result<String, Box<dyn Error>> {
    let mut value: Value = serde_json::from_str(json)?;
    value
        .as_object_mut()
        .ok_or("snapshot JSON is not an object")?
        .remove(field)
        .ok_or("snapshot JSON does not have the field")?;
    Ok(serde_json::to_string(&value)?)
}

fn documented_authn_request_snapshot() -> PendingAuthnRequestSnapshot {
    let mut snapshot = PendingAuthnRequestSnapshot::new(
        "_request123",
        "https://idp.example.com/metadata",
        "post",
        "https://sp.example.com/acs",
    );
    snapshot.relay_state = Some("return-to-cart".to_string());
    snapshot
}

fn documented_logout_request_snapshot() -> PendingLogoutRequestSnapshot {
    let mut snapshot = PendingLogoutRequestSnapshot::new(
        "_logout123",
        "https://idp.example.com/metadata",
        "redirect",
    );
    snapshot.not_on_or_after = Some("2026-01-01T00:05:00Z".to_string());
    snapshot
}

fn documented_manage_name_id_request_snapshot() -> PendingManageNameIdRequestSnapshot {
    PendingManageNameIdRequestSnapshot::new("_manage123", "https://idp.example.com/metadata")
}

#[test]
fn pending_snapshot_serde_authn_request_matches_the_documented_json() -> Result<(), Box<dyn Error>>
{
    let snapshot = documented_authn_request_snapshot();

    assert_eq!(
        serde_json::to_value(&snapshot)?,
        serde_json::from_str::<Value>(AUTHN_REQUEST_JSON)?
    );
    assert_eq!(
        serde_json::from_str::<PendingAuthnRequestSnapshot>(AUTHN_REQUEST_JSON)?,
        snapshot
    );
    Ok(())
}

#[test]
fn pending_snapshot_serde_authn_request_round_trips() -> Result<(), Box<dyn Error>> {
    let mut snapshot = PendingAuthnRequestSnapshot::new(
        "_request456",
        "https://idp.example.com/metadata",
        "simpleSign",
        "https://sp.example.com/acs/simple-sign",
    );
    snapshot.relay_state = Some(String::new());
    snapshot.acs_index = Some(2);
    snapshot.acs_is_default = true;
    let pending = PendingAuthnRequest::from_snapshot(snapshot)?;

    let json = serde_json::to_string(&pending.snapshot())?;

    assert_eq!(
        PendingAuthnRequest::from_snapshot(serde_json::from_str(&json)?)?,
        pending
    );
    Ok(())
}

#[test]
fn pending_snapshot_serde_authn_request_reads_absent_optional_fields() -> Result<(), Box<dyn Error>>
{
    let json = r#"{
      "request_id": "_request123",
      "idp_entity_id": "https://idp.example.com/metadata",
      "acs_binding": "post",
      "acs_url": "https://sp.example.com/acs"
    }"#;

    assert_eq!(
        serde_json::from_str::<PendingAuthnRequestSnapshot>(json)?,
        PendingAuthnRequestSnapshot::new(
            "_request123",
            "https://idp.example.com/metadata",
            "post",
            "https://sp.example.com/acs",
        )
    );
    Ok(())
}

#[test]
fn pending_snapshot_serde_authn_request_ignores_unknown_fields() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        serde_json::from_str::<PendingAuthnRequestSnapshot>(&with_unknown_field(
            AUTHN_REQUEST_JSON
        )?)?,
        documented_authn_request_snapshot()
    );
    Ok(())
}

#[test]
fn pending_snapshot_serde_authn_request_writes_absent_optional_fields() -> Result<(), Box<dyn Error>>
{
    let json = r#"{
      "request_id": "_request123",
      "relay_state": null,
      "idp_entity_id": "https://idp.example.com/metadata",
      "acs_binding": "post",
      "acs_url": "https://sp.example.com/acs",
      "acs_index": null,
      "acs_is_default": false
    }"#;

    assert_eq!(
        serde_json::to_value(PendingAuthnRequestSnapshot::new(
            "_request123",
            "https://idp.example.com/metadata",
            "post",
            "https://sp.example.com/acs",
        ))?,
        serde_json::from_str::<Value>(json)?
    );
    Ok(())
}

#[test]
fn pending_snapshot_serde_authn_request_refuses_json_without_a_required_field(
) -> Result<(), Box<dyn Error>> {
    for field in ["request_id", "idp_entity_id", "acs_binding", "acs_url"] {
        assert!(
            serde_json::from_str::<PendingAuthnRequestSnapshot>(&without_field(
                AUTHN_REQUEST_JSON,
                field
            )?)
            .is_err(),
            "{field}"
        );
    }
    Ok(())
}

#[test]
fn pending_snapshot_serde_logout_request_matches_the_documented_json() -> Result<(), Box<dyn Error>>
{
    let snapshot = documented_logout_request_snapshot();

    assert_eq!(
        serde_json::to_value(&snapshot)?,
        serde_json::from_str::<Value>(LOGOUT_REQUEST_JSON)?
    );
    assert_eq!(
        serde_json::from_str::<PendingLogoutRequestSnapshot>(LOGOUT_REQUEST_JSON)?,
        snapshot
    );
    Ok(())
}

#[test]
fn pending_snapshot_serde_logout_request_round_trips() -> Result<(), Box<dyn Error>> {
    let mut snapshot = PendingLogoutRequestSnapshot::new(
        "_logout456",
        "https://idp.example.com/metadata",
        "simpleSign",
    );
    snapshot.relay_state = Some(String::new());
    snapshot.not_on_or_after = Some("2026-07-04T12:05:00Z".to_string());
    let pending = PendingLogoutRequest::from_snapshot(snapshot)?;

    let json = serde_json::to_string(&pending.snapshot())?;

    assert_eq!(
        PendingLogoutRequest::from_snapshot(serde_json::from_str(&json)?)?,
        pending
    );
    Ok(())
}

#[test]
fn pending_snapshot_serde_logout_request_reads_absent_optional_fields() -> Result<(), Box<dyn Error>>
{
    let json = r#"{
      "request_id": "_logout123",
      "peer_entity_id": "https://idp.example.com/metadata",
      "request_binding": "redirect"
    }"#;

    assert_eq!(
        serde_json::from_str::<PendingLogoutRequestSnapshot>(json)?,
        PendingLogoutRequestSnapshot::new(
            "_logout123",
            "https://idp.example.com/metadata",
            "redirect",
        )
    );
    Ok(())
}

#[test]
fn pending_snapshot_serde_logout_request_ignores_unknown_fields() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        serde_json::from_str::<PendingLogoutRequestSnapshot>(&with_unknown_field(
            LOGOUT_REQUEST_JSON
        )?)?,
        documented_logout_request_snapshot()
    );
    Ok(())
}

#[test]
fn pending_snapshot_serde_logout_request_writes_absent_optional_fields(
) -> Result<(), Box<dyn Error>> {
    let json = r#"{
      "request_id": "_logout123",
      "relay_state": null,
      "peer_entity_id": "https://idp.example.com/metadata",
      "request_binding": "redirect",
      "not_on_or_after": null
    }"#;

    assert_eq!(
        serde_json::to_value(PendingLogoutRequestSnapshot::new(
            "_logout123",
            "https://idp.example.com/metadata",
            "redirect",
        ))?,
        serde_json::from_str::<Value>(json)?
    );
    Ok(())
}

#[test]
fn pending_snapshot_serde_logout_request_refuses_json_without_a_required_field(
) -> Result<(), Box<dyn Error>> {
    for field in ["request_id", "peer_entity_id", "request_binding"] {
        assert!(
            serde_json::from_str::<PendingLogoutRequestSnapshot>(&without_field(
                LOGOUT_REQUEST_JSON,
                field
            )?)
            .is_err(),
            "{field}"
        );
    }
    Ok(())
}

#[test]
fn pending_snapshot_serde_manage_name_id_request_matches_the_documented_json(
) -> Result<(), Box<dyn Error>> {
    let snapshot = documented_manage_name_id_request_snapshot();

    assert_eq!(
        serde_json::to_value(&snapshot)?,
        serde_json::from_str::<Value>(MANAGE_NAME_ID_REQUEST_JSON)?
    );
    assert_eq!(
        serde_json::from_str::<PendingManageNameIdRequestSnapshot>(MANAGE_NAME_ID_REQUEST_JSON)?,
        snapshot
    );
    Ok(())
}

#[test]
fn pending_snapshot_serde_manage_name_id_request_round_trips() -> Result<(), Box<dyn Error>> {
    let mut snapshot =
        PendingManageNameIdRequestSnapshot::new("_manage456", "https://idp.example.com/metadata");
    snapshot.relay_state = Some(String::new());
    let pending = PendingManageNameIdRequest::from_snapshot(snapshot)?;

    let json = serde_json::to_string(&pending.snapshot())?;

    assert_eq!(
        PendingManageNameIdRequest::from_snapshot(serde_json::from_str(&json)?)?,
        pending
    );
    Ok(())
}

#[test]
fn pending_snapshot_serde_manage_name_id_request_reads_absent_optional_fields(
) -> Result<(), Box<dyn Error>> {
    let json = r#"{
      "request_id": "_manage123",
      "peer_entity_id": "https://idp.example.com/metadata"
    }"#;

    assert_eq!(
        serde_json::from_str::<PendingManageNameIdRequestSnapshot>(json)?,
        PendingManageNameIdRequestSnapshot::new("_manage123", "https://idp.example.com/metadata")
    );
    Ok(())
}

#[test]
fn pending_snapshot_serde_manage_name_id_request_ignores_unknown_fields(
) -> Result<(), Box<dyn Error>> {
    assert_eq!(
        serde_json::from_str::<PendingManageNameIdRequestSnapshot>(&with_unknown_field(
            MANAGE_NAME_ID_REQUEST_JSON
        )?)?,
        documented_manage_name_id_request_snapshot()
    );
    Ok(())
}

#[test]
fn pending_snapshot_serde_manage_name_id_request_refuses_json_without_a_required_field(
) -> Result<(), Box<dyn Error>> {
    for field in ["request_id", "peer_entity_id"] {
        assert!(
            serde_json::from_str::<PendingManageNameIdRequestSnapshot>(&without_field(
                MANAGE_NAME_ID_REQUEST_JSON,
                field
            )?)
            .is_err(),
            "{field}"
        );
    }
    Ok(())
}
