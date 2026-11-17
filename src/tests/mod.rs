#[cfg(crypto)]
#[path = "../../tests/common/mod.rs"]
mod common;
#[cfg(crypto)]
#[path = "../../tests/common/replay_cache.rs"]
mod replay_cache;

mod artifact_sso;
mod assertion_conditions;
mod authentication_context;
mod decryption_work;
mod default_xml_limits;
mod encrypted_assertion_elements;
mod encrypted_requested_subject;
mod hardening;
#[cfg_attr(
    crypto,
    expect(deprecated, reason = "pins the deprecated signature verifiers")
)]
mod index_conformance;
mod issues_conformance;
#[cfg_attr(
    crypto,
    expect(deprecated, reason = "pins the deprecated signature verifiers")
)]
mod metadata_signature;
mod metadata_trust;
mod name_id_management_encryption;
mod name_id_management_redirect;
mod namespace_version;
mod paos_destination;
#[cfg_attr(
    crypto,
    expect(deprecated, reason = "pins the deprecated signature verifiers")
)]
mod provider_regression;
mod robustness;
mod simplesign_xml_limits;
mod sso_response_issuer;
mod typed_slo;
mod typed_sso;
mod xml_injection;
mod xml_line_endings;
#[cfg_attr(
    crypto,
    expect(deprecated, reason = "pins the deprecated signature verifiers")
)]
mod xml_signature_processing;
#[cfg_attr(
    crypto,
    expect(deprecated, reason = "pins the deprecated signature verifiers")
)]
mod xsw;
