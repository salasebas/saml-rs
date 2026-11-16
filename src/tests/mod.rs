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
mod index_conformance;
mod issues_conformance;
mod metadata_signature;
mod metadata_trust;
mod name_id_management_encryption;
mod name_id_management_redirect;
mod namespace_version;
mod provider_regression;
mod robustness;
mod simplesign_xml_limits;
mod sso_response_issuer;
mod typed_slo;
mod typed_sso;
mod xml_injection;
mod xml_line_endings;
mod xml_signature_processing;
mod xsw;
