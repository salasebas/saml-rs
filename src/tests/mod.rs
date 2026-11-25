#[cfg(crypto)]
#[path = "../../tests/common/mod.rs"]
mod common;
#[cfg(crypto)]
#[path = "../../tests/common/post_validation.rs"]
mod post_validation;
#[path = "../../tests/common/replay_cache.rs"]
mod replay_cache;

mod artifact_sso;
mod assertion_conditions;
mod authentication_context;
mod authn_request_options;
mod binding;
mod browser_namespace_profile;
mod browser_signing_bindings;
mod conformance;
mod decryption_work;
mod default_xml_limits;
#[cfg(crypto)]
mod elliptic_curve_signatures;
mod encrypted_assertion_elements;
mod encrypted_requested_subject;
mod encryption_key_selection;
pub(crate) mod engine;
mod error_taxonomy;
mod external_slo_redirect;
mod extractor_conformance;
mod flow_conformance;
mod hardening;
mod identifier_formats;
mod idp_tag_prefixes;
mod index_conformance;
mod issues_conformance;
mod logout_session_index;
mod metadata_role_keys;
mod metadata_trust;
mod name_id_management_encryption;
mod name_id_management_redirect;
#[cfg(crypto)]
mod name_id_management_soap_signatures;
mod namespace_version;
mod no_default_features;
pub(crate) mod policies_without_crypto;
mod policy_presets;
mod provider_regression;
mod redirect_inflate_limit;
mod redirect_xml_limits;
mod robustness;
mod simplesign_xml_limits;
mod sso_flow_document;
mod sso_response_issuer;
mod subject_identifier_attributes;
mod template;
mod typed_config;
mod typed_models;
mod typed_slo;
mod typed_sso;
mod typed_validation_context;
mod xml_document;
mod xml_injection;
mod xml_line_endings;
mod xml_signature_processing;
mod xsw;
