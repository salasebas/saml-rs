#![cfg(crypto)]

use saml_rs::constants::Binding;
use saml_rs::entity::EntitySetting;
use saml_rs::idp;
use saml_rs::metadata::{Endpoint, IdpMetadataInput, SpMetadataInput};
use saml_rs::sp;
use saml_rs::sp::LoginRequestOptions;
use saml_rs::tests::engine::create_logout_request;
use saml_rs::tests::engine::LogoutUser;
use saml_rs::tests::engine::SpMessages;
use saml_rs::SamlError;

const PRIVATE_KEY: &str = include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERTIFICATE: &str = include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");

#[test]
fn signed_login_request_rejects_soap_and_artifact_after_credentials(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in [Binding::Soap, Binding::Artifact] {
        let mut idp_config = IdpMetadataInput {
            entity_id: "https://idp.example.com/metadata".into(),
            ..IdpMetadataInput::default()
        };
        idp_config.single_sign_on_services =
            vec![Endpoint::new(binding, "https://idp.example.com/sso")];
        let idp = idp::Engine::from_config(&idp_config, EntitySetting::default())?;
        let mut sp_config = SpMetadataInput {
            entity_id: "https://sp.example.com/metadata".into(),
            authn_requests_signed: true,
            ..SpMetadataInput::default()
        };
        sp_config.assertion_consumer_services =
            vec![Endpoint::new(Binding::Post, "https://sp.example.com/acs")];
        let mut sp = sp::Engine::from_config(&sp_config, EntitySetting::default())?;

        assert!(matches!(
            sp.create_login_request(&idp, binding, &LoginRequestOptions::default()),
            Err(SamlError::MissingKey(key)) if key == "private_key"
        ));
        sp.setting.private_key = Some(PRIVATE_KEY.into());
        assert!(matches!(
            sp.create_login_request(&idp, binding, &LoginRequestOptions::default()),
            Err(SamlError::MissingKey(key)) if key == "signing_cert"
        ));
        sp.setting.signing_cert = Some(CERTIFICATE.into());
        assert!(matches!(
            sp.create_login_request(&idp, binding, &LoginRequestOptions::default()),
            Err(SamlError::UnsupportedBinding { binding: rejected, .. }) if rejected == binding
        ));
    }
    Ok(())
}

#[test]
fn signed_logout_artifact_rejects_binding_before_credentials(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut idp_config = IdpMetadataInput {
        entity_id: "https://idp.example.com/metadata".into(),
        ..IdpMetadataInput::default()
    };
    idp_config.single_sign_on_services =
        vec![Endpoint::new(Binding::Post, "https://idp.example.com/sso")];
    idp_config.single_logout_services = vec![Endpoint::new(
        Binding::Artifact,
        "https://idp.example.com/slo",
    )];
    let idp = idp::Engine::from_config(&idp_config, EntitySetting::default())?;
    let mut sp_config = SpMetadataInput {
        entity_id: "https://sp.example.com/metadata".into(),
        ..SpMetadataInput::default()
    };
    sp_config.assertion_consumer_services =
        vec![Endpoint::new(Binding::Post, "https://sp.example.com/acs")];
    let sp = sp::Engine::from_config(&sp_config, EntitySetting::default())?;
    for private_key in [None, Some("invalid private key".into())] {
        let setting = EntitySetting {
            private_key,
            ..EntitySetting::default()
        };
        assert!(matches!(
            create_logout_request(
                &setting,
                sp.metadata.as_metadata(),
                idp.metadata.as_metadata(),
                Binding::Artifact,
                &LogoutUser::new("alice@example.com"),
                None,
                true,
            ),
            Err(SamlError::UnsupportedBinding {
                binding: Binding::Artifact,
                ..
            })
        ));
    }
    Ok(())
}
