#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use saml_rs::constants::Binding;
use saml_rs::entity::{EntitySetting, User};
use saml_rs::logout::create_logout_request;
use saml_rs::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
use saml_rs::{IdentityProvider, SamlError, ServiceProvider};

const PRIVATE_KEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const CERTIFICATE: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");

#[test]
fn signed_login_request_rejects_soap_and_artifact_after_credentials(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in [Binding::Soap, Binding::Artifact] {
        let idp = IdentityProvider::from_config(
            &IdpMetadataConfig {
                entity_id: "https://idp.example.com/metadata".into(),
                single_sign_on_service: vec![Endpoint::new(binding, "https://idp.example.com/sso")],
                ..Default::default()
            },
            EntitySetting::default(),
        )?;
        let mut sp = ServiceProvider::from_config(
            &SpMetadataConfig {
                entity_id: "https://sp.example.com/metadata".into(),
                authn_requests_signed: true,
                assertion_consumer_service: vec![Endpoint::new(
                    Binding::Post,
                    "https://sp.example.com/acs",
                )],
                ..Default::default()
            },
            EntitySetting::default(),
        )?;

        assert!(matches!(
            sp.create_login_request(&idp, binding, None),
            Err(SamlError::MissingKey(key)) if key == "private_key"
        ));
        sp.setting.private_key = Some(PRIVATE_KEY.into());
        assert!(matches!(
            sp.create_login_request(&idp, binding, None),
            Err(SamlError::MissingKey(key)) if key == "signing_cert"
        ));
        sp.setting.signing_cert = Some(CERTIFICATE.into());
        assert!(matches!(
            sp.create_login_request(&idp, binding, None),
            Err(SamlError::UnsupportedBinding { binding: rejected }) if rejected == binding
        ));
    }
    Ok(())
}

#[test]
fn signed_logout_artifact_rejects_binding_before_credentials(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            single_sign_on_service: vec![Endpoint::new(
                Binding::Post,
                "https://idp.example.com/sso",
            )],
            single_logout_service: vec![Endpoint::new(
                Binding::Artifact,
                "https://idp.example.com/slo",
            )],
            ..Default::default()
        },
        EntitySetting::default(),
    )?;
    let sp = ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            assertion_consumer_service: vec![Endpoint::new(
                Binding::Post,
                "https://sp.example.com/acs",
            )],
            ..Default::default()
        },
        EntitySetting::default(),
    )?;
    for private_key in [None, Some("invalid private key".into())] {
        let mut setting = EntitySetting::default();
        setting.private_key = private_key;
        assert!(matches!(
            create_logout_request(
                &setting,
                &sp.metadata,
                &idp.metadata,
                Binding::Artifact,
                &User::new("alice@example.com"),
                None,
                true,
            ),
            Err(SamlError::UnsupportedBinding {
                binding: Binding::Artifact
            })
        ));
    }
    Ok(())
}
