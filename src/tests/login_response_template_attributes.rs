#![cfg(crypto)]

use super::common;
use saml_rs::tests::engine::IdpMessages;

use common::signing_credentials;

use saml_rs::config::SSO_RESPONSE_TEMPLATE;
use saml_rs::constants::Binding;
use saml_rs::entity::User;
use saml_rs::idp::LoginResponseOptions;
use saml_rs::template::LoginResponseAttribute;
use saml_rs::template::LoginResponseTemplate;
use saml_rs::{
    AcsEndpoint, EntityId, IdentityProvider, IdpConfig, SamlError, ServiceProvider, SpConfig,
    SpValidationPolicy, SsoEndpoint,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";

fn email_attribute() -> LoginResponseAttribute {
    LoginResponseAttribute {
        name: "mail".into(),
        name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".into(),
        value_xsi_type: "xs:string".into(),
        value_tag: "email".into(),
        value_xmlns_xs: None,
        value_xmlns_xsi: None,
    }
}

#[test]
fn login_response_template_rejects_an_attribute_without_a_value_for_both_renderers(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post("https://sp.example.com/acs")?.with_default(),
        )
        .credentials(signing_credentials())
        .validation(SpValidationPolicy::recommended())
        .build()?,
    );
    let idp = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post("https://idp.example.com/sso")?,
        )
        .credentials(signing_credentials())
        .build()?,
    );

    for (renderer, context) in [
        ("built-in", None),
        ("custom template", Some(SSO_RESPONSE_TEMPLATE.to_string())),
    ] {
        let mut raw_idp = idp.engine().clone();
        raw_idp.setting.login_response_template = Some(LoginResponseTemplate {
            context,
            attributes: vec![email_attribute()],
        });

        match raw_idp.create_login_response(
            sp.engine(),
            Binding::Post,
            &User::new("alice@example.com"),
            &LoginResponseOptions::default(),
        ) {
            Err(SamlError::Invalid(message)) => assert_eq!(
                message, "missing login response attribute value for `email`",
                "{renderer} renderer"
            ),
            Err(error) => return Err(format!("{renderer} renderer: {error:?}").into()),
            Ok(_) => return Err(format!("{renderer} renderer signed a response").into()),
        }
    }
    Ok(())
}
