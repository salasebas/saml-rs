#![cfg(crypto)]

mod common;

use common::signing_credentials;

use saml_rs::config::LOGIN_RESPONSE_TEMPLATE;
use saml_rs::{
    AcsEndpoint, EntityId, IdpConfig, LoginResponseAttribute, LoginResponseTemplate,
    MetadataTrustPolicy, NameId, RespondSso, Saml, SamlError, SpConfig, SpDescriptor,
    SpValidationPolicy, SsoEndpoint, TemplatePolicy,
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
    let sp = Saml::sp(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post("https://sp.example.com/acs")?.with_default(),
        )
        .credentials(signing_credentials())
        .validation(SpValidationPolicy::recommended())
        .build()?,
    );
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;

    for (renderer, context) in [
        ("built-in", None),
        ("custom template", Some(LOGIN_RESPONSE_TEMPLATE.to_string())),
    ] {
        let idp = Saml::idp(
            IdpConfig::builder(
                EntityId::try_new(IDP_ENTITY_ID)?,
                SsoEndpoint::post("https://idp.example.com/sso")?,
            )
            .credentials(signing_credentials())
            .templates(TemplatePolicy {
                login_response_template: Some(LoginResponseTemplate {
                    context,
                    attributes: vec![email_attribute()],
                }),
                ..TemplatePolicy::default()
            })
            .build()?,
        );
        let name_id = NameId::new("alice@example.com");

        match idp.initiate_sso(&sp_descriptor, &name_id, RespondSso::post()) {
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
