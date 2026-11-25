use super::*;
use saml_rs::{Attribute, AttributeValue, Attributes};
use std::time::SystemTime;

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn typed_encrypted_assertion_takes_the_assertion_prefix() -> Result<(), Box<dyn std::error::Error>>
{
    let sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new(SP_ENTITY_ID)?,
            AcsEndpoint::post(SP_ACS)?.with_default(),
        )
        .credentials(signing_credentials().with_decryption_credential(
            saml_rs::X509Credential::new(CertificatePem::new(CERT), PrivateKeyPem::new(PRIVKEY)),
        ))
        .validation(signing_sp_validation())
        .build()?,
    );
    for prefix in ["xs", "xsi", "é"] {
        let idp = IdentityProvider::new(
            IdpConfig::builder(
                EntityId::try_new(IDP_ENTITY_ID)?,
                SsoEndpoint::post(IDP_SSO_POST)?,
            )
            .credentials(signing_credentials())
            .validation(signed_authn_request_idp_validation())
            .xml(encrypted_assertions())
            .templates(tag_prefixes::templates("samlp", prefix))
            .build()?,
        );
        let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
        let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
        let received = idp.receive_sso(
            &sp_descriptor,
            Inbound::post(started.outbound.post_form()?.fields().to_vec()),
            validation(),
        )?;
        let response = idp.respond_sso(
            &sp_descriptor,
            &received,
            SsoAssertion::new(principal(), SystemTime::now()),
            RespondSso::post(),
        )?;

        let xml = response_xml(&response)?;
        assert!(
            xml.contains(&format!("<{prefix}:EncryptedAssertion ")),
            "{xml}"
        );
    }
    Ok(())
}

#[test]
fn assertion_prefix_preserves_attribute_value_namespaces() -> Result<(), Box<dyn std::error::Error>>
{
    let sp = sp_with(signing_sp_validation())?;
    for prefix in ["xs", "xsi"] {
        let idp = IdentityProvider::new(
            IdpConfig::builder(
                EntityId::try_new(IDP_ENTITY_ID)?,
                SsoEndpoint::post(IDP_SSO_POST)?,
            )
            .credentials(signing_credentials())
            .templates(tag_prefixes::templates("samlp", prefix))
            .build()?,
        );
        let (sp_descriptor, _) = descriptors(&sp, &idp)?;
        let role = Attribute::new("role", vec![AttributeValue::new("staff")]);
        let response = idp.initiate_sso(
            &sp_descriptor,
            SsoAssertion::new(principal(), SystemTime::now()).attributes(Attributes::new([role])),
            RespondSso::post(),
        )?;
        let xml = response_xml(&response)?;
        let doc = roxmltree::Document::parse(&xml)?;
        let value = doc
            .descendants()
            .find(|n| n.has_tag_name((saml_rs::constants::namespace::ASSERTION, "AttributeValue")))
            .ok_or("missing SAML AttributeValue")?;
        let datatype = value
            .attribute(("http://www.w3.org/2001/XMLSchema-instance", "type"))
            .ok_or("missing schema instance type")?;
        let (type_prefix, local) = datatype
            .split_once(':')
            .ok_or("expected a qualified type")?;
        assert_eq!(
            (value.lookup_namespace_uri(Some(type_prefix)), local),
            (Some("http://www.w3.org/2001/XMLSchema"), "string"),
            "{datatype}"
        );
    }
    Ok(())
}
