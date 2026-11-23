//! Keys, flags, endpoints, and name identifier formats come from the SAML 2.0
//! metadata role descriptor of the role a message is from.
#![cfg(crypto)]

use super::post_validation::post_validation;
use saml_rs::tests::engine::{IdpMessages, SpMessages};
use std::time::SystemTime;

use saml_rs::error::SignatureVerificationReason;
use saml_rs::{
    AcsEndpoint, AssertionSignaturePolicy, CertificatePem, Credentials, EntityId, IdentityProvider,
    IdpConfig, IdpDescriptor, IdpValidationPolicy, Inbound, MetadataTrustPolicy, NameId,
    NameIdFormat, PrivateKeyPem, ReplayPolicy, RespondSso, SamlError, SamlValidationContext,
    ServiceProvider, SpConfig, SpDescriptor, SpValidationPolicy, SsoAssertion, SsoEndpoint,
    StartSso, X509Credential,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const IDP_SSO: &str = "https://idp.example.com/sso";

const SP_ROLE_KEY: &str = include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const SP_ROLE_CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const IDP_ROLE_KEY: &str =
    include_str!("../../tests/fixtures/key/idp/provider_matrix_privkey.pkcs8.pem");
const IDP_ROLE_CERT: &str = include_str!("../../tests/fixtures/key/idp/cert.cer");

fn certificate_base64(pem: &str) -> String {
    pem.lines()
        .filter(|line| !line.trim_start().starts_with("-----"))
        .flat_map(str::split_whitespace)
        .collect()
}

fn credentials(key: &str, cert: &str) -> Credentials {
    Credentials::default().with_signing_credential(X509Credential::new(
        CertificatePem::new(cert),
        PrivateKeyPem::new(key),
    ))
}

fn idp_signing_with(key: &str, cert: &str) -> Result<saml_rs::IdentityProvider, SamlError> {
    Ok(IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO)?,
        )
        .credentials(credentials(key, cert))
        .validation(IdpValidationPolicy::default())
        .build()?,
    ))
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::Disabled)
}

fn sso_response_from(
    sp: &saml_rs::ServiceProvider,
    sp_descriptor: &SpDescriptor,
    idp_descriptor: &IdpDescriptor,
    responder: &saml_rs::IdentityProvider,
) -> Result<Result<saml_rs::SsoSession, SamlError>, SamlError> {
    let started = sp.start_sso(idp_descriptor, StartSso::post())?;
    let received = responder.receive_sso(
        sp_descriptor,
        Inbound::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let response = responder.respond_sso(
        sp_descriptor,
        &received,
        SsoAssertion::new(NameId::new("alice@example.com").with_format(NameIdFormat::EmailAddress)),
        RespondSso::post(),
    )?;
    Ok(sp.finish_sso(
        idp_descriptor,
        &started.pending,
        Inbound::post(response.post_form()?.fields().to_vec()),
        post_validation(&mut Default::default()),
    ))
}

#[test]
fn sso_response_signed_with_the_sp_role_key_of_a_dual_role_idp_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?, AcsEndpoint::post(SP_ACS)?)
            .credentials(credentials(SP_ROLE_KEY, SP_ROLE_CERT))
            .validation(SpValidationPolicy::default())
            .build()?,
    );
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let identity_provider = idp_signing_with(IDP_ROLE_KEY, IDP_ROLE_CERT)?;
    let sp_role_of_idp = format!(
        r#"<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/as-sp/acs" index="0"/></SPSSODescriptor></EntityDescriptor>"#,
        certificate_base64(SP_ROLE_CERT)
    );
    let dual_role_idp = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        &identity_provider
            .metadata_xml()
            .replace("</EntityDescriptor>", &sp_role_of_idp),
        MetadataTrustPolicy::AllowUnsigned,
    )?;

    let session = sso_response_from(&sp, &sp_descriptor, &dual_role_idp, &identity_provider)??;
    assert_eq!(session.issuer().as_str(), IDP_ENTITY_ID);

    let signed_with_sp_role_key = idp_signing_with(SP_ROLE_KEY, SP_ROLE_CERT)?;
    let rejected = sso_response_from(
        &sp,
        &sp_descriptor,
        &dual_role_idp,
        &signed_with_sp_role_key,
    )?;
    assert!(
        matches!(
            rejected,
            Err(SamlError::SignatureVerification {
                reason: SignatureVerificationReason::XmlSignature,
                ..
            })
        ),
        "{rejected:?}"
    );
    Ok(())
}

const SAML2_PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const SAML11_PROTOCOL: &str = "urn:oasis:names:tc:SAML:1.1:protocol";
const SAML11_IDP_SSO: &str = "https://idp.example.com/saml11/sso";
const SAML11_SP_ACS: &str = "https://sp.example.com/saml11/acs";
const SAML11_NAME_ID_FORMAT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
const EXPIRED: &str = "2001-01-01T00:00:00Z";

fn signing_key_descriptor(certificate: &str) -> String {
    format!(
        r#"<KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>"#,
        certificate_base64(certificate)
    )
}

fn saml11_idp_role(certificate: &str) -> String {
    format!(
        r#"<IDPSSODescriptor protocolSupportEnumeration="{SAML11_PROTOCOL}" WantAuthnRequestsSigned="true" validUntil="{EXPIRED}">{}<ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://idp.example.com/saml11/artifact" index="0"/><SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/saml11/slo"/><NameIDFormat>{SAML11_NAME_ID_FORMAT}</NameIDFormat><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{SAML11_IDP_SSO}"/></IDPSSODescriptor>"#,
        signing_key_descriptor(certificate)
    )
}

fn saml11_sp_role(certificate: &str) -> String {
    format!(
        r#"<SPSSODescriptor protocolSupportEnumeration="{SAML11_PROTOCOL}" AuthnRequestsSigned="false" WantAssertionsSigned="true" validUntil="{EXPIRED}">{}<NameIDFormat>{SAML11_NAME_ID_FORMAT}</NameIDFormat><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{SAML11_SP_ACS}" index="0"/></SPSSODescriptor>"#,
        signing_key_descriptor(certificate)
    )
}

fn with_role_in_both_orders(metadata: &str, descriptor: &str, role: &str) -> [String; 2] {
    let opening = format!("<{descriptor}");
    [
        metadata.replacen(&opening, &format!("{role}{opening}"), 1),
        metadata.replace("</EntityDescriptor>", &format!("{role}</EntityDescriptor>")),
    ]
}

#[test]
fn http_post_honors_want_assertions_signed_with_multiple_saml2_sp_roles(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::new(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?, AcsEndpoint::post(SP_ACS)?)
            .validation(SpValidationPolicy {
                assertions: AssertionSignaturePolicy::RequireSigned,
                ..Default::default()
            })
            .build()?,
    );
    let idp = idp_signing_with(IDP_ROLE_KEY, IDP_ROLE_CERT)?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let second_acs_role = format!(
        r#"<SPSSODescriptor protocolSupportEnumeration="{SAML2_PROTOCOL}" WantAssertionsSigned="false">
  <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/second/acs" index="1"/>
</SPSSODescriptor>"#
    );

    for metadata in with_role_in_both_orders(sp.metadata_xml(), "SPSSODescriptor", &second_acs_role)
    {
        let sp_descriptor = SpDescriptor::from_metadata_xml(
            EntityId::try_new(SP_ENTITY_ID)?,
            &metadata,
            MetadataTrustPolicy::AllowUnsigned,
        )?;
        let session = sso_response_from(&sp, &sp_descriptor, &idp_descriptor, &idp)??;
        assert_eq!(session.name_id().value(), "alice@example.com");
    }
    Ok(())
}

fn sp_signing_authn_requests(key: &str, cert: &str) -> Result<saml_rs::ServiceProvider, SamlError> {
    let validation = SpValidationPolicy {
        authn_requests: saml_rs::AuthnRequestSigningPolicy::Sign,
        ..Default::default()
    };
    Ok(ServiceProvider::new(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?, AcsEndpoint::post(SP_ACS)?)
            .credentials(credentials(key, cert))
            .validation(validation)
            .build()?,
    ))
}

#[test]
fn typed_signing_rollover_verifies_both_keys_with_metadata_published_before_the_switch(
) -> Result<(), Box<dyn std::error::Error>> {
    let rolling = credentials(SP_ROLE_KEY, SP_ROLE_CERT)
        .with_additional_signing_certificate(CertificatePem::new(IDP_ROLE_CERT));
    let sp_validation = SpValidationPolicy {
        authn_requests: saml_rs::AuthnRequestSigningPolicy::Sign,
        ..Default::default()
    };
    let sp_config = SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?, AcsEndpoint::post(SP_ACS)?)
        .validation(sp_validation);
    let idp_validation = IdpValidationPolicy {
        authn_requests: saml_rs::AuthnRequestValidationPolicy::RequireSigned,
        ..Default::default()
    };
    let idp_config = IdpConfig::builder(
        EntityId::try_new(IDP_ENTITY_ID)?,
        SsoEndpoint::post(IDP_SSO)?,
    )
    .validation(idp_validation);
    let published_sp =
        ServiceProvider::new(sp_config.clone().credentials(rolling.clone()).build()?);
    let published_idp = IdentityProvider::new(idp_config.clone().credentials(rolling).build()?);
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        published_sp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        published_idp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;

    for (key, current, overlap) in [
        (SP_ROLE_KEY, SP_ROLE_CERT, IDP_ROLE_CERT),
        (IDP_ROLE_KEY, IDP_ROLE_CERT, SP_ROLE_CERT),
    ] {
        let rolling = credentials(key, current)
            .with_additional_signing_certificate(CertificatePem::new(overlap));
        let sp = ServiceProvider::new(sp_config.clone().credentials(rolling.clone()).build()?);
        let idp = IdentityProvider::new(idp_config.clone().credentials(rolling).build()?);

        for metadata in [sp.metadata_xml(), idp.metadata_xml()] {
            let document = roxmltree::Document::parse(metadata)?;
            let descriptors: Vec<_> = document
                .root_element()
                .children()
                .flat_map(|role| role.children())
                .filter(|node| node.has_tag_name("KeyDescriptor"))
                .collect();
            assert_eq!(descriptors.len(), 2);
            for (descriptor, expected) in descriptors.iter().zip([current, overlap]) {
                assert_eq!(descriptor.attribute("use"), Some("signing"));
                let certificates: Vec<_> = descriptor
                    .children()
                    .flat_map(|key_info| key_info.children())
                    .flat_map(|x509_data| x509_data.children())
                    .filter(|node| node.has_tag_name("X509Certificate"))
                    .map(|node| node.text().unwrap_or_default())
                    .collect();
                assert_eq!(certificates, [certificate_base64(expected)]);
            }
        }

        let session = sso_response_from(&sp, &sp_descriptor, &idp_descriptor, &idp)??;
        assert_eq!(session.issuer().as_str(), IDP_ENTITY_ID);

        let current_sp = SpDescriptor::from_metadata_xml(
            EntityId::try_new(SP_ENTITY_ID)?,
            sp_signing_authn_requests(key, current)?.metadata_xml(),
            MetadataTrustPolicy::AllowUnsigned,
        )?;
        let current_idp = IdpDescriptor::from_metadata_xml(
            EntityId::try_new(IDP_ENTITY_ID)?,
            idp_signing_with(key, current)?.metadata_xml(),
            MetadataTrustPolicy::AllowUnsigned,
        )?;
        sso_response_from(&sp, &current_sp, &current_idp, &idp)??;
    }
    Ok(())
}

#[test]
fn sso_response_signed_with_a_saml11_role_key_is_rejected() -> Result<(), Box<dyn std::error::Error>>
{
    let sp = ServiceProvider::new(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?, AcsEndpoint::post(SP_ACS)?)
            .credentials(credentials(SP_ROLE_KEY, SP_ROLE_CERT))
            .validation(SpValidationPolicy::default())
            .build()?,
    );
    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let identity_provider = idp_signing_with(IDP_ROLE_KEY, IDP_ROLE_CERT)?;
    let signed_with_saml11_role_key = idp_signing_with(SP_ROLE_KEY, SP_ROLE_CERT)?;

    for metadata in with_role_in_both_orders(
        identity_provider.metadata_xml(),
        "IDPSSODescriptor",
        &saml11_idp_role(SP_ROLE_CERT),
    ) {
        let idp_descriptor = IdpDescriptor::from_metadata_xml(
            EntityId::try_new(IDP_ENTITY_ID)?,
            &metadata,
            MetadataTrustPolicy::AllowUnsigned,
        )?;
        let idp_metadata = saml_rs::metadata::IdpMetadata::from_xml(&metadata)?;
        assert_eq!(
            (
                idp_metadata
                    .as_metadata()
                    .x509_certificates(saml_rs::constants::CertUse::Signing),
                idp_metadata.want_authn_requests_signed(),
                idp_metadata
                    .single_sign_on_location(saml_rs::constants::Binding::Post)
                    .as_deref(),
                idp_metadata.artifact_resolution_services()?.len(),
                idp_metadata
                    .as_metadata()
                    .single_logout_location(saml_rs::constants::Binding::Post),
                idp_metadata.as_metadata().name_id_formats(),
            ),
            (
                [certificate_base64(IDP_ROLE_CERT)].as_slice(),
                false,
                Some(IDP_SSO),
                0,
                None,
                Vec::<saml_rs::NameIdFormat>::new(),
            ),
            "{metadata}"
        );

        let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
        assert_eq!(started.outbound.post_form()?.action().as_str(), IDP_SSO);

        let session = sso_response_from(&sp, &sp_descriptor, &idp_descriptor, &identity_provider)??;
        assert_eq!(session.issuer().as_str(), IDP_ENTITY_ID);
        let rejected = sso_response_from(
            &sp,
            &sp_descriptor,
            &idp_descriptor,
            &signed_with_saml11_role_key,
        )?;
        assert!(
            matches!(
                rejected,
                Err(SamlError::SignatureVerification {
                    reason: SignatureVerificationReason::XmlSignature,
                    ..
                })
            ),
            "{rejected:?}"
        );
    }
    Ok(())
}

#[test]
fn authn_request_signed_with_a_saml11_role_key_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_signing_authn_requests(SP_ROLE_KEY, SP_ROLE_CERT)?;
    let signed_with_saml11_role_key = sp_signing_authn_requests(IDP_ROLE_KEY, IDP_ROLE_CERT)?;
    let idp_validation = IdpValidationPolicy {
        authn_requests: saml_rs::AuthnRequestValidationPolicy::RequireSigned,
        ..Default::default()
    };
    let idp = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new(IDP_ENTITY_ID)?,
            SsoEndpoint::post(IDP_SSO)?,
        )
        .credentials(credentials(IDP_ROLE_KEY, IDP_ROLE_CERT))
        .validation(idp_validation)
        .build()?,
    );
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;

    for metadata in with_role_in_both_orders(
        sp.metadata_xml(),
        "SPSSODescriptor",
        &saml11_sp_role(IDP_ROLE_CERT),
    ) {
        let sp_descriptor = SpDescriptor::from_metadata_xml(
            EntityId::try_new(SP_ENTITY_ID)?,
            &metadata,
            MetadataTrustPolicy::AllowUnsigned,
        )?;
        let sp_metadata = saml_rs::metadata::SpMetadata::from_xml(&metadata)?;
        assert_eq!(
            (
                sp_metadata
                    .as_metadata()
                    .x509_certificates(saml_rs::constants::CertUse::Signing),
                sp_metadata.authn_requests_signed(),
                sp_metadata.want_assertions_signed(),
                sp_metadata
                    .assertion_consumer_location(saml_rs::constants::Binding::Post)
                    .as_deref(),
                sp_metadata.as_metadata().name_id_formats(),
            ),
            (
                [certificate_base64(SP_ROLE_CERT)].as_slice(),
                true,
                false,
                Some(SP_ACS),
                vec![saml_rs::NameIdFormat::EmailAddress],
            ),
            "{metadata}"
        );

        let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
        idp.receive_sso(
            &sp_descriptor,
            Inbound::post(started.outbound.post_form()?.fields().to_vec()),
            validation(),
        )?;
        let forged = signed_with_saml11_role_key.start_sso(&idp_descriptor, StartSso::post())?;
        let rejected = idp.receive_sso(
            &sp_descriptor,
            Inbound::post(forged.outbound.post_form()?.fields().to_vec()),
            validation(),
        );
        assert!(
            matches!(
                rejected,
                Err(SamlError::SignatureVerification {
                    reason: SignatureVerificationReason::XmlSignature,
                    ..
                })
            ),
            "{rejected:?}"
        );
    }
    Ok(())
}

#[test]
fn an_entity_without_a_saml2_role_of_the_peer_kind_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp_metadata = idp_signing_with(IDP_ROLE_KEY, IDP_ROLE_CERT)?
        .metadata_xml()
        .to_string();
    let sp_metadata = sp_signing_authn_requests(SP_ROLE_KEY, SP_ROLE_CERT)?
        .metadata_xml()
        .to_string();
    let saml2 = format!(r#"protocolSupportEnumeration="{SAML2_PROTOCOL}""#);
    for protocols in [SAML11_PROTOCOL, "urn:oasis:names:tc:SAML:2.0:protocolx", ""] {
        let listed = format!(r#"protocolSupportEnumeration="{protocols}""#);
        let idp = IdpDescriptor::from_metadata_xml(
            EntityId::try_new(IDP_ENTITY_ID)?,
            &idp_metadata.replace(&saml2, &listed),
            MetadataTrustPolicy::AllowUnsigned,
        );
        assert!(
            matches!(&idp, Err(SamlError::MissingMetadata(role)) if role == "IDPSSODescriptor"),
            "{protocols}: {idp:?}"
        );
        let sp = SpDescriptor::from_metadata_xml(
            EntityId::try_new(SP_ENTITY_ID)?,
            &sp_metadata.replace(&saml2, &listed),
            MetadataTrustPolicy::AllowUnsigned,
        );
        assert!(
            matches!(&sp, Err(SamlError::MissingMetadata(role)) if role == "SPSSODescriptor"),
            "{protocols}: {sp:?}"
        );
    }

    let idp_outside_an_entity = saml_rs::metadata::IdpMetadata::from_xml(
        &idp_metadata.replace("EntityDescriptor", "Entity"),
    );
    assert!(
        matches!(&idp_outside_an_entity, Err(SamlError::MissingMetadata(role)) if role == "IDPSSODescriptor"),
        "{idp_outside_an_entity:?}"
    );
    let sp_outside_an_entity =
        saml_rs::metadata::SpMetadata::from_xml(&sp_metadata.replace("EntityDescriptor", "Entity"));
    assert!(
        matches!(&sp_outside_an_entity, Err(SamlError::MissingMetadata(role)) if role == "SPSSODescriptor"),
        "{sp_outside_an_entity:?}"
    );

    let foreign_namespace = idp_metadata.replacen(
        "<IDPSSODescriptor",
        r#"<IDPSSODescriptor xmlns="urn:example:not-metadata""#,
        1,
    );
    let foreign = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        &foreign_namespace,
        MetadataTrustPolicy::AllowUnsigned,
    );
    assert!(
        matches!(&foreign, Err(SamlError::MissingMetadata(role)) if role == "IDPSSODescriptor"),
        "{foreign:?}"
    );

    let listed_with_saml11 =
        format!("protocolSupportEnumeration=\"{SAML11_PROTOCOL}&#x9;&#xA;{SAML2_PROTOCOL}&#xD;\"");
    let idp = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        &idp_metadata.replace(&saml2, &listed_with_saml11),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    assert_eq!(
        idp.single_sign_on_location(saml_rs::SsoRequestBinding::Post)?
            .as_ref()
            .map(saml_rs::EndpointUrl::as_str),
        Some(IDP_SSO)
    );
    let sp = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        &sp_metadata.replace(&saml2, &listed_with_saml11),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    assert_eq!(
        sp.assertion_consumer_location(saml_rs::SsoResponseBinding::Post)?
            .as_ref()
            .map(saml_rs::EndpointUrl::as_str),
        Some(SP_ACS)
    );
    Ok(())
}

#[test]
fn a_saml2_role_is_found_through_namespace_references_and_raised_limits(
) -> Result<(), Box<dyn std::error::Error>> {
    let metadata_namespace = r#"xmlns="urn:oasis:names:tc:SAML:2.0:metadata""#;
    let referenced_namespace = r#"xmlns="urn:oasis:names:tc:SAML:2.0:metadat&#x61;""#;
    let many_namespaces: String = (0..129)
        .map(|index| format!(r#" xmlns:n{index}="urn:example:{index}""#))
        .collect();
    let idp_metadata = idp_signing_with(IDP_ROLE_KEY, IDP_ROLE_CERT)?
        .metadata_xml()
        .to_string();
    let sp_metadata = sp_signing_authn_requests(SP_ROLE_KEY, SP_ROLE_CERT)?
        .metadata_xml()
        .to_string();

    let idp = IdpDescriptor::from_metadata_xml(
        EntityId::try_new(IDP_ENTITY_ID)?,
        &idp_metadata.replace(metadata_namespace, referenced_namespace),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    assert_eq!(
        idp.single_sign_on_location(saml_rs::SsoRequestBinding::Post)?
            .as_ref()
            .map(saml_rs::EndpointUrl::as_str),
        Some(IDP_SSO)
    );
    let sp = SpDescriptor::from_metadata_xml(
        EntityId::try_new(SP_ENTITY_ID)?,
        &sp_metadata.replace(metadata_namespace, referenced_namespace),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    assert_eq!(
        sp.assertion_consumer_location(saml_rs::SsoResponseBinding::Post)?
            .as_ref()
            .map(saml_rs::EndpointUrl::as_str),
        Some(SP_ACS)
    );

    let mut unbounded = saml_rs::XmlPolicy::default();
    unbounded.limits = saml_rs::XmlLimits::unbounded();
    let idp = saml_rs::metadata::IdpMetadata::from_xml_with_policy(
        &idp_metadata.replacen(
            "<EntityDescriptor",
            &format!("<EntityDescriptor{many_namespaces}"),
            1,
        ),
        &unbounded,
    )?;
    assert_eq!(
        idp.single_sign_on_location(saml_rs::constants::Binding::Post)
            .as_deref(),
        Some(IDP_SSO)
    );
    let sp = saml_rs::metadata::SpMetadata::from_xml_with_policy(
        &sp_metadata.replacen(
            "<EntityDescriptor",
            &format!("<EntityDescriptor{many_namespaces}"),
            1,
        ),
        &unbounded,
    )?;
    assert_eq!(
        sp.assertion_consumer_location(saml_rs::constants::Binding::Post)
            .as_deref(),
        Some(SP_ACS)
    );
    Ok(())
}

#[test]
fn a_dual_role_entity_reads_and_issues_the_name_id_formats_of_the_parsed_role(
) -> Result<(), Box<dyn std::error::Error>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use saml_rs::constants::name_id_format::{PERSISTENT, TRANSIENT};
    use saml_rs::constants::Binding;
    use saml_rs::entity::{EntitySetting, User};
    use saml_rs::idp;
    use saml_rs::idp::LoginResponseOptions;
    use saml_rs::metadata::{IdpMetadata, SpMetadata};
    use saml_rs::sp;
    use saml_rs::sp::LoginRequestOptions;

    let sp_role = format!(
        r#"<SPSSODescriptor protocolSupportEnumeration="{SAML2_PROTOCOL}"><NameIDFormat>&#x9; {TRANSIENT} &#xD;&#xA;</NameIDFormat><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://proxy.example.com/acs" index="0"/></SPSSODescriptor>"#
    );
    let idp_only = format!(
        r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://proxy.example.com/metadata"><IDPSSODescriptor protocolSupportEnumeration="{SAML2_PROTOCOL}">{}<NameIDFormat>&#xA; {PERSISTENT} &#x9;&#xD;</NameIDFormat><NameIDFormat> urn:example:custom&#x9;  value </NameIDFormat><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://proxy.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>"#,
        signing_key_descriptor(IDP_ROLE_CERT)
    );
    for metadata in with_role_in_both_orders(&idp_only, "IDPSSODescriptor", &sp_role) {
        assert_eq!(
            (
                IdpMetadata::from_xml(&metadata)?
                    .as_metadata()
                    .name_id_formats(),
                SpMetadata::from_xml(&metadata)?
                    .as_metadata()
                    .name_id_formats(),
            ),
            (
                vec![
                    saml_rs::NameIdFormat::Persistent,
                    saml_rs::NameIdFormat::Custom("urn:example:custom value".into())
                ],
                vec![saml_rs::NameIdFormat::Transient]
            )
        );

        let signing = EntitySetting {
            private_key: Some(IDP_ROLE_KEY.into()),
            signing_cert: Some(IDP_ROLE_CERT.into()),
            ..EntitySetting::default()
        };
        let idp = idp::Engine::from_metadata(&metadata, signing)?;
        let sp = sp::Engine::from_metadata(&metadata, EntitySetting::default())?;
        let response = idp.create_login_response(
            &sp,
            Binding::Post,
            &User::new("alice@example.com"),
            &LoginResponseOptions::default(),
        )?;
        let request =
            sp.create_login_request(&idp, Binding::Post, &LoginRequestOptions::default())?;
        let response_xml = String::from_utf8(STANDARD.decode(&response.context)?)?;
        let request_xml = String::from_utf8(STANDARD.decode(&request.context)?)?;
        assert!(
            response_xml.contains(&format!(r#"Format="{PERSISTENT}""#))
                && !response_xml.contains(TRANSIENT),
            "{response_xml}"
        );
        assert!(
            request_xml.contains(&format!(r#"Format="{TRANSIENT}""#))
                && !request_xml.contains(PERSISTENT),
            "{request_xml}"
        );
    }
    Ok(())
}
