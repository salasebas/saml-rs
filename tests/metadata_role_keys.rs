//! Keys, flags, endpoints, and name identifier formats come from the SAML 2.0
//! metadata role descriptor of the role a message is from.
#![cfg(crypto)]

use std::time::SystemTime;

use saml_rs::error::SignatureVerificationReason;
use saml_rs::util::normalize_cert_string;
use saml_rs::{
    AcsEndpoint, AuthnRequest, BrowserInput, CertificatePem, Credentials, EntityId, IdpConfig,
    IdpDescriptor, IdpValidationPolicy, MetadataTrustPolicy, NameId, PrivateKeyPem, ReplayPolicy,
    RespondSso, Saml, SamlError, SamlValidationContext, SpConfig, SpDescriptor, SpValidationPolicy,
    SsoEndpoint, SsoResponse, StartSso, Subject,
};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS: &str = "https://sp.example.com/acs";
const IDP_SSO: &str = "https://idp.example.com/sso";

const SP_ROLE_KEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const SP_ROLE_CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const IDP_ROLE_KEY: &str = include_str!("fixtures/key/idp/provider_matrix_privkey.pkcs8.pem");
const IDP_ROLE_CERT: &str = include_str!("fixtures/key/idp/cert.cer");

fn credentials(key: &str, cert: &str) -> Credentials {
    Credentials {
        signing_key: Some(PrivateKeyPem::new(key)),
        signing_certificate: Some(CertificatePem::new(cert)),
        ..Credentials::default()
    }
}

fn idp_signing_with(key: &str, cert: &str) -> Result<Saml<saml_rs::Idp>, SamlError> {
    Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post(IDP_SSO)?)
            .credentials(credentials(key, cert))
            .validation(IdpValidationPolicy::recommended())
            .build()?,
    )
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility)
}

fn sso_response_from(
    sp: &Saml<saml_rs::Sp>,
    sp_descriptor: &SpDescriptor,
    idp_descriptor: &IdpDescriptor,
    responder: &Saml<saml_rs::Idp>,
) -> Result<Result<saml_rs::SsoSession, SamlError>, SamlError> {
    let started = sp.start_sso(idp_descriptor, StartSso::post())?;
    let received = responder.receive_sso(
        sp_descriptor,
        BrowserInput::<AuthnRequest>::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    let response = responder.respond_sso(
        sp_descriptor,
        &received,
        Subject::new(NameId::new("alice@example.com", None), Vec::new()),
        RespondSso::post(),
    )?;
    Ok(sp.finish_sso(
        idp_descriptor,
        &started.pending,
        BrowserInput::<SsoResponse>::post(response.post_form()?.fields().to_vec()),
        validation(),
    ))
}

#[test]
fn sso_response_signed_with_the_sp_role_key_of_a_dual_role_idp_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS)?)
            .credentials(credentials(SP_ROLE_KEY, SP_ROLE_CERT))
            .validation(SpValidationPolicy::recommended())
            .build()?,
    )?;
    let sp_descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let identity_provider = idp_signing_with(IDP_ROLE_KEY, IDP_ROLE_CERT)?;
    let sp_role_of_idp = format!(
        r#"<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/as-sp/acs" index="0"/></SPSSODescriptor></EntityDescriptor>"#,
        normalize_cert_string(SP_ROLE_CERT)
    );
    let dual_role_idp = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        &identity_provider
            .metadata_xml()
            .replace("</EntityDescriptor>", &sp_role_of_idp),
        MetadataTrustPolicy::UnsignedForCompatibility,
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
                reason: SignatureVerificationReason::XmlSignature
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
        normalize_cert_string(certificate)
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

fn sp_signing_authn_requests(key: &str, cert: &str) -> Result<Saml<saml_rs::Sp>, SamlError> {
    Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS)?)
            .credentials(credentials(key, cert))
            .validation(SpValidationPolicy {
                authn_requests: saml_rs::AuthnRequestSigningPolicy::Sign,
                ..SpValidationPolicy::recommended()
            })
            .build()?,
    )
}

#[test]
fn typed_signing_rollover_verifies_both_keys_with_metadata_published_before_the_switch(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut rolling = credentials(SP_ROLE_KEY, SP_ROLE_CERT);
    rolling.additional_signing_certificates = vec![CertificatePem::new(IDP_ROLE_CERT)];
    let mut sp_config = SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
        .acs_endpoint(AcsEndpoint::post(SP_ACS)?)
        .credentials(rolling.clone())
        .validation(SpValidationPolicy {
            authn_requests: saml_rs::AuthnRequestSigningPolicy::Sign,
            ..SpValidationPolicy::recommended()
        })
        .build()?;
    let mut idp_config = IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::post(IDP_SSO)?)
        .credentials(rolling)
        .validation(IdpValidationPolicy {
            authn_requests: saml_rs::AuthnRequestValidationPolicy::RequireSigned,
            ..IdpValidationPolicy::recommended()
        })
        .build()?;
    let published_sp = Saml::sp(sp_config.clone())?;
    let published_idp = Saml::idp(idp_config.clone())?;
    let sp_descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        published_sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        published_idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;

    for (key, current, overlap) in [
        (SP_ROLE_KEY, SP_ROLE_CERT, IDP_ROLE_CERT),
        (IDP_ROLE_KEY, IDP_ROLE_CERT, SP_ROLE_CERT),
    ] {
        let mut rolling = credentials(key, current);
        rolling.additional_signing_certificates = vec![CertificatePem::new(overlap)];
        sp_config.credentials = rolling.clone();
        idp_config.credentials = rolling;
        let sp = Saml::sp(sp_config.clone())?;
        let idp = Saml::idp(idp_config.clone())?;

        for metadata in [sp.metadata_xml(), idp.metadata_xml()] {
            let document = saml_rs::xml::dom::parse(metadata)?;
            let descriptors: Vec<_> = document
                .root
                .children
                .iter()
                .flat_map(|role| &role.children)
                .filter(|node| node.local_name == "KeyDescriptor")
                .collect();
            assert_eq!(descriptors.len(), 2);
            for (descriptor, expected) in descriptors.iter().zip([current, overlap]) {
                assert_eq!(descriptor.attr("use"), Some("signing"));
                let certificates: Vec<_> = descriptor
                    .children
                    .iter()
                    .flat_map(|key_info| &key_info.children)
                    .flat_map(|x509_data| &x509_data.children)
                    .filter(|node| node.local_name == "X509Certificate")
                    .map(|node| node.text.as_str())
                    .collect();
                assert_eq!(certificates, [normalize_cert_string(expected)]);
            }
        }

        let session = sso_response_from(&sp, &sp_descriptor, &idp_descriptor, &idp)??;
        assert_eq!(session.issuer().as_str(), IDP_ENTITY_ID);

        let current_sp = SpDescriptor::from_metadata_xml_for(
            EntityId::try_new(SP_ENTITY_ID)?,
            sp_signing_authn_requests(key, current)?.metadata_xml(),
            MetadataTrustPolicy::UnsignedForCompatibility,
        )?;
        let current_idp = IdpDescriptor::from_metadata_xml_for(
            EntityId::try_new(IDP_ENTITY_ID)?,
            idp_signing_with(key, current)?.metadata_xml(),
            MetadataTrustPolicy::UnsignedForCompatibility,
        )?;
        sso_response_from(&sp, &current_sp, &current_idp, &idp)??;
    }
    Ok(())
}

#[test]
fn sso_response_signed_with_a_saml11_role_key_is_rejected() -> Result<(), Box<dyn std::error::Error>>
{
    let sp = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS)?)
            .credentials(credentials(SP_ROLE_KEY, SP_ROLE_CERT))
            .validation(SpValidationPolicy::recommended())
            .build()?,
    )?;
    let sp_descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let identity_provider = idp_signing_with(IDP_ROLE_KEY, IDP_ROLE_CERT)?;
    let signed_with_saml11_role_key = idp_signing_with(SP_ROLE_KEY, SP_ROLE_CERT)?;

    for metadata in with_role_in_both_orders(
        identity_provider.metadata_xml(),
        "IDPSSODescriptor",
        &saml11_idp_role(SP_ROLE_CERT),
    ) {
        let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
            EntityId::try_new(IDP_ENTITY_ID)?,
            &metadata,
            MetadataTrustPolicy::UnsignedForCompatibility,
        )?;
        let idp_metadata = idp_descriptor.metadata();
        assert_eq!(
            (
                idp_metadata.x509_certificates(saml_rs::constants::CertUse::Signing),
                idp_metadata.is_want_authn_requests_signed(),
                idp_metadata
                    .get_single_sign_on_service(saml_rs::constants::Binding::Post)
                    .as_deref(),
                idp_metadata.artifact_resolution_services()?.len(),
                idp_metadata.get_single_logout_service(saml_rs::constants::Binding::Post),
                idp_metadata.get_name_id_format(),
            ),
            (
                vec![normalize_cert_string(IDP_ROLE_CERT)],
                false,
                Some(IDP_SSO),
                0,
                None,
                Vec::<String>::new(),
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
                    reason: SignatureVerificationReason::XmlSignature
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
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post(IDP_SSO)?)
            .credentials(credentials(IDP_ROLE_KEY, IDP_ROLE_CERT))
            .validation(IdpValidationPolicy {
                authn_requests: saml_rs::AuthnRequestValidationPolicy::RequireSigned,
                ..IdpValidationPolicy::recommended()
            })
            .build()?,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;

    for metadata in with_role_in_both_orders(
        sp.metadata_xml(),
        "SPSSODescriptor",
        &saml11_sp_role(IDP_ROLE_CERT),
    ) {
        let sp_descriptor = SpDescriptor::from_metadata_xml_for(
            EntityId::try_new(SP_ENTITY_ID)?,
            &metadata,
            MetadataTrustPolicy::UnsignedForCompatibility,
        )?;
        let sp_metadata = sp_descriptor.metadata();
        assert_eq!(
            (
                sp_metadata.x509_certificates(saml_rs::constants::CertUse::Signing),
                sp_metadata.is_authn_request_signed(),
                sp_metadata.is_want_assertions_signed(),
                sp_metadata
                    .get_assertion_consumer_service(saml_rs::constants::Binding::Post)
                    .as_deref(),
                sp_metadata.get_name_id_format(),
            ),
            (
                vec![normalize_cert_string(SP_ROLE_CERT)],
                true,
                false,
                Some(SP_ACS),
                vec![saml_rs::constants::name_id_format::EMAIL_ADDRESS.to_string()],
            ),
            "{metadata}"
        );

        let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
        idp.receive_sso(
            &sp_descriptor,
            BrowserInput::<AuthnRequest>::post(started.outbound.post_form()?.fields().to_vec()),
            validation(),
        )?;
        let forged = signed_with_saml11_role_key.start_sso(&idp_descriptor, StartSso::post())?;
        let rejected = idp.receive_sso(
            &sp_descriptor,
            BrowserInput::<AuthnRequest>::post(forged.outbound.post_form()?.fields().to_vec()),
            validation(),
        );
        assert!(
            matches!(
                rejected,
                Err(SamlError::SignatureVerification {
                    reason: SignatureVerificationReason::XmlSignature
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
        let idp = IdpDescriptor::from_metadata_xml_for(
            EntityId::try_new(IDP_ENTITY_ID)?,
            &idp_metadata.replace(&saml2, &listed),
            MetadataTrustPolicy::UnsignedForCompatibility,
        );
        assert!(
            matches!(&idp, Err(SamlError::MissingMetadata(role)) if role == "IDPSSODescriptor"),
            "{protocols}: {idp:?}"
        );
        let sp = SpDescriptor::from_metadata_xml_for(
            EntityId::try_new(SP_ENTITY_ID)?,
            &sp_metadata.replace(&saml2, &listed),
            MetadataTrustPolicy::UnsignedForCompatibility,
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
    let foreign = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        &foreign_namespace,
        MetadataTrustPolicy::UnsignedForCompatibility,
    );
    assert!(
        matches!(&foreign, Err(SamlError::MissingMetadata(role)) if role == "IDPSSODescriptor"),
        "{foreign:?}"
    );

    let listed_with_saml11 =
        format!("protocolSupportEnumeration=\"{SAML11_PROTOCOL}&#x9;&#xA;{SAML2_PROTOCOL}&#xD;\"");
    let idp = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        &idp_metadata.replace(&saml2, &listed_with_saml11),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    assert_eq!(
        idp.metadata()
            .get_single_sign_on_service(saml_rs::constants::Binding::Post)
            .as_deref(),
        Some(IDP_SSO)
    );
    let sp = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        &sp_metadata.replace(&saml2, &listed_with_saml11),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    assert_eq!(
        sp.metadata()
            .get_assertion_consumer_service(saml_rs::constants::Binding::Post)
            .as_deref(),
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

    let idp = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        &idp_metadata.replace(metadata_namespace, referenced_namespace),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    assert_eq!(
        idp.metadata()
            .get_single_sign_on_service(saml_rs::constants::Binding::Post)
            .as_deref(),
        Some(IDP_SSO)
    );
    let sp = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        &sp_metadata.replace(metadata_namespace, referenced_namespace),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    assert_eq!(
        sp.metadata()
            .get_assertion_consumer_service(saml_rs::constants::Binding::Post)
            .as_deref(),
        Some(SP_ACS)
    );

    let unbounded = saml_rs::xml::XmlLimits::unbounded();
    let idp = saml_rs::metadata::IdpMetadata::from_xml_with_limits(
        &idp_metadata.replacen(
            "<EntityDescriptor",
            &format!("<EntityDescriptor{many_namespaces}"),
            1,
        ),
        unbounded,
    )?;
    assert_eq!(
        idp.get_single_sign_on_service(saml_rs::constants::Binding::Post)
            .as_deref(),
        Some(IDP_SSO)
    );
    let sp = saml_rs::metadata::SpMetadata::from_xml_with_limits(
        &sp_metadata.replacen(
            "<EntityDescriptor",
            &format!("<EntityDescriptor{many_namespaces}"),
            1,
        ),
        unbounded,
    )?;
    assert_eq!(
        sp.get_assertion_consumer_service(saml_rs::constants::Binding::Post)
            .as_deref(),
        Some(SP_ACS)
    );
    Ok(())
}

#[test]
fn a_dual_role_entity_reads_and_issues_the_name_id_formats_of_the_parsed_role(
) -> Result<(), Box<dyn std::error::Error>> {
    use saml_rs::binding::base64_decode;
    use saml_rs::constants::name_id_format::{PERSISTENT, TRANSIENT};
    use saml_rs::constants::Binding;
    use saml_rs::entity::{EntitySetting, User};
    use saml_rs::idp::LoginResponseOptions;
    use saml_rs::metadata::{IdpMetadata, SpMetadata};
    use saml_rs::{IdentityProvider, ServiceProvider};

    let sp_role = format!(
        r#"<SPSSODescriptor protocolSupportEnumeration="{SAML2_PROTOCOL}"><NameIDFormat>{TRANSIENT}</NameIDFormat><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://proxy.example.com/acs" index="0"/></SPSSODescriptor>"#
    );
    let idp_only = format!(
        r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://proxy.example.com/metadata"><IDPSSODescriptor protocolSupportEnumeration="{SAML2_PROTOCOL}">{}<NameIDFormat>{PERSISTENT}</NameIDFormat><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://proxy.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>"#,
        signing_key_descriptor(IDP_ROLE_CERT)
    );
    for metadata in with_role_in_both_orders(&idp_only, "IDPSSODescriptor", &sp_role) {
        assert_eq!(
            (
                IdpMetadata::from_xml(&metadata)?.get_name_id_format(),
                SpMetadata::from_xml(&metadata)?.get_name_id_format(),
            ),
            (vec![PERSISTENT.to_string()], vec![TRANSIENT.to_string()])
        );

        let mut signing = EntitySetting::default();
        signing.private_key = Some(IDP_ROLE_KEY.into());
        signing.signing_cert = Some(IDP_ROLE_CERT.into());
        let idp = IdentityProvider::from_metadata(&metadata, signing)?;
        let sp = ServiceProvider::from_metadata(&metadata, EntitySetting::default())?;
        let response = idp.create_login_response(
            &sp,
            Binding::Post,
            &User::new("alice@example.com"),
            &LoginResponseOptions::default(),
        )?;
        let request = sp.create_login_request(&idp, Binding::Post, None)?;
        let response_xml = String::from_utf8(base64_decode(&response.context)?)?;
        let request_xml = String::from_utf8(base64_decode(&request.context)?)?;
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
