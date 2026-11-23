#![cfg(crypto)]

use saml_rs::constants::digest_algorithm::{SHA256, SHA512};
use saml_rs::constants::signature_algorithm::{RSA_SHA256, RSA_SHA512};
use saml_rs::constants::transform_algorithm::{ENVELOPED_SIGNATURE, EXC_C14N};
use saml_rs::metadata::sign_metadata;
use saml_rs::util::normalize_cert_string;
use saml_rs::xml::dom::{parse_document, Node};
use saml_rs::{
    AcsEndpoint, AlgorithmPolicy, CertificatePem, Credentials, EntityId, IdentityProvider,
    IdpConfig, IdpDescriptor, MetadataTrustPolicy, PrivateKeyPem, SamlError, ServiceProvider,
    SignatureAlgorithm, SpConfig, SpDescriptor, SsoEndpoint, X509Credential, XmlLimits,
};

const METADATA_KEY: &str =
    include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const METADATA_CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");
const MESSAGE_KEY: &str =
    include_str!("../../tests/fixtures/key/idp/provider_matrix_privkey.pkcs8.pem");
const MESSAGE_CERT: &str = include_str!("../../tests/fixtures/key/idp/cert.cer");

const IDP_ROLE: &str = r#"<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso"/></IDPSSODescriptor>"#;

fn metadata_credential() -> X509Credential {
    X509Credential::new(
        CertificatePem::new(METADATA_CERT),
        PrivateKeyPem::new(METADATA_KEY),
    )
}

fn require_signature(certificates: &[CertificatePem]) -> MetadataTrustPolicy<'_> {
    MetadataTrustPolicy::RequireSignature {
        trusted_certificates: certificates,
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SignatureShape {
    root_children: Vec<String>,
    reference_uri: String,
    canonicalization: String,
    transforms: Vec<String>,
    signature_method: String,
    digest_method: String,
    certificate: String,
}

fn child<'a>(node: &'a Node, name: &str) -> Result<&'a Node, String> {
    node.child_named(name)
        .ok_or_else(|| format!("{} has no {name}", node.local_name))
}

fn algorithm(node: &Node, name: &str) -> Result<String, String> {
    child(node, name)?
        .attr("Algorithm")
        .map(str::to_string)
        .ok_or_else(|| format!("{name} has no Algorithm"))
}

fn signature_shape(xml: &str) -> Result<(String, SignatureShape), Box<dyn std::error::Error>> {
    let root = parse_document(xml, XmlLimits::default())?.root;
    let root_id = root.attr("ID").ok_or("root has no ID")?.to_string();
    let signature = root.children.first().ok_or("root has no children")?;
    let signed_info = child(signature, "SignedInfo")?;
    let reference = child(signed_info, "Reference")?;
    let shape = SignatureShape {
        root_children: root
            .children
            .iter()
            .map(|node| node.local_name.clone())
            .collect(),
        reference_uri: reference.attr("URI").ok_or("Reference has no URI")?.into(),
        canonicalization: algorithm(signed_info, "CanonicalizationMethod")?,
        transforms: child(reference, "Transforms")?
            .children_named("Transform")
            .map(|transform| transform.attr("Algorithm").unwrap_or_default().to_string())
            .collect(),
        signature_method: algorithm(signed_info, "SignatureMethod")?,
        digest_method: algorithm(reference, "DigestMethod")?,
        certificate: child(
            child(child(signature, "KeyInfo")?, "X509Data")?,
            "X509Certificate",
        )?
        .text
        .clone(),
    };
    Ok((root_id, shape))
}

fn expected_shape(
    root_children: &[&str],
    root_id: &str,
    signature_method: &str,
    digest_method: &str,
) -> SignatureShape {
    SignatureShape {
        root_children: root_children.iter().map(|name| name.to_string()).collect(),
        reference_uri: format!("#{root_id}"),
        canonicalization: EXC_C14N.into(),
        transforms: vec![ENVELOPED_SIGNATURE.into(), EXC_C14N.into()],
        signature_method: signature_method.into(),
        digest_method: digest_method.into(),
        certificate: normalize_cert_string(METADATA_CERT),
    }
}

#[test]
fn service_provider_publishes_metadata_signed_under_the_algorithm_policy(
) -> Result<(), Box<dyn std::error::Error>> {
    let entity_id = EntityId::try_new("https://sp.example.com/metadata")?;
    let algorithms = AlgorithmPolicy {
        signature: SignatureAlgorithm::RsaSha512,
        ..AlgorithmPolicy::default()
    };
    let sp = ServiceProvider::new(
        SpConfig::builder(
            entity_id.clone(),
            AcsEndpoint::post("https://sp.example.com/acs")?,
        )
        .credentials(Credentials::default().with_metadata_signing_credential(metadata_credential()))
        .algorithms(algorithms)
        .build()?,
    );
    let pinned = [CertificatePem::new(METADATA_CERT)];

    let (root_id, shape) = signature_shape(sp.metadata_xml())?;
    assert_eq!(
        shape,
        expected_shape(
            &["Signature", "SPSSODescriptor"],
            &root_id,
            RSA_SHA512,
            SHA512
        )
    );
    let descriptor = SpDescriptor::from_metadata_xml(
        entity_id.clone(),
        sp.metadata_xml(),
        require_signature(&pinned),
    )?;
    assert!(descriptor.signed_metadata_xml().is_some());

    let tampered = sp.metadata_xml().replace(
        "https://sp.example.com/acs",
        "https://attacker.example.com/acs",
    );
    let result = SpDescriptor::from_metadata_xml(entity_id, &tampered, require_signature(&pinned));
    assert!(
        matches!(result, Err(SamlError::SignatureVerification { .. })),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn identity_provider_signs_metadata_with_the_metadata_key_not_the_message_key(
) -> Result<(), Box<dyn std::error::Error>> {
    let entity_id = EntityId::try_new("https://idp.example.com/metadata")?;
    let idp = IdentityProvider::new(
        IdpConfig::builder(
            entity_id.clone(),
            SsoEndpoint::post("https://idp.example.com/sso")?,
        )
        .credentials(
            Credentials::default()
                .with_signing_credential(X509Credential::new(
                    CertificatePem::new(MESSAGE_CERT),
                    PrivateKeyPem::new(MESSAGE_KEY),
                ))
                .with_metadata_signing_credential(metadata_credential()),
        )
        .build()?,
    );

    let (root_id, shape) = signature_shape(idp.metadata_xml())?;
    assert_eq!(
        shape,
        expected_shape(
            &["Signature", "IDPSSODescriptor"],
            &root_id,
            RSA_SHA256,
            SHA256
        )
    );
    let descriptor = IdpDescriptor::from_metadata_xml(
        entity_id.clone(),
        idp.metadata_xml(),
        require_signature(&[CertificatePem::new(METADATA_CERT)]),
    )?;
    assert!(descriptor.signed_metadata_xml().is_some());
    let result = IdpDescriptor::from_metadata_xml(
        entity_id,
        idp.metadata_xml(),
        require_signature(&[CertificatePem::new(MESSAGE_CERT)]),
    );
    assert!(result.is_err(), "{result:?}");
    Ok(())
}

#[test]
fn sign_metadata_signs_an_aggregate_or_a_root_with_its_own_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let aggregate = format!(
        r#"<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" Name="https://federation.example.com"><Extensions><Publisher xmlns="urn:example:publisher"/></Extensions><EntityDescriptor entityID="https://idp.example.com/metadata">{IDP_ROLE}</EntityDescriptor></EntitiesDescriptor>"#
    );
    let identified = format!(
        r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="_given" entityID="https://idp.example.com/metadata"><md:Extensions><Publisher xmlns="urn:example:publisher"/></md:Extensions>{}</md:EntityDescriptor>"#,
        IDP_ROLE
            .replace("<IDPSSODescriptor", "<md:IDPSSODescriptor")
            .replace("</IDPSSODescriptor", "</md:IDPSSODescriptor")
            .replace("<SingleSignOnService", "<md:SingleSignOnService")
    );
    let cases: [(&str, &str, Option<&str>, &[&str]); 2] = [
        (
            "aggregate without an ID",
            &aggregate,
            None,
            &["Signature", "Extensions", "EntityDescriptor"],
        ),
        (
            "entity with an ID",
            &identified,
            Some("_given"),
            &["Signature", "Extensions", "IDPSSODescriptor"],
        ),
    ];
    let pinned = [CertificatePem::new(METADATA_CERT)];
    for (case, xml, given_id, children) in cases {
        let signed = sign_metadata(xml, &metadata_credential(), &SignatureAlgorithm::RsaSha256)?;

        let (root_id, shape) = signature_shape(&signed)?;
        if let Some(given_id) = given_id {
            assert_eq!(root_id, given_id, "{case}");
        }
        assert_eq!(
            shape,
            expected_shape(children, &root_id, RSA_SHA256, SHA256),
            "{case}"
        );
        IdpDescriptor::from_metadata_xml(
            EntityId::try_new("https://idp.example.com/metadata")?,
            &signed,
            require_signature(&pinned),
        )?;
    }
    Ok(())
}

#[test]
fn sign_metadata_rejects_inputs_it_cannot_sign() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = format!(
        r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/metadata">{IDP_ROLE}</EntityDescriptor>"#
    );
    let signed = sign_metadata(
        &metadata,
        &metadata_credential(),
        &SignatureAlgorithm::RsaSha256,
    )?;
    let empty_id = metadata.replace("<EntityDescriptor ", "<EntityDescriptor ID=\"\" ");
    let request = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_request" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"/>"#;
    let cases = [
        (
            "signed root",
            signed.as_str(),
            SignatureAlgorithm::RsaSha256,
        ),
        (
            "empty root ID",
            empty_id.as_str(),
            SignatureAlgorithm::RsaSha256,
        ),
        ("protocol message", request, SignatureAlgorithm::RsaSha256),
        ("HMAC-SHA1", metadata.as_str(), SignatureAlgorithm::HmacSha1),
    ];
    for (case, xml, algorithm) in cases {
        let result = sign_metadata(xml, &metadata_credential(), &algorithm);
        assert!(
            matches!(result, Err(SamlError::Invalid(_))),
            "{case}: {result:?}"
        );
    }
    Ok(())
}
