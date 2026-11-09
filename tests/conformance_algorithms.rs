#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use std::time::SystemTime;

use saml_rs::binding::{base64_decode, deflate_raw_decode};
use saml_rs::constants::{
    data_encryption_algorithm, digest_algorithm, key_encryption_algorithm, signature_algorithm,
    transform_algorithm,
};
#[cfg(feature = "crypto-rustcrypto")]
use saml_rs::SignatureAlgorithm;
use saml_rs::{
    AcsEndpoint, AlgorithmPolicy, AuthnRequest, AuthnRequestSigningPolicy,
    AuthnRequestValidationPolicy, BrowserInput, CertificatePem, Credentials, EntityId, FormField,
    IdpConfig, IdpDescriptor, IdpValidationPolicy, MetadataTrustPolicy, NameId, Outbound,
    PrivateKeyPem, ReplayPolicy, RespondSso, Saml, SamlError, SamlValidationContext, SpConfig,
    SpDescriptor, SpValidationPolicy, SsoEndpoint, SsoResponse, SsoSession, StartSso, Subject,
    TransformAlgorithm, XmlPolicy,
};
#[cfg(not(feature = "crypto-fips"))]
use saml_rs::{DataEncryptionAlgorithm, KeyEncryptionAlgorithm, XmlEncryptionPolicy};
use url::Url;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS_POST: &str = "https://sp.example.com/acs/post";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const IDP_SSO_REDIRECT: &str = "https://idp.example.com/sso/redirect";

const RSA_KEY: &str = include_str!("fixtures/key/sp_privkey.pem");
const RSA_CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");
#[cfg(all(feature = "crypto-rustcrypto", feature = "crypto-legacy-algorithms"))]
const DSA_KEY: &str = include_str!("fixtures/key/dsa/privkey.pkcs8.pem");
#[cfg(all(feature = "crypto-rustcrypto", feature = "crypto-legacy-algorithms"))]
const DSA_CERT: &str = include_str!("fixtures/key/dsa/cert.pem");

struct Signer {
    key: &'static str,
    cert: &'static str,
}

const RSA_SIGNER: Signer = Signer {
    key: RSA_KEY,
    cert: RSA_CERT,
};

fn credentials(signer: &Signer) -> Credentials {
    Credentials {
        signing_key: Some(PrivateKeyPem::new(signer.key)),
        signing_certificate: Some(CertificatePem::new(signer.cert)),
        encryption_certificate: Some(CertificatePem::new(RSA_CERT)),
        decryption_key: Some(PrivateKeyPem::new(RSA_KEY)),
        ..Credentials::default()
    }
}

#[cfg(not(feature = "crypto-fips"))]
fn encrypted_assertions() -> XmlPolicy {
    XmlPolicy {
        encryption: XmlEncryptionPolicy::encrypt_assertions()
            .with_insecure_software_rsa_key_transport_decryption_allowed(),
        ..XmlPolicy::default()
    }
}

struct Peers {
    sp: Saml<saml_rs::Sp>,
    idp: Saml<saml_rs::Idp>,
    sp_descriptor: SpDescriptor,
    idp_descriptor: IdpDescriptor,
}

fn peers(
    sp_algorithms: AlgorithmPolicy,
    idp_algorithms: AlgorithmPolicy,
    idp_signer: &Signer,
    xml: XmlPolicy,
) -> Result<Peers, SamlError> {
    let sp = SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
        .acs_endpoint(AcsEndpoint::post(SP_ACS_POST)?.mark_default())
        .credentials(credentials(&RSA_SIGNER))
        .validation(SpValidationPolicy {
            authn_requests: AuthnRequestSigningPolicy::Sign,
            ..SpValidationPolicy::recommended()
        })
        .algorithms(sp_algorithms)
        .xml(xml)
        .build()?;
    let idp = IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
        .sso_endpoint(SsoEndpoint::redirect(IDP_SSO_REDIRECT)?)
        .credentials(credentials(idp_signer))
        .validation(IdpValidationPolicy {
            authn_requests: AuthnRequestValidationPolicy::RequireSigned,
            ..IdpValidationPolicy::recommended()
        })
        .algorithms(idp_algorithms)
        .xml(xml)
        .build()?;
    let sp = Saml::sp(sp)?;
    let idp = Saml::idp(idp)?;
    let sp_descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    Ok(Peers {
        sp,
        idp,
        sp_descriptor,
        idp_descriptor,
    })
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility)
}

fn post_fields<Message>(outbound: &Outbound<Message>) -> Result<Vec<FormField>, SamlError> {
    Ok(outbound.post_form()?.fields().to_vec())
}

struct Exchange {
    redirect_sig_alg: String,
    authn_request_xml: String,
    response_xml: String,
    session: SsoSession,
}

fn signed_redirect_request_then_post_response(
    peers: &Peers,
) -> Result<Exchange, Box<dyn std::error::Error>> {
    let started = peers
        .sp
        .start_sso(&peers.idp_descriptor, StartSso::redirect())?;
    let url = Url::parse(started.outbound.redirect_url()?)?;
    let query = |name: &str| {
        url.query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
            .ok_or(format!("missing {name}"))
    };
    let redirect_sig_alg = query("SigAlg")?;
    let authn_request_xml =
        String::from_utf8(deflate_raw_decode(&base64_decode(&query("SAMLRequest")?)?)?)?;

    let received = peers.idp.receive_sso(
        &peers.sp_descriptor,
        BrowserInput::<AuthnRequest>::redirect(url.query().unwrap_or_default()),
        validation(),
    )?;
    let subject = Subject::new(NameId::new("alice@example.com", None), Vec::new());
    let response =
        peers
            .idp
            .respond_sso(&peers.sp_descriptor, &received, subject, RespondSso::post())?;
    let fields = post_fields(&response)?;
    let encoded = fields
        .iter()
        .find(|field| field.name() == "SAMLResponse")
        .map(FormField::value)
        .ok_or("missing SAMLResponse")?;
    let response_xml = String::from_utf8(base64_decode(encoded)?)?;

    let session = peers.sp.finish_sso(
        &peers.idp_descriptor,
        &started.pending,
        BrowserInput::<SsoResponse>::post(fields),
        validation(),
    )?;
    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(Exchange {
        redirect_sig_alg,
        authn_request_xml,
        response_xml,
        session,
    })
}

fn algorithm_attributes(xml: &str, element: &str) -> Vec<String> {
    let opening = format!(":{element} Algorithm=\"");
    xml.match_indices(&opening)
        .filter_map(|(start, _)| {
            let value = &xml[start + opening.len()..];
            value.split_once('"').map(|(uri, _)| uri.to_string())
        })
        .collect()
}

fn verified_algorithms(session: &SsoSession) -> Vec<&str> {
    session
        .verified_xml_signatures()
        .iter()
        .map(|signature| signature.algorithm_uri())
        .collect()
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn recommended_generation_uses_rsa_sha256_aes256_and_rsa_oaep(
) -> Result<(), Box<dyn std::error::Error>> {
    let peers = peers(
        AlgorithmPolicy::default(),
        AlgorithmPolicy::default(),
        &RSA_SIGNER,
        encrypted_assertions(),
    )?;
    let exchange = signed_redirect_request_then_post_response(&peers)?;

    assert_eq!(exchange.redirect_sig_alg, signature_algorithm::RSA_SHA256);
    assert!(!exchange.authn_request_xml.contains("<ds:Signature"));
    assert_eq!(
        algorithm_attributes(&exchange.response_xml, "SignatureMethod"),
        [signature_algorithm::RSA_SHA256]
    );
    assert_eq!(
        algorithm_attributes(&exchange.response_xml, "DigestMethod"),
        [digest_algorithm::SHA256]
    );
    assert_eq!(
        algorithm_attributes(&exchange.response_xml, "Transform"),
        [
            transform_algorithm::ENVELOPED_SIGNATURE,
            transform_algorithm::EXC_C14N
        ]
    );
    assert_eq!(
        algorithm_attributes(&exchange.response_xml, "EncryptionMethod"),
        [
            data_encryption_algorithm::AES_256,
            key_encryption_algorithm::RSA_OAEP_MGF1P
        ]
    );
    for legacy in [
        signature_algorithm::RSA_SHA1,
        signature_algorithm::DSA_SHA1,
        digest_algorithm::SHA1,
        data_encryption_algorithm::TRIPLE_DES,
        key_encryption_algorithm::RSA_1_5,
    ] {
        assert!(!exchange.response_xml.contains(legacy), "{legacy}");
    }
    assert_eq!(
        verified_algorithms(&exchange.session),
        [signature_algorithm::RSA_SHA256]
    );
    Ok(())
}

#[cfg(feature = "crypto-rustcrypto")]
#[test]
fn selected_rsa_sha1_signs_the_authn_request_and_the_response(
) -> Result<(), Box<dyn std::error::Error>> {
    let rsa_sha1 = || AlgorithmPolicy {
        signature: SignatureAlgorithm::RsaSha1,
        ..AlgorithmPolicy::default()
    };
    let peers = peers(rsa_sha1(), rsa_sha1(), &RSA_SIGNER, XmlPolicy::default())?;
    let exchange = signed_redirect_request_then_post_response(&peers)?;

    assert_eq!(exchange.redirect_sig_alg, signature_algorithm::RSA_SHA1);
    assert_eq!(
        algorithm_attributes(&exchange.response_xml, "SignatureMethod"),
        [signature_algorithm::RSA_SHA1]
    );
    assert_eq!(
        algorithm_attributes(&exchange.response_xml, "DigestMethod"),
        [digest_algorithm::SHA1]
    );
    assert_eq!(
        verified_algorithms(&exchange.session),
        [signature_algorithm::RSA_SHA1]
    );
    Ok(())
}

#[cfg(all(feature = "crypto-rustcrypto", feature = "crypto-legacy-algorithms"))]
#[test]
fn selected_dsa_sha1_signs_the_response() -> Result<(), Box<dyn std::error::Error>> {
    let peers = peers(
        AlgorithmPolicy::default(),
        AlgorithmPolicy {
            signature: SignatureAlgorithm::DsaSha1,
            ..AlgorithmPolicy::default()
        },
        &Signer {
            key: DSA_KEY,
            cert: DSA_CERT,
        },
        XmlPolicy::default(),
    )?;
    let exchange = signed_redirect_request_then_post_response(&peers)?;

    assert_eq!(
        algorithm_attributes(&exchange.response_xml, "SignatureMethod"),
        [signature_algorithm::DSA_SHA1]
    );
    assert_eq!(
        algorithm_attributes(&exchange.response_xml, "DigestMethod"),
        [digest_algorithm::SHA1]
    );
    assert_eq!(
        verified_algorithms(&exchange.session),
        [signature_algorithm::DSA_SHA1]
    );
    Ok(())
}

#[test]
fn selected_canonical_xml_transform_signs_the_response() -> Result<(), Box<dyn std::error::Error>> {
    let peers = peers(
        AlgorithmPolicy::default(),
        AlgorithmPolicy {
            signed_reference_transforms: vec![
                TransformAlgorithm::EnvelopedSignature,
                TransformAlgorithm::CanonicalXml,
            ],
            ..AlgorithmPolicy::default()
        },
        &RSA_SIGNER,
        XmlPolicy::default(),
    )?;
    let exchange = signed_redirect_request_then_post_response(&peers)?;

    assert_eq!(
        algorithm_attributes(&exchange.response_xml, "Transform"),
        [
            transform_algorithm::ENVELOPED_SIGNATURE,
            transform_algorithm::C14N
        ]
    );
    assert_eq!(
        verified_algorithms(&exchange.session),
        [signature_algorithm::RSA_SHA256]
    );
    Ok(())
}

#[cfg(all(feature = "crypto-rustcrypto", feature = "crypto-legacy-algorithms"))]
#[test]
fn selected_block_encryption_and_key_transport_round_trip() -> Result<(), Box<dyn std::error::Error>>
{
    for data_encryption in [
        DataEncryptionAlgorithm::TripleDesForCompatibility,
        DataEncryptionAlgorithm::Aes128,
        DataEncryptionAlgorithm::Aes256,
    ] {
        for key_encryption in [
            KeyEncryptionAlgorithm::Rsa15ForCompatibility,
            KeyEncryptionAlgorithm::RsaOaepMgf1p,
        ] {
            let expected = [
                data_encryption.as_uri().to_string(),
                key_encryption.as_uri().to_string(),
            ];
            let peers = peers(
                AlgorithmPolicy::default(),
                AlgorithmPolicy {
                    data_encryption: data_encryption.clone(),
                    key_encryption: key_encryption.clone(),
                    ..AlgorithmPolicy::default()
                },
                &RSA_SIGNER,
                encrypted_assertions(),
            )?;
            let exchange = signed_redirect_request_then_post_response(&peers)?;

            assert_eq!(
                algorithm_attributes(&exchange.response_xml, "EncryptionMethod"),
                expected
            );
        }
    }
    Ok(())
}
