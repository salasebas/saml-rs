#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use std::time::SystemTime;

use saml_rs::binding::base64_decode;
use saml_rs::constants::{signature_algorithm, transform_algorithm};
#[cfg(feature = "crypto-rustcrypto")]
use saml_rs::error::SignatureVerificationReason;
#[cfg(not(feature = "crypto-fips"))]
use saml_rs::XmlEncryptionPolicy;
use saml_rs::{
    AcsEndpoint, AlgorithmPolicy, AuthnRequest, AuthnRequestSigningPolicy,
    AuthnRequestValidationPolicy, BrowserInput, CertificatePem, Credentials, EntityId, FormField,
    IdpConfig, IdpDescriptor, IdpValidationPolicy, LogoutRequest, LogoutSubject,
    MetadataTrustPolicy, NameId, Outbound, PrivateKeyPem, ReplayPolicy, RespondSso, Saml,
    SamlError, SamlValidationContext, SessionIndex, SloEndpoint, SpConfig, SpDescriptor,
    SpValidationPolicy, SsoEndpoint, SsoResponse, SsoSession, StartSlo, StartSso, Subject,
    TransformAlgorithm, XmlPolicy,
};
#[cfg(all(feature = "crypto-rustcrypto", feature = "crypto-legacy-algorithms"))]
use saml_rs::{DataEncryptionAlgorithm, KeyEncryptionAlgorithm};
#[cfg(feature = "crypto-rustcrypto")]
use saml_rs::{HmacSecret, SignatureAlgorithm};
use url::Url;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS_POST: &str = "https://sp.example.com/acs/post";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const IDP_SSO_REDIRECT: &str = "https://idp.example.com/sso/redirect";
const SP_SLO_REDIRECT: &str = "https://sp.example.com/slo/redirect";
const IDP_SLO_REDIRECT: &str = "https://idp.example.com/slo/redirect";
const SP_SLO_SOAP: &str = "https://sp.example.com/slo/soap";
const IDP_SLO_SOAP: &str = "https://idp.example.com/slo/soap";

const RSA_KEY: &str = include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
const RSA_CERT: &str = include_str!("fixtures/key/sp/cert.unencrypted.pkcs8.cer");
#[cfg(all(feature = "crypto-rustcrypto", feature = "crypto-legacy-algorithms"))]
const DSA_KEY: &str = include_str!("fixtures/key/dsa/privkey.pkcs8.pem");
#[cfg(all(feature = "crypto-rustcrypto", feature = "crypto-legacy-algorithms"))]
const DSA_CERT: &str = include_str!("fixtures/key/dsa/cert.pem");

struct Side {
    algorithms: AlgorithmPolicy,
    credentials: Credentials,
}

fn signed_with(algorithms: AlgorithmPolicy, key: &str, cert: &str) -> Side {
    Side {
        algorithms,
        credentials: Credentials {
            signing_key: Some(PrivateKeyPem::new(key)),
            signing_certificate: Some(CertificatePem::new(cert)),
            encryption_certificate: Some(CertificatePem::new(RSA_CERT)),
            decryption_key: Some(PrivateKeyPem::new(RSA_KEY)),
            ..Credentials::default()
        },
    }
}

fn rsa(algorithms: AlgorithmPolicy) -> Side {
    signed_with(algorithms, RSA_KEY, RSA_CERT)
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

fn peers(sp: Side, idp: Side, xml: XmlPolicy) -> Result<Peers, SamlError> {
    let sp = SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
        .acs_endpoint(AcsEndpoint::post(SP_ACS_POST)?.mark_default())
        .slo_endpoint(SloEndpoint::redirect(SP_SLO_REDIRECT)?)
        .slo_endpoint(SloEndpoint::soap(SP_SLO_SOAP)?)
        .credentials(sp.credentials)
        .validation(SpValidationPolicy {
            authn_requests: AuthnRequestSigningPolicy::Sign,
            ..SpValidationPolicy::recommended()
        })
        .algorithms(sp.algorithms)
        .xml(xml)
        .build()?;
    let idp = IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
        .sso_endpoint(SsoEndpoint::redirect(IDP_SSO_REDIRECT)?)
        .slo_endpoint(SloEndpoint::redirect(IDP_SLO_REDIRECT)?)
        .slo_endpoint(SloEndpoint::soap(IDP_SLO_SOAP)?)
        .credentials(idp.credentials)
        .validation(IdpValidationPolicy {
            authn_requests: AuthnRequestValidationPolicy::RequireSigned,
            ..IdpValidationPolicy::recommended()
        })
        .algorithms(idp.algorithms)
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
        rsa(AlgorithmPolicy::default()),
        rsa(AlgorithmPolicy::default()),
        encrypted_assertions(),
    )?;
    let exchange = signed_redirect_request_then_post_response(&peers)?;

    assert_eq!(exchange.redirect_sig_alg, signature_algorithm::RSA_SHA256);
    assert_eq!(
        algorithm_attributes(&exchange.response_xml, "SignatureMethod"),
        [signature_algorithm::RSA_SHA256]
    );
    assert_eq!(
        algorithm_attributes(&exchange.response_xml, "DigestMethod"),
        [saml_rs::constants::digest_algorithm::SHA256]
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
            saml_rs::constants::data_encryption_algorithm::AES_256,
            saml_rs::constants::key_encryption_algorithm::RSA_OAEP_MGF1P
        ]
    );
    for legacy in [
        signature_algorithm::RSA_SHA1,
        signature_algorithm::DSA_SHA1,
        saml_rs::constants::digest_algorithm::SHA1,
        saml_rs::constants::data_encryption_algorithm::TRIPLE_DES,
        saml_rs::constants::key_encryption_algorithm::RSA_1_5,
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
    let peers = peers(rsa(rsa_sha1()), rsa(rsa_sha1()), XmlPolicy::default())?;
    let exchange = signed_redirect_request_then_post_response(&peers)?;

    assert_eq!(exchange.redirect_sig_alg, signature_algorithm::RSA_SHA1);
    assert_eq!(
        algorithm_attributes(&exchange.response_xml, "SignatureMethod"),
        [signature_algorithm::RSA_SHA1]
    );
    assert_eq!(
        algorithm_attributes(&exchange.response_xml, "DigestMethod"),
        [saml_rs::constants::digest_algorithm::SHA1]
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
        rsa(AlgorithmPolicy::default()),
        signed_with(
            AlgorithmPolicy {
                signature: SignatureAlgorithm::DsaSha1,
                ..AlgorithmPolicy::default()
            },
            DSA_KEY,
            DSA_CERT,
        ),
        XmlPolicy::default(),
    )?;
    let exchange = signed_redirect_request_then_post_response(&peers)?;

    assert_eq!(
        algorithm_attributes(&exchange.response_xml, "SignatureMethod"),
        [signature_algorithm::DSA_SHA1]
    );
    assert_eq!(
        algorithm_attributes(&exchange.response_xml, "DigestMethod"),
        [saml_rs::constants::digest_algorithm::SHA1]
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
        rsa(AlgorithmPolicy::default()),
        rsa(AlgorithmPolicy {
            signed_reference_transforms: vec![
                TransformAlgorithm::EnvelopedSignature,
                TransformAlgorithm::CanonicalXml,
            ],
            ..AlgorithmPolicy::default()
        }),
        XmlPolicy::default(),
    )?;
    let exchange = signed_redirect_request_then_post_response(&peers)?;

    assert_eq!(exchange.redirect_sig_alg, signature_algorithm::RSA_SHA256);

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

    let started = peers.idp.start_slo(
        &peers.sp_descriptor,
        LogoutSubject::with_session_index(
            NameId::new("alice@example.com", None),
            SessionIndex::try_new("_session")?,
        ),
        StartSlo::soap(),
    )?;
    let envelope = started.outbound.soap_request()?.envelope();
    assert_eq!(
        algorithm_attributes(envelope, "Transform"),
        [
            transform_algorithm::ENVELOPED_SIGNATURE,
            transform_algorithm::EXC_C14N
        ]
    );
    peers.sp.receive_slo(
        &peers.idp_descriptor,
        BrowserInput::<LogoutRequest>::soap(envelope),
        validation(),
    )?;
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
                rsa(AlgorithmPolicy::default()),
                rsa(AlgorithmPolicy {
                    data_encryption: data_encryption.clone(),
                    key_encryption: key_encryption.clone(),
                    ..AlgorithmPolicy::default()
                }),
                XmlPolicy {
                    encryption: encrypted_assertions()
                        .encryption
                        .with_rsa15_key_transport_decryption_allowed(),
                    ..XmlPolicy::default()
                },
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

#[cfg(all(feature = "crypto-rustcrypto", feature = "crypto-legacy-algorithms"))]
#[test]
fn rsa15_key_transport_is_decrypted_only_when_selected() -> Result<(), Box<dyn std::error::Error>> {
    let rsa15 = AlgorithmPolicy {
        key_encryption: KeyEncryptionAlgorithm::Rsa15ForCompatibility,
        ..AlgorithmPolicy::default()
    };
    for encryption in [
        XmlEncryptionPolicy::encrypt_assertions(),
        XmlEncryptionPolicy::encrypt_ids(),
    ] {
        let encryption = encryption.with_insecure_software_rsa_key_transport_decryption_allowed();
        let default = peers(
            rsa(AlgorithmPolicy::default()),
            rsa(rsa15.clone()),
            XmlPolicy {
                encryption,
                ..XmlPolicy::default()
            },
        )?;
        let refused = signed_redirect_request_then_post_response(&default)
            .err()
            .ok_or("RSA-v1.5 accepted without the opt-in")?;
        assert!(
            matches!(
                refused.downcast_ref::<SamlError>(),
                Some(SamlError::Unsupported(message)) if message.contains("rsa-1_5")
            ),
            "{refused:?}"
        );

        let selected = peers(
            rsa(AlgorithmPolicy::default()),
            rsa(rsa15.clone()),
            XmlPolicy {
                encryption: encryption.with_rsa15_key_transport_decryption_allowed(),
                ..XmlPolicy::default()
            },
        )?;
        let exchange = signed_redirect_request_then_post_response(&selected)?;
        assert!(exchange
            .response_xml
            .contains(saml_rs::constants::key_encryption_algorithm::RSA_1_5));
    }
    Ok(())
}

#[cfg(feature = "crypto-rustcrypto")]
const SP_HMAC_SECRET: &[u8] = b"service-provider-hmac-sha1-secret";
#[cfg(feature = "crypto-rustcrypto")]
const IDP_HMAC_SECRET: &[u8] = b"identity-provider-hmac-sha1-secret";

#[cfg(feature = "crypto-rustcrypto")]
fn hmac_sha1(secret: &[u8]) -> Result<Side, SamlError> {
    Ok(Side {
        algorithms: AlgorithmPolicy {
            signature: SignatureAlgorithm::HmacSha1,
            ..AlgorithmPolicy::default()
        },
        credentials: Credentials {
            hmac_secret: Some(HmacSecret::try_new(secret)?),
            ..Credentials::default()
        },
    })
}

#[cfg(feature = "crypto-rustcrypto")]
fn hmac_sha1_peers(
    sp_secret_at_idp: Option<&[u8]>,
    idp_secret_at_sp: Option<&[u8]>,
) -> Result<Peers, SamlError> {
    let mut peers = peers(
        hmac_sha1(SP_HMAC_SECRET)?,
        hmac_sha1(IDP_HMAC_SECRET)?,
        XmlPolicy::default(),
    )?;
    if let Some(secret) = sp_secret_at_idp {
        peers.sp_descriptor = peers
            .sp_descriptor
            .with_hmac_secret(HmacSecret::try_new(secret)?);
    }
    if let Some(secret) = idp_secret_at_sp {
        peers.idp_descriptor = peers
            .idp_descriptor
            .with_hmac_secret(HmacSecret::try_new(secret)?);
    }
    Ok(peers)
}

#[cfg(feature = "crypto-rustcrypto")]
#[test]
fn selected_hmac_sha1_signs_with_the_shared_secrets() -> Result<(), Box<dyn std::error::Error>> {
    let peers = hmac_sha1_peers(Some(SP_HMAC_SECRET), Some(IDP_HMAC_SECRET))?;
    let exchange = signed_redirect_request_then_post_response(&peers)?;

    assert_eq!(exchange.redirect_sig_alg, signature_algorithm::HMAC_SHA1);
    assert_eq!(
        algorithm_attributes(&exchange.response_xml, "SignatureMethod"),
        [signature_algorithm::HMAC_SHA1]
    );
    assert_eq!(
        algorithm_attributes(&exchange.response_xml, "DigestMethod"),
        [saml_rs::constants::digest_algorithm::SHA1]
    );
    assert!(!exchange.response_xml.contains("KeyInfo"));
    assert_eq!(
        verified_algorithms(&exchange.session),
        [signature_algorithm::HMAC_SHA1]
    );

    let started = peers.sp.start_slo(
        &peers.idp_descriptor,
        LogoutSubject::with_session_index(
            NameId::new("alice@example.com", None),
            SessionIndex::try_new("_session")?,
        ),
        StartSlo::redirect(),
    )?;
    let url = Url::parse(started.outbound.redirect_url()?)?;
    let received = peers.idp.receive_slo(
        &peers.sp_descriptor,
        BrowserInput::<LogoutRequest>::redirect(url.query().unwrap_or_default()),
        validation(),
    )?;
    assert_eq!(received.message().issuer().as_str(), SP_ENTITY_ID);
    assert!(url
        .query_pairs()
        .any(|(key, value)| key == "SigAlg" && value == signature_algorithm::HMAC_SHA1));

    let started = peers.sp.start_slo(
        &peers.idp_descriptor,
        LogoutSubject::with_session_index(
            NameId::new("alice@example.com", None),
            SessionIndex::try_new("_session")?,
        ),
        StartSlo::soap(),
    )?;
    let envelope = started.outbound.soap_request()?.envelope();
    assert_eq!(
        algorithm_attributes(envelope, "SignatureMethod"),
        [signature_algorithm::HMAC_SHA1]
    );
    peers.idp.receive_slo(
        &peers.sp_descriptor,
        BrowserInput::<LogoutRequest>::soap(envelope),
        validation(),
    )?;
    Ok(())
}

#[cfg(feature = "crypto-rustcrypto")]
#[test]
fn hmac_sha1_signature_needs_the_signers_secret() -> Result<(), Box<dyn std::error::Error>> {
    let detached = || SamlError::SignatureVerification {
        reason: SignatureVerificationReason::DetachedMessageSignature,
    };
    let cases = [
        (None, Some(IDP_HMAC_SECRET), detached()),
        (Some(IDP_HMAC_SECRET), Some(IDP_HMAC_SECRET), detached()),
        (Some(SP_HMAC_SECRET), None, SamlError::NoTrustedCertificate),
        (
            Some(SP_HMAC_SECRET),
            Some(SP_HMAC_SECRET),
            SamlError::SignatureVerification {
                reason: SignatureVerificationReason::XmlSignature,
            },
        ),
    ];
    for (sp_secret_at_idp, idp_secret_at_sp, expected) in cases {
        let peers = hmac_sha1_peers(sp_secret_at_idp, idp_secret_at_sp)?;
        let error = match signed_redirect_request_then_post_response(&peers) {
            Ok(_) => return Err("verified without the signer's secret".into()),
            Err(error) => error,
        };
        assert_eq!(
            error.downcast_ref::<SamlError>().map(ToString::to_string),
            Some(expected.to_string())
        );
    }
    Ok(())
}
