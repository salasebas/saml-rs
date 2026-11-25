use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use saml_rs::binding::{deflate_raw_decode, deflate_raw_encode, MAX_DEFLATE_RAW_DECODE_BYTES};
use saml_rs::constants::{signature_algorithm::RSA_SHA256, Binding, CertUse};
use saml_rs::entity::{iso8601_offset, EntitySetting};
use saml_rs::idp;
use saml_rs::metadata::{
    generate_sp_metadata, Endpoint, IdpMetadata, IdpMetadataInput, SpMetadata, SpMetadataInput,
};
use saml_rs::util::normalize_cert_string;
use saml_rs::validator::TimeWindow;
use saml_rs::ClockSkew;
use time::OffsetDateTime;

const SP_CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.cer");
const SP_KNOWN_CERT: &str = include_str!("../../tests/fixtures/key/sp/knownGoodCert.cer");
const IDPMETA: &str = include_str!("../../tests/fixtures/misc/idpmeta.xml");
const IDPMETA_ROLLING: &str = include_str!("../../tests/fixtures/misc/idpmeta_rollingcert.xml");
const IDPMETA_SHARE: &str = include_str!("../../tests/fixtures/misc/idpmeta_share_cert.xml");
const SPMETA: &str = include_str!("../../tests/fixtures/misc/spmeta.xml");
const MULTI_ENTITY: &str = include_str!("../../tests/fixtures/misc/multiple_entitydescriptor.xml");
const IDP_CERT: &str = include_str!("../../tests/fixtures/key/idp/cert.cer");
const IDP_CERT2: &str = include_str!("../../tests/fixtures/key/idp/cert2.cer");
const IDP_ENC_CERT: &str = include_str!("../../tests/fixtures/key/idp/encryptionCert.cer");

#[test]
fn deflate_plus_base64_encoded() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        STANDARD.encode(&deflate_raw_encode(b"Hello World")?),
        "80jNyclXCM8vykkBAA=="
    );
    Ok(())
}

#[test]
fn base64_decoded_plus_inflate() -> Result<(), Box<dyn std::error::Error>> {
    let inflated = deflate_raw_decode(
        &STANDARD.decode("80jNyclXCM8vykkBAA==")?,
        MAX_DEFLATE_RAW_DECODE_BYTES,
    )?;
    assert_eq!(String::from_utf8(inflated)?, "Hello World");
    Ok(())
}

#[test]
fn parse_cer_format_resulting_clean_certificate() {
    assert_eq!(normalize_cert_string(SP_CERT), SP_KNOWN_CERT.trim());
}

#[test]
fn get_acs_with_one_binding() -> Result<(), Box<dyn std::error::Error>> {
    let loc = "https:sp.example.org/sp/sso/post";
    let sp = SpMetadata::from_xml(&generate_sp_metadata(&SpMetadataInput {
        entity_id: "https://sp".into(),
        assertion_consumer_services: vec![Endpoint::new(Binding::Post, loc)],
        single_logout_services: vec![Endpoint::new(
            Binding::Redirect,
            "https:sp.example.org/sp/slo",
        )],
        ..Default::default()
    })?)?;
    assert_eq!(
        sp.assertion_consumer_location(Binding::Post).as_deref(),
        Some(loc)
    );
    Ok(())
}

#[test]
fn get_acs_with_two_bindings() -> Result<(), Box<dyn std::error::Error>> {
    let post = "https:sp.example.org/sp/sso/post";
    let artifact = "https:sp.example.org/sp/sso/artifact";
    let sp = SpMetadata::from_xml(&generate_sp_metadata(&SpMetadataInput {
        entity_id: "https://sp".into(),
        assertion_consumer_services: vec![
            Endpoint::new(Binding::Post, post),
            Endpoint::new(Binding::Artifact, artifact),
        ],
        ..Default::default()
    })?)?;
    assert_eq!(
        sp.assertion_consumer_location(Binding::Post).as_deref(),
        Some(post)
    );
    assert_eq!(
        sp.assertion_consumer_location(Binding::Artifact).as_deref(),
        Some(artifact)
    );
    Ok(())
}

#[test]
fn idp_with_multiple_signing_and_encryption_certificates() -> Result<(), Box<dyn std::error::Error>>
{
    let idp = idp::Engine::from_config(
        &IdpMetadataInput {
            entity_id: "https://idp".into(),
            signing_certs: vec![IDP_CERT.into(), IDP_CERT2.into()],
            encrypt_certs: vec![IDP_ENC_CERT.into(), IDP_ENC_CERT.into()],
            single_sign_on_services: vec![Endpoint::new(
                Binding::Post,
                "https://idp.example.com/sso",
            )],
            ..Default::default()
        },
        EntitySetting::default(),
    )?;
    assert_eq!(
        idp.metadata
            .as_metadata()
            .x509_certificates(CertUse::Signing)
            .len(),
        2
    );
    assert_eq!(
        idp.metadata
            .as_metadata()
            .x509_certificates(CertUse::Encryption)
            .len(),
        2
    );
    Ok(())
}

fn window<'a>(not_before: Option<&'a str>, not_on_or_after: Option<&'a str>) -> TimeWindow<'a> {
    TimeWindow {
        not_before,
        not_on_or_after,
    }
}

#[test]
fn time_window_with_and_without_drift_tolerance() {
    let before10 = iso8601_offset(-600);
    let before5 = iso8601_offset(-300);
    let after5 = iso8601_offset(300);
    let after10 = iso8601_offset(600);
    let now = OffsetDateTime::now_utc();

    let strict = ClockSkew::strict();
    assert!(window(Some(&before5), Some(&after5)).contains(now, strict));
    assert!(window(Some(&before5), None).contains(now, strict));
    assert!(window(None, Some(&after5)).contains(now, strict));
    assert!(!window(None, Some(&before5)).contains(now, strict));
    assert!(!window(Some(&after5), None).contains(now, strict));
    assert!(!window(Some(&before10), Some(&before5)).contains(now, strict));
    assert!(!window(Some(&after5), Some(&after10)).contains(now, strict));
    assert!(window(None, None).contains(now, strict));

    let d = ClockSkew::from_millis(-301_000, 301_000);
    assert!(window(Some(&before5), Some(&after5)).contains(now, d));
    assert!(window(Some(&before5), None).contains(now, d));
    assert!(window(None, Some(&after5)).contains(now, d));
    assert!(window(None, Some(&before5)).contains(now, d));
    assert!(window(Some(&after5), None).contains(now, d));
    assert!(window(Some(&before10), Some(&before5)).contains(now, d));
    assert!(window(Some(&after5), Some(&after10)).contains(now, d));
    assert!(window(None, None).contains(now, d));
}

#[test]
fn metadata_with_multiple_entity_descriptors_is_invalid() {
    assert!(IdpMetadata::from_xml(MULTI_ENTITY).is_err());
}

#[test]
fn undefined_x509_key_in_metadata_returns_none() -> Result<(), Box<dyn std::error::Error>> {
    let sp = SpMetadata::from_xml(&generate_sp_metadata(&SpMetadataInput {
        entity_id: "https://sp".into(),
        assertion_consumer_services: vec![Endpoint::new(Binding::Post, "http://sp/acs")],
        ..Default::default()
    })?)?;
    assert!(sp
        .as_metadata()
        .x509_certificates(CertUse::Signing)
        .is_empty());
    assert!(sp
        .as_metadata()
        .x509_certificates(CertUse::Encryption)
        .is_empty());
    Ok(())
}

#[test]
fn list_of_x509_keys_when_multiple_keys_used() -> Result<(), Box<dyn std::error::Error>> {
    let idp = IdpMetadata::from_xml(IDPMETA_ROLLING)?;
    assert_eq!(
        idp.as_metadata().x509_certificates(CertUse::Signing).len(),
        2
    );
    assert_eq!(
        idp.as_metadata()
            .x509_certificates(CertUse::Encryption)
            .len(),
        1
    );
    Ok(())
}

#[test]
fn get_name_id_format_in_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let sp = SpMetadata::from_xml(SPMETA)?;
    let idp = IdpMetadata::from_xml(IDPMETA)?;
    assert!(sp
        .as_metadata()
        .name_id_formats()
        .contains(&saml_rs::NameIdFormat::EmailAddress));
    assert!(!idp.as_metadata().name_id_formats().is_empty());
    Ok(())
}

#[test]
fn get_entity_setting() -> Result<(), Box<dyn std::error::Error>> {
    let idp = IdpMetadata::from_xml(IDPMETA)?;
    let sp = SpMetadata::from_xml(SPMETA)?;
    assert!(idp.as_metadata().entity_id().is_some());
    assert_eq!(
        EntitySetting::default().request_signature_algorithm,
        RSA_SHA256
    );
    assert!(sp.as_metadata().entity_id().is_some());
    Ok(())
}

#[test]
fn shared_certificate_for_signing_and_encryption() -> Result<(), Box<dyn std::error::Error>> {
    let m = IdpMetadata::from_xml(IDPMETA_SHARE)?;
    let signing = m.as_metadata().x509_certificates(CertUse::Signing).first();
    let encryption = m
        .as_metadata()
        .x509_certificates(CertUse::Encryption)
        .first();
    assert!(signing.is_some() && encryption.is_some());
    assert_eq!(signing, encryption);
    Ok(())
}

#[test]
fn explicit_certificate_declaration_for_signing_and_encryption(
) -> Result<(), Box<dyn std::error::Error>> {
    let m = IdpMetadata::from_xml(IDPMETA)?;
    let signing = m.as_metadata().x509_certificates(CertUse::Signing).first();
    let encryption = m
        .as_metadata()
        .x509_certificates(CertUse::Encryption)
        .first();
    assert!(signing.is_some() && encryption.is_some());
    assert_ne!(signing, encryption);
    Ok(())
}

#[cfg(crypto)]
mod crypto {
    use super::*;
    use saml_rs::constants::data_encryption_algorithm::AES_256;
    use saml_rs::constants::key_encryption_algorithm::RSA_OAEP_MGF1P;
    #[cfg(feature = "crypto-rustcrypto")]
    use saml_rs::constants::signature_algorithm::RSA_SHA1;
    use saml_rs::constants::signature_algorithm::RSA_SHA512;
    use saml_rs::crypto::keys::read_private_key;
    use saml_rs::crypto::{
        encrypt_assertion, sign_octet_string, sign_saml_xml, verify_octet_string_signature,
        verify_signature,
    };
    use saml_rs::SamlError;

    const SP_PRIVKEY: &str =
        include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
    const SIGN_CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");
    const REQUEST: &str = include_str!("../../tests/fixtures/misc/request.xml");
    #[cfg(not(feature = "crypto-fips"))]
    const RESPONSE_SIGNED: &str = include_str!("../../tests/fixtures/misc/response_signed.xml");
    #[cfg(feature = "crypto-rustcrypto")]
    const SIGNED_SHA1: &str = include_str!("../../tests/fixtures/misc/signed_request_sha1.xml");
    const SIGNED_SHA256: &str = include_str!("../../tests/fixtures/misc/signed_request_sha256.xml");
    const SIGNED_SHA512: &str = include_str!("../../tests/fixtures/misc/signed_request_sha512.xml");
    #[cfg(feature = "crypto-rustcrypto")]
    const FALSE_SHA1: &str =
        include_str!("../../tests/fixtures/misc/false_signed_request_sha1.xml");
    const FALSE_SHA256: &str =
        include_str!("../../tests/fixtures/misc/false_signed_request_sha256.xml");
    const FALSE_SHA512: &str =
        include_str!("../../tests/fixtures/misc/false_signed_request_sha512.xml");
    const INVALID_RESPONSE: &str = include_str!("../../tests/fixtures/misc/invalid_response.xml");

    #[cfg(feature = "crypto-rustcrypto")]
    const OCTET_SHA1: &str = "SAMLRequest=fVNdj9MwEHxH4j9Yfm/i5PpBrLaotEJUOrioKTzwgoy9oZZiO9ibu/LvcXLtKUhHnyzZM7Mzu+tlEKZp+abDkz3A7w4CkrNpbODDw4p23nIngg7cCgOBo+TV5vM9zxPGW+/QSdfQEeU2Q4QAHrWzlOx3K/rjHSsWbFEzdsfETDE2z5ksVKHqYlHP84WooVBS5lNKvoEPkbeiUYaS0rtHrcB/iRVWtCoJRuNRM4QO9jagsBiRLJtO2GKSzY/5HZ/lfDr7TskuIrUVOIidEFueplq1CZyFaRtIpDNpVT1U4B+1hKQ9tUO5IegHbZW2v25n/PkMCvzT8VhOyofqSMnmmnvrbOgM+Iv818P9i4nwrwcFxmVp1IJzb+K9kIGu374hZNm3mQ9R/fp1rgEUSqBYpmPsC7nlfd/2u9I1Wv4hH503Av8fKkuy4UarST1AORihm41SHkKI4ZrGPW09CIyzQN8BTce1LmsFaliy2ACEM5KtM63wOvRTiNYlPoe7xhtjt01cmwPU65ubJbnscfG6jMeT8+qS/lWpwV96w2BEXN/Hn2P9Fw==&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1";
    const OCTET_SHA256: &str = "SAMLRequest=fZJbTwIxEIX/yqbvy3Yv3BogQYiRBIWw6INvY3eAJt0WO10v/966YIKJkPRpek7nfDMdEdT6IKaN35s1vjVIPvqstSHRXoxZ44ywQIqEgRpJeCnK6f1SZB0uDs56K61mZ5brDiBC55U1LFrMx2wrB8P+IB/GeQHbuOgVwxigB3EqewXfDjDPZJ9Fz+goWMYsvBB8RA0uDHkwPpR42o1THvNswzMRTtHtpEX2wqJ5QFEGfOvce38QSaKtBL235EXOeZoQ2aRUZqexVDvzaEp070pikveG3W5otTrx3ShTBdl1tNejiMTdZrOKV4/lhkXTX9yZNdTU6E4dntbLfzIVnGdtJpDEJqOfaYqW1k0ua2v0UIGHUXKuHx3X+hBSLuYrq5X8im6tq8Ffhkg7aVtRVbxtpQJrUHpaVQ6JAozW9mPmEDyGzYEmZMnk2PbvB5p8Aw==&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256";
    const OCTET_SHA512: &str = "SAMLRequest=fZJfT8IwFMW/ytL3sY5tCA0jQYiRBIWw6INvY3eAJt0WO10v/966YIKJkPRpek7nfDMdEdT6IKaN35s1vjVIPvqstSHRXoxZ44ywQIqEgRpJeCnK6f1SZB0uDs56K61mZ5brDiBC55U1LFrMx2wrB8P+IB/GeQHbuOgVwxigB3EqewXfDjDPZJ9Fz+goWMYsvBB8RA0uDHkwPpR42o1THvNswzMRTtHtpEX2wqJ5QFEGfOvce38QSaKtBL235EXOeZoQ2aRUZqexVDvzaEp070pikveG3W5otTrx3ShTBdl1tNejiMTdZrOKV4/lhkXTX9yZNdTU6E4dntbLfzIVnGdtJpDEJqOfaYqW1k0ua2v0UIGHUXKuHx3X+hBSLuYrq5X8im6tq8Ffhkg7aVtRVbxtpQJrUHpaVQ6JAozW9mPmEDyGzYEmZMnk2PbvB5p8Aw==&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha512";

    fn sp_signing() -> Result<Vec<String>, SamlError> {
        let metadata = SpMetadata::from_xml(SPMETA)?;
        Ok(metadata
            .as_metadata()
            .x509_certificates(CertUse::Signing)
            .to_vec())
    }
    #[cfg(feature = "crypto-rustcrypto")]
    fn idp_signing() -> Result<Vec<String>, SamlError> {
        let metadata = IdpMetadata::from_xml(IDPMETA)?;
        Ok(metadata
            .as_metadata()
            .x509_certificates(CertUse::Signing)
            .to_vec())
    }
    fn assert_content_not_covered(
        result: Result<(bool, Option<String>), SamlError>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match result {
            Err(SamlError::SignedReferenceMismatch) => Ok(()),
            other => {
                Err(format!("expected uncovered signed content rejection, got {other:?}").into())
            }
        }
    }

    fn sign_and_verify(octet: &str, alg: &str) -> Result<(), Box<dyn std::error::Error>> {
        let key = read_private_key(SP_PRIVKEY, None)?;
        let sig = sign_octet_string(octet, &key, alg)?;
        assert!(verify_octet_string_signature(octet, &sig, SIGN_CERT, alg)?);
        Ok(())
    }
    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn sign_message_rsa_sha1() -> Result<(), Box<dyn std::error::Error>> {
        sign_and_verify(OCTET_SHA1, RSA_SHA1)
    }
    #[test]
    fn sign_message_rsa_sha256() -> Result<(), Box<dyn std::error::Error>> {
        sign_and_verify(OCTET_SHA256, RSA_SHA256)
    }
    #[test]
    fn sign_message_rsa_sha512() -> Result<(), Box<dyn std::error::Error>> {
        sign_and_verify(OCTET_SHA512, RSA_SHA512)
    }

    fn construct_and_verify(alg: &str) -> Result<(), Box<dyn std::error::Error>> {
        let key = read_private_key(SP_PRIVKEY, None)?;
        let signed = sign_saml_xml(REQUEST, true, &key, SIGN_CERT, alg, &[], None)?;
        assert!(verify_signature(&signed, &[SIGN_CERT.to_string()])?.0);
        Ok(())
    }
    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn construct_signature_rsa_sha1() -> Result<(), Box<dyn std::error::Error>> {
        construct_and_verify(RSA_SHA1)
    }
    #[test]
    fn construct_signature_rsa_sha256() -> Result<(), Box<dyn std::error::Error>> {
        construct_and_verify(RSA_SHA256)
    }
    #[test]
    fn construct_signature_rsa_sha512() -> Result<(), Box<dyn std::error::Error>> {
        construct_and_verify(RSA_SHA512)
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn verify_xml_signature_sha1_with_metadata() -> Result<(), Box<dyn std::error::Error>> {
        assert!(verify_signature(RESPONSE_SIGNED, &idp_signing()?)?.0);
        Ok(())
    }
    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn integrity_check_request_sha1() -> Result<(), Box<dyn std::error::Error>> {
        assert!(!verify_signature(FALSE_SHA1, &sp_signing()?)?.0);
        Ok(())
    }
    #[test]
    fn reject_issuer_only_request_sha256_with_metadata() -> Result<(), Box<dyn std::error::Error>> {
        assert_content_not_covered(verify_signature(SIGNED_SHA256, &sp_signing()?))
    }
    #[test]
    fn integrity_check_request_sha256() -> Result<(), Box<dyn std::error::Error>> {
        assert!(!verify_signature(FALSE_SHA256, &sp_signing()?)?.0);
        Ok(())
    }
    #[test]
    fn reject_issuer_only_request_sha512_with_metadata() -> Result<(), Box<dyn std::error::Error>> {
        assert_content_not_covered(verify_signature(SIGNED_SHA512, &sp_signing()?))
    }
    #[test]
    fn integrity_check_request_sha512() -> Result<(), Box<dyn std::error::Error>> {
        assert!(!verify_signature(FALSE_SHA512, &sp_signing()?)?.0);
        Ok(())
    }

    #[test]
    fn verify_xml_signature_with_rolling_certificate() -> Result<(), Box<dyn std::error::Error>> {
        let key = read_private_key(SP_PRIVKEY, None)?;
        let signed = sign_saml_xml(REQUEST, true, &key, SIGN_CERT, RSA_SHA256, &[], None)?;
        let certs = vec![IDP_CERT.to_string(), SIGN_CERT.to_string()];
        assert!(verify_signature(&signed, &certs)?.0);
        Ok(())
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn reject_issuer_only_request_sha1_with_cert() -> Result<(), Box<dyn std::error::Error>> {
        assert_content_not_covered(verify_signature(SIGNED_SHA1, &[SP_CERT.to_string()]))
    }
    #[test]
    fn reject_issuer_only_request_sha256_with_cert() -> Result<(), Box<dyn std::error::Error>> {
        assert_content_not_covered(verify_signature(SIGNED_SHA256, &[SP_CERT.to_string()]))
    }
    #[test]
    fn reject_issuer_only_request_sha512_with_cert() -> Result<(), Box<dyn std::error::Error>> {
        assert_content_not_covered(verify_signature(SIGNED_SHA512, &[SP_CERT.to_string()]))
    }

    #[cfg(not(feature = "crypto-fips"))]
    #[test]
    fn encrypt_assertion_passes() -> Result<(), Box<dyn std::error::Error>> {
        encrypt_assertion(RESPONSE_SIGNED, SP_CERT, AES_256, RSA_OAEP_MGF1P, "saml")?;
        Ok(())
    }
    #[test]
    fn encrypt_assertion_without_assertion_errors() {
        assert!(
            encrypt_assertion(INVALID_RESPONSE, SP_CERT, AES_256, RSA_OAEP_MGF1P, "saml").is_err()
        );
    }
    #[test]
    fn encrypt_assertion_invalid_xml_errors() {
        assert!(encrypt_assertion(
            "This is not a xml format string",
            SP_CERT,
            AES_256,
            RSA_OAEP_MGF1P,
            "saml"
        )
        .is_err());
    }
    #[test]
    fn encrypt_assertion_empty_string_errors() {
        assert!(encrypt_assertion("", SP_CERT, AES_256, RSA_OAEP_MGF1P, "saml").is_err());
    }
    #[test]
    fn encrypt_assertion_blank_string_errors() {
        assert!(encrypt_assertion("   ", SP_CERT, AES_256, RSA_OAEP_MGF1P, "saml").is_err());
    }
}
