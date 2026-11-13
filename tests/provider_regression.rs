#![cfg(crypto)]

use saml_rs::constants::data_encryption_algorithm::AES_256;
use saml_rs::constants::key_encryption_algorithm::RSA_OAEP_MGF1P;
use saml_rs::constants::signature_algorithm::{RSA_SHA1, RSA_SHA256};
use saml_rs::crypto::keys::load_private_key;
use saml_rs::crypto::{
    construct_message_signature, construct_saml_signature, encrypt_assertion,
    verify_message_signature, verify_signature,
};
#[cfg(not(feature = "crypto-fips"))]
use saml_rs::crypto::{decrypt_assertion, AssertionDecryptionOptions};
use saml_rs::SamlError;
use saml_rs::{initialize_crypto_provider, CryptoFipsStatus, CryptoProvider};

const PRIVATE_KEY: &str = include_str!("fixtures/key/idp/provider_matrix_privkey.pkcs8.pem");
const CERTIFICATE: &str = include_str!("fixtures/key/idp/cert.cer");
const RESPONSE: &str = include_str!("fixtures/misc/response.xml");
const RESPONSE_SIGNED_SHA1: &str = include_str!("fixtures/misc/response_signed.xml");
const RSA_SHA1_OCTETS: &str = "SAMLRequest=provider-matrix";
// PKCS#1 v1.5 RSA-SHA1 over RSA_SHA1_OCTETS with provider_matrix_privkey.
const RSA_SHA1_SIGNATURE: &str = "C6V+Aylkp2rFZJEZrpZrYFZDl2xn8kLuuSZcsxZ6ClDkYUBADwl3cVdDstU0i1Kx9CV56m3La/iT463DoKASWY+Jg31NU2741dgH6q3vuWLnUOlKTWHCHrbGOBdpU1DzZw2Ab9CA2KOg7KPlOFvJZMfY2IfdznPyQk4GNr54ij/HZWTZbASdBca6yGONqbsyU2f+IdKAYd+qDOgXn7WZQ3LkCNY1tOTGSoGmRv1FRCfJ4MP2FW2MMSueuS8NLPeW4tsgZ7pIK5Vx2HGeKNz4QtEOlMkOnWNJb6o9MgdywQ0sxbN+vI/m2O1qZz4G/JuoX1NXj+hoQ7UJ2UejcdiscA==";

#[cfg(any(feature = "crypto-aws-lc", feature = "crypto-fips"))]
const RSA_512_PRIVATE_KEY: &str = include_str!("fixtures/key/rsa512/privkey.pkcs8.pem");
const RSA_512_CERTIFICATE: &str = include_str!("fixtures/key/rsa512/cert.pem");
const RSA_512_RESPONSE_SIGNED: &str = include_str!("fixtures/key/rsa512/response_signed.xml");
const RSA_512_OCTETS: &str = "SAMLRequest=rsa-512";
// PKCS#1 v1.5 RSA-SHA256 over RSA_512_OCTETS with rsa512/privkey.pkcs8.pem.
const RSA_512_SIGNATURE: &str =
    "A34mA3xCl9z1j77oDAk2A+o9JTAgYpZnnpw2uJlFlP+cGf8xrpsW/nseSnqMyMJxCjh/OWh3YDb1DsOra4jOyA==";

#[test]
fn provider_initialization_reports_selected_provider_and_attestation(
) -> Result<(), Box<dyn std::error::Error>> {
    let info = initialize_crypto_provider()?;

    #[cfg(feature = "crypto-rustcrypto")]
    assert_eq!(info.provider(), CryptoProvider::RustCrypto);
    #[cfg(any(feature = "crypto-aws-lc", feature = "crypto-fips"))]
    assert_eq!(info.provider(), CryptoProvider::AwsLc);
    #[cfg(feature = "crypto-fips")]
    assert_eq!(info.fips_status(), CryptoFipsStatus::Active);
    #[cfg(not(feature = "crypto-fips"))]
    assert_eq!(info.fips_status(), CryptoFipsStatus::Disabled);

    Ok(())
}

#[test]
fn provider_xml_signature_round_trip_uses_sha256() -> Result<(), Box<dyn std::error::Error>> {
    let key = load_private_key(PRIVATE_KEY, None)?;
    let signed =
        construct_saml_signature(RESPONSE, true, &key, CERTIFICATE, RSA_SHA256, &[], None)?;
    let (verified, signed_content) = verify_signature(&signed, &[CERTIFICATE.to_string()])?;

    assert!(verified);
    assert!(signed_content.is_some());
    Ok(())
}

#[test]
fn provider_detached_signature_round_trip_uses_sha256() -> Result<(), Box<dyn std::error::Error>> {
    let key = load_private_key(PRIVATE_KEY, None)?;
    let signed_octets = "SAMLRequest=provider-matrix&RelayState=state";
    let signature = construct_message_signature(signed_octets, &key, RSA_SHA256)?;

    assert!(verify_message_signature(
        signed_octets,
        &signature,
        CERTIFICATE,
        RSA_SHA256,
    )?);
    Ok(())
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn provider_xml_encryption_round_trip_preserves_assertion() -> Result<(), Box<dyn std::error::Error>>
{
    let encrypted = encrypt_assertion(RESPONSE, CERTIFICATE, AES_256, RSA_OAEP_MGF1P, "saml")?;
    let key = load_private_key(PRIVATE_KEY, None)?;
    let (response, assertion) =
        decrypt_assertion(&encrypted, &key, AssertionDecryptionOptions::default())?;

    assert!(assertion.contains("Assertion"));
    assert!(assertion.contains("_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7"));
    assert!(response.contains("Assertion"));
    assert!(!response.contains("EncryptedAssertion"));
    Ok(())
}

#[cfg(feature = "crypto-aws-lc")]
#[test]
fn aws_lc_xml_encryption_round_trip_uses_default_decryption_options(
) -> Result<(), Box<dyn std::error::Error>> {
    let encrypted = encrypt_assertion(RESPONSE, CERTIFICATE, AES_256, RSA_OAEP_MGF1P, "saml")?;
    let key = load_private_key(PRIVATE_KEY, None)?;
    let (response, assertion) =
        decrypt_assertion(&encrypted, &key, AssertionDecryptionOptions::default())?;

    assert!(assertion.contains("Assertion"));
    assert!(assertion.contains("_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7"));
    assert!(response.contains("Assertion"));
    assert!(!response.contains("EncryptedAssertion"));
    Ok(())
}

#[cfg(feature = "crypto-fips")]
#[test]
fn fips_provider_rejects_sha1_rsa_oaep_key_transport() -> Result<(), Box<dyn std::error::Error>> {
    initialize_crypto_provider()?;

    assert!(matches!(
        encrypt_assertion(RESPONSE, CERTIFICATE, AES_256, RSA_OAEP_MGF1P, "saml",),
        Err(SamlError::Crypto(_))
    ));
    Ok(())
}

#[cfg(feature = "crypto-rustcrypto")]
#[test]
fn rustcrypto_signs_the_committed_rsa_sha1_detached_vector(
) -> Result<(), Box<dyn std::error::Error>> {
    let key = load_private_key(PRIVATE_KEY, None)?;
    let signature = construct_message_signature(RSA_SHA1_OCTETS, &key, RSA_SHA1)?;

    assert_eq!(signature, RSA_SHA1_SIGNATURE);
    Ok(())
}

#[cfg(any(feature = "crypto-aws-lc", feature = "crypto-fips"))]
#[test]
fn aws_lc_providers_reject_signing_rsa_sha1() -> Result<(), Box<dyn std::error::Error>> {
    let key = load_private_key(PRIVATE_KEY, None)?;

    assert!(matches!(
        construct_message_signature(RSA_SHA1_OCTETS, &key, RSA_SHA1),
        Err(SamlError::Crypto(_))
    ));
    Ok(())
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn non_fips_providers_verify_rsa_sha1_detached_signature() -> Result<(), Box<dyn std::error::Error>>
{
    initialize_crypto_provider()?;

    assert!(verify_message_signature(
        RSA_SHA1_OCTETS,
        RSA_SHA1_SIGNATURE,
        CERTIFICATE,
        RSA_SHA1,
    )?);
    Ok(())
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn non_fips_providers_verify_rsa_sha1_enveloped_signature() -> Result<(), Box<dyn std::error::Error>>
{
    initialize_crypto_provider()?;
    let (verified, _) = verify_signature(RESPONSE_SIGNED_SHA1, &[CERTIFICATE.to_string()])?;

    assert!(verified);
    Ok(())
}

#[cfg(feature = "crypto-fips")]
#[test]
fn fips_provider_rejects_verifying_rsa_sha1() -> Result<(), Box<dyn std::error::Error>> {
    initialize_crypto_provider()?;

    assert!(matches!(
        verify_message_signature(RSA_SHA1_OCTETS, RSA_SHA1_SIGNATURE, CERTIFICATE, RSA_SHA1),
        Err(SamlError::Crypto(_))
    ));
    assert!(matches!(
        verify_signature(RESPONSE_SIGNED_SHA1, &[CERTIFICATE.to_string()]),
        Err(SamlError::Crypto(_))
    ));
    Ok(())
}

#[test]
fn providers_reject_a_512_bit_rsa_certificate_for_signature_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    initialize_crypto_provider()?;

    assert!(matches!(
        verify_message_signature(
            RSA_512_OCTETS,
            RSA_512_SIGNATURE,
            RSA_512_CERTIFICATE,
            RSA_SHA256,
        ),
        Err(SamlError::Crypto(_))
    ));
    assert!(matches!(
        verify_signature(RSA_512_RESPONSE_SIGNED, &[RSA_512_CERTIFICATE.to_string()]),
        Err(SamlError::Crypto(_))
    ));
    Ok(())
}

#[cfg(any(feature = "crypto-aws-lc", feature = "crypto-fips"))]
#[test]
fn aws_lc_providers_reject_a_512_bit_rsa_private_key() -> Result<(), Box<dyn std::error::Error>> {
    initialize_crypto_provider()?;

    assert!(matches!(
        load_private_key(RSA_512_PRIVATE_KEY, None),
        Err(SamlError::Crypto(_))
    ));
    Ok(())
}
