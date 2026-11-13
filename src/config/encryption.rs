use super::{AlgorithmPolicy, KeyEncryptionAlgorithm};
use crate::error::SamlError;

#[cfg(crypto)]
pub(super) fn validate_algorithms(algorithms: &AlgorithmPolicy) -> Result<(), SamlError> {
    if let KeyEncryptionAlgorithm::RsaOaep { digest, mgf } = &algorithms.key_encryption {
        let params = bergshamra::crypto::keytransport::OaepParams {
            digest_uri: Some(digest.as_uri().to_string()),
            mgf_uri: Some(mgf.as_uri().to_string()),
            oaep_params: None,
        };
        bergshamra::crypto::keytransport::from_uri_with_params(
            algorithms.key_encryption.as_uri(),
            params,
        )
        .map_err(|error| SamlError::Unsupported(error.to_string()))?;
        if cfg!(any(feature = "crypto-aws-lc", feature = "crypto-fips"))
            && digest.as_uri() != mgf.digest_uri()
        {
            return Err(SamlError::Unsupported(
                "AWS-LC RSA-OAEP requires matching SHA-256, SHA-384, or SHA-512 digest and MGF1"
                    .into(),
            ));
        }
    }
    Ok(())
}

#[cfg(not(crypto))]
pub(super) fn validate_algorithms(algorithms: &AlgorithmPolicy) -> Result<(), SamlError> {
    if matches!(
        algorithms.key_encryption,
        KeyEncryptionAlgorithm::RsaOaep { .. }
    ) || matches!(
        algorithms.data_encryption,
        super::DataEncryptionAlgorithm::Aes256Gcm
    ) {
        return Err(SamlError::Unsupported(
            "selected XML Encryption 1.1 algorithm requires a crypto provider feature".into(),
        ));
    }
    Ok(())
}
