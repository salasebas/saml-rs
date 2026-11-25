use super::{AlgorithmPolicy, KeyEncryptionAlgorithm};
use crate::constants::key_encryption_algorithm;
use crate::error::SamlError;

pub(super) fn validate_algorithms(algorithms: &AlgorithmPolicy) -> Result<(), SamlError> {
    if cfg!(feature = "crypto-fips")
        && algorithms.key_encryption.as_uri() == key_encryption_algorithm::RSA_OAEP_MGF1P
    {
        return Err(SamlError::Unsupported(
            "crypto-fips does not encrypt with RSA-OAEP-MGF1P, which uses SHA-1; select KeyEncryptionAlgorithm::RsaOaep with SHA-256, SHA-384, or SHA-512"
                .into(),
        ));
    }
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
