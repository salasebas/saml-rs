//! Bergshamra document-crypto provider initialization and attestation.

use std::fmt;

use crate::error::SamlError;

/// Compile-time selected document-crypto provider.
///
/// Available with `crypto-rustcrypto` (also enabled by `crypto-bergshamra`),
/// `crypto-aws-lc`, or `crypto-fips`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CryptoProvider {
    /// RustCrypto ecosystem implementations.
    RustCrypto,
    /// AWS-LC through `aws-lc-rs`.
    AwsLc,
}

impl fmt::Display for CryptoProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RustCrypto => "rustcrypto",
            Self::AwsLc => "aws-lc",
        })
    }
}

/// Runtime FIPS attestation state for the selected provider.
///
/// Available with `crypto-rustcrypto` (also enabled by `crypto-bergshamra`),
/// `crypto-aws-lc`, or `crypto-fips`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CryptoFipsStatus {
    /// The build did not request FIPS enforcement.
    Disabled,
    /// FIPS enforcement was compiled in but provider initialization has not run.
    Uninitialized,
    /// The selected provider attested that FIPS mode is active.
    Active,
}

/// Attested information about the selected document-crypto provider.
///
/// Available with `crypto-rustcrypto` (also enabled by `crypto-bergshamra`),
/// `crypto-aws-lc`, or `crypto-fips`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct CryptoProviderInfo {
    provider: CryptoProvider,
    fips: CryptoFipsStatus,
}

impl CryptoProviderInfo {
    /// Return the compile-time selected provider.
    #[must_use]
    pub const fn provider(&self) -> CryptoProvider {
        self.provider
    }

    /// Return the provider's runtime FIPS attestation state.
    #[must_use]
    pub const fn fips_status(&self) -> CryptoFipsStatus {
        self.fips
    }
}

fn provider_info(info: bergshamra::BackendInfo) -> CryptoProviderInfo {
    let provider = match info.document {
        bergshamra::BackendId::RustCrypto => CryptoProvider::RustCrypto,
        bergshamra::BackendId::AwsLc => CryptoProvider::AwsLc,
    };
    let fips = match info.fips {
        bergshamra::FipsStatus::Disabled => CryptoFipsStatus::Disabled,
        bergshamra::FipsStatus::Uninitialized => CryptoFipsStatus::Uninitialized,
        bergshamra::FipsStatus::Active => CryptoFipsStatus::Active,
    };
    CryptoProviderInfo { provider, fips }
}

fn provider_error(
    action: &str,
    error: impl std::error::Error + Send + Sync + 'static,
) -> SamlError {
    SamlError::Crypto {
        message: format!("crypto provider {action} failed"),
        source: Some(Box::new(error)),
    }
}

/// Inspect the selected provider without triggering initialization.
///
/// Available with `crypto-rustcrypto` (also enabled by `crypto-bergshamra`),
/// `crypto-aws-lc`, or `crypto-fips`.
///
/// A `crypto-fips` build reports [`CryptoFipsStatus::Uninitialized`] until
/// [`initialize_crypto_provider`] or another `saml-rs` crypto operation runs.
///
/// # Errors
///
/// Returns [`SamlError::Crypto`] if Bergshamra cannot report provider state.
pub fn crypto_provider_info() -> Result<CryptoProviderInfo, SamlError> {
    bergshamra::backend_info()
        .map(provider_info)
        .map_err(|error| provider_error("inspection", error))
}

/// Initialize and attest the selected document-crypto provider.
///
/// Available with `crypto-rustcrypto` (also enabled by `crypto-bergshamra`),
/// `crypto-aws-lc`, or `crypto-fips`.
///
/// Initialization is idempotent and its first result is retained for the
/// process lifetime. `saml-rs` calls this automatically before its first
/// Bergshamra operation; applications may call it during startup to fail
/// early and inspect FIPS attestation before accepting traffic.
///
/// # Errors
///
/// Returns [`SamlError::Crypto`] when provider initialization or FIPS
/// attestation fails.
pub fn initialize_crypto_provider() -> Result<CryptoProviderInfo, SamlError> {
    bergshamra::initialize_backend()
        .map(provider_info)
        .map_err(|error| provider_error("initialization", error))
}

pub(crate) fn ensure_crypto_provider_initialized() -> Result<(), SamlError> {
    initialize_crypto_provider().map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialization_reports_selected_provider() -> Result<(), Box<dyn std::error::Error>> {
        let info = initialize_crypto_provider()?;

        #[cfg(feature = "crypto-rustcrypto")]
        assert_eq!(info.provider(), CryptoProvider::RustCrypto);
        #[cfg(any(feature = "crypto-aws-lc", feature = "crypto-fips"))]
        assert_eq!(info.provider(), CryptoProvider::AwsLc);

        Ok(())
    }

    #[cfg(not(feature = "crypto-fips"))]
    #[test]
    fn initialization_reports_fips_disabled_without_fips_feature(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let info = initialize_crypto_provider()?;

        assert_eq!(info.fips_status(), CryptoFipsStatus::Disabled);
        Ok(())
    }

    #[cfg(feature = "crypto-fips")]
    #[test]
    fn initialization_attests_active_fips_mode() -> Result<(), Box<dyn std::error::Error>> {
        let info = initialize_crypto_provider()?;

        assert_eq!(info.fips_status(), CryptoFipsStatus::Active);
        Ok(())
    }
}
