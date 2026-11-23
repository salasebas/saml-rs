//! Typed configuration building blocks for high-level SAML APIs.

mod algorithms;
mod builders;
mod credentials;
mod descriptors;
#[cfg(crypto)]
mod encryption;
mod entity_setting;
mod metadata_signature_shape;
mod metadata_trust;
mod policies;
mod provider;

pub use crate::entity::{SignatureAction, SignatureConfig};
pub use crate::xml::XmlLimits;
pub use algorithms::{
    DataEncryptionAlgorithm, DigestAlgorithm, KeyEncryptionAlgorithm, MaskGenerationFunction,
    NameIdFormat, SignatureAlgorithm, TransformAlgorithm,
};
pub use builders::{IdpConfig, IdpConfigBuilder, SpConfig, SpConfigBuilder};
pub use credentials::{
    CertificatePem, Credentials, HmacSecret, Passphrase, PrivateKeyPem, X509Credential,
};
pub(crate) use descriptors::validate_entity_id_syntax;
pub use descriptors::{
    ArtifactResolutionService, EntityId, IdpDescriptor, IdpMetadataConfig, ManageNameIdService,
    SpDescriptor, SpMetadataConfig,
};
pub use metadata_trust::MetadataTrustPolicy;
pub(crate) use policies::AssertionElementEncryption;
pub use policies::{
    AlgorithmPolicy, AssertionEncryptionPolicy, AssertionSignaturePolicy,
    AttributeEncryptionPolicy, AudienceValidationPolicy, AuthnRequestSigningPolicy,
    AuthnRequestValidationPolicy, IdentifierEncryptionPolicy, IdpValidationPolicy,
    NameIdCreationPolicy, ResponseSignaturePolicy, Rsa15KeyTransportPolicy, SpValidationPolicy,
    TemplatePolicy, XmlEncryptionPolicy, XmlPolicy, XmlSignatureProfile,
};
