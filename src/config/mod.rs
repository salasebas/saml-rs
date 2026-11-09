//! Typed configuration building blocks for high-level SAML APIs.

mod algorithms;
mod builders;
mod credentials;
mod descriptors;
mod metadata_signature_shape;
mod metadata_trust;
mod policies;

pub use algorithms::{
    DataEncryptionAlgorithm, DigestAlgorithm, KeyEncryptionAlgorithm, NameIdFormat,
    SignatureAlgorithm, TransformAlgorithm,
};
pub(crate) use builders::validated_idp_issuance_lifetime;
pub use builders::{IdpConfig, IdpConfigBuilder, SpConfig, SpConfigBuilder};
pub use credentials::{CertificatePem, Credentials, HmacSecret, Passphrase, PrivateKeyPem};
pub use descriptors::{
    ArtifactResolutionService, EntityId, IdpDescriptor, IdpMetadataConfig, ManageNameIdService,
    SpDescriptor, SpMetadataConfig,
};
pub use metadata_trust::MetadataTrustPolicy;
pub(crate) use policies::AssertionElementEncryption;
pub use policies::{
    AlgorithmPolicy, AssertionEncryptionPolicy, AssertionSignaturePolicy,
    AttributeEncryptionPolicy, AudienceValidationPolicy, AuthnRequestSigningPolicy,
    AuthnRequestValidationPolicy, IdentifierEncryptionPolicy, IdpValidationPolicy, LogoutPolicy,
    LogoutSignaturePolicy, NameIdCreationPolicy, ResponseSignaturePolicy, SpValidationPolicy,
    TemplatePolicy, XmlEncryptionPolicy, XmlPolicy, XmlSignatureProfile,
};
