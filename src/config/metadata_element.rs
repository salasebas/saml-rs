/// A group of `<SPSSODescriptor>` children whose position in generated SP
/// metadata [`SpConfigBuilder::elements_order`](crate::SpConfigBuilder::elements_order)
/// sets.
///
/// Each group stands for every element of that name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SpMetadataElement {
    /// `<KeyDescriptor>` elements.
    KeyDescriptor,
    /// `<SingleLogoutService>` elements.
    SingleLogoutService,
    /// `<ManageNameIDService>` elements.
    ManageNameIdService,
    /// `<NameIDFormat>` elements.
    NameIdFormat,
    /// `<AssertionConsumerService>` elements.
    AssertionConsumerService,
}

impl SpMetadataElement {
    pub(super) fn element_name(self) -> &'static str {
        match self {
            Self::KeyDescriptor => "KeyDescriptor",
            Self::SingleLogoutService => "SingleLogoutService",
            Self::ManageNameIdService => "ManageNameIDService",
            Self::NameIdFormat => "NameIDFormat",
            Self::AssertionConsumerService => "AssertionConsumerService",
        }
    }
}

/// A group of `<IDPSSODescriptor>` children whose position in generated IdP
/// metadata [`IdpConfigBuilder::elements_order`](crate::IdpConfigBuilder::elements_order)
/// sets.
///
/// Each group stands for every element of that name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IdpMetadataElement {
    /// `<KeyDescriptor>` elements.
    KeyDescriptor,
    /// `<ArtifactResolutionService>` elements.
    ArtifactResolutionService,
    /// `<SingleLogoutService>` elements.
    SingleLogoutService,
    /// `<ManageNameIDService>` elements.
    ManageNameIdService,
    /// `<NameIDFormat>` elements.
    NameIdFormat,
    /// `<SingleSignOnService>` elements.
    SingleSignOnService,
}

impl IdpMetadataElement {
    pub(super) fn element_name(self) -> &'static str {
        match self {
            Self::KeyDescriptor => "KeyDescriptor",
            Self::ArtifactResolutionService => "ArtifactResolutionService",
            Self::SingleLogoutService => "SingleLogoutService",
            Self::ManageNameIdService => "ManageNameIDService",
            Self::NameIdFormat => "NameIDFormat",
            Self::SingleSignOnService => "SingleSignOnService",
        }
    }
}
