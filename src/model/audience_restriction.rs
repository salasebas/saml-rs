use crate::config::EntityId;

/// One `<AudienceRestriction>` in the `<Conditions>` of an accepted assertion.
///
/// The assertion is addressed to a relying party that is one of the
/// [`Self::audiences`] of every restriction.
/// [`crate::SsoSession::audience_restrictions`] lists one value for each
/// restriction, in document order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudienceRestriction {
    audiences: Vec<EntityId>,
}

impl AudienceRestriction {
    pub(super) fn new(audiences: Vec<EntityId>) -> Self {
        Self { audiences }
    }

    /// The `<Audience>` values of this restriction, in document order, with
    /// their XML Schema `anyURI` whitespace collapsed.
    pub fn audiences(&self) -> &[EntityId] {
        &self.audiences
    }
}
