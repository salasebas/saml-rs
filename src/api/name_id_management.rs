use crate::config::SpDescriptor;
use crate::constants::Binding;
use crate::model::{NameId, Received, RelayState, SamlValidationContext, Status};
use crate::name_id_management::{
    self, LocalIdentityProvider, ManageNameIdRequest, NameIdChange, NameIdManagementReceipt,
    StartedNameIdManagement,
};
use crate::soap::{SoapChannel, SoapResponse};
use std::time::SystemTime;

mod redirect;

pub use redirect::NameIdManagementRedirectReceipt;

use super::{IdentityProvider, SamlError, StartNameIdManagement};

impl IdentityProvider {
    /// Send `ManageNameIDRequest` to the service provider's SOAP
    /// `ManageNameIDService`.
    ///
    /// `name_id` is the identifier as both providers currently know it. A
    /// `NameId` without a format is sent with the first configured NameID
    /// format, the one [`Self::respond_sso`] writes for it. A persistent
    /// identifier without `NameQualifier` or `SPNameQualifier` is sent with
    /// this identity provider and the service provider as those qualifiers.
    ///
    /// [`StartNameIdManagement::identifier_encryption`] with
    /// [`IdentifierEncryptionPolicy::EncryptIdentifiers`](crate::IdentifierEncryptionPolicy::EncryptIdentifiers) sends the
    /// identifier as `EncryptedID`, and a new value as `NewEncryptedID`, for
    /// the first encryption certificate in the service provider's metadata.
    /// The default, [`IdentifierEncryptionPolicy::PlaintextIdentifiers`](crate::IdentifierEncryptionPolicy::PlaintextIdentifiers),
    /// sends `NameID` and `NewID`. A SOAP request carries no RelayState, so
    /// [`StartNameIdManagement::relay_state`] must stay unset.
    /// [`StartNameIdManagement::allow_http`] has no effect here: the
    /// deployment sends the request and chooses its transport.
    ///
    /// To end the principal's sessions before [`NameIdChange::Terminate`],
    /// send `LogoutRequest` first: a `LogoutRequest` must not follow the
    /// termination.
    ///
    /// Post [`StartedNameIdManagement::request`] with the deployment's HTTP
    /// client, then call [`StartedNameIdManagement::finish`] with the SOAP
    /// response. `channel` records the protection that client provides.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::ProtocolProfile`] when
    /// [`StartNameIdManagement::relay_state`] is set, or when `name_id` is
    /// transient, including a `NameId` without a format whose default format
    /// is transient. Returns
    /// [`SamlError::MissingMetadata`] when this identity provider publishes no
    /// SOAP `ManageNameIDService`, or the service provider's metadata has
    /// none. Returns [`SamlError::SoapChannelProtection`] when `channel` does
    /// not authenticate both parties and protect integrity. Returns
    /// [`SamlError::Invalid`] when the persistent `name_id` value or a new
    /// value is longer than 256 characters, or when the NameID format is not
    /// an absolute URI reference. With
    /// [`IdentifierEncryptionPolicy::EncryptIdentifiers`](crate::IdentifierEncryptionPolicy::EncryptIdentifiers), returns
    /// [`SamlError::MissingMetadata`] when the service provider publishes no
    /// encryption certificate.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     IdentityProvider, NameId, NameIdChange, SoapChannel, SpDescriptor,
    ///     StartNameIdManagement,
    /// };
    ///
    /// # fn change(
    /// #     idp: &IdentityProvider,
    /// #     sp: &SpDescriptor,
    /// #     response_envelope: &str,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let current = NameId::persistent("current-value")?;
    /// let started = idp.start_name_id_management(
    ///     sp,
    ///     &current,
    ///     &NameIdChange::NewId("new-value".into()),
    ///     StartNameIdManagement::new(),
    ///     SoapChannel::mutually_authenticated_confidential(),
    /// )?;
    /// let envelope = started.request().envelope();
    /// # let _ = envelope;
    /// started.finish(response_envelope)?;
    /// # Ok(()) }
    /// ```
    pub fn start_name_id_management(
        &self,
        sp: &SpDescriptor,
        name_id: &NameId,
        change: &NameIdChange,
        options: StartNameIdManagement,
        channel: SoapChannel,
    ) -> Result<StartedNameIdManagement, SamlError> {
        let StartNameIdManagement {
            relay_state,
            identifier_encryption,
            ..
        } = options;
        crate::logout::reject_soap_relay_state(
            Binding::Soap,
            relay_state.as_ref().map(RelayState::as_str),
        )?;
        sp.ensure_valid_at(SystemTime::now())?;
        name_id_management::start(
            &self.local_identity_provider()?,
            sp,
            name_id,
            change,
            identifier_encryption,
            channel,
        )
    }

    /// Read a service provider's SOAP `ManageNameIDRequest`.
    ///
    /// A [`NameIdManagementReceipt::Request`] is ready for the caller to
    /// apply. Answer it with [`Self::respond_name_id_management`]. A
    /// [`NameIdManagementReceipt::Refused`] already carries the SOAP response
    /// to return. The responder refuses an authenticated newer version with
    /// `VersionMismatch` and adds `RequestVersionTooHigh` for a newer major
    /// version. It also refuses a request outside the configured age window
    /// or with an `EncryptedID` or `NewEncryptedID` that cannot be decrypted.
    ///
    /// `sp` is the service provider the deployment authenticated on
    /// `channel`. A present XML signature must cover the request and verify
    /// against `sp`'s signing keys. `validation` selects the receiving endpoint
    /// when this identity provider publishes more than one, applies its
    /// `ManageNameIDRequest` age policy, and stores the request `ID` for replay
    /// detection.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::MissingMetadata`] when this identity provider
    /// publishes no SOAP `ManageNameIDService`. Returns
    /// [`SamlError::SoapChannelProtection`] when `channel` does not
    /// authenticate both parties and protect integrity. Returns another
    /// [`SamlError`] when the envelope is not a SOAP 1.1
    /// `ManageNameIDRequest` from `sp`, its `Destination` is not the receiving
    /// endpoint, or the request version is too low for a SAML 2.0 response.
    /// A repeated request `ID` returns [`SamlError::ReplayDetected`]. Returns
    /// [`SamlError::TimeWindowInvalid`] when
    /// [`ReplayPolicy::RequireCache`](crate::ReplayPolicy::RequireCache) is
    /// selected and `validation` has no
    /// [`SamlValidationContext::with_replay_retention`]. The deployment can
    /// answer those with an HTTP error or a SOAP fault.
    pub fn receive_name_id_management(
        &self,
        sp: &SpDescriptor,
        request_envelope: &str,
        channel: SoapChannel,
        validation: SamlValidationContext<'_>,
    ) -> Result<NameIdManagementReceipt, SamlError> {
        sp.ensure_valid_at(validation.now())?;
        name_id_management::receive(
            &self.local_identity_provider()?,
            sp,
            request_envelope,
            channel,
            validation,
        )
    }

    /// Answer a received `ManageNameIDRequest` with `ManageNameIDResponse`.
    ///
    /// Return the [`SoapResponse`] on the request's HTTP exchange.
    ///
    /// `status` is what the response reports. Pass [`Status::success`] after
    /// applying the change. After a [`NameIdChange::NewId`], send that value
    /// as the identifier's `SPProvidedID` from then on: [`Self::respond_sso`]
    /// writes it from [`NameId::with_sp_provided_id`]. For an identifier this
    /// identity provider does not recognize, pass an error status:
    /// [`Status::requester`] or [`Status::responder`], optionally with
    /// [`SubordinateStatusCode::unknown_principal`](crate::SubordinateStatusCode::unknown_principal).
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::IssuerMismatch`] when the request was not received
    /// from `sp`. Returns [`SamlError::UnsupportedBinding`] when the request
    /// arrived over HTTP-Redirect.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     IdentityProvider, NameIdManagementReceipt, ReplayPolicy, SamlValidationContext,
    ///     SoapChannel, SpDescriptor, Status, SubordinateStatusCode,
    /// };
    /// use std::time::SystemTime;
    ///
    /// # fn answer(
    /// #     idp: &IdentityProvider,
    /// #     sp: &SpDescriptor,
    /// #     request_envelope: &str,
    /// #     recognized: bool,
    /// #     apply: impl Fn(&saml_rs::NameIdChange) -> std::io::Result<()>,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let validation =
    ///     SamlValidationContext::new(SystemTime::now(), ReplayPolicy::NoCache);
    /// let received = idp.receive_name_id_management(
    ///     sp,
    ///     request_envelope,
    ///     SoapChannel::mutually_authenticated_confidential(),
    ///     validation,
    /// )?;
    /// let response = match received {
    ///     NameIdManagementReceipt::Request(request) => {
    ///         let status = if !recognized {
    ///             Status::requester().with_subordinate(SubordinateStatusCode::unknown_principal())
    ///         } else if apply(request.message().change()).is_ok() {
    ///             Status::success()
    ///         } else {
    ///             Status::responder()
    ///         };
    ///         idp.respond_name_id_management(sp, &request, &status)?
    ///     }
    ///     NameIdManagementReceipt::Refused(refused) => refused.response().clone(),
    /// };
    /// let envelope = response.envelope();
    /// # let _ = envelope;
    /// # Ok(()) }
    /// ```
    pub fn respond_name_id_management(
        &self,
        sp: &SpDescriptor,
        request: &Received<ManageNameIdRequest>,
        status: &Status,
    ) -> Result<SoapResponse, SamlError> {
        sp.ensure_valid_at(SystemTime::now())?;
        name_id_management::respond(&self.local_identity_provider()?, sp, request, status)
    }

    fn local_identity_provider(&self) -> Result<LocalIdentityProvider<'_>, SamlError> {
        let idp = self.engine();
        Ok(LocalIdentityProvider {
            entity_id: idp
                .metadata
                .as_metadata()
                .entity_id()
                .ok_or_else(|| SamlError::MissingMetadata("entityID".into()))?,
            metadata: idp.metadata.as_metadata(),
            setting: &idp.setting,
        })
    }
}
