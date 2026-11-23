# Name identifier management

Rules for typed name identifier management, over SOAP at the identity provider (`IdentityProvider::start_name_id_management`, `StartedNameIdManagement::finish`, `receive_name_id_management`, `respond_name_id_management`) and over HTTP-Redirect at either provider (`start_name_id_management_redirect`, `receive_name_id_management_redirect`, `respond_name_id_management_redirect`, `finish_name_id_management_redirect` on `IdentityProvider` and `ServiceProvider`). Normative text is Core §§3.2 and 3.6, Profiles §4.5, Bindings §§3.2 and 3.4, and Metadata §2.4.2, as corrected by Approved Errata 05 (E8, E11, E12, E14, E19, E43, E55). Conformance Requirements Table 2 makes HTTP-Redirect `MUST` for the IdP and SP, SOAP `MUST` for the IdP and `OPTIONAL` for the SP, and every cell `MUST NOT` for IdP Lite and SP Lite, and this record does not claim the IdP or SP operational mode. SOAP envelope, header, and transport rules are in [Artifact resolution](artifact-resolution.md#soap-envelope-rules). `NameID` format and length rules are in [Identifiers](identifiers.md#name-identifier-formats).

Both bindings use the shared [issuer](identifiers.md#entity-identifiers)
and [status code](web-browser-sso-acceptance.md#status-codes) rules.

## Turning the protocol on

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Publish a `ManageNameIDService` per configured endpoint | Optional | Metadata §2.4.2 | `IdpConfigBuilder::manage_name_id_service`, `SpConfigBuilder::manage_name_id_redirect_service` |
| Write `ManageNameIDService` after `SingleLogoutService` and before `NameIDFormat` | Mandatory | `SSODescriptorType` | Always |
| Neither send nor accept the protocol on a binding without a published `ManageNameIDService` for it | Library policy: Table 2 prohibits the protocol for IdP Lite and SP Lite, and only the endpoint tells a full configuration from a Lite one. | Conformance Table 2 | `IdpConfigBuilder::manage_name_id_service`, `SpConfigBuilder::manage_name_id_redirect_service` |
| Address the peer by its role descriptor: `Binding`, `Location`, and `ResponseLocation` of its first endpoint for the binding | Optional | Profiles §4.5.3.1, §4.5.3.2 | Always |
| Reject a request for a transient identifier, including an unformatted `NameId` whose identity-provider default format is transient | Mandatory | Core §3.6, E14 | Always |
| Return a received transient `NameID` to the caller, who answers with an error status | Library policy: E14 binds the requester, and Core §3.6.2 still requires an answer. | E14, Core §3.6.2 | Always |

## SOAP: ManageNameIDRequest from the identity provider

`IdentityProvider::start_name_id_management` is the requester.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Send the request over SOAP 1.1 | Optional | Profiles §4.5.3.1, Bindings §3.2.2 | `start_name_id_management` |
| Put one `ManageNameIDRequest` in the SOAP body | Mandatory | Bindings §3.2.2.1 | Always |
| Write `ID`, `Version` `2.0`, and a UTC `IssueInstant` | Mandatory | `RequestAbstractType`, Core §1.3.3 | Always |
| Set `Destination` to the service provider's endpoint | Optional | Core §3.2.1 | Always |
| Write the requesting entity's ID as `Issuer`, with `Format` omitted or `entity`. The writer omits `Format` | Mandatory | Profiles §4.5.4.1 | Always |
| Write the `NameID` as both providers know it, preserving supplied attributes. For an omitted `Format`, the IdP uses its configured default and the SP leaves it absent | Mandatory | Core §3.6.3 | Always |
| For a persistent identifier, write each qualifier whose established value differs from `Issuer`. `NameQualifier` identifies the originating IdP and `SPNameQualifier` identifies the SP or affiliation | Mandatory | Core §3.6.3 | `NameId::with_name_qualifier`, `NameId::with_sp_name_qualifier` |
| Also write each qualifier whose established value equals `Issuer` | Recommended | Core §3.6.3 | `NameId::with_name_qualifier`, `NameId::with_sp_name_qualifier` |
| Write `NewID` with the new value only, or an empty `Terminate` | Mandatory | E12, E55, `TerminateType` | `NameIdChange` |
| Reject a persistent `NameID` value or `NewID` value over 256 characters | Mandatory | Core §8.3.7 | Always |
| Authenticate the sending party and protect message integrity. The crate uses a mutually authenticated, integrity-protected `SoapChannel` | Mandatory | Profiles §4.5.3.1, §4.5.4.1 | `SoapChannel` |
| Reject a `RelayState` | Library policy: the SOAP binding has no place to carry `RelayState`, so it is rejected rather than dropped. | Bindings §3.2, §3.4.3 | `StartNameIdManagement::relay_state` |
| Send `Cache-Control: no-cache, no-store` and `Pragma: no-cache` | Recommended | Bindings §3.2.3.2 | Always |

## SOAP: ManageNameIDResponse from the service provider

`StartedNameIdManagement::finish` is the requester.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Accept exactly one `ManageNameIDResponse` in the SOAP body | Mandatory | Bindings §3.2.2.1 | Always |
| Require `ID`, `Version`, and a UTC `IssueInstant` | Mandatory | `StatusResponseType`, Core §1.3.3, §3.2.2 | Always |
| Accept only response version `2.0` | Library policy: reason not recorded. | Core §4.1.3.2 | Always |
| Require the response `InResponseTo` to equal the pending request ID, including on an error response | Library policy: a missing or different value cannot identify this response as the answer to the pending request. | Core §3.2.1, §3.2.2 | Always |
| Require one `Status` with one direct `StatusCode` | Mandatory | `StatusResponseType`, `StatusType` | Always |
| Report a status other than `Success` as an error | Library policy: only `Success` confirms the change, and the caller needs the peer's refusal status. | Core §3.6.3 | Always |
| Require an `Issuer` equal to the service provider, with `Format` omitted or `entity` | Library policy: Profiles §4.5.4.2 binds the responder, and the requester attributes the response to the service provider by that `Issuer` and the `SoapChannel`. | Profiles §4.5.4.2 | Always |
| Authenticate the sending party and protect message integrity. The crate uses a mutually authenticated, integrity-protected `SoapChannel`, attested at start | Mandatory | Profiles §4.5.3.2, §4.5.4.2 | `SoapChannel` |
| Verify the message signature when present, including on a protected channel | Library policy: the receiver rejects a signature it cannot verify before trusting the response status. | Core §3.2.2, Profiles §4.5.4.2 | Always |
| Require the verified signature to reference the response's `ID` | Mandatory | Core §5.4.2 | Always |
| Allow enveloped signature and canonicalization transforms | Library policy: a signature must cover the entire response. | Core §5.4.4 | Always |
| Use the SP's configured signing keys and require channel protection for signed responses as well | Library policy: the caller binds the response to the authenticated peer and its pending SOAP exchange. | Profiles §4.5.3.2, §4.5.4.2 | `SoapChannel`, SP metadata or HMAC secret |

## SOAP: ManageNameIDRequest from the service provider

`IdentityProvider::receive_name_id_management` is the responder. See [EncryptedID and NewEncryptedID](#encryptedid-and-newencryptedid) for encrypted identifiers.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Accept exactly one `ManageNameIDRequest` in the SOAP body | Mandatory | Bindings §3.2.2.1 | Always |
| Require `ID`, `Version`, and a UTC `IssueInstant` | Mandatory | `RequestAbstractType`, Core §1.3.3 | Always |
| Reject an unsupported major request version | Mandatory | Core §4.1.3.1 | Always |
| Reject a higher minor request version | Optional | Core §4.1.3.1 | Always |
| Answer a newer authenticated request version with `VersionMismatch`. Add `RequestVersionTooHigh` for a newer major version | Mandatory | Core §4.1.3.2 | `NameIdManagementRefusal::VersionMismatch` |
| Return an error for an older request version that forbids a SAML 2.0 response | Mandatory | Core §4.1.3.2 | Always |
| Authenticate the sending party and protect message integrity. The crate uses a mutually authenticated, integrity-protected `SoapChannel` | Mandatory | Profiles §4.5.4.1 | `SoapChannel` |
| Verify the message signature when present, including on a protected channel | Library policy: the receiver rejects a signature it cannot verify before passing a change to the caller. | Core §3.2.1, Profiles §4.5.4.1 | Always |
| Require the verified signature to reference the request's `ID` | Mandatory | Core §5.4.2 | Always |
| Allow enveloped signature and canonicalization transforms | Library policy: a signature must cover the entire request. | Core §5.4.4 | Always |
| Use the SP's configured signing keys and require channel protection for signed requests as well | Library policy: the caller binds the receipt to the SP it authenticated on the SOAP channel. | Profiles §4.5.3.1, §4.5.4.1 | `SoapChannel`, SP metadata or HMAC secret |
| Require an `Issuer` equal to the service provider, with `Format` omitted or `entity` | Library policy: Profiles §4.5.4.1 binds the requester, and the responder ties the change to the service provider by that `Issuer` and the `SoapChannel`. | Profiles §4.5.4.1 | Always |
| Compare a present `Destination` with the receiving SOAP `ManageNameIDService` after collapsing XML whitespace. Accept an absent value | Mandatory | Core §3.2.1, XML Schema Part 2 §4.3.6 | `SamlValidationContext::with_recipient_endpoint` |
| Require at most one `Issuer`, `ds:Signature`, and `Extensions` in that order, then one `NameID` or `EncryptedID`, then one `NewID`, `NewEncryptedID`, or `Terminate`, with text-only `NameID` and `NewID` and an empty `Terminate` | Mandatory | `RequestAbstractType`, `ManageNameIDRequestType`, `TerminateType` | Always |
| Answer an authenticated request outside the configured age window with `Requester` and leave its ID out of the replay cache | Library policy: the age window limits acceptance after replay storage expires. | Core §1.3.3 | `SamlValidationContext::with_manage_name_id_request_age`. Disabled by default |
| Reject a repeated request `ID` | Library policy: retaining the ID prevents the same message from being accepted twice during the retention period. | — | `ReplayPolicy::RequireCache`, `SamlValidationContext::with_replay_retention` |
| Accept a persistent `NameID` without its qualifiers | Library policy: the receiver preserves the identifier as sent, including absent qualifiers. | Core §3.6.3 | Always |

## SOAP: ManageNameIDResponse from the identity provider

`IdentityProvider::respond_name_id_management` is the responder.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Answer every processed request with a `ManageNameIDResponse` | Mandatory | Core §3.6.2, Profiles §4.5.3.2 | `respond_name_id_management` |
| For a `2.0` request, write `ID`, `Version` `2.0`, a UTC `IssueInstant`, and `InResponseTo` equal to the request `ID` | Mandatory | `StatusResponseType`, Core §3.2.2, §4.1.3.2 | Always |
| Write the responding entity's ID as `Issuer`, with `Format` omitted or `entity`. The writer omits `Format` | Mandatory | Profiles §4.5.4.2 | Always |
| Answer only a request received from the given service provider | Library policy: reason not recorded. | — | Always |
| Authenticate the sending party and protect message integrity. The crate uses a mutually authenticated, integrity-protected `SoapChannel`, the one the request arrived on | Mandatory | Profiles §4.5.3.2, §4.5.4.2 | `SoapChannel` |
| Send `Cache-Control: no-cache, no-store, must-revalidate, private` and `Pragma: no-cache` | Recommended | Bindings §3.2.3.2 | Always |

## HTTP-Redirect: ManageNameIDRequest

`start_name_id_management_redirect` on either role is the requester.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Write `ID`, `Version` `2.0`, and a UTC `IssueInstant` | Mandatory | `RequestAbstractType`, Core §1.3.3 | Always |
| Write the requesting entity's ID as `Issuer`, with `Format` omitted or `entity`. The writer omits `Format` | Mandatory | Profiles §4.5.4.1 | Always |
| Write the `NameID` as both providers know it, preserving supplied attributes. For an omitted `Format`, the IdP uses its configured default and the SP leaves it absent | Mandatory | Core §3.6.1, §3.6.3 | Always |
| For a persistent identifier, write each qualifier whose established value differs from `Issuer`. `NameQualifier` identifies the originating IdP and `SPNameQualifier` identifies the SP or affiliation | Mandatory | Core §3.6.3 | `NameId::with_name_qualifier`, `NameId::with_sp_name_qualifier` |
| Also write each qualifier whose established value equals `Issuer` | Recommended | Core §3.6.3 | `NameId::with_name_qualifier`, `NameId::with_sp_name_qualifier` |
| Write `NewID` with the new value only, or an empty `Terminate` | Mandatory | E12, E55, `TerminateType` | `NameIdChange` |
| Reject an identity provider's persistent `NameID` value or `NewID` over 256 characters. A service provider's `NewID` sets `SPProvidedID` and has no 256-character limit | Mandatory | Core §8.3.7 | Always |
| Reject a service provider's persistent `NameID` value over 256 characters | Library policy: reason not recorded. | Core §8.3.7 | Always |
| Sign the request | Mandatory | Profiles §4.5.3.1 | Always |
| Set `Destination` to the peer's first HTTP-Redirect `ManageNameIDService` `Location` | Mandatory | Bindings §3.4.5.2 | Always |
| Send only to an `https` peer endpoint | Recommended | Profiles §4.5.3.1 | `StartNameIdManagement::allow_http` |
| Reject a `RelayState` over 80 bytes | Mandatory | Bindings §3.4.3 | `StartNameIdManagement::relay_state` |
| Send `Cache-Control: no-cache, no-store` and `Pragma: no-cache` | Recommended | Bindings §3.4.5.1 | Always |

## HTTP-Redirect: receiving a ManageNameIDRequest

`receive_name_id_management_redirect` on either role is the responder. See [EncryptedID and NewEncryptedID](#encryptedid-and-newencryptedid) for encrypted identifiers.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Reject an unsigned request | Library policy: the Redirect signature authenticates the peer and protects the message across the browser redirect. | Profiles §4.5.3.1, §4.5.4.1 | Always. An HMAC signature uses the secret from `with_hmac_secret` on the peer descriptor |
| Require an `Issuer` equal to the peer descriptor's entity ID | Library policy: Profiles §4.5.4.1 requires an `Issuer` and does not name the descriptor, and the signature is verified with that descriptor's keys, so the change is attributed to it. | Profiles §4.5.4.1 | Always |
| Require `Destination` on the signed request. Compare it with the receiving `ManageNameIDService` after collapsing XML whitespace | Mandatory | Core §3.2.1, Bindings §3.4.5.2, XML Schema Part 2 §4.3.6 | `SamlValidationContext::with_recipient_endpoint` |
| Require `ID`, `Version`, and a UTC `IssueInstant` | Mandatory | `RequestAbstractType`, Core §1.3.3 | Always |
| Require at most one `Issuer`, `ds:Signature`, and `Extensions` in that order, then one `NameID` or `EncryptedID`, then one `NewID`, `NewEncryptedID`, or `Terminate`, with text-only `NameID` and `NewID` and an empty `Terminate` | Mandatory | `RequestAbstractType`, `ManageNameIDRequestType`, `TerminateType` | Always |
| Reject an unsupported major request version | Mandatory | Core §4.1.3.1 | Always |
| Reject a higher minor request version | Optional | Core §4.1.3.1 | Always |
| Answer a newer authenticated request version with signed `VersionMismatch`. Add `RequestVersionTooHigh` for a newer major version | Mandatory | Core §4.1.3.2, Profiles §4.5.3.2 | `NameIdManagementRefusal::VersionMismatch` |
| Return an error for an older request version that forbids a SAML 2.0 response | Mandatory | Core §4.1.3.2 | Always |
| Answer an authenticated 2.0 request outside the configured age window with signed `Requester`, before replay storage and decryption | Library policy: the age window limits acceptance after replay storage expires. | Core §1.3.3 | `SamlValidationContext::with_manage_name_id_request_age`. Disabled by default |
| Accept a persistent `NameID` without its qualifiers | Library policy: the receiver preserves the identifier as sent, including absent qualifiers. | Core §3.6.3 | Always |
| Reject a repeated request `ID` | Library policy: retaining the ID prevents the same message from being accepted twice during the retention period. | — | `ReplayPolicy::RequireCache`, `SamlValidationContext::with_replay_retention` |
| Accept a received `RelayState` over 80 bytes, up to 4096 bytes | Library policy: Bindings §3.4.3 binds the creator and gives the receiver no rule, and the 4096-byte bound limits unauthenticated input. | Bindings §3.4.3 | `MAX_RECEIVED_RELAY_STATE_BYTES` |
| Reject a repeated `RelayState` parameter | Library policy: Bindings §3.4.3 defines one value per message and no receiver rule, and saml-rs compares and echoes one value while a caller's framework may read another. | Bindings §3.4.3 | Always |

With an enabled age window, retain request IDs for at least `max_age` plus
both clock-skew tolerances to cover the full window on either binding.

## HTTP-Redirect: ManageNameIDResponse

`respond_name_id_management_redirect` and the refusal that `receive_name_id_management_redirect` returns are the responder.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Answer every processed request with a `ManageNameIDResponse` | Mandatory | Core §3.6.2, Profiles §4.5.3.2 | `respond_name_id_management_redirect` |
| For a `2.0` request, write `ID`, `Version` `2.0`, a UTC `IssueInstant`, and `InResponseTo` equal to the request `ID` | Mandatory | `StatusResponseType`, Core §3.2.2, §4.1.3.2 | Always |
| Write the responding entity's ID as `Issuer`, with `Format` omitted or `entity`. The writer omits `Format` | Mandatory | Profiles §4.5.4.2 | Always |
| Answer only a request received from the given peer | Library policy: no response is built for another party's endpoint. | — | Always |
| Sign the response | Mandatory | Profiles §4.5.3.2 | Always |
| Take the response endpoint from the peer's first HTTP-Redirect `ManageNameIDService`: `ResponseLocation`, else `Location` | Optional | Metadata §2.2.2, E41, Profiles §4.5.3.2 | Always |
| Set `Destination` to that endpoint | Mandatory | Bindings §3.4.5.2 | Always |
| Return the exact `RelayState` received with the request | Mandatory | Bindings §3.4.3 | Always |
| Send only to an `https` peer endpoint | Recommended | Profiles §4.5.3.2 | `RespondNameIdManagement::allow_http`, `ReceiveNameIdManagement::allow_http` for a refusal |
| Send `Cache-Control: no-cache, no-store` and `Pragma: no-cache` | Recommended | Bindings §3.4.5.1 | Always |

## HTTP-Redirect: receiving a ManageNameIDResponse

`finish_name_id_management_redirect` on either role is the requester.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Reject an unsigned response | Library policy: the Redirect signature authenticates the peer and protects the message across the browser redirect. | Profiles §4.5.3.2, §4.5.4.2 | Always. An HMAC signature uses the secret from `with_hmac_secret` on the peer descriptor |
| Require the response `InResponseTo` to equal the pending request ID, including on an error response | Library policy: a missing or different value cannot identify this response as the answer to the pending request. | Core §3.2.1, §3.2.2 | `PendingManageNameIdRequest` |
| Require the response to come from the peer the request went to | Library policy: another peer must not complete the pending transaction. | Profiles §4.5.4.2 | Always |
| Require the `RelayState` the request carried, and accept any when it carried none | Library policy: Bindings §3.4.3 binds the responder, and another transaction's state must not complete this one. | Bindings §3.4.3 | Always |
| Accept a received `RelayState` over 80 bytes, up to 4096 bytes | Library policy: Bindings §3.4.3 binds the creator and gives the receiver no rule, and the 4096-byte bound limits unauthenticated input. | Bindings §3.4.3 | `MAX_RECEIVED_RELAY_STATE_BYTES` |
| Reject a repeated `RelayState` parameter | Library policy: Bindings §3.4.3 defines one value per message and no receiver rule, and saml-rs compares and echoes one value while a caller's framework may read another. | Bindings §3.4.3 | Always |
| Require `Destination` on the signed response. Compare it with this provider's response location after collapsing XML whitespace | Mandatory | Core §3.2.2, Bindings §3.4.5.2, XML Schema Part 2 §4.3.6 | `SamlValidationContext::with_recipient_endpoint` |
| Require one `Status` with one direct `StatusCode` | Mandatory | `StatusResponseType`, `StatusType` | Always |
| Report a status other than `Success` after verifying the signature, issuer, request ID, and destination | Library policy: failed authentication or correlation takes precedence over a reported status. | Core §3.2.2.2 | Always |
| Reject a repeated response `ID` | Library policy: retaining the ID prevents the same message from being accepted twice during the retention period. | — | `ReplayPolicy::RequireCache`, `SamlValidationContext::with_replay_retention` |

## EncryptedID and NewEncryptedID

Both bindings, at the identity provider and the service provider.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Send either representation of each value: `NameID` or `EncryptedID`, and `NewID` or `NewEncryptedID`. `Terminate` is never encrypted | Optional | Core §3.6.1, §3.6.3, E12 | `StartNameIdManagement::identifier_encryption`, `IdentifierEncryptionPolicy::EncryptIdentifiers` |
| Write `NewEncryptedID` as a `NewID` with the new value only | Mandatory | E12 | Always |
| Encrypt for the responder's first X.509 certificate published for encryption or with no key use specified | Optional | Profiles §4.5.5 | `AlgorithmPolicy::data_encryption`, `AlgorithmPolicy::key_encryption` |
| Support `EncryptedID` wherever the operational mode requires `NameID` support | Mandatory | Conformance §3.4 | `IdentifierEncryptionPolicy::EncryptIdentifiers`, `Credentials::with_decryption_credential` |
| Find an `EncryptedKey` embedded in `EncryptedData`, or beside it and named by a `ds:RetrievalMethod` | Optional | Core §6.2, E43 | Always |
| Require the `EncryptedID` plaintext to be one `NameID` and the `NewEncryptedID` plaintext one `NewID`, each text-only, and treat other content as undecryptable | Library policy: reason not recorded. | Core §3.6.1, E12 | Always |
| With a crypto provider and decryption credentials, accept `NameID` or `EncryptedID` and `NewID` or `NewEncryptedID` in any combination, whatever `XmlEncryptionPolicy::identifiers` says | Mandatory | Core §3.6.3 | `Credentials::with_decryption_credential` |
| For a SAML-domain decryption error over SOAP, return a SAML error status in the response | Recommended | Bindings §§3.2.2.1, 3.2.3.3, E19 | Always |
| Answer an element that does not decrypt, including a missing key, with `Requester` and `UnknownPrincipal` for `EncryptedID` and `Requester` for `NewEncryptedID` | Library policy: the crate follows the Shibboleth SP's status mapping for decryption failures. | Core §3.6.2, §3.6.3, E19 | `NameIdManagementRefusal::UndecryptableIdentifier`, `NameIdManagementRefusal::UndecryptableNewIdentifier` |

## After the exchange

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| When the IdP next uses that primary identifier with the requesting SP, include the SP's new value as `SPProvidedID` | Mandatory | Core §3.6.3, §8.3.7, E55 | `NameId::with_sp_provided_id` |

The caller owns these rules, and the crate keeps no identifier state or sessions.

- When the application does not recognize the identifier, it supplies an error status to the response builder, and may include `UnknownPrincipal`. Mandatory, Core §3.6.3. See `Status::requester`, `Status::responder`, and `SubordinateStatusCode::unknown_principal`.
- If logout is intended as part of identifier termination, send the `LogoutRequest` before the terminating `ManageNameIDRequest`. Mandatory, E8.
- After an identity provider's `NewID`, write the new value as the `NameID` content in later assertions. Mandatory, Core §3.6.1.
- When the SP next communicates with the requesting IdP, use the new `NameID` wherever the changed identifier would have been used. Mandatory, Core §3.6.3, E55.
- After a termination, stop issuing assertions with that identifier. Mandatory, Core §3.6.3, E55.
- After a termination, delete or mark obsolete the state kept for the identifier, and act as if it never existed. Recommended, Core §3.6.3, E14.
- After a termination, do not invalidate the principal's active sessions, and an identity provider does not end sessions with other service providers. Recommended, E8.
- Accept either identifier while a change propagates. Optional, Core §3.6.3.
- Sanitize the permitted URL schemes of a `RelayState` that is used in a redirect or in response content. Mandatory, E90.
- Keep the `RelayState` value free of information beyond what the exchange needs. Recommended, Profiles §4.5.3.1.

## Outside this flow

- Name identifier management over HTTP-POST and HTTP-Artifact. Optional, Profiles §4.5.3.1.
- SOAP name identifier management at the service provider. Optional, Conformance Table 2.
- Signing outbound SOAP management messages. Optional, Profiles §§4.5.3.1-2.
- A responder that adds `RelayState` to a request that had none. Optional, Bindings §3.4.3.
- Checking a present `Destination` on a SOAP `ManageNameIDResponse`. Mandatory, Core §3.2.2. The synchronous `finish` API has no receiving URL and skips this check.
- Name identifier mapping over SOAP. Mandatory for the Extended IdP and SP, Conformance Table 3.
- The IdP operational mode and the SP operational mode.
