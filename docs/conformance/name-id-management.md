# Name identifier management

Rules for typed name identifier management. Over SOAP, at the identity
provider: `Saml<Idp>::start_name_id_management`,
`StartedNameIdManagement::finish`, `Saml<Idp>::receive_name_id_management`,
and `Saml<Idp>::respond_name_id_management`. Over HTTP-Redirect, at the
identity provider and the service provider: `start_name_id_management_redirect`,
`receive_name_id_management_redirect`, `respond_name_id_management_redirect`,
and `finish_name_id_management_redirect` on `Saml<Idp>` and `Saml<Sp>`. Both
bindings carry one change, `NameIdChange::NewId` or `NameIdChange::Terminate`,
and return a received request as `ManageNameIdRequest`.

SAML V2.0 Conformance Requirements Table 2, with the labels from Approved
Errata 05 E11, has four rows for this protocol. Name Identifier Management,
HTTP-Redirect, IdP-initiated and SP-initiated, is `MUST` for the IdP and the
SP. Name Identifier Management, SOAP, IdP-initiated and SP-initiated, is
`MUST` for the IdP and `OPTIONAL` for the SP. The SP SOAP cells stay off:
`Saml<Sp>` has no SOAP name identifier management. Every cell is `MUST NOT`
for IdP Lite and SP Lite. Name identifier mapping is not implemented. This
record does not claim the IdP or SP operational mode.

Normative text is SAML Core 2.0 §§3.2 and 3.6, Profiles 2.0 §4.5, Bindings 2.0
§§3.2 and 3.4, and Metadata 2.0 §2.4.2, as corrected by Approved Errata 05.
Errata that change this flow are E8, E11, E12, E14, E19, E43, and E55. Schema
citations are the OASIS protocol and metadata schemas.

For SOAP, the deployment POSTs the envelope. TLS, HTTP authentication, and an
HTTP 500 SOAP fault stay there. Conformance Requirements §3.5 and §5 are those
deployment duties. `SoapChannel` records the protection the deployment
provided, as in [Artifact resolution](artifact-resolution.md). For
HTTP-Redirect, the deployment sends the browser redirect that carries each
message.

## Turning the protocol on

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Publish a `ManageNameIDService` | Identity provider or service provider | Generate metadata | Metadata §2.4.2 allows zero or more. `manage_name_id_service` on `IdpConfigBuilder` takes `ManageNameIdService::soap` or `ManageNameIdService::redirect`. On `SpConfigBuilder` it takes `ManageNameIdService::redirect`; a SOAP endpoint makes `build` return `SamlError::Unsupported`. Unless the element order names it, the endpoint is written before the first of `NameIDFormat`, `SingleSignOnService`, `AssertionConsumerService`, and `AttributeConsumingService`, as `SSODescriptorType` and its role types require |
| Without a published `ManageNameIDService` for the binding, neither send nor accept the protocol on it | Identity provider or service provider | Local API | Library policy. Table 2 prohibits the protocol for IdP Lite and SP Lite. A provider without the endpoint is that configuration: the start and receive operations for that binding return `SamlError::MissingMetadata`. A SOAP requester does not need its own endpoint; the looser rule cannot be applied because the endpoint is the only setting that tells a full configuration from a Lite one. An HTTP-Redirect requester needs it to receive the response |
| The service provider has no SOAP name identifier management | Service provider | Local API | Table 2 marks the SP SOAP cells `OPTIONAL`. They stay off. SP Lite is `MUST NOT` |
| The peer's endpoint comes from the peer's role descriptor | Requester and responder | Generate a message | Optional. Profiles §4.5.3.1 and §4.5.3.2. `Binding`, `Location`, and `ResponseLocation` are read from the `SPSSODescriptor` for a service provider and the `IDPSSODescriptor` for an identity provider, so an entity with both roles is addressed in the right one. The first endpoint for the binding is used. A peer without one is `SamlError::MissingMetadata` |
| The protocol is not used with a transient identifier | Requester | Generate ManageNameIDRequest | Mandatory prohibition. Core §3.6 as amended by Errata 05 E14. A transient `NameId`, or an unformatted one whose identity-provider default format is transient, is `SamlError::ProtocolProfile` on every binding. The format is compared after the `xs:anyURI` whitespace collapse, so a padded transient URI is transient |
| A received transient `NameID` is returned to the caller | Responder | Inbound ManageNameIDRequest | No receiver rule. E14 binds the requester, and Core §3.6.2 still requires an answer. The caller answers with an error status |

## SOAP: ManageNameIDRequest from the identity provider

`Saml<Idp>::start_name_id_management` is this actor. Core §3.6.1 and §3.6.3,
Profiles §4.5.3.1 and §4.5.4.1.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Send the request on a synchronous binding | Requester | Generate ManageNameIDRequest | Optional binding choice. Profiles §4.5.3.1. The binding is SOAP 1.1 |
| `ID`, `Version` `2.0`, and UTC `IssueInstant` are present | Requester | Generate ManageNameIDRequest | Mandatory. Protocol schema `RequestAbstractType`; Core §1.3.3 |
| `Destination` is the service provider's endpoint | Requester | Generate ManageNameIDRequest | Optional in Core §3.2.1. Set to the metadata location |
| `Issuer` is present and omits `Format` | Requester | Generate ManageNameIDRequest | Mandatory. Profiles §4.5.4.1 allows an omitted `Format` or `entity`. Generation omits it |
| The `NameID` is the identifier as both providers know it | Requester | Generate ManageNameIDRequest | Mandatory. Core §3.6.3. The caller passes the established `NameId`. `Format`, `NameQualifier`, `SPNameQualifier`, and `SPProvidedID` are sent as given. A `NameId` without a format takes the first configured NameID format, the one `respond_sso` writes. A `Format` that is not an absolute URI reference is `SamlError::Invalid` (Core §1.3.2, as read in [identifiers](identifiers.md#name-identifier-formats)) |
| A persistent identifier carries `SPNameQualifier` | Requester | Generate ManageNameIDRequest | Mandatory. Core §3.6.3. It is the service provider, or the affiliation the caller passes. When the caller passes none, the service provider's entity ID is written |
| A persistent identifier carries `NameQualifier` | Requester | Generate ManageNameIDRequest | Core §3.6.3: it must be the identity provider that created the identifier. It may be omitted when it equals `Issuer`, which is not recommended. When the caller passes none, this identity provider's entity ID is written. There is no switch to omit it |
| `NewID` carries the new value only | Requester | Generate ManageNameIDRequest | Mandatory. Errata 05 E12: format and qualifiers cannot be changed once established. `NameIdChange::NewId` holds the value |
| A persistent or transient identifier is at most 256 characters | Requester | Generate ManageNameIDRequest | Mandatory. Core §§8.3.7 and 8.3.8. The current `NameID` value and the new value are checked. A longer value is `SamlError::Invalid`. This rule and the persistent qualifier rules compare the format after the `xs:anyURI` whitespace collapse |
| `Terminate` ends the identifier | Requester | Generate ManageNameIDRequest | Core §3.6.3, as amended by E55. `NameIdChange::Terminate` writes an empty `Terminate` |
| A `LogoutRequest` meant to end activity comes before the termination | Requester | Application | Mandatory ordering. Errata 05 E8: the requester must not send `LogoutRequest` after the `ManageNameIDRequest`. The method documentation states it. saml-rs does not track sessions |
| Authenticate the requester and protect integrity | Requester | SOAP exchange | Mandatory. Profiles §4.5.3.1 and §4.5.4.1 allow a signature or a binding mechanism. The mechanism is `SoapChannel`: mutual authentication and integrity, or `SamlError::SoapChannelProtection` before a request is built. The request is not signed. Core §3.6.1 recommends a signature or binding protection; the channel is that protection |
| The SOAP body contains exactly one SAML request | Requester | SOAP envelope | Mandatory. Bindings §3.2.2.1, as left by Errata 05 E19 |
| `Cache-Control: no-cache, no-store` and `Pragma: no-cache` | Requester | HTTP | Recommendation. Bindings §3.2.3.2. `SoapRequest` reports those values |

## SOAP: ManageNameIDResponse from the service provider

`StartedNameIdManagement::finish` is this actor. Core §3.2.2 and §3.6.2,
Profiles §4.5.3.2 and §4.5.4.2.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| The SOAP body is one `ManageNameIDResponse` | Requester | Inbound ManageNameIDResponse | Bindings §3.2.2.1; Core §3.6.2 |
| `Version` is `2.0`, `ID` is present, and `IssueInstant` is a UTC `xs:dateTime` | Requester | Inbound ManageNameIDResponse | Protocol schema `StatusResponseType`; Core §1.3.3 |
| `InResponseTo` is present and equals the request `ID` | Requester | Inbound ManageNameIDResponse | Mandatory. Core §3.2.1 and §3.2.2 |
| One `Status` with one `StatusCode` | Requester | Inbound ManageNameIDResponse | Protocol schema `StatusResponseType` and `StatusType`. A second `Status` or a second direct `StatusCode` is malformed |
| A status other than Success is returned to the caller | Requester | Inbound ManageNameIDResponse | Core §3.6.3: an unrecognized identifier is an error status, optionally `UnknownPrincipal`. `finish` returns `SamlError::StatusNotSuccess` with both codes. `Ok` means Success |
| `Issuer` is present, equals the service provider, and omits `Format` or sets it to `entity` | Requester | Inbound ManageNameIDResponse | Library policy. Profiles §4.5.4.2 requires the responder to send that `Issuer` and does not require the requester to reject another response. The looser rule cannot be applied because the requester attributes the response by that `Issuer` together with `SoapChannel`. Without it, `finish` would report a change that is not attributed to the service provider |
| The responder authenticates itself and protects integrity | Responder | SOAP exchange | Mandatory. Profiles §4.5.3.2 and §4.5.4.2. Satisfied by the `SoapChannel` attested on `start_name_id_management`. A response signature is not verified |
| A `Destination` on the response is not compared | Requester | Inbound ManageNameIDResponse | Core §3.2.2 compares `Destination` with the location where the message was received. A synchronous SOAP response is read from the requester's own HTTP exchange and has no receiving location |

## SOAP: ManageNameIDRequest from the service provider

`Saml<Idp>::receive_name_id_management` is this actor. Core §§3.2.1, 3.6.1,
and 3.6.3, Profiles §4.5.3.2 and §4.5.4.1.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| The SOAP body is one `ManageNameIDRequest` | Responder | Inbound ManageNameIDRequest | Bindings §3.2.2.1. Another body, a second body element, a SOAP header with `mustUnderstand`, or a `Header` that is not one element before the `Body` is `SamlError`, as in artifact resolution. The deployment can answer it with a SOAP fault |
| `ID` is present and `IssueInstant` is a UTC `xs:dateTime` | Responder | Inbound ManageNameIDRequest | Protocol schema `RequestAbstractType`; Core §1.3.3 |
| A `Version` other than `2.0` is answered with `VersionMismatch` | Responder | Generate ManageNameIDResponse | Core §3.2.2.2. `ReceivedNameIdManagement::Refused` carries the response, with `NameIdManagementRefusal::VersionMismatch` |
| The requester authenticated itself and protected integrity | Requester | SOAP exchange | Mandatory. Profiles §4.5.4.1. The check is `SoapChannel`: mutual authentication and integrity, or `SamlError::SoapChannelProtection` before the envelope is read. A request signature is not verified. Refusing a signed request on a channel that does not authenticate the requester is library policy: Profiles §4.5.3.1 also accepts a signature. The looser rule cannot be applied because this identity provider does not verify signatures on this message, so the request would be processed without any authentication |
| `Issuer` is present, equals the service provider, and omits `Format` or sets it to `entity` | Responder | Inbound ManageNameIDRequest | Library policy. Profiles §4.5.4.1 requires the requester to send that `Issuer` and does not require the responder to reject another request. The looser rule cannot be applied because the responder ties the change to the service provider by that `Issuer` together with `SoapChannel`. A missing or different `Issuer` is `SamlError::IssuerMismatch`. A second `Issuer` is malformed |
| A present `Destination` is the receiving endpoint | Responder | Inbound ManageNameIDRequest | Mandatory. Core §3.2.1: a request whose `Destination` is not the receiving location is discarded. The receiving location is this identity provider's SOAP `ManageNameIDService`. With more than one, `SamlValidationContext::with_recipient_endpoint` selects it. An absent `Destination` is accepted |
| At most one `Issuer`, `ds:Signature`, and `Extensions`, in that order, then one `NameID` or `EncryptedID`, then one `NewID`, `NewEncryptedID`, or `Terminate` | Responder | Inbound ManageNameIDRequest | Protocol schema `RequestAbstractType` and `ManageNameIDRequestType`. Another element, a missing one, a second one, or another order is malformed. `NameID` and `NewID` are `xs:string` content and `Terminate` is empty, so a child element, or text in `Terminate`, is malformed |
| `EncryptedID` and `NewEncryptedID` are decrypted | Responder | Inbound ManageNameIDRequest | Mandatory. Conformance §3.4. See [EncryptedID and NewEncryptedID](#encryptedid-and-newencryptedid) |
| Limit `IssueInstant` to a caller-chosen maximum age | Responder | Inbound ManageNameIDRequest | Library hardening, off. Core §1.3.3 requires a UTC `IssueInstant` and Core §3.6 defines no maximum age, so enabling it can reject a conformant request. `SamlValidationContext::with_manage_name_id_request_age` with `ManageNameIdRequestAgePolicy::Bounded { max_age }` applies the window of the HTTP-Redirect row. An instant outside it is `SamlError::TimeWindowInvalid` with `TimeWindowField::ManageNameIdRequestIssueInstant`. The check runs after the `Issuer` and `Destination` checks and before replay storage, so a rejected request does not occupy its `ID`. A request with another `Version` is answered with `VersionMismatch` before the check |
| The request `ID` is recorded for replay detection | Responder | Inbound ManageNameIDRequest | Library policy, active when the caller selects `ReplayPolicy::RequireCache`. The key is `ReplayKey::ManageNameIdRequestId`. A repeated `ID` is `SamlError::ReplayDetected` |
| The `NameID` is returned as sent | Responder | Inbound ManageNameIDRequest | Core §3.6.3 makes the requester send the most recent identifier. `ManageNameIdRequest::name_id` carries the value, `Format`, `NameQualifier`, `SPNameQualifier`, and `SPProvidedID`. A persistent identifier without its qualifiers is not rejected: the qualifier rule binds the requester |

## SOAP: ManageNameIDResponse from the identity provider

`Saml<Idp>::respond_name_id_management` is this actor. Core §3.6.2 and
§3.6.3, Profiles §4.5.3.2 and §4.5.4.2.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Answer every processed request with `ManageNameIDResponse` | Responder | Generate ManageNameIDResponse | Mandatory. Core §3.6.2 and Profiles §4.5.3.2. `respond_name_id_management` answers a `ReceivedNameIdManagement::Request`. A refused request already carries its response |
| An unrecognized identifier is an error status | Responder | Generate ManageNameIDResponse | Mandatory. Core §3.6.3. The caller recognizes the identifier and passes `Status::requester` or `Status::responder`, optionally with `SubordinateStatusCode::unknown_principal` |
| `ID`, `Version` `2.0`, UTC `IssueInstant`, and `InResponseTo` the request `ID` | Responder | Generate ManageNameIDResponse | Mandatory. Protocol schema `StatusResponseType`; Core §3.2.2. `InResponseTo` comes from the received request |
| `Issuer` is present and omits `Format` | Responder | Generate ManageNameIDResponse | Mandatory. Profiles §4.5.4.2 allows an omitted `Format` or `entity`. Generation omits it |
| The request came from the service provider being answered | Responder | Generate ManageNameIDResponse | Library policy. A request received from another `SpDescriptor` is `SamlError::IssuerMismatch` |
| The responder authenticates itself and protects integrity | Responder | SOAP exchange | Mandatory. Profiles §4.5.4.2. The mechanism is the `SoapChannel` the request arrived on. The response is not signed |
| `Cache-Control: no-cache, no-store, must-revalidate, private` and `Pragma: no-cache` | Responder | HTTP | Recommendation. Bindings §3.2.3.2. `SoapResponse` reports those values |

## HTTP-Redirect: ManageNameIDRequest

`start_name_id_management_redirect` on either role. Core §3.6.1 and §3.6.3,
Profiles §4.5.3.1 and §4.5.4.1, Bindings §3.4.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| `ID`, `Version` `2.0`, and UTC `IssueInstant` are present | Requester | Generate ManageNameIDRequest | Mandatory. Protocol schema `RequestAbstractType`; Core §1.3.3 |
| `Issuer` is the requester's entity ID and omits `Format` | Requester | Generate ManageNameIDRequest | Mandatory. Profiles §4.5.4.1 |
| `NameID` carries the identifier as both providers know it, with its `SPProvidedID` | Requester | Generate ManageNameIDRequest | Mandatory. Core §3.6.1 and §3.6.3. Same rules as the SOAP rows, on both roles. A service provider sends a `NameId` without a format as given. A persistent identifier without `NameQualifier` or `SPNameQualifier` gets the identity provider's and the service provider's entity IDs |
| `NewID` carries only the new value | Requester | Generate ManageNameIDRequest | Mandatory. Errata 05 E12 |
| A new identity-provider value for a persistent or transient identifier is at most 256 characters | Identity provider | Generate ManageNameIDRequest | Mandatory. Core §§8.3.7 and 8.3.8. A service provider's `NewID` becomes `SPProvidedID`, which has no length rule |
| Sign the message | Requester | Generate ManageNameIDRequest | Mandatory for this binding. Profiles §4.5.3.1. The request is always signed, with no off switch |
| `Destination` is the peer's `ManageNameIDService` | Requester | Generate ManageNameIDRequest | Bindings §3.4.5.2 requires `Destination` on a signed message. It is the peer's first HTTP-Redirect `Location` |
| Send the user agent over TLS | Requester | Generate ManageNameIDRequest | Recommendation. Profiles §4.5.3.1. The peer endpoint must be `https`. `StartNameIdManagement::allow_http_name_id_management` relaxes that recommendation alone and leaves the request signed |
| `RelayState` does not exceed 80 bytes and reveals as little as possible | Requester | Generate ManageNameIDRequest | Mandatory length, Bindings §3.4.3. The content is a recommendation, Profiles §4.5.3.1, and the caller chooses it with `StartNameIdManagement::relay_state` |
| Send no `LogoutRequest` after a `ManageNameIDRequest` | Requester | Sequence of exchanges | Mandatory prohibition. Errata 05 E8. A logout, if intended, goes first. One call is one request, so the order belongs to the caller |
| `EncryptedID` and `NewEncryptedID` | Requester | Generate ManageNameIDRequest | Optional. Core §3.6.1. See [EncryptedID and NewEncryptedID](#encryptedid-and-newencryptedid) |

## HTTP-Redirect: receiving a ManageNameIDRequest

`receive_name_id_management_redirect` on either role. Core §§3.2.1, 3.6.1, and
3.6.3, Profiles §4.5.3.1 and §4.5.4.1.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Authenticate the request by requiring its signature | Responder | Inbound ManageNameIDRequest | Mandatory for this binding. Profiles §4.5.3.1 and §4.5.4.1. An unsigned request is `SamlError::SignatureMissing`. An HMAC signature is verified with the secret set by `with_hmac_secret` on the peer descriptor |
| `Issuer` is the peer descriptor's entity ID | Responder | Inbound ManageNameIDRequest | Library policy. Profiles §4.5.4.1 requires the requester to send `Issuer` and does not name the descriptor. The looser rule cannot be applied because the signature is verified with that descriptor's keys, and the change is attributed to it |
| A signed message carries `Destination`, and it is the receiving `ManageNameIDService` | Responder | Inbound ManageNameIDRequest | Mandatory. Core §3.2.1 and Bindings §3.4.5.2. With several published endpoints, `SamlValidationContext::with_recipient_endpoint` selects it |
| UTC `IssueInstant` | Responder | Inbound ManageNameIDRequest | Mandatory. Protocol schema; Core §1.3.3 |
| At most one `Issuer`, `ds:Signature`, and `Extensions`, in that order, then one `NameID` or `EncryptedID`, then one `NewID`, `NewEncryptedID`, or `Terminate` | Responder | Inbound ManageNameIDRequest | Mandatory. Protocol schema `RequestAbstractType` and `ManageNameIDRequestType`, checked by the same reader as SOAP. Another count, another order, another element, a child element in `NameID` or `NewID`, or content in `Terminate` is `SamlError::ProtocolProfile` |
| A `Version` other than `2.0` is answered with `VersionMismatch` | Responder | Generate ManageNameIDResponse | Core §3.2.2.2 and Profiles §4.5.3.2. The signature, `Issuer`, and `Destination` are verified first; then `ReceivedNameIdManagement::Refused` carries the signed answer, with `NameIdManagementRefusal::VersionMismatch`. Other HTTP-Redirect messages still reject another `Version` before authentication |
| `EncryptedID` and `NewEncryptedID` are decrypted | Responder | Inbound ManageNameIDRequest | Mandatory. Conformance §3.4. See [EncryptedID and NewEncryptedID](#encryptedid-and-newencryptedid). The refusal for one that does not decrypt is signed and goes to the requester's `ManageNameIDService` |
| Limit `IssueInstant` to a caller-chosen maximum age | Responder | Inbound ManageNameIDRequest | Library hardening, off. Core §1.3.3 requires a UTC `IssueInstant` and Core §3.6 defines no maximum age, so enabling it can reject a conformant request. `ManageNameIdRequestAgePolicy::Disabled` is the default on `SamlValidationContext::new`. `with_manage_name_id_request_age` with `Bounded { max_age }` uses the window, clock-skew tolerance, and overflow handling of the `AuthnRequest` age policy in [Web Browser SSO acceptance](web-browser-sso-acceptance.md). An instant outside it is `SamlError::TimeWindowInvalid` with `TimeWindowField::ManageNameIdRequestIssueInstant`. The check runs after the signature, `Destination`, and `Issuer` checks and before replay storage, so a rejected request does not occupy its `ID`. A request with another `Version` outside the window gets that error, not a `VersionMismatch` answer. A `with_replay_retention` of at least `max_age` plus both skew tolerances rejects a signed request replayed after its `ID` leaves the cache |
| The request ID is stored for replay detection | Responder | Inbound ManageNameIDRequest | Library policy, active with `ReplayPolicy::RequireCache`. The key is `ReplayKey::ManageNameIdRequestId` |
| A received `RelayState` longer than 80 bytes is accepted | Responder | Inbound ManageNameIDRequest | Bindings §3.4.3 forbids the entity creating the message from exceeding 80 bytes and has no receiver rule. The response returns the exact value. Library policy for the bound: a value longer than `MAX_RECEIVED_RELAY_STATE_BYTES`, 4096 bytes, returns `SamlError::Invalid`. It is a resource limit on unauthenticated input, not an OASIS rule |
| At most one `RelayState` value | Responder | Inbound ManageNameIDRequest | Library policy. Bindings §3.4.3 defines one `RelayState` value per message and has no receiver rule for a repeat. The looser rule is not applied because two values cannot both be the one the request carried. A second `RelayState`, matched by its decoded name, returns `SamlError::Invalid` |

## HTTP-Redirect: ManageNameIDResponse

`respond_name_id_management_redirect` and the automatic refusal. Core §3.6.2,
Profiles §4.5.3.2 and §4.5.4.2, Bindings §3.4.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Answer every processed request | Responder | Generate ManageNameIDResponse | Mandatory. Core §3.6.2 and Profiles §4.5.3.2 |
| An unrecognized identifier gets an error status, which may carry `UnknownPrincipal` | Responder | Generate ManageNameIDResponse | Mandatory error status, optional subordinate code. Core §3.6.3. The caller passes `RespondNameIdManagement::status`. Omitting it emits `Success`; that default is library policy |
| `ID`, `Version` `2.0`, UTC `IssueInstant`, and `InResponseTo` the request ID | Responder | Generate ManageNameIDResponse | Mandatory. Protocol schema `StatusResponseType`; Core §3.2.2 |
| `Issuer` is the responder's entity ID and omits `Format` | Responder | Generate ManageNameIDResponse | Mandatory. Profiles §4.5.4.2 |
| The request came from the peer being answered | Responder | Generate ManageNameIDResponse | Library policy. A request received from another descriptor is `SamlError::IssuerMismatch`, so no response is built for another party's endpoint |
| Sign the message | Responder | Generate ManageNameIDResponse | Mandatory for this binding. Profiles §4.5.3.2. Always signed |
| Send the response to `ResponseLocation` when present, otherwise `Location` | Responder | Generate ManageNameIDResponse | Metadata §2.2.2. The peer's first HTTP-Redirect `ManageNameIDService` supplies it, and it is `Destination` |
| Return the exact `RelayState` received with the request | Responder | Generate ManageNameIDResponse | Mandatory. Bindings §3.4.3. The response always echoes it. A responder may add `RelayState` to a request that had none; that is not implemented |
| Send the user agent over TLS | Responder | Generate ManageNameIDResponse | Recommendation. Profiles §4.5.3.2. Same `https` rule, relaxed alone by `RespondNameIdManagement::allow_http_name_id_management`, and for the automatic refusal by `ReceiveNameIdManagement::allow_http_name_id_management` |

## HTTP-Redirect: receiving a ManageNameIDResponse

`finish_name_id_management_redirect` on either role. Profiles §4.5.3.2 and
§4.5.4.2.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Authenticate the response by requiring its signature | Requester | Inbound ManageNameIDResponse | Mandatory for this binding. Profiles §4.5.3.2 and §4.5.4.2 |
| `InResponseTo` is the pending request ID | Requester | Inbound ManageNameIDResponse | Mandatory. Core §3.2.2. `PendingManageNameIdRequest` is the source of the expected ID. It restores from a `PendingSnapshot` |
| The response comes from the peer the request went to, with the `RelayState` the request carried | Requester | Inbound ManageNameIDResponse | Library policy for the peer and for `RelayState`. Bindings §3.4.3 obliges the responder to return the exact `RelayState` and has no receiver rule. Present empty and a present value are distinct. When the request carried none, Bindings §3.4.3 lets the responder include one, empty or not; it is accepted, and `finish_name_id_management_redirect` returns it. A received value longer than 80 bytes is accepted up to `MAX_RECEIVED_RELAY_STATE_BYTES`, as for the request |
| At most one `RelayState` value | Requester | Inbound ManageNameIDResponse | Library policy, as for the request. Bindings §3.4.3 defines one `RelayState` value per message and has no receiver rule for a repeat. The looser rule is not applied because two values cannot both be the one the request carried. A second `RelayState`, matched by its decoded name, returns `SamlError::Invalid` |
| A signed message carries `Destination`, and it is this provider's response location | Requester | Inbound ManageNameIDResponse | Mandatory. Core §3.2.2 and Bindings §3.4.5.2 |
| One `Status` with one `StatusCode` | Requester | Inbound ManageNameIDResponse | Protocol schema `StatusResponseType` and `StatusType`. A second `Status` or a second direct `StatusCode` is `SamlError::ProtocolProfile`, so a later error status is never hidden behind a first `Success` |
| A status other than `Success` is returned as an error | Requester | Inbound ManageNameIDResponse | `SamlError::StatusNotSuccess` with both codes. Library policy: the status is read only after the signature, `Issuer`, `InResponseTo`, and `Destination` checks pass, so an unauthenticated or unrelated error response returns that check's error. Web SSO runs the same checks without requiring a signature, as recorded in [acceptance](web-browser-sso-acceptance.md) |
| The response ID is stored for replay detection | Requester | Inbound ManageNameIDResponse | Library policy, active with `ReplayPolicy::RequireCache`. The key is `ReplayKey::ManageNameIdResponseId` |

## EncryptedID and NewEncryptedID

Both bindings, at the identity provider and the service provider. Core
§3.6.1, Conformance Requirements §3.4, and Profiles §4.5.5, as corrected by
Approved Errata 05 E12, E19, and E43.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Send `EncryptedID` in place of `NameID`, and `NewEncryptedID` in place of `NewID` | Requester | Generate ManageNameIDRequest | Optional. Core §3.6.1 allows either form. Conformance §3.4 requires the capability, which stays off until the caller selects `IdentifierEncryptionPolicy::EncryptIdentifiers` for one request: the `identifier_encryption` argument of `start_name_id_management`, or `StartNameIdManagement::identifier_encryption` for `start_name_id_management_redirect`, as `StartSlo::identifier_encryption` does for logout. `XmlEncryptionPolicy::identifiers` does not select it. `Terminate` is not encrypted. Unselected, the request carries `NameID` and `NewID` |
| `NewEncryptedID` carries a `NewID` with the new value only | Requester | Generate ManageNameIDRequest | Mandatory. Errata 05 E12 |
| Encrypt for the responder | Requester | Generate ManageNameIDRequest | Optional. Profiles §4.5.5: the requester can use the responder's `KeyDescriptor` with `use="encryption"`. The first encryption certificate the peer's metadata publishes is the recipient. None is `SamlError::MissingMetadata`. `AlgorithmPolicy::data_encryption` and `key_encryption` choose the algorithms. The encrypted element is its inclusive canonical form, and the `EncryptedKey` is in the `ds:KeyInfo` of `EncryptedData` |
| Decrypt `EncryptedID` and `NewEncryptedID` | Responder | Inbound ManageNameIDRequest | Mandatory. Conformance §3.4: every operational mode processes the encrypted form wherever it processes `NameID`, and Table 2 makes this protocol such a context. Decryption does not depend on `XmlEncryptionPolicy::identifiers`. The key is the receiver's `Credentials::decryption_key`. It runs after the request is authenticated: by `SoapChannel` over SOAP, by the signature over HTTP-Redirect. On both bindings it also runs after the `Issuer` check and, when the caller enables them, the `IssueInstant` age check and replay storage, so a request those checks reject is not decrypted. `ManageNameIdRequest::name_id` and `ManageNameIdRequest::change` return the plaintext |
| Find the `EncryptedKey` | Responder | Inbound ManageNameIDRequest | Core §6.2 as replaced by Errata 05 E43. A key embedded in `EncryptedData`, or beside it and named by a `ds:RetrievalMethod`, is resolved, as for the assertion `EncryptedID` |
| The `EncryptedID` plaintext is one `NameID`, and the `NewEncryptedID` plaintext one `NewID`, each with text content only | Responder | Inbound ManageNameIDRequest | Library policy. Core §3.6.1 and Errata 05 E12 require that content of the requester. Other content is treated as an element that does not decrypt |
| A plaintext `NameID` or `NewID` is accepted | Responder | Inbound ManageNameIDRequest | No receiver rule. Core §3.6.1 allows either form, whatever this provider's `XmlEncryptionPolicy` |
| An element that does not decrypt is answered with an error status | Responder | Generate ManageNameIDResponse | Core §3.6.2 requires an answer. Errata 05 E19 recommends a SAML status, not a SOAP fault, for a SAML-domain error. The codes are library policy, as the Shibboleth SP answers: `EncryptedID` gets `Requester` with `UnknownPrincipal`, which Core §3.6.3 names for an unrecognized principal, and `NewEncryptedID` gets `Requester`. `ReceivedNameIdManagement::Refused` carries the response, with `NameIdManagementRefusal::UndecryptableIdentifier` or `UndecryptableNewIdentifier`. A missing decryption key, a key that does not match, and an unsupported algorithm are such elements. `RefusedNameIdManagement::decryption_error` returns that cause to the caller; the response carries only the status |

## After the exchange

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| After the service provider's `NewID`, send that value as `SPProvidedID` | Identity provider | Generate Response | Mandatory. Core §3.6.3, as amended by E55, and Core §8.3.7. The caller stores the value. `respond_sso`, `respond_sso_artifact`, and `respond_paos_sso` write the subject `NameId` `SPProvidedID`. A login response template cannot carry it, so that combination is `SamlError::Invalid` |
| After the identity provider's `NewID`, issue the new value | Identity provider | Generate Response | Core §3.6.3. The caller passes the new value in later responses |
| After the identity provider's `NewID`, use the new value | Service provider | Later messages | Mandatory. Core §3.6.3, as amended by E55. The service provider stores it and sends it as the `NameID` content, for example in a later `LogoutSubject` |
| After a termination, remove state kept for the identifier | Responder | Application | Recommendation. Core §3.6.3 as amended by E14: later operations should behave as if that state never existed. saml-rs keeps no identifier state |
| After a termination, stop issuing assertions with that identifier | Identity provider | Application | Core §3.6.3, as amended by E55. The caller's account store owns the relationship |
| A termination does not end sessions | Responder | Application | Recommendation. Errata 05 E8: the receiver should not invalidate active sessions, and an identity provider should not end the principal's sessions at other service providers. saml-rs does not track sessions and ends none |
| Accept either identifier while a change propagates | Both providers | Application | Optional. Core §3.6.3. Left to the caller |

## Outside this flow

- Name identifier management over HTTP-POST and HTTP-Artifact.
- SOAP name identifier management at the service provider.
- Signing or verifying `ManageNameIDRequest` and `ManageNameIDResponse` over
  SOAP.
- Name identifier mapping.
- The IdP operational mode and the SP operational mode.
