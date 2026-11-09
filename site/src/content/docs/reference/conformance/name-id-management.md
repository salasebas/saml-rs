---
title: "Name identifier management"
description: "Rules for typed name identifier management over SOAP at the identity provider: start_name_id_management, receive_name_id_management, and respond_name_id_management."
---

Rules for typed name identifier management at the identity provider:
`Saml<Idp>::start_name_id_management`, `StartedNameIdManagement::finish`,
`Saml<Idp>::receive_name_id_management`, and
`Saml<Idp>::respond_name_id_management`.

SAML V2.0 Conformance Requirements Table 2, with the labels from Approved
Errata 05 E11, marks two cells this record covers. Name Identifier Management,
SOAP (IdP-initiated) is `MUST` for the IdP. Name Identifier Management, SOAP
(SP-initiated) is `MUST` for the IdP. Both cells are `OPTIONAL` for the SP and
stay off: `Saml<Sp>` has no SOAP name identifier management. Both cells are
`MUST NOT` for IdP Lite and SP Lite. The HTTP-Redirect cells are not
implemented. Name identifier mapping is not implemented. This record does not
claim the IdP or SP operational mode.

Normative text is SAML Core 2.0 §§3.2 and 3.6, Profiles 2.0 §4.5, Bindings 2.0
§3.2, and Metadata 2.0 §2.4.2, as corrected by Approved Errata 05. Errata that
change this flow are E8, E11, E12, E19, and E55. Schema citations are the
OASIS protocol and metadata schemas.

The deployment POSTs the SOAP envelope. TLS, HTTP authentication, and an HTTP
500 SOAP fault stay there. Conformance Requirements §3.5 and §5 are those
deployment duties. `SoapChannel` records the protection the deployment
provided, as in [Artifact resolution](artifact-resolution.md).

## Turning the protocol on

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Publish a SOAP `ManageNameIDService` | Identity provider | IdP metadata | Metadata §2.4.2 defines the endpoint. `IdpConfigBuilder::manage_name_id_service` publishes it with the SOAP binding |
| Without a published `ManageNameIDService`, neither send nor accept the protocol | Identity provider | Local API | Library policy. Table 2 prohibits the protocol for IdP Lite. An identity provider without the endpoint is that configuration: `start_name_id_management` and `receive_name_id_management` return `SamlError::MissingMetadata`. A requester does not need its own endpoint for a SOAP exchange; the looser rule cannot be applied because the endpoint is the only setting that tells an IdP from an IdP Lite configuration |
| The service provider has no SOAP name identifier management | Service provider | Local API | Table 2 marks the SP SOAP cells `OPTIONAL`. They stay off. SP Lite is `MUST NOT` |
| The service provider's endpoint comes from its metadata | Identity provider | Generate ManageNameIDRequest | Optional. Profiles §4.5.3.1. The first SOAP `ManageNameIDService` `Location` in the `SPSSODescriptor` is used. An endpoint of another role in the same entity is not. A service provider without one is `SamlError::MissingMetadata` |

## ManageNameIDRequest from the identity provider

`Saml<Idp>::start_name_id_management` is this actor. Core §3.6.1 and §3.6.3,
Profiles §4.5.3.1 and §4.5.4.1.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Send the request on a synchronous binding | Requester | Generate ManageNameIDRequest | Optional binding choice. Profiles §4.5.3.1. The binding is SOAP 1.1 |
| `ID`, `Version` `2.0`, and UTC `IssueInstant` are present | Requester | Generate ManageNameIDRequest | Mandatory. Protocol schema `RequestAbstractType`; Core §1.3.3 |
| `Destination` is the service provider's endpoint | Requester | Generate ManageNameIDRequest | Optional in Core §3.2.1. Set to the metadata location |
| `Issuer` is present and omits `Format` | Requester | Generate ManageNameIDRequest | Mandatory. Profiles §4.5.4.1 allows an omitted `Format` or `entity`. Generation omits it |
| The `NameID` is the identifier as both providers know it | Requester | Generate ManageNameIDRequest | Mandatory. Core §3.6.3. The caller passes the established `NameId`. `Format`, `NameQualifier`, `SPNameQualifier`, and `SPProvidedID` are sent as given. A `NameId` without a format takes the first configured NameID format, the one `respond_sso` writes |
| A persistent identifier carries `SPNameQualifier` | Requester | Generate ManageNameIDRequest | Mandatory. Core §3.6.3. It is the service provider, or the affiliation the caller passes. When the caller passes none, the service provider's entity ID is written |
| A persistent identifier carries `NameQualifier` | Requester | Generate ManageNameIDRequest | Core §3.6.3: it must be the identity provider that created the identifier. It may be omitted when it equals `Issuer`, which is not recommended. When the caller passes none, this identity provider's entity ID is written. There is no switch to omit it |
| `NewID` carries the new value only | Requester | Generate ManageNameIDRequest | Mandatory. Errata 05 E12: format and qualifiers cannot be changed once established. `NameIdChange::NewId` holds the value |
| A persistent or transient identifier is at most 256 characters | Requester | Generate ManageNameIDRequest | Mandatory. Core §§8.3.7 and 8.3.8. The current `NameID` value and the new value are checked. A longer value is `SamlError::Invalid` |
| `Terminate` ends the identifier | Requester | Generate ManageNameIDRequest | Core §3.6.3, as amended by E55. `NameIdChange::Terminate` writes an empty `Terminate` |
| A `LogoutRequest` meant to end activity comes before the termination | Requester | Application | Mandatory ordering. Errata 05 E8: the requester must not send `LogoutRequest` after the `ManageNameIDRequest`. The method documentation states it. saml-rs does not track sessions |
| Authenticate the requester and protect integrity | Requester | SOAP exchange | Mandatory. Profiles §4.5.3.1 and §4.5.4.1 allow a signature or a binding mechanism. The mechanism is `SoapChannel`: mutual authentication and integrity, or `SamlError::SoapChannelProtection` before a request is built. The request is not signed. Core §3.6.1 recommends a signature or binding protection; the channel is that protection |
| The SOAP body contains exactly one SAML request | Requester | SOAP envelope | Mandatory. Bindings §3.2.2.1, as left by Errata 05 E19 |
| `Cache-Control: no-cache, no-store` and `Pragma: no-cache` | Requester | HTTP | Recommendation. Bindings §3.2.3.2. `SoapRequest` reports those values |

## ManageNameIDResponse from the service provider

`StartedNameIdManagement::finish` is this actor. Core §3.2.2 and §3.6.2,
Profiles §4.5.3.2 and §4.5.4.2.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| The SOAP body is one `ManageNameIDResponse` | Requester | Inbound ManageNameIDResponse | Bindings §3.2.2.1; Core §3.6.2 |
| `Version` is `2.0`, `ID` is present, and `IssueInstant` is a UTC `xs:dateTime` | Requester | Inbound ManageNameIDResponse | Protocol schema `StatusResponseType`; Core §1.3.3 |
| `InResponseTo` is present and equals the request `ID` | Requester | Inbound ManageNameIDResponse | Mandatory. Core §3.2.1 and §3.2.2 |
| One `Status` | Requester | Inbound ManageNameIDResponse | Protocol schema. A second `Status` is malformed |
| A status other than Success is returned to the caller | Requester | Inbound ManageNameIDResponse | Core §3.6.3: an unrecognized identifier is an error status, optionally `UnknownPrincipal`. `finish` returns `SamlError::StatusNotSuccess` with both codes. `Ok` means Success |
| `Issuer` is present, equals the service provider, and omits `Format` or sets it to `entity` | Requester | Inbound ManageNameIDResponse | Library policy. Profiles §4.5.4.2 requires the responder to send that `Issuer` and does not require the requester to reject another response. The looser rule cannot be applied because the requester attributes the response by that `Issuer` together with `SoapChannel`. Without it, `finish` would report a change that is not attributed to the service provider |
| The responder authenticates itself and protects integrity | Responder | SOAP exchange | Mandatory. Profiles §4.5.3.2 and §4.5.4.2. Satisfied by the `SoapChannel` attested on `start_name_id_management`. A response signature is not verified |
| A `Destination` on the response is not compared | Requester | Inbound ManageNameIDResponse | Core §3.2.2 compares `Destination` with the location where the message was received. A synchronous SOAP response is read from the requester's own HTTP exchange and has no receiving location |

## ManageNameIDRequest from the service provider

`Saml<Idp>::receive_name_id_management` is this actor. Core §§3.2.1, 3.6.1,
and 3.6.3, Profiles §4.5.3.2 and §4.5.4.1.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| The SOAP body is one `ManageNameIDRequest` | Responder | Inbound ManageNameIDRequest | Bindings §3.2.2.1. Another body, a second body element, or a SOAP header with `mustUnderstand` is `SamlError`. The deployment can answer it with a SOAP fault |
| `ID` is present and `IssueInstant` is a UTC `xs:dateTime` | Responder | Inbound ManageNameIDRequest | Protocol schema `RequestAbstractType`; Core §1.3.3 |
| A `Version` other than `2.0` is answered with `VersionMismatch` | Responder | Generate ManageNameIDResponse | Core §3.2.2.2. `ReceivedNameIdManagement::Refused` carries the response, with `NameIdManagementRefusal::VersionMismatch` |
| The requester authenticated itself and protected integrity | Requester | SOAP exchange | Mandatory. Profiles §4.5.4.1. The check is `SoapChannel`: mutual authentication and integrity, or `SamlError::SoapChannelProtection` before the envelope is read. A request signature is not verified. Refusing a signed request on a channel that does not authenticate the requester is library policy: Profiles §4.5.3.1 also accepts a signature. The looser rule cannot be applied because this identity provider does not verify signatures on this message, so the request would be processed without any authentication |
| `Issuer` is present, equals the service provider, and omits `Format` or sets it to `entity` | Responder | Inbound ManageNameIDRequest | Library policy. Profiles §4.5.4.1 requires the requester to send that `Issuer` and does not require the responder to reject another request. The looser rule cannot be applied because the responder ties the change to the service provider by that `Issuer` together with `SoapChannel`. A missing or different `Issuer` is `SamlError::IssuerMismatch`. A second `Issuer` is malformed |
| A present `Destination` is the receiving endpoint | Responder | Inbound ManageNameIDRequest | Mandatory. Core §3.2.1: a request whose `Destination` is not the receiving location is discarded. The receiving location is this identity provider's SOAP `ManageNameIDService`. With more than one, `SamlValidationContext::with_recipient_endpoint` selects it. An absent `Destination` is accepted |
| One `NameID` or `EncryptedID`, then one `NewID`, `NewEncryptedID`, or `Terminate` | Responder | Inbound ManageNameIDRequest | Protocol schema `ManageNameIDRequestType`. Another element, a missing one, or a second one is malformed. `Issuer`, `ds:Signature`, and `Extensions` are not counted. `NameID` and `NewID` are `xs:string` content and `Terminate` is empty, so a child element, or text in `Terminate`, is malformed |
| `EncryptedID` or `NewEncryptedID` is answered with an error status | Responder | Generate ManageNameIDResponse | Profiles §4.5.3.2 requires a response with an appropriate status. This identity provider does not decrypt either element. The response is `Responder` with `RequestUnsupported`, in `ReceivedNameIdManagement::Refused` with `NameIdManagementRefusal::EncryptedIdentifier`. Errata 05 E19 recommends a SAML status, not a SOAP fault, for a SAML-domain error |
| The request `ID` is recorded for replay detection | Responder | Inbound ManageNameIDRequest | Library policy, active when the caller selects `ReplayPolicy::RequireCache`. The key is `ReplayKey::ManageNameIdRequestId`. A repeated `ID` is `SamlError::ReplayDetected` |
| The `NameID` is returned as sent | Responder | Inbound ManageNameIDRequest | Core §3.6.3 makes the requester send the most recent identifier. `ManageNameIdRequest::name_id` carries the value, `Format`, `NameQualifier`, `SPNameQualifier`, and `SPProvidedID`. A persistent identifier without its qualifiers is not rejected: the qualifier rule binds the requester |

## ManageNameIDResponse from the identity provider

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

## After the exchange

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| After the service provider's `NewID`, send that value as `SPProvidedID` | Identity provider | Generate Response | Mandatory. Core §3.6.3, as amended by E55, and Core §8.3.7. The caller stores the value. `respond_sso`, `respond_sso_artifact`, and `respond_paos_sso` write the subject `NameId` `SPProvidedID`. A login response template cannot carry it, so that combination is `SamlError::Invalid` |
| After the identity provider's `NewID`, issue the new value | Identity provider | Generate Response | Core §3.6.3. The caller passes the new value in later responses |
| After a termination, stop issuing assertions with that identifier | Identity provider | Application | Core §3.6.3, as amended by E55. The caller's account store owns the relationship |
| A termination does not end sessions | Responder | Application | Recommendation. Errata 05 E8: the receiver should not invalidate active sessions, and an identity provider should not end the principal's sessions at other service providers. saml-rs does not track sessions and ends none |
| Accept either identifier while a change propagates | Both providers | Application | Optional. Core §3.6.3. Left to the caller |

## Outside this flow

- Name identifier management over HTTP-Redirect, HTTP-POST, and HTTP-Artifact.
- SOAP name identifier management at the service provider.
- Decrypting `EncryptedID` and `NewEncryptedID`, or generating them.
- Signing or verifying `ManageNameIDRequest` and `ManageNameIDResponse`.
- Name identifier mapping.
- The IdP operational mode and the SP operational mode.
