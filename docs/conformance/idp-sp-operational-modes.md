# IdP and SP operational modes

SAML V2.0 Conformance names the operational modes that an implementation can
claim, and its feature matrix gives each feature a level for each mode. This
record sets `IdentityProvider` and `ServiceProvider` against those levels:
which modes the crate plays, the status of each feature at each role, and
what keeps each mode from being claimed. It claims no mode.

Normative text is
[Conformance Requirements](https://docs.oasis-open.org/security/saml/v2.0/saml-conformance-2.0-os.pdf)
§§3 to 5, as corrected by
[Approved Errata 05](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/).
E11 relabels the four name identifier management rows of Table 2. E25 adds
the Metadata Structures and Metadata Interoperation rows to Tables 2 and 4,
with §3.6 and §3.7, and E29 adds the Request for Assertion by Identifier and
SAML URI Binding rows to Table 2. E42 sets to N/A the cells of an authority
for another authority's query, and E50 makes the §4 and §5 algorithms a
minimal set.

An implementation of a mode implements every feature that the mode's column
marks `MUST` and none that it marks `MUST NOT` (Conformance §1, §3.1), and
§§3.3 to 5 add requirements for every relevant mode. Each status below is
the status that the record in the Record column gives, and that record holds
the rules. A cell takes the status of the record's row for the message on
that binding, and drops to `Partial` when a form of the message that a
Mandatory rule requires of the role is `Partial` or `Not supported` there.

The statuses hold on builds with a crypto provider. A build without one
signs, verifies, encrypts, and decrypts nothing, so its identity provider
issues no SSO `Response` and neither role completes a logout. The build
paragraph of each flow record says which of its exchanges still run.

## Modes

Conformance §3.1 lists the modes. Table 2 gives the features of IdP, IdP
Lite, SP, SP Lite, and ECP, Table 3 adds two features to IdP and SP, and
Table 4 gives those of the SAML authorities and the requester.

| Mode | Table | Role in saml-rs | Required features not fully supported |
| --- | --- | --- | --- |
| IdP | 2 | `IdentityProvider` | [1 of 14](#idp), and the [algorithms](#all-four-modes) on some builds |
| IdP Lite | 2 | `IdentityProvider` | [1 of 8](#idp-lite), and the algorithms on some builds. 4 `MUST NOT` features to leave off |
| SP | 2 | `ServiceProvider` | [6 of 11](#sp), §3.3 and §3.4, and the algorithms on some builds |
| SP Lite | 2 | `ServiceProvider` | [4 of 7](#sp-lite), §3.3 and §3.4, and the algorithms on some builds. 2 `MUST NOT` features to leave off |
| IdP Extended | 3 | Not implemented | [2 of 2](#extended-idp-and-sp) in Table 3, with each gap of IdP |
| SP Extended | 3 | Not implemented | 2 of 2 in Table 3, with each gap of SP |
| ECP | 2 | Not implemented | [1 of 1](#exchanges-not-implemented): Enhanced Client/Proxy SSO |
| SAML Authentication Authority | 4 | Not implemented | [3 of 3](#saml-authorities-and-requester) |
| SAML Attribute Authority | 4 | Not implemented | 3 of 3 |
| SAML Authorization Decision Authority | 4 | Not implemented | 3 of 3 |
| SAML Requester | 4 | Not implemented | No cell is `MUST`. The crate sends none of the five requests |

<a id="metadata"></a>

## Feature matrix

The rows are Table 2 as corrected by E11, E25, and E29, and the level
columns are the four modes that the crate plays. The ECP column of Table 2
requires only Enhanced Client/Proxy SSO.

| Feature | IdP | IdP Lite | SP | SP Lite | Identity provider | Service provider | Record |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Web SSO, `<AuthnRequest>`, HTTP redirect | `MUST` | `MUST` | `MUST` | `MUST` | Supported | Supported | [SSO generation](web-browser-sso-generation.md#authnrequest), [SSO acceptance](web-browser-sso-acceptance.md#identity-provider-authnrequest) |
| Web SSO, `<Response>`, HTTP POST | `MUST` | `MUST` | `MUST` | `MUST` | Supported | Partial | [SSO generation](web-browser-sso-generation.md#response), [SSO acceptance](web-browser-sso-acceptance.md#service-provider-delivery-and-signatures) |
| Web SSO, `<Response>`, HTTP artifact | `MUST` | `MUST` | `MUST` | `MUST` | Supported | Partial | [HTTP-Artifact response](web-browser-sso-artifact.md#support), [SSO acceptance](web-browser-sso-acceptance.md#service-provider-delivery-and-signatures) |
| Artifact Resolution, SOAP | `MUST` | `MUST` | `MUST` | `MUST` | Supported | Supported | [Artifact resolution](artifact-resolution.md#artifact-exchange) |
| Enhanced Client/Proxy SSO, PAOS | `MUST` | `MUST` | `MUST` | `MUST` | Not supported | Not supported | [Exchanges not implemented](#exchanges-not-implemented) |
| Name Identifier Management (IdP-Initiated), HTTP Redirect | `MUST` | `MUST NOT` | `MUST` | `MUST NOT` | Supported | Supported | [Name identifier management](name-id-management.md#messages-and-bindings) |
| Name Identifier Management (IdP-Initiated), SOAP | `MUST` | `MUST NOT` | `OPTIONAL` | `MUST NOT` | Supported | Not supported | [Name identifier management](name-id-management.md#messages-and-bindings) |
| Name Identifier Management (SP-Initiated), HTTP Redirect | `MUST` | `MUST NOT` | `MUST` | `MUST NOT` | Supported | Partial | [Name identifier management](name-id-management.md#requests) |
| Name Identifier Management (SP-Initiated), SOAP | `MUST` | `MUST NOT` | `OPTIONAL` | `MUST NOT` | Supported | Not supported | [Name identifier management](name-id-management.md#messages-and-bindings) |
| Single Logout (IdP-initiated), HTTP redirect | `MUST` | `MUST` | `MUST` | `MUST` | Supported | Supported | [Single Logout](single-logout.md#messages-and-bindings) |
| Single Logout (IdP-initiated), SOAP | `MUST` | `OPTIONAL` | `MUST` | `OPTIONAL` | Supported | Supported | [Single Logout](single-logout.md#messages-and-bindings) |
| Single Logout (SP-initiated), HTTP redirect | `MUST` | `MUST` | `MUST` | `MUST` | Supported | Partial | [Single Logout](single-logout.md#logout-requests) |
| Single Logout (SP-initiated), SOAP | `MUST` | `OPTIONAL` | `MUST` | `OPTIONAL` | Supported | Partial | [Single Logout](single-logout.md#logout-requests) |
| Identity Provider Discovery (cookie) | `MUST` | `MUST` | `OPTIONAL` | `OPTIONAL` | Supported | Not supported | [Identity Provider Discovery](identity-provider-discovery.md#common-domain-cookie) |
| Metadata Structures | `OPTIONAL` | `OPTIONAL` | `OPTIONAL` | `OPTIONAL` | Partial | Partial | [Metadata documents](metadata-and-replay.md#metadata-documents), [not supported](metadata-and-replay.md#not-supported) |
| Metadata Interoperation | `OPTIONAL` | `OPTIONAL` | `OPTIONAL` | `OPTIONAL` | Not supported | Not supported | [Metadata documents](metadata-and-replay.md#metadata-documents) |
| Request for Assertion by Identifier | `OPTIONAL` | N/A | N/A | N/A | Not supported | — | [Exchanges not implemented](#exchanges-not-implemented) |
| SAML URI Binding | `OPTIONAL` | N/A | N/A | N/A | Not supported | — | [Exchanges not implemented](#exchanges-not-implemented) |

Table 2 lists the Web SSO `AuthnRequest` on HTTP redirect and the `Response`
on HTTP POST and HTTP artifact. Profiles §4.1.2 forbids
HTTP-Redirect for the `Response`, and `SsoResponseBinding` has no such
variant. The flow records also cover the `AuthnRequest` over HTTP-POST and
HTTP-POST-SimpleSign, the `Response` over HTTP-POST-SimpleSign, and Single
Logout over HTTP-POST and HTTP-POST-SimpleSign.

The `SigAlg` methods of HTTP redirect depend on the build, so one
[requirement row](#requirements-outside-the-matrix) holds them and the HTTP
redirect rows do not count them.
[Browser bindings](browser-bindings.md#detached-signatures) marks the
HTTP-Redirect signature `Partial` for the same reason.

Single Logout marks a `BaseID` principal `Partial` at both roles. No cell
here drops for it, because Core §3.7.1 lets the requester choose that
identifier and neither role issues or accepts an assertion whose `Subject`
names one.

Metadata Structures (§3.6) asks a mode that elects it to make its metadata
available to each peer that may depend on it, and to use a peer's metadata
again when the cached copy has expired or is no longer valid, if a copy is
available and policy, the operation, and the exchange permit it. The crate
writes its own role's metadata and imports a peer's document, and the
metadata record lists serving a document and fetching a fresh copy as not
supported, so the cell is `Partial`.

## What blocks each mode

Each list names the `MUST` features and requirements of the mode that its
role does not support in full, and the `MUST NOT` features that the role
supports. [All four modes](#all-four-modes) lists the algorithm requirements
that the four modes share.

### IdP

- Enhanced Client/Proxy SSO, PAOS: Not supported. The crate implements no
  end of the ECP profile and no PAOS binding.

### IdP Lite

- Enhanced Client/Proxy SSO, PAOS: Not supported, as for IdP.
- The four name identifier management features are `MUST NOT`, and the
  identity provider supports all four. Configure no `ManageNameIDService`
  with `IdpConfigBuilder::manage_name_id_service`. Without one, the identity
  provider neither sends nor accepts the protocol, as the
  [library policies](name-id-management.md#library-policies) of name
  identifier management record.

### SP

- Web SSO, `<Response>`, HTTP POST, and Web SSO, `<Response>`, HTTP
  artifact: Partial. A `Response` whose namespace declaration spells the
  protocol or assertion namespace with an XML character reference can fail,
  as [SSO acceptance](web-browser-sso-acceptance.md#namespace-declarations-with-character-references)
  records, and an artifact `Response` follows the same rows.
- Enhanced Client/Proxy SSO, PAOS: Not supported, as for IdP.
- Name Identifier Management (SP-Initiated), HTTP Redirect: Partial. The
  service provider writes an `entity` `NameID` that breaks Core §8.3.6 into
  its `ManageNameIDRequest` unchanged, as
  [service provider requests](name-id-management.md#service-provider-requests)
  records.
- Single Logout (SP-initiated), HTTP redirect, and Single Logout
  (SP-initiated), SOAP: Partial. The service provider writes such a `NameID`
  into its `LogoutRequest` unchanged, as
  [service provider `NameID`](single-logout.md#service-provider-nameid)
  records.
- Every name identifier format, §3.3: Partial, for that `entity` `NameID`, as
  [identifiers](identifiers.md#service-provider-requests) records.
- `EncryptedID` in a `LogoutRequest` and in a `ManageNameIDRequest`, §3.4:
  Partial, because it carries that `NameID`.

### SP Lite

- Web SSO, `<Response>`, HTTP POST, and Web SSO, `<Response>`, HTTP
  artifact: Partial, as for SP.
- Enhanced Client/Proxy SSO, PAOS: Not supported, as for IdP.
- Single Logout (SP-initiated), HTTP redirect: Partial, as for SP.
- Every name identifier format, §3.3, and `EncryptedID` in a
  `LogoutRequest`, §3.4: Partial, as for SP.
- Name Identifier Management (IdP-Initiated), HTTP Redirect, and Name
  Identifier Management (SP-Initiated), HTTP Redirect, are `MUST NOT`, and the
  service provider supports both. Configure no `ManageNameIDService` with
  `SpConfigBuilder::manage_name_id_redirect_service`. The service provider
  implements neither SOAP feature.

### All four modes

These algorithm [requirements](#requirements-outside-the-matrix) are `MUST`
for each of the four modes and are not supported in full at either role:

- SHA-1 digest, HMAC-SHA1, and RSAwithSHA1, §4.1: `crypto-fips` lacks all
  three, and `crypto-aws-lc` verifies RSAwithSHA1 but does not sign with it.
- RSAwithSHA1 and DSAwithSHA1 as the `SigAlg`, Bindings §3.4.4.1, for each
  HTTP redirect feature of Table 2: only RustCrypto with
  `crypto-legacy-algorithms` signs and verifies both.
- Triple DES, RSA-v1.5, and RSA-OAEP, §4.2: RustCrypto without
  `crypto-legacy-algorithms` lacks Triple DES and RSA-v1.5, `crypto-aws-lc`
  lacks Triple DES and needs `crypto-legacy-algorithms` for RSA-v1.5, and
  `crypto-fips` lacks all three.

On RustCrypto with `crypto-legacy-algorithms`, as in the default build,
every algorithm requirement holds. RSA-v1.5 decryption also needs
`Rsa15KeyTransportPolicy::AllowDecryption`.

<a id="saml-defined-identifiers"></a>
<a id="encrypted-elements"></a>
<a id="xml-signature-and-xml-encryption-algorithms"></a>

## Requirements outside the matrix

Conformance §§3.3, 3.4, and 4 apply to each relevant mode, and Bindings
§3.4.4.1 to each HTTP redirect feature. E50 lets an implementation use
algorithms beyond the §4 set.

| Requirement | Level | Section | Identity provider | Service provider | Record |
| --- | --- | --- | --- | --- | --- |
| Create and process every attribute name format of Core §8.2 | `MUST` | Conformance §3.3 | Supported | Supported | [Attributes](identifiers.md#attributes) |
| Create and process every name identifier format of Core §8.3 | `MUST` | Conformance §3.3 | Supported | Partial | [Name identifiers](identifiers.md#name-identifiers) |
| The processing rules of persistent and transient identifiers, Core §8.3.7 and §8.3.8 | `MUST` | Conformance §3.3 | Supported | Supported | [Name identifier formats](identifiers.md#name-identifier-formats), [duties](identifiers.md#application-duties) |
| `EncryptedAssertion` in a `Response`, and `EncryptedID` and `EncryptedAttribute` in its assertions | `MUST` | Conformance §3.4 | Supported | Supported | [SSO generation](web-browser-sso-generation.md#response), [SSO acceptance](web-browser-sso-acceptance.md#service-provider-assertions-and-statements) |
| `EncryptedID` in the requested `Subject` of an `AuthnRequest` | `MUST` | Conformance §3.4 | Supported | — | [SSO acceptance](web-browser-sso-acceptance.md#identity-provider-authnrequest) |
| `EncryptedID` in a `LogoutRequest` | `MUST` | Conformance §3.4 | Supported | Partial | [Logout requests](single-logout.md#logout-requests) |
| `EncryptedID` and `NewEncryptedID` in a `ManageNameIDRequest` | `MUST` | Conformance §3.4 | Supported | Partial | [Requests](name-id-management.md#requests) |
| SHA-1 digest, HMAC-SHA1, and RSAwithSHA1 | `MUST` | Conformance §4.1 | Partial | Partial | [Signature algorithms by build](xml-security-algorithms.md#signature-algorithms-by-build) |
| Canonical XML 1.0 without comments, and the enveloped-signature transform | `MUST` | Conformance §4.1 | Supported | Supported | [XML Signature](xml-security-algorithms.md#xml-signature) |
| DSAwithSHA1 | `RECOMMENDED` | Conformance §4.1 | Partial | Partial | [Signature algorithms by build](xml-security-algorithms.md#signature-algorithms-by-build) |
| RSAwithSHA1 and DSAwithSHA1 as the HTTP-Redirect `SigAlg` | `MUST` | Bindings §3.4.4.1 | Partial | Partial | [Signature algorithms by build](xml-security-algorithms.md#signature-algorithms-by-build) |
| AES-128 and AES-256 | `MUST` | Conformance §4.2 | Supported | Supported | [XML Encryption](xml-security-algorithms.md#xml-encryption) |
| Triple DES, RSA-v1.5, and RSA-OAEP | `MUST` | Conformance §4.2 | Partial | Partial | [Encryption algorithms by provider](xml-security-algorithms.md#encryption-algorithms-by-provider) |

The crate handles every Core §8.2 and §8.3 identifier natively, and
`AttributeNameFormat::Custom` and `NameIdFormat::Custom` carry any other URI.
§3.4 asks nothing where the crate neither writes nor reads the unencrypted
element: the `Subject` of a service provider `AuthnRequest`, the identifier
of a `SubjectConfirmation` (Core §2.4.1.1), an assertion in `Advice` or
`Evidence`, and the messages of attribute queries and name identifier
mapping.

<a id="soap-and-uri-security-models"></a>
<a id="tls"></a>

## Application duties

The crate builds and reads messages and opens no connection. The
deployment's HTTP client and server carry each SOAP exchange and pass
`SoapChannel` the protection they established, as
[artifact resolution](artifact-resolution.md#application-duties) describes.

| Duty | Level | Section |
| --- | --- | --- |
| Implement four authentication methods for each SOAP exchange: none, HTTP basic authentication with and without SSL 3.0 or TLS 1.0, server authentication over SSL 3.0 or TLS 1.0, and mutual authentication over SSL 3.0 or TLS 1.0. With HTTP basic authentication, the requester sends the `Authorization` header with its first request | Mandatory | Conformance §3.5 |
| Use a server certificate when a SAML authority runs SSL 3.0 or TLS 1.0 | Mandatory | Conformance §3.5 |
| Authenticate each SSL 3.0 or TLS 1.0 server with an X.509 v3 certificate, and establish the server's identity from that certificate at the client | Mandatory | Conformance §5 |
| Implement `TLS_RSA_WITH_3DES_EDE_CBC_SHA` when TLS-capable and `SSL_RSA_WITH_3DES_EDE_CBC_SHA` when SSL-capable. For SOAP, a FIPS deployment implements their FIPS counterparts | Mandatory | Conformance §5.1, §5.2 |
| Use `TLS_RSA_AES_128_CBC_SHA` or its FIPS counterpart for SOAP, or another SSL 3.0 or TLS 1.0 algorithm | Optional | Conformance §5.1, E50 |

## Exchanges not implemented

Each item is an exchange that the crate implements at neither role, unless
the item names one role.

- Enhanced Client/Proxy SSO over PAOS, at the identity provider, the service
  provider, and the enhanced client. `MUST` in every column of Table 2.
  [ECP was removed](https://github.com/salasebas/saml-rs/blob/main/docs/migrations/0.8.x-to-0.9.0/ecp-removal.md).
- `<AuthnRequest>` over HTTP-Artifact. Optional, Bindings §3.6, and no mode
  of Table 2 requires it.
- Single Logout over HTTP-Artifact. Optional, Profiles §4.4.3.1, §4.4.3.4,
  and no mode of Table 2 requires it.
- Name identifier management over HTTP-POST and HTTP-Artifact. Optional,
  Profiles §4.5.3.1, and no mode of Table 2 requires them.
- Name identifier management over SOAP at the service provider. `OPTIONAL`
  for SP, `MUST NOT` for SP Lite.
- Reading the common domain cookie at the service provider. `OPTIONAL` for
  SP and SP Lite.
- Metadata publication and resolution at the well-known location, the
  Metadata Interoperation option of §3.7. `OPTIONAL` for every mode but
  ECP, which has N/A.
- Request for Assertion by Identifier and the SAML URI Binding. `OPTIONAL`
  for IdP (E29) and `MUST` for every SAML authority.
- The features of the IdP Extended, SP Extended, authority, and requester
  modes, and the attribute profiles, in the tables below.

<a id="extended-authority-and-requester-modes"></a>

### Extended IdP and SP

Table 3. A mode of the feature matrix with these two features is IdP
Extended or SP Extended.

| Feature | IdP Extended | SP Extended | Identity provider | Service provider | Record |
| --- | --- | --- | --- | --- | --- |
| Identity Provider proxy (Core §3.4.1.5) | `MUST` | `MUST` | Not supported | Not supported | [SSO generation](web-browser-sso-generation.md#authnrequest), [SSO acceptance](web-browser-sso-acceptance.md#identity-provider-authnrequest) |
| Name identifier mapping, SOAP (Core §3.8, Profiles §7) | `MUST` | `MUST` | Not supported | Not supported | [Metadata documents](metadata-and-replay.md#metadata-documents) |

### SAML authorities and requester

Table 4 as corrected by E25 and E42. The queries and the assertion request
use the Assertion Query/Request profile (Profiles §6) over SOAP.

| Feature | Authentication Authority | Attribute Authority | Authorization Decision Authority | Requester | Identity provider | Service provider |
| --- | --- | --- | --- | --- | --- | --- |
| Authentication Query, SOAP (Core §3.3.2.2) | `MUST` | N/A | N/A | `OPTIONAL` | Not supported | Not supported |
| Attribute Query, SOAP (Core §3.3.2.3) | N/A | `MUST` | N/A | `OPTIONAL` | Not supported | Not supported |
| Authorization Decision Query, SOAP (Core §3.3.2.4) | N/A | N/A | `MUST` | `OPTIONAL` | Not supported | Not supported |
| Request for Assertion by Identifier, SOAP (Core §3.3.1) | `MUST` | `MUST` | `MUST` | `OPTIONAL` | Not supported | Not supported |
| SAML URI Binding (Bindings §3.7) | `MUST` | `MUST` | `MUST` | `OPTIONAL` | Not supported | Not supported |
| Metadata Structures | `OPTIONAL` | `OPTIONAL` | `OPTIONAL` | `OPTIONAL` | Partial | Partial |
| Metadata Interoperation | `OPTIONAL` | `OPTIONAL` | `OPTIONAL` | `OPTIONAL` | Not supported | Not supported |

### Attribute profiles

Table 1 lists four attribute profiles, and no cell of Tables 2 to 4 names
them. E53 deprecates the X.500/LDAP profile. An X.500/LDAP attribute is
written and read with `AttributeNameFormat::Uri`, and the crate neither
generates nor exposes `x500:Encoding`.

| Profile | Section | Identity provider | Service provider |
| --- | --- | --- | --- |
| X.500/LDAP | Profiles §8.2 | Not supported | Not supported |
| UUID | Profiles §8.3 | Not supported | Not supported |
| DCE PAC | Profiles §8.4 | Not supported | Not supported |
| XACML | Profiles §8.5 | Not supported | Not supported |
