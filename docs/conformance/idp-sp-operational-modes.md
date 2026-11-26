# IdP and SP operational modes

This inventory covers SAML V2.0 Conformance Requirements Table 2 (IdP,
IdP Lite, SP, and SP Lite), Tables 3 and 4, §§3.3 to 5, and the attribute
profiles. Each supported exchange links to its record.

The crate claims individual exchanges. [Conformance Requirements Table 2](https://docs.oasis-open.org/security/saml/v2.0/saml-conformance-2.0-os.pdf#page=9)
requires Enhanced Client/Proxy SSO over PAOS for all four IdP and SP modes.
[ECP was removed](https://github.com/salasebas/saml-rs/blob/main/docs/migrations/0.8.x-to-0.9.0/ecp-removal.md),
so the crate claims none of those modes. The HTTP-Redirect claims apply to
the default build only.

Normative text is Conformance Requirements as corrected by Approved Errata 05. E11 relabels the name identifier management rows. E25 adds the Metadata Structures and Metadata Interoperation rows and §§3.6 and 3.7. E29 adds the Request for Assertion by Identifier and SAML URI Binding rows. E42 replaces the `OPTIONAL` cells of an authority for another authority's query with `N/A`. E50 says the §4 and §5 lists are minimal sets.

A disposition is one of:

- **Claimed feature**: implemented, with its rules on the linked record.
- **Prohibited**: a `MUST NOT` cell. The column does not use the feature.
- **Not implemented, off**: an `OPTIONAL` cell the crate does not implement.
- **Open issue**: a `MUST` cell the crate does not meet yet.
- **Exclusion**: not implemented, because the deployment is the obligated actor or the mode is not claimed.

Table 2 lists the enhanced client as a separate operational mode.

## Feature matrix

| Feature | IdP | IdP Lite | SP | SP Lite | Disposition |
| --- | --- | --- | --- | --- | --- |
| Web SSO, `<AuthnRequest>`, HTTP Redirect | `MUST` | `MUST` | `MUST` | `MUST` | Claimed feature: `start_sso`, `receive_sso`. [SSO generation](web-browser-sso-generation.md), [SSO acceptance](web-browser-sso-acceptance.md). HTTP-POST and HTTP-POST-SimpleSign are claimed too. HTTP-Artifact is not implemented, and Table 2 does not require it |
| Web SSO, `<Response>`, HTTP POST | `MUST` | `MUST` | `MUST` | `MUST` | Claimed feature: `respond_sso`, `initiate_sso`, `finish_sso`, `accept_unsolicited_sso`. Same records. Profiles §4.1.2 prohibits HTTP-Redirect for a `<Response>`, and the typed API has no such input. HTTP-POST-SimpleSign is also claimed for responses |
| Web SSO, `<Response>`, HTTP Artifact | `MUST` | `MUST` | `MUST` | `MUST` | The IdP issues an artifact for the SSO response. The SP resolves it and requires an XML signature on the response or each assertion to establish a session. [HTTP-Artifact response](web-browser-sso-artifact.md) |
| Artifact Resolution, SOAP | `MUST` | `MUST` | `MUST` | `MUST` | For an IdP-issued artifact, the SP builds `ArtifactResolve` and validates the reply. The IdP reads the request and builds `ArtifactResponse`. The application carries the SOAP HTTP exchange. [Artifact resolution](artifact-resolution.md) |
| Enhanced Client/Proxy SSO, PAOS | `MUST` | `MUST` | `MUST` | `MUST` | Exclusion. The crate removed the IdP and SP ends of this profile |
| Name Identifier Management (IdP-Initiated), HTTP Redirect | `MUST` | `MUST NOT` | `MUST` | `MUST NOT` | Claimed feature for the IdP and SP: `start_name_id_management_redirect`. Prohibited for IdP Lite and SP Lite: such a deployment publishes no `ManageNameIDService`. [Name identifier management](name-id-management.md) |
| Name Identifier Management (IdP-Initiated), SOAP | `MUST` | `MUST NOT` | `OPTIONAL` | `MUST NOT` | Claimed feature for the IdP: `start_name_id_management`. Not implemented, off, for the SP. Prohibited for IdP Lite and SP Lite |
| Name Identifier Management (SP-Initiated), HTTP Redirect | `MUST` | `MUST NOT` | `MUST` | `MUST NOT` | Claimed feature for the IdP and SP. Prohibited for IdP Lite and SP Lite |
| Name Identifier Management (SP-Initiated), SOAP | `MUST` | `MUST NOT` | `OPTIONAL` | `MUST NOT` | Claimed feature for the IdP: `receive_name_id_management`, `respond_name_id_management`. Not implemented, off, for the SP. Prohibited for IdP Lite and SP Lite |
| Single Logout (IdP-Initiated), HTTP Redirect | `MUST` | `MUST` | `MUST` | `MUST` | The IdP requests logout from one SP and validates its reply. HTTP-POST and HTTP-POST-SimpleSign also support this exchange. [Single Logout](single-logout.md) |
| Single Logout (IdP-Initiated), SOAP | `MUST` | `OPTIONAL` | `MUST` | `OPTIONAL` | The IdP requests logout from one SP over application-provided HTTP. The SP replies on the same SOAP exchange. [SOAP binding](single-logout.md#soap-binding) |
| Single Logout (SP-Initiated), HTTP Redirect | `MUST` | `MUST` | `MUST` | `MUST` | The SP requests logout and validates the IdP's reply. HTTP-POST and HTTP-POST-SimpleSign also support this exchange. The IdP application owns propagation and aggregation. [Application duties](single-logout.md#session-authority-application-duties) |
| Single Logout (SP-Initiated), SOAP | `MUST` | `OPTIONAL` | `MUST` | `OPTIONAL` | The SP requests logout over application-provided HTTP. The IdP replies on the same SOAP exchange. Its application owns propagation and aggregation. [SOAP binding](single-logout.md#soap-binding) |
| Identity Provider Discovery (cookie) | `MUST` | `MUST` | `OPTIONAL` | `OPTIONAL` | Claimed feature for the IdP and IdP Lite: `common_domain_cookie`. [Identity Provider Discovery](identity-provider-discovery.md). Not implemented, off, for the SP and SP Lite |
| Metadata Structures | `OPTIONAL` | `OPTIONAL` | `OPTIONAL` | `OPTIONAL` | Not implemented, off. E25, [§3.6](#metadata) |
| Metadata Interoperation | `OPTIONAL` | `OPTIONAL` | `OPTIONAL` | `OPTIONAL` | Not implemented, off. E25, [§3.7](#metadata) |
| Request for Assertion by Identifier | `OPTIONAL` | N/A | N/A | N/A | Not implemented, off. E29. [Extended, authority, and requester modes](#extended-authority-and-requester-modes) |
| SAML URI Binding | `OPTIONAL` | N/A | N/A | N/A | Not implemented, off. E29. [Extended, authority, and requester modes](#extended-authority-and-requester-modes) |

The HTTP Redirect rows are claimed for the default build. Bindings §3.4.4.1 signature rule 5 makes DSAwithSHA1 and RSAwithSHA1 mandatory for the HTTP-Redirect `SigAlg`. `crypto-aws-lc`, `crypto-fips`, RustCrypto without `crypto-legacy-algorithms`, and a verifier with `XmlSignatureProfile::StrictRsaSha2` do not meet it. See [XML Signature and XML Encryption algorithms](#xml-signature-and-xml-encryption-algorithms).

## SAML-defined identifiers

Conformance §3.3. Rules are in [SAML-defined identifiers](identifiers.md).

| Obligation | Actor | Disposition |
| --- | --- | --- |
| Create and process every attribute name format of Core §8.2 | Producer and consumer of `<Attribute>`: both roles | Claimed feature: `AttributeNameFormat` |
| Create and process every name identifier format of Core §8.3 | Producer and consumer of `<NameID>`: both roles | Claimed feature: `NameIdFormat` |
| Support the processing rules of Core §8.3.7 (persistent) and §8.3.8 (transient) | Producer of the identifier: the IdP | Claimed feature: `NameId::generate_persistent`, `NameId::persistent`, `NameId::generate_transient`. The deployment protects persistent values from disclosure to other providers and from unprotected logging, and keeps each value bound to one principal (Core §8.3.7, E78) |
| Let the implementation handle identifiers it does not handle natively | Both roles | Claimed feature: `AttributeNameFormat::Custom`, `NameIdFormat::Custom` |

## Encrypted elements

Conformance §3.4: a mode processes or generates `<EncryptedID>`, `<EncryptedAssertion>`, and `<EncryptedAttribute>` wherever it processes or generates `<NameID>`, `<Assertion>`, or `<Attribute>`. Generation is the producer's choice (Core §§2.2.4, 2.3.4, 2.7.3.2) and is off until selected. An entity with `Credentials::with_decryption_credential` decrypts what it receives.

| Context | Actor | Disposition |
| --- | --- | --- |
| `<EncryptedAssertion>`, assertion `<EncryptedID>`, and `<EncryptedAttribute>` in a `<Response>` | IdP, generate | Claimed feature: the `assertions`, `identifiers`, and `attributes` fields of `XmlEncryptionPolicy`. [SSO generation](web-browser-sso-generation.md) |
| The same three in a received `<Response>`, on every supported response binding | SP, process | Claimed feature. [SSO acceptance](web-browser-sso-acceptance.md) |
| `<EncryptedID>` in the requested `<Subject>` of an `<AuthnRequest>` | IdP, process | Claimed feature. [SSO acceptance](web-browser-sso-acceptance.md). Library policy leaves the `<EncryptedID>` of an unsigned request unread when its data encryption is not AES-GCM |
| `<EncryptedID>` in a `<LogoutRequest>` | Both roles, generate and process | Claimed feature. [Encrypted principal identifier](single-logout.md#encrypted-principal-identifier) |
| `<EncryptedID>` and `<NewEncryptedID>` in a `<ManageNameIDRequest>` | Requester, generate. Responder, process | Claimed feature. [EncryptedID and NewEncryptedID](name-id-management.md#encryptedid-and-newencryptedid) |

The crate neither processes nor generates the unencrypted element in these places, so they are not contexts:

- An `<AuthnRequest>` `<Subject>` from the SP, which writes none.
- The identifier of a `<SubjectConfirmation>` (Core §2.4.1.1).
- An assertion inside `<Advice>` (Core §2.6.1) or `<Evidence>`.
- Attribute queries and name identifier mapping, in [Extended, authority, and requester modes](#extended-authority-and-requester-modes).

## SOAP and URI security models

Conformance §3.5 obligates SAML authorities and requesters, for profiles on the SOAP binding and for the URI binding, to implement no authentication, HTTP basic authentication, TLS server authentication, and TLS mutual authentication.

| Obligation | Actor | Disposition |
| --- | --- | --- |
| The four authentication methods, the preemptive `Authorization` header, and a server certificate under TLS | The HTTP client and server that carry the SOAP exchange | Exclusion. The crate builds and reads the SOAP envelope and does not open the connection. `SoapChannel` records the protection the deployment provided |

## Metadata

| Obligation | Actor | Disposition |
| --- | --- | --- |
| §3.6 Metadata Structures: make metadata available to a peer that may depend on it, and refresh expired or invalid cached peer metadata when it is available and the policy, operation, and exchange permit its use | Each mode that elects the option | Not elected, E25, because no deployment has asked for it. The crate generates and imports metadata documents but does not publish, fetch, or refresh them. The caller owns refresh. [Metadata and replay](metadata-and-replay.md) |
| §3.7 Metadata Interoperation: the well-known location publication and resolution mechanism | Each mode that elects the option | Not elected, E25, because no deployment has asked for it. Well-known location publication and resolution are not implemented |

## XML Signature and XML Encryption algorithms

Conformance §4. Rules, including what each backend supports, are in [XML Signature and XML Encryption algorithms](xml-security-algorithms.md).

| Obligation | Actor | Disposition |
| --- | --- | --- |
| §4.1 SHA-1 digest, HMAC-SHA1, Canonical XML 1.0 without comments, enveloped-signature transform, and RSAwithSHA1 | Signer and verifier: both roles | Claimed feature. Generated only when selected |
| §4.1 DSAwithSHA1, recommended. Bindings §3.4.4.1 signature rule 5 makes it and RSAwithSHA1 mandatory for the HTTP-Redirect `SigAlg` | Signer and verifier: both roles | Claimed feature on the default build only. Generated only when selected |
| §4.2 Triple DES, AES-128, AES-256, RSA-v1.5, and RSA-OAEP | Encrypter and decrypter: both roles | Claimed feature. Triple DES and RSA-v1.5 are generated only when selected. RSA-v1.5 is decrypted only when selected |

## TLS

| Obligation | Actor | Disposition |
| --- | --- | --- |
| §5: the server authenticates with an X.509 v3 certificate, and the client checks its identity | The deployment's TLS stack | Exclusion. The crate does not terminate TLS |
| §§5.1 and 5.2: `TLS_RSA_WITH_3DES_EDE_CBC_SHA` and the SSL and FIPS counterparts | A TLS-capable or SSL-capable deployment | Exclusion, for the same reason |

## Extended, authority, and requester modes

Table 3 (IdP Extended and SP Extended), Table 4 (SAML Authentication Authority, Attribute Authority, Authorization Decision Authority, and Requester), and the attribute profiles that Table 1 lists and no other table names. None of these modes is claimed. Conformance §1 states features for implementations that claim conformance, so an unclaimed mode carries no obligation.

Table 3 extends a mode of the [feature matrix](#feature-matrix) with two more `MUST` rows. Every authority column of Table 4 has `MUST` for Request for Assertion by Identifier and for the SAML URI Binding, which are not implemented, so no authority mode can be claimed. Every SAML Requester cell is `OPTIONAL`.

### Extended IdP and SP

Table 3.

| Feature | IdP Extended | SP Extended | Disposition |
| --- | --- | --- | --- |
| Identity Provider proxy (Core §3.4.1.5) | `MUST` | `MUST` | Open issue. No API reads or writes `<Scoping>`, `ProxyCount`, or `RequesterID`. The IdP accepts a request that carries `<Scoping>` and never proxies, which Core §3.4.1.5.1 leaves to local policy |
| Name identifier mapping, SOAP (Core §3.8, Profiles §7) | `MUST` | `MUST` | Exclusion, mode not claimed. No `<NameIDMappingRequest>` or `<NameIDMappingResponse>` is generated or processed |

### SAML authorities and requester

Table 4, as corrected by E25 and E42. The exchanges use the Assertion Query/Request profile (Profiles §6) over the SOAP binding.

| Feature | Authentication Authority | Attribute Authority | Authorization Decision Authority | Requester | Disposition |
| --- | --- | --- | --- | --- | --- |
| Authentication Query, SOAP (Core §3.3.2.2) | `MUST` | N/A | N/A | `OPTIONAL` | Exclusion, mode not claimed. No `<AuthnQuery>` is generated or answered |
| Attribute Query, SOAP (Core §3.3.2.3) | N/A | `MUST` | N/A | `OPTIONAL` | Open issue. No `<AttributeQuery>` is generated or answered |
| Authorization Decision Query, SOAP (Core §3.3.2.4) | N/A | N/A | `MUST` | `OPTIONAL` | Exclusion, mode not claimed. No `<AuthzDecisionQuery>` is generated or answered |
| Request for Assertion by Identifier, SOAP (Core §3.3.1) | `MUST` | `MUST` | `MUST` | `OPTIONAL` | Exclusion, mode not claimed. No `<AssertionIDRequest>` is generated or answered. The same feature is the `OPTIONAL` IdP row of Table 2 (E29) |
| SAML URI Binding (Bindings §3.7) | `MUST` | `MUST` | `MUST` | `OPTIONAL` | Exclusion, mode not claimed. No assertion is served by URI reference |
| Metadata Structures | `OPTIONAL` | `OPTIONAL` | `OPTIONAL` | `OPTIONAL` | Not implemented, off, as in Table 2 |
| Metadata Interoperation | `OPTIONAL` | `OPTIONAL` | `OPTIONAL` | `OPTIONAL` | Not implemented, off, as in Table 2 |

Conformance §3.5 for authorities and requesters is an exclusion under [SOAP and URI security models](#soap-and-uri-security-models).

### Attribute profiles

Table 1 lists the X.500/LDAP, UUID, DCE PAC, and XACML attribute profiles (Profiles §§8.2 to 8.5). No cell of Tables 2, 3, or 4 names them, so they carry no conformance requirement for any mode.

| Profile | Disposition |
| --- | --- |
| X.500/LDAP (Profiles §8.2) | Exclusion, no conformance cell. E53 deprecates this profile. Its attributes use `AttributeNameFormat::Uri`. The crate does not generate or expose `x500:Encoding` |
| UUID (Profiles §8.3) | Exclusion, no conformance cell |
| DCE PAC (Profiles §8.4) | Exclusion, no conformance cell |
| XACML (Profiles §8.5) | Exclusion, no conformance cell |
