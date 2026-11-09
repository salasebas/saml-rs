# IdP and SP operational modes

The inventory of the IdP, IdP Lite, SP, and SP Lite columns of SAML V2.0
Conformance Requirements Table 2, and of Conformance §§3.3 to 3.7, 4, and 5.
Each row names the obligated actor, the level for each column, and one
disposition. The rules of a claimed feature are on the record it links to.

The IdP operational mode and the SP operational mode are not claimed. Every
Table 2 `MUST` cell of the IdP and SP columns has a claimed feature. Two
§3.4 limits remain: an `EncryptedAssertion` after the first one in a response,
which is not decrypted
([#273](https://github.com/salasebas/saml-rs/issues/273)), and the unsigned
CBC `AuthnRequest` subject that the identity provider leaves unread by library
policy. This page is the inventory, not the claim.

Normative text is Conformance Requirements, as corrected by Approved
Errata 05. E11 relabels the name identifier management rows. E25 adds the
Metadata Structures and Metadata Interoperation rows and §§3.6 and 3.7. E29
adds the Request for Assertion by Identifier and SAML URI Binding rows. E50
says the §4 and §5 algorithm lists are minimal sets.

A disposition is one of:

- **Claimed feature**: implemented, with its rules on the linked record.
- **Prohibited**: a `MUST NOT` cell. The column does not use the feature.
- **Not implemented, off**: an `OPTIONAL` cell this crate does not implement.
- **Open issue**: an obligation with a tracked gap.
- **Exclusion**: the obligated actor is the deployment, not this crate.

The ECP column of Table 2 is a separate operational mode. The enhanced client
is not a facade, and this page does not record that column. The IdP Extended
and SP Extended modes of Table 3, the authorities and requester of Table 4,
and the attribute profiles are in
[Extended, authority, and requester modes](extended-and-authority-modes.md).

## Feature matrix

| Feature | IdP | IdP Lite | SP | SP Lite | Disposition |
| --- | --- | --- | --- | --- | --- |
| Web SSO, `<AuthnRequest>`, HTTP Redirect | `MUST` | `MUST` | `MUST` | `MUST` | Claimed feature. `start_sso` and `receive_sso`, in [SSO generation](web-browser-sso-generation.md) and [SSO acceptance](web-browser-sso-acceptance.md). HTTP-POST and HTTP-POST-SimpleSign are claimed as well. HTTP-Artifact is not implemented, and Table 2 does not require it |
| Web SSO, `<Response>`, HTTP POST | `MUST` | `MUST` | `MUST` | `MUST` | Claimed feature. `respond_sso`, `initiate_sso`, `finish_sso`, and `accept_unsolicited_sso`, in the same records. HTTP-POST-SimpleSign is claimed as well. The identity provider never sends a `<Response>` over HTTP-Redirect: Profiles §4.1.2 prohibits it. The service provider still reads one, because no receiver rule rejects it |
| Web SSO, `<Response>`, HTTP Artifact | `MUST` | `MUST` | `MUST` | `MUST` | Claimed feature. [HTTP-Artifact response](web-browser-sso-artifact.md) |
| Artifact Resolution, SOAP | `MUST` | `MUST` | `MUST` | `MUST` | Claimed feature. [Artifact resolution](artifact-resolution.md). The identity provider issues and answers. The service provider is the requester. It issues no artifact that a Table 2 `MUST` cell needs, so it does not answer `ArtifactResolve` |
| Enhanced Client/Proxy SSO, PAOS | `MUST` | `MUST` | `MUST` | `MUST` | Claimed feature for the service-provider and identity-provider ends. [Enhanced Client/Proxy](enhanced-client-proxy.md) |
| Name Identifier Management (IdP-Initiated), HTTP Redirect | `MUST` | `MUST NOT` | `MUST` | `MUST NOT` | Claimed feature for the IdP and the SP. [Name identifier management](name-id-management.md). Prohibited for IdP Lite and SP Lite: such a deployment publishes no `ManageNameIDService` and calls no `start_name_id_management_redirect`. Publishing none is the default, and without one the operations return `SamlError::MissingMetadata` |
| Name Identifier Management (IdP-Initiated), SOAP | `MUST` | `MUST NOT` | `OPTIONAL` | `MUST NOT` | Claimed feature for the IdP: `start_name_id_management`. Not implemented, off, for the SP. Prohibited for IdP Lite and SP Lite, as in the row above |
| Name Identifier Management (SP-Initiated), HTTP Redirect | `MUST` | `MUST NOT` | `MUST` | `MUST NOT` | Claimed feature for the IdP and the SP. Prohibited for IdP Lite and SP Lite, as in the rows above |
| Name Identifier Management (SP-Initiated), SOAP | `MUST` | `MUST NOT` | `OPTIONAL` | `MUST NOT` | Claimed feature for the IdP: `receive_name_id_management` and `respond_name_id_management`. Not implemented, off, for the SP. Prohibited for IdP Lite and SP Lite |
| Single Logout (IdP-Initiated), HTTP Redirect | `MUST` | `MUST` | `MUST` | `MUST` | Claimed feature. [Logout](single-logout.md). HTTP-POST and HTTP-POST-SimpleSign are claimed as well. HTTP-Artifact is not implemented, and Table 2 does not require it |
| Single Logout (IdP-Initiated), SOAP | `MUST` | `OPTIONAL` | `MUST` | `OPTIONAL` | Claimed feature for the IdP and the SP. [SOAP binding](single-logout.md#soap-binding). The same flow is available to IdP Lite and SP Lite, which do not need it |
| Single Logout (SP-Initiated), HTTP Redirect | `MUST` | `MUST` | `MUST` | `MUST` | Claimed feature, as the IdP-initiated row |
| Single Logout (SP-Initiated), SOAP | `MUST` | `OPTIONAL` | `MUST` | `OPTIONAL` | Claimed feature for the IdP and the SP, as the IdP-initiated row |
| Identity Provider Discovery (cookie) | `MUST` | `MUST` | `OPTIONAL` | `OPTIONAL` | Claimed feature for the IdP and IdP Lite: `remember_identity_provider`. [Identity Provider Discovery](identity-provider-discovery.md). Not implemented, off, for the SP and SP Lite |
| Metadata Structures | `OPTIONAL` | `OPTIONAL` | `OPTIONAL` | `OPTIONAL` | Not implemented, off. Errata 05 E25 and §3.6 below. The crate reads and writes metadata, as in [Metadata and replay](metadata-and-replay.md), and does not elect this option |
| Metadata Interoperation | `OPTIONAL` | `OPTIONAL` | `OPTIONAL` | `OPTIONAL` | Not implemented, off. Errata 05 E25 and §3.7 below |
| Request for Assertion by Identifier | `OPTIONAL` | N/A | N/A | N/A | Not implemented, off. Errata 05 E29. `AssertionIDRequest` is in [Extended, authority, and requester modes](extended-and-authority-modes.md) |
| SAML URI Binding | `OPTIONAL` | N/A | N/A | N/A | Not implemented, off. Errata 05 E29. In [Extended, authority, and requester modes](extended-and-authority-modes.md) |

## SAML-defined identifiers

Conformance §3.3. [SAML-defined identifiers](identifiers.md) has the rules.

| Obligation | Actor | Disposition |
| --- | --- | --- |
| Create and process every attribute name format of Core §8.2 | Producer and consumer of `<Attribute>`: the identity provider and the service provider in Web SSO | Claimed feature. `AttributeNameFormat` |
| Create and process every name identifier format of Core §8.3 | Producer and consumer of `<NameID>`: both roles | Claimed feature. `NameIdFormat` |
| Support the processing rules of Core §8.3.7 (persistent) and §8.3.8 (transient) | Producer of the identifier: the identity provider | Claimed feature. `NameId::generate_persistent`, `NameId::persistent`, and `NameId::generate_transient`. The deployment keeps the persistent value confidential and assigned to one principal |
| Let the implementation be extended to identifiers it does not handle natively | Both roles | Claimed feature. `AttributeNameFormat::Custom` and `NameIdFormat::Custom` |

## Encrypted elements

Conformance §3.4: a mode processes or generates `<EncryptedID>`,
`<EncryptedAssertion>`, and `<EncryptedAttribute>` wherever it processes or
generates `<NameID>`, `<Assertion>`, or `<Attribute>`. Generating the
encrypted form is the producer's choice (Core §§2.2.4, 2.3.4, 2.7.3.2), so
generation stays off until it is selected. Processing does not wait for a
selection: an entity with `Credentials::decryption_key` decrypts what it
receives.

| Context | Actor | Disposition |
| --- | --- | --- |
| `<EncryptedAssertion>`, assertion `<EncryptedID>`, and `<EncryptedAttribute>` in a `<Response>` | Identity provider, generate | Claimed feature. `encrypt_assertions`, `encrypt_ids`, and `encrypt_attributes`. [SSO generation](web-browser-sso-generation.md) |
| The same three in a received `<Response>`, on every response binding and over PAOS | Service provider, process | Claimed feature. [SSO acceptance](web-browser-sso-acceptance.md). Open issue for an `<EncryptedAssertion>` after the first: [#273](https://github.com/salasebas/saml-rs/issues/273) |
| `<EncryptedID>` in the requested `<Subject>` of an `<AuthnRequest>` | Identity provider, process | Claimed feature. [SSO acceptance](web-browser-sso-acceptance.md). Library policy leaves an unsigned request whose data encryption is CBC unread |
| `<EncryptedID>` in a `<LogoutRequest>` | Both roles, generate and process | Claimed feature. [Encrypted principal identifier](single-logout.md#encrypted-principal-identifier) |
| `<EncryptedID>` and `<NewEncryptedID>` in a `<ManageNameIDRequest>` | Requester, generate. Responder, process | Claimed feature. [EncryptedID and NewEncryptedID](name-id-management.md#encryptedid-and-newencryptedid) |

These are not contexts, because the crate neither processes nor generates the
unencrypted element there:

- An `<AuthnRequest>` `<Subject>` from the service provider, which writes none.
- The identifier of a `<SubjectConfirmation>` (Core §2.4.1.1), kept as raw XML
  and never generated.
- An assertion inside `<Advice>` (Core §2.6.1) or `<Evidence>`.
- Attribute queries and name identifier mapping, in
  [Extended, authority, and requester modes](extended-and-authority-modes.md).

## SOAP and URI security models

Conformance §3.5 obligates SAML authorities and requesters, for profiles on
the SOAP binding and for the URI binding, to implement no authentication, HTTP
basic authentication, TLS server authentication, and TLS mutual
authentication.

| Obligation | Actor | Disposition |
| --- | --- | --- |
| The four authentication methods, the preemptive `Authorization` header, and a server certificate under TLS | The HTTP client and server that carry the SOAP exchange | Exclusion. saml-rs builds and reads the SOAP envelope and does not open the connection. `SoapChannel` records the protection the deployment provided |

## Metadata

| Obligation | Actor | Disposition |
| --- | --- | --- |
| §3.6 Metadata Structures: make metadata available to a peer that may depend on it, and consult a peer's metadata again once the cached copy expires | Each mode that elects the option | Not implemented, off. Errata 05 E25. Refreshing expired metadata is the caller's, as in [Metadata and replay](metadata-and-replay.md) |
| §3.7 Metadata Interoperation: the well-known location publication and resolution mechanism | Each mode that elects the option | Not implemented, off. Errata 05 E25 |

## XML Signature and XML Encryption algorithms

Conformance §4. [XML Signature and XML Encryption algorithms](xml-security-algorithms.md)
has the rules, including what each backend supports.

| Obligation | Actor | Disposition |
| --- | --- | --- |
| §4.1 SHA-1 digest, HMAC-SHA1, Canonical XML 1.0 without comments, enveloped-signature transform, and RSAwithSHA1 | Signer and verifier: both roles | Claimed feature. Generated only when selected |
| §4.1 DSAwithSHA1, recommended | Signer and verifier: both roles | Claimed feature. Generated only when selected, on the same SHA-1 rule |
| §4.2 Triple DES, AES-128, AES-256, RSA-v1.5, and RSA-OAEP | Encrypter and decrypter: both roles | Claimed feature. Triple DES and RSA-v1.5 are generated only when selected. RSA-v1.5 is decrypted only when selected |

## TLS

| Obligation | Actor | Disposition |
| --- | --- | --- |
| §5: the server authenticates with an X.509 v3 certificate, and the client checks its identity | The deployment's TLS stack | Exclusion. saml-rs does not terminate TLS |
| §5.1 and §5.2: `TLS_RSA_WITH_3DES_EDE_CBC_SHA` and the SSL and FIPS counterparts | A TLS-capable or SSL-capable deployment | Exclusion, for the same reason |
