# Extended, authority, and requester modes

The inventory of SAML V2.0 Conformance Requirements Table 3 (IdP Extended and
SP Extended) and Table 4 (SAML Authentication Authority, SAML Attribute
Authority, SAML Authorization Decision Authority, and SAML Requester), and of
the attribute profiles that Table 1 lists and no other table names. Each row
names the level for each column and one disposition.

None of these modes is claimed. Table 3 extends a mode in
[IdP and SP operational modes](idp-sp-operational-modes.md) with two more
`MUST` rows. Every authority column of Table 4 has `MUST` for Request for
Assertion by Identifier and for the SAML URI Binding, which are excluded, so
no authority mode can be claimed. Every SAML Requester cell is `OPTIONAL`.
This page is the inventory, not the claim.

Normative text is Conformance Requirements, as corrected by Approved
Errata 05. E25 adds the Metadata Structures and Metadata Interoperation rows to
Table 4. E42 replaces the `OPTIONAL` cells of an authority for another
authority's query with `N/A`. E28 regroups the query rows of Table 1 under
Assertion Query/Request.

A disposition is one of:

- **Open issue**: not implemented, and a follow-up ticket tracks it.
- **Not implemented, off**: an `OPTIONAL` cell this crate does not implement.
- **Exclusion**: not implemented, and no ticket. The row gives the reason.

An exchange excluded as "not implemented elsewhere" has no implementation in
Shibboleth IdP 5, Shibboleth SP 4, SimpleSAMLphp, Keycloak, crewjam/saml,
python3-saml, ruby-saml, node-saml, samlify, or Sustainsys.Saml2. Some of them
define its schema types only. The mode that needs it is not claimed.
Conformance Requirements §1 states features for implementations that claim
conformance, so a mode that is not claimed carries no obligation.

## Extended IdP and SP

Table 3. An extended mode is an IdP or SP mode of Table 2 plus both rows.

| Feature | IdP Extended | SP Extended | Disposition |
| --- | --- | --- | --- |
| Identity Provider proxy (Core §3.4.1.5) | `MUST` | `MUST` | Open issue: [#277](https://github.com/salasebas/saml-rs/issues/277). The identity provider accepts a request that carries `<Scoping>` and never proxies, which Core §3.4.1.5.1 leaves to local policy. An application that proxies cannot yet read the received `ProxyCount`, `<IDPList>`, and `<RequesterID>`, or write them on its own `<AuthnRequest>` |
| Name identifier mapping, SOAP (Core §3.8, Profiles §7) | `MUST` | `MUST` | Exclusion, not implemented elsewhere. No `<NameIDMappingRequest>` or `<NameIDMappingResponse>` is generated or processed |

## SAML authorities and requester

Table 4, as corrected by Errata 05 E25 and E42. The exchanges use the
Assertion Query/Request profile (Profiles §6) over the SOAP binding.

| Feature | Authentication Authority | Attribute Authority | Authorization Decision Authority | Requester | Disposition |
| --- | --- | --- | --- | --- | --- |
| Authentication Query, SOAP (Core §3.3.2.2) | `MUST` | N/A | N/A | `OPTIONAL` | Exclusion, not implemented elsewhere. No `<AuthnQuery>` is generated or answered |
| Attribute Query, SOAP (Core §3.3.2.3) | N/A | `MUST` | N/A | `OPTIONAL` | Open issue: [#278](https://github.com/salasebas/saml-rs/issues/278). Shibboleth IdP 5 answers it, and Shibboleth SP 4 and crewjam/saml send it |
| Authorization Decision Query, SOAP (Core §3.3.2.4) | N/A | N/A | `MUST` | `OPTIONAL` | Exclusion, not implemented elsewhere. No `<AuthzDecisionQuery>` is generated or answered |
| Request for Assertion by Identifier, SOAP (Core §3.3.1) | `MUST` | `MUST` | `MUST` | `OPTIONAL` | Exclusion, not implemented elsewhere. No `<AssertionIDRequest>` is generated or answered. The same feature is the `OPTIONAL` IdP row of Table 2 (Errata 05 E29). SimpleSAMLphp and crewjam/saml read and write `<md:AssertionIDRequestService>` in metadata only |
| SAML URI Binding (Bindings §3.7) | `MUST` | `MUST` | `MUST` | `OPTIONAL` | Exclusion, not implemented elsewhere. No assertion is served by URI reference |
| Metadata Structures | `OPTIONAL` | `OPTIONAL` | `OPTIONAL` | `OPTIONAL` | Not implemented, off. As the Table 2 row of the same name |
| Metadata Interoperation | `OPTIONAL` | `OPTIONAL` | `OPTIONAL` | `OPTIONAL` | Not implemented, off. As the Table 2 row of the same name |

Conformance §3.5, the SOAP and URI security models of authorities and
requesters, is an exclusion in
[IdP and SP operational modes](idp-sp-operational-modes.md#soap-and-uri-security-models).

## Attribute profiles

Table 1 lists the UUID, DCE PAC, X.500/LDAP, and XACML attribute profiles
(Profiles §§8.2 to 8.5). No cell of Tables 2, 3, or 4 names them, so they
carry no conformance requirement for any mode.

| Profile | Disposition |
| --- | --- |
| X.500/LDAP (Profiles §8.2) | Exclusion, no conformance cell. An `<Attribute>` named under this profile is an ordinary `<Attribute>` with the `uri` name format. The `x500:Encoding` XML attribute is not generated or exposed |
| UUID (Profiles §8.3) | Exclusion, no conformance cell |
| DCE PAC (Profiles §8.4) | Exclusion, no conformance cell |
| XACML (Profiles §8.5) | Exclusion, no conformance cell |
