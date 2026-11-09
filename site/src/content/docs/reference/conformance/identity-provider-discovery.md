---
title: "Identity Provider Discovery"
description: "The identity provider returns the common domain cookie for the caller to write. `remember_identity_provider` is that operation. `respond_sso` does not write the cookie."
---

The identity provider returns the common domain cookie for the caller to
write. `Saml<Idp>::remember_identity_provider` is that operation.
`respond_sso` does not write the cookie. The same operation is the IdP Lite
column, because this crate has one identity-provider facade. The IdP
operational mode and the SP operational mode stay unclaimed.

The service provider and SP Lite cells stay off. There is no service-provider
method, and this crate does not read `_saml_idp`.

Normative text is Profiles §4.3 as renumbered by Approved Errata 05 E32, the
cookie note in E63, Core §8.3.6, and Conformance Requirements Table 2. E32
inserts §4.3.1 Required Information and shifts the original subsections up by
one. After that erratum, §4.3.2 is the cookie, §4.3.3 is setting it, and
§4.3.4 is obtaining it. The profile identifier in the inserted §4.3.1 is
`urn:oasis:names:tc:SAML:2.0:profiles:SSO:idp-discovery`. The DNS-alias
redirect described in §4.3.3 is non-normative. The means of setting the cookie
are implementation-specific. This crate returns the cookie.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Cookie name is `_saml_idp` | Identity provider, including IdP Lite | Write common domain cookie | Mandatory. Profiles §4.3.2 after E32 |
| Value is one or more base64-encoded entity identifiers separated by a single space, then URL-encoded | Identity provider, including IdP Lite | Write common domain cookie | Mandatory. Profiles §4.3.2 after E32. This identity provider's identifier is an entity identifier, Core §8.3.6: a URI of at most 1024 characters. A non-ASCII identifier is not a URI, so it is rejected. `+`, `/`, `=`, and the separating space are percent-encoded (`%2B`, `%2F`, `%3D`, `%20`). An existing value is percent-decoded and split on space, so a base64 `+` stays in its entry. If that list is not valid and the value contains a raw `+`, that `+` is a URL-encoded space |
| Append this identity provider. When it is already listed, remove it and append it so the latest entry is last | Identity provider, including IdP Lite | Write common domain cookie | Append is a recommendation. Removing an existing entry and appending it is optional. Profiles §4.3.2 after E32. This operation does both. Other identity providers stay in their existing order |
| Path is `/` | Identity provider, including IdP Lite | Write common domain cookie | Mandatory. Profiles §4.3.2 after E32 |
| Domain is `.{common-domain}` with one leading period | Identity provider, including IdP Lite | Write common domain cookie | Mandatory. Profiles §4.3.2 after E32. The caller passes `common-domain` without the period. An empty value, a leading period, or a value that is not an ASCII hostname is rejected so the attribute is that domain. An IPv4 literal is rejected as well: an IP address has no subdomain scope, so it cannot be the common domain. That rejection is library policy; the profile does not define it |
| Cookie is marked secure | Identity provider, including IdP Lite | Write common domain cookie | Mandatory. Profiles §4.3.2 after E32 |
| Cookie may be session-only or persistent | Identity provider, including IdP Lite | Write common domain cookie | Optional. Profiles §4.3.2 after E32, including the E63 note. The caller chooses `CommonDomainCookieLifetime::Session` or `Persistent`. A session cookie does not mean the principal still has a session here. A persistent lifetime must be a whole number of seconds, at least one second, and at most 2147483647 seconds. Any other duration is rejected so it is not written as `Max-Age=0`, as a truncated second, or as a number a 32-bit cookie parser cannot read. Those bounds are library policy; the profile does not define them |
| The identity provider may set the cookie after it authenticates a principal | Identity provider, including IdP Lite | Write common domain cookie | Optional. Profiles §4.3.3 after E32. The caller asks with `remember_identity_provider`. `respond_sso` does not set the cookie. Conformance Table 2 marks the feature `MUST` for the IdP and IdP Lite columns. Those operational modes stay unclaimed |
| The service provider may read the cookie | Service provider and SP Lite | Read common domain cookie | Optional. Profiles §4.3.4 after E32. Conformance Table 2 marks both cells `OPTIONAL`. They stay off |
| An existing value that is not the profile list is rejected | Identity provider | Write common domain cookie | Library policy. The written value has to be the encoded list. A value that is not that list is rejected, rather than dropped or replaced with only this identity provider. An empty value starts a new list. An existing entry is kept when it is base64 of UTF-8 text; the Core §8.3.6 URI rule applies to this identity provider's identifier only. An existing value larger than 8192 bytes is rejected. That size is a resource limit, not an OASIS rule. The cookie name and the encoded value handed to the caller are together at most 4096 bytes, because Chromium discards a cookie whose name and value exceed that size. The oldest entries are dropped until the pair fits. That size is a resource limit, not an OASIS rule |
