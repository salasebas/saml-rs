# Identity Provider Discovery

Code: `src/discovery.rs`

`IdentityProvider::common_domain_cookie` builds the common domain cookie, and
the caller writes it. `respond_sso` does not write the cookie, and no
service-provider method reads it. The IdP and SP operational modes stay
unclaimed.

Normative text is Profiles §4.3 as renumbered by Approved Errata 05 E32:
§4.3.2 is the cookie, §4.3.3 is setting it, and §4.3.4 is reading it. Under
E63, either cookie lifetime records identity providers used in the past. A
session-only cookie does not mean the user still has a session there. Core
§8.3.6 defines entity identifiers. The
[Identity Provider Discovery Service Protocol and Profile](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-idp-discovery-cs-01.pdf)
(SAMLDS, Committee Specification 01) is a separate exchange.

## Support

### Common domain cookie

| Feature | Section | Identity provider | Service provider |
| --- | --- | --- | --- |
| Build the common domain cookie `_saml_idp` | Profiles §4.3.2 | Supported | — |
| Append this identity provider to the list in an existing cookie | Profiles §4.3.2 | Supported | — |
| Choose a session-only or a persistent cookie | Profiles §4.3.2, E63 | Supported | — |
| Set the cookie after the principal authenticates | Profiles §4.3.3 | Supported | — |
| Read the cookie to learn which identity providers a principal uses | Profiles §4.3.4 | — | Not supported |
| Relay the `AuthnRequest` through the HTTP server in the common domain | Profiles §4.3.4 | — | Not supported |

### Discovery service protocol

| Feature | Section | Service provider | Discovery service |
| --- | --- | --- | --- |
| HTTP request to the discovery service | SAMLDS §2.4.1 | Not supported | Not supported |
| Choice of the identity provider | SAMLDS §2.4.2 | — | Not supported |
| HTTP redirect back to the service provider | SAMLDS §2.4.3 | Not supported | Not supported |
| `idpdisc:DiscoveryResponse` endpoints in metadata | SAMLDS §2.5 | Not supported | — |

## Rules

<a id="identity-provider"></a>

### Identity provider: `common_domain_cookie`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Name the cookie `_saml_idp` | Mandatory | Profiles §4.3.2 | Always |
| Write the value as base64 entity identifiers separated by one space, then URL-encode it | Mandatory | Profiles §4.3.2 | Always |
| Write only URI entity identifiers of at most 1024 characters, including those carried over from the existing cookie | Mandatory | Profiles §4.3.2, Core §8.3.6 | Always |
| Append this identity provider to the list | Recommended | Profiles §4.3.2 | Always |
| Move this identity provider to the end when it is already listed | Optional | Profiles §4.3.2 | Always |
| Set `Path=/`, `Domain=.{common-domain}`, and `Secure` | Mandatory | Profiles §4.3.2 | Always |
| Make the cookie session-only or persistent | Optional | Profiles §4.3.2, E63 | `CommonDomainCookieLifetime` |

## Library policies

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Reject a common domain that is not an ASCII host name: labels of 1 to 63 letters, digits, and hyphens with no hyphen at either end, at most 253 characters, and no leading or trailing period | The value becomes the cookie `Domain`, which browsers match against DNS host names, and the check keeps `;`, spaces, and other header syntax out of `Set-Cookie`. | Profiles §4.3.2 | Always |
| Reject an IPv4 literal as the common domain | An IP address has no subdomains, so it cannot scope a common domain. | Profiles §4.3.2 | Always |
| Accept a persistent lifetime from 1 to 2147483647 whole seconds | Other values would be written as `Max-Age=0`, truncated, or overflow a 32-bit cookie parser. | Profiles §4.3.2 | Always |
| Read a raw `+` in an existing value as base64. When that list does not decode or has an entry that is not UTF-8, read the `+` as a form-encoded space if the list then decodes | Base64 uses `+` and form encoding writes a space as `+`, so reading both keeps the history that either kind of writer left. | Profiles §4.3.2 | Always |
| Skip an existing base64 entry that does not decode to a URI of at most 1024 characters, bytes that are not UTF-8 included, and keep the other entries in order | Skipping one entry keeps the rest of the history and still appends this identity provider, which Profiles §4.3.2 recommends. | Profiles §4.3.2 | Always |
| Start a new list for an empty existing value. Reject a value that is not percent-encoded text, or that has an empty entry or an entry that is not base64 | The writer cannot tell which entries such a value holds, so rewriting it could erase discovery history. | Profiles §4.3.2 | Always |
| Reject an existing value over 8192 bytes, and drop the oldest entries until the name and value fit in 4096 bytes | A resource limit, and Chromium discards a larger cookie. | — | Always |

[SimpleSAMLphp CDC v1.2.0](https://github.com/simplesamlphp/simplesamlphp-module-cdc/blob/v1.2.0/src/Server.php#L211-L227)
also moves the current identity provider to the end. Its
[cookie reader](https://github.com/simplesamlphp/simplesamlphp-module-cdc/blob/v1.2.0/src/Server.php#L387-L408)
throws when a decoded identifier fails its URI check.
[Shibboleth SP 3.5.2](https://codeberg.org/Shibboleth/cpp-sp/src/tag/3.5.2/shibsp/lite/CommonDomainCookie.cpp#L61-L69)
drops an entry that is not base64 and keeps every decoded one.

## Application duties

| Duty | Level | Section |
| --- | --- | --- |
| After the principal authenticates, write the cookie that `common_domain_cookie` returns | Optional | Profiles §4.3.3 |
| Write `CommonDomainCookie::set_cookie_header` as the whole `Set-Cookie` value, or write its `NAME`, `value`, `PATH`, `domain`, and `lifetime` with another cookie API and mark the cookie `Secure` | Mandatory | Profiles §4.3.2 |

<a id="not-implemented"></a>

## Not supported

- Reading the cookie at the service provider and SP Lite. Optional in
  Conformance Table 2. Profiles §4.3.4 describes how a service provider
  obtains it.
- The service provider side of SAMLDS: the §2.4.1 request, the §2.4.3
  response, and `idpdisc:DiscoveryResponse` endpoints in SP metadata (§2.5).
  The application chooses the identity provider and passes its
  `IdpDescriptor` to `start_sso`.
- A SAMLDS discovery service.
