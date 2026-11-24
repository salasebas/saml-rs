# Identity Provider Discovery

`IdentityProvider::common_domain_cookie` builds the common domain cookie, and
the caller writes it. `respond_sso` does not write the cookie, and no
service-provider method reads it. The IdP and SP operational modes stay
unclaimed.

Normative text is Profiles §4.3 as renumbered by Approved Errata 05 E32:
§4.3.2 is the cookie, §4.3.3 is setting it, and §4.3.4 is reading it. Under
E63, either cookie lifetime records identity providers used in the past. A
session-only cookie does not mean the user still has a session there. Core
§8.3.6 defines entity identifiers.

## Identity provider

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Name the cookie `_saml_idp` | Mandatory | Profiles §4.3.2 | Always |
| Write the value as base64 entity identifiers separated by one space, then URL-encode it | Mandatory | Profiles §4.3.2 | Always |
| Write only URI entity identifiers of at most 1024 characters, including those carried over from the existing cookie | Mandatory | Profiles §4.3.2, Core §8.3.6 | Always |
| Append this identity provider to the list | Recommended | Profiles §4.3.2 | Always |
| Move this identity provider to the end when it is already listed | Optional | Profiles §4.3.2 | Always |
| Set `Path=/`, `Domain=.{common-domain}`, and `Secure` | Mandatory | Profiles §4.3.2 | Always |
| Make the cookie session-only or persistent | Optional | Profiles §4.3.2, E63 | `CommonDomainCookieLifetime` |
| Set the cookie after the principal authenticates | Optional | Profiles §4.3.3 | `common_domain_cookie` |
| Reject an IPv4 literal as the common domain | Library policy: an IP address has no subdomains, so it cannot scope a common domain. | Profiles §4.3.2 | Always |
| Accept a persistent lifetime from 1 to 2147483647 whole seconds | Library policy: other values would be written as `Max-Age=0`, truncated, or overflow a 32-bit cookie parser. | Profiles §4.3.2 | Always |
| Skip invalid identifiers in a decodable existing list and keep valid identifiers in order | Library policy: skipping individual entries preserves usable discovery history. | Profiles §4.3.2 | Always |
| Start a new list for an empty existing value and reject a list that does not decode | Library policy: rewriting an undecodable list could erase discovery history. | Profiles §4.3.2 | Always |
| Reject an existing value over 8192 bytes, and drop the oldest entries until the name and value fit in 4096 bytes | Library policy: a resource limit, and Chromium discards a larger cookie. | — | Always |

A raw `+` in an existing value is read as base64 first. When that list does
not decode, the `+` is read as a URL-encoded space.

Profiles §4.3.2 specifies the value an identity provider writes. It leaves
recovery from a stored invalid identifier to the writer.
[SimpleSAMLphp CDC v1.2.0](https://github.com/simplesamlphp/simplesamlphp-module-cdc/blob/v1.2.0/src/Server.php#L211-L227)
also moves the current identity provider to the end. Its
[cookie reader](https://github.com/simplesamlphp/simplesamlphp-module-cdc/blob/v1.2.0/src/Server.php#L387-L408)
throws when a decoded identifier fails its URI check. `saml-rs` skips that
entry so the write can still remember the current identity provider and
preserve valid history. There is no option to republish invalid identifiers.

## Not implemented

- The service provider and SP Lite read the cookie. Optional in Conformance
  Table 2. Profiles §4.3.4 describes how a service provider obtains it.
