# Update response signing

[How to upgrade from 0.2 to 0.3](README.md)

## Rename the response signature policy

`MessageSignaturePolicy` and `SpValidationPolicy::messages` are removed. There
is no deprecated alias.

Before:

```rust
use saml_rs::{MessageSignaturePolicy, SpValidationPolicy};

let mut validation = SpValidationPolicy::strict();
validation.messages = MessageSignaturePolicy::RequireSigned;
```

After:

```rust
use saml_rs::{ResponseSignaturePolicy, SpValidationPolicy};

let mut validation = SpValidationPolicy::strict();
validation.responses = ResponseSignaturePolicy::RequireSigned;
```

The replacement variants are:

- `RequireSigned`, which authenticates every Response;
- `RequireForEncryptedCbc`, which signs a Response that contains a
  CBC-encrypted Assertion;
- `AllowUnsignedEncryptedCbcForCompatibility`, which relaxes that CBC case.
  This variant is the default of the standalone enum. From 0.6, use
  `AllowUnsignedEncryptedCbc` and `RespondSso::allow_unsigned_encrypted_cbc`
  ([0.5 to 0.6](../0.5-to-0.6/validation.md#rename-the-cbc-response-signature-relaxation)).

`SpValidationPolicy::strict()` still requires a trusted signature directly
over the consumed Assertion, and it uses
`ResponseSignaturePolicy::RequireForEncryptedCbc`. Plaintext responses do not
need Response-root coverage unless you opt in:

```rust
use saml_rs::{ResponseSignaturePolicy, SpValidationPolicy};

let validation = SpValidationPolicy {
    responses: ResponseSignaturePolicy::RequireSigned,
    ..SpValidationPolicy::strict()
};
```

`RequireSigned` is satisfied only by trusted signature evidence over the
Response root. An Assertion-only signature does not satisfy it. A verified
HTTP-Redirect detached signature, or an HTTP-POST-SimpleSign CD04 signature,
still satisfies the response-message requirement on those bindings.

When one of those binding-level messages is authenticated, the typed receiver
requires `Response@Destination` and rejects both a missing value and a
mismatch. An unsigned HTTP-POST Response whose Assertion is signed directly
does not pick up that Destination requirement.

A signature directly over the Assertion is saml-rs policy. It matches
`WantAssertionsSigned` in SAML metadata. Why a signed Response without a
signed Assertion can still be valid is explained in
[standards conformance](../../standards-conformance.md).

## Sign typed IdP responses that encrypt with CBC

A typed IdP signs the top-level Response when it generates an
`EncryptedAssertion` with a known CBC-mode algorithm. To force an embedded
XML signature on any HTTP-POST response:

```rust
let options = RespondSso::post().sign_response();
let response = idp.respond_sso(sp, &request, subject, options)?;
```

`sign_response()` does not replace HTTP-POST-SimpleSign. That binding still
uses its detached signature.

To keep an unsigned CBC-encrypted response for a legacy peer:

```rust
let options =
    RespondSso::post().allow_unsigned_encrypted_cbc_for_compatibility();
let response = idp.respond_sso(sp, &request, subject, options)?;
```
