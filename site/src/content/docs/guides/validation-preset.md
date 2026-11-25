---
title: "Validation"
description: "Start with the role defaults and change an individual validation rule when a peer or deployment needs it."
---

Configure validation for the typed service provider and identity provider.

## Start with the role defaults

```rust
let policy = SpValidationPolicy::default();
```

To require a signature directly on the Assertion, and leave the XML-DSig profile unchanged:

```rust
let mut require_assertion_signature = SpValidationPolicy::default();
require_assertion_signature.assertion_signatures = AssertionSignaturePolicy::RequireSigned;
```

To require the RSA-SHA2 XML-DSig profile, and leave Assertion signatures optional:

```rust
let mut require_rsa_sha2 = SpValidationPolicy::default();
require_rsa_sha2.xml_signatures = XmlSignatureProfile::StrictRsaSha2;
```

Set both fields when you want both. Use `IdpValidationPolicy::default()` for the identity provider.

## Relax one rule

If a peer uses CBC encryption and cannot sign the enclosing SSO response,
you can relax the SP's outer signature requirement for those responses.

```rust
let mut validation = SpValidationPolicy::default();
validation.response_signatures = ResponseSignaturePolicy::AllowUnsignedEncryptedCbc;
```

The SP and IdP builders use the corresponding role's `Default`. The
[conformance records](../reference/conformance.md) list the options for each
flow.

An upgrade from 0.6, including a call to `strict()`, is [0.6 to 0.7](upgrade/v0-6-to-v0-7.md).

See [Validation defaults](../explanation/validation-presets.md) for the rules
these policies select.
