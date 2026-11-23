---
title: "Validation"
description: "Start on Recommended, add a direct Assertion signature or the RSA-SHA2 profile when that check is required, and relax a rule by naming its field."
---

This guide shows you how to choose the validation preset for typed service-provider and identity-provider code.

## Start on Recommended

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

The validation policies' `Default` and the `SpConfig` and `IdpConfig` builders already use Recommended. Each field and what its values relax is in the [conformance records](../reference/conformance.md).

An upgrade from 0.6, including a call to `strict()`, is [0.6 to 0.7](upgrade/v0-6-to-v0-7.md).

Why Recommended is the only preset is in [Validation presets](../explanation/validation-presets.md). Each published row is in the [conformance records](../reference/conformance.md).
