---
title: "Validation"
description: "Start on Recommended, add a direct Assertion signature or the RSA-SHA2 profile when that check is required, and relax a rule by naming its field."
---

This guide shows you how to choose the validation preset for typed service-provider and identity-provider code.

## Start on Recommended

```rust
let policy = SpValidationPolicy::recommended();
```

To require a signature directly on the Assertion, and leave the XML-DSig profile unchanged:

```rust
let mut require_assertion_signature = SpValidationPolicy::recommended();
require_assertion_signature.assertions = AssertionSignaturePolicy::RequireSigned;
```

To require the RSA-SHA2 XML-DSig profile, and leave Assertion signatures optional:

```rust
let mut require_rsa_sha2 = SpValidationPolicy::recommended();
require_rsa_sha2.xml_signatures = XmlSignatureProfile::StrictRsaSha2;
```

Set both fields when you want both. `IdpValidationPolicy::recommended()` and `LogoutPolicy::recommended()` are the matching presets. `LogoutPolicy::recommended()` requires a signature on logout requests and responses.

## Relax one rule

To relax a rule, assign the field that names it. For example, to accept unsigned logout requests and responses:

```rust
let mut unsigned_logout = SpValidationPolicy::recommended();
unsigned_logout.logout.requests = LogoutSignaturePolicy::AllowUnsigned;
unsigned_logout.logout.responses = LogoutSignaturePolicy::AllowUnsigned;
```

The other fields stay on Recommended. The validation policies' `Default` and the `SpConfig` and `IdpConfig` builders already use Recommended. Each field and what its values relax is in the [conformance records](../reference/conformance.md).

An upgrade from 0.6, including a call to `strict()`, is [0.6 to 0.7](upgrade/v0-6-to-v0-7.md).

Why Recommended is the only preset is in [Validation presets](../explanation/validation-presets.md). Each published row is in the [conformance records](../reference/conformance.md).
