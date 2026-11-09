---
title: "Validation"
description: "Choose Recommended for typed construction, then add a direct Assertion signature or the RSA-SHA2 profile when that check is required."
---

This guide shows you how to choose the validation preset for typed service-provider and identity-provider code.

## Start on Recommended

```rust
let policy = SpValidationPolicy::recommended();
```

To require a signature directly on the Assertion, and leave the XML-DSig profile unchanged:

```rust
let require_assertion_signature = SpValidationPolicy {
    assertions: AssertionSignaturePolicy::RequireSigned,
    ..SpValidationPolicy::recommended()
};
```

To require the RSA-SHA2 XML-DSig profile, and leave Assertion signatures optional:

```rust
let require_rsa_sha2 = SpValidationPolicy {
    xml_signatures: XmlSignatureProfile::StrictRsaSha2,
    ..SpValidationPolicy::recommended()
};
```

Set both fields when you want both. `IdpValidationPolicy::recommended()` and `LogoutPolicy::recommended()` are the matching presets. `LogoutPolicy::recommended()` requires a signature on logout requests and responses.

## Keep Compatibility

To keep the legacy permissive preset, name it:

```rust
SpValidationPolicy::compatibility()
```

`Default`, `new`, `try_new`, and the config builders already use Recommended. Pass `compatibility()` when one of those constructors must stay permissive.

An upgrade from 0.6, including a call to `strict()`, is [0.6 to 0.7](upgrade/v0-6-to-v0-7.md).

Why the presets are separate is in [Validation presets](../explanation/validation-presets.md). Each published row is in the [conformance records](../reference/conformance.md).
