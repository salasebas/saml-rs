---
title: "Validation presets"
description: "saml-rs keeps two presets."
---

saml-rs keeps two presets.

**Recommended** is the preset for features the crate claims. Mandatory requirements stay in force. Recommendations start enabled and can be relaxed only by an explicit named option. A producer recommendation does not, by itself, become a receiver rejection. Optional capabilities stay off until you select them. Recommended is not an implementation of SAML V2.0 as a whole.

**Compatibility** is the legacy permissive preset: the samlify-port behaviour kept for callers leaving the raw API. It can still relax a mandatory requirement where that port did. It does not claim standards conformance. Raw settings keep their own historical defaults.

Library hardening that OASIS does not require stays off Recommended. Two examples are a signature directly on the Assertion, and the RSA-SHA2 XML-DSig profile. Each is selected by name, on top of Recommended. They are not collected into a third preset. A MAY in the standard is an optional capability, not a stricter conformance level. That is why a bundled `strict()` preset was rejected.

`recommended()` publishes the combination recorded under [Conformance](../reference/conformance.md).

With that bundle gone, `Default`, `new`, `try_new`, and the config builders share Recommended. One construction path avoids a silent split between a permissive `Default` and a hardened builder. `compatibility()` remains the named legacy preset. Raw settings keep their historical defaults.

How to select the preset is [Validation](../guides/validation-preset.md). How to upgrade from 0.6 is [0.6 to 0.7](../guides/upgrade/v0-6-to-v0-7.md). This page restates [ADR 0002](https://github.com/salasebas/saml-rs/blob/main/docs/adr/0002-validation-presets.md).
