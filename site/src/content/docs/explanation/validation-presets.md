---
title: "Validation presets"
description: "saml-rs keeps one preset, Recommended, and names each relaxation as a field."
---

saml-rs keeps one preset, Recommended.

**Recommended** is the preset for features the crate claims. Mandatory requirements stay in force. Recommendations start enabled and can be relaxed only by an explicit named option. A producer recommendation does not, by itself, become a receiver rejection. Optional capabilities stay off until you select them. Recommended is not an implementation of SAML V2.0 as a whole.

Library hardening that OASIS does not require stays off Recommended. Two examples are a signature directly on the Assertion, and the RSA-SHA2 XML-DSig profile. Each is selected by name, on top of Recommended. They are not collected into a second preset. One implementation-security default is the exception: Recommended excludes MD5 and RIPEMD-160 signature and digest algorithms and RSA keys shorter than 2048 bits (`XmlSignatureProfile::ExcludeWeakAlgorithms`), and `AllowWeakAlgorithms` relaxes it. Signed metadata import applies the same exclusion under `MetadataTrustPolicy::RequireSignature` and `RequireSignatureAllowingInclusiveCanonicalization`, and `RequireSignatureAllowingWeakAlgorithms` relaxes it. A MAY in the standard is an optional capability, not a stricter conformance level. That is why a bundled `strict()` preset was rejected.

The conformance records call these settings Recommended. The role policies
expose them through `Default`. Both config builders use the
corresponding role default. See [Conformance](../reference/conformance.md).

Earlier releases had a permissive `compatibility()` preset. Selecting it for unsigned logout also allowed weak signature algorithms and skipped audience evaluation. Browser logout now requires a verified signature, and the SP checks every present audience restriction. To keep an individual relaxation, such as allowing weak signature algorithms, see the [0.8 to 0.9 migration guide](https://github.com/salasebas/saml-rs/blob/main/docs/migrations/0.8-to-0.9/compile-errors.md#126-replace-compatibility-with-the-fields-it-relaxed).

How to select and relax the preset is [Validation](../guides/validation-preset.md). How to upgrade from 0.6 is [0.6 to 0.7](../guides/upgrade/v0-6-to-v0-7.md).
