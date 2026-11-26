---
title: "Validation defaults"
description: "How the SP and IdP validation defaults apply mandatory rules, recommendations, and library policies."
---

The SP and IdP config builders start from `SpValidationPolicy::default()` and
`IdpValidationPolicy::default()`, respectively. Change the field for the
rule you need.

Mandatory requirements apply whenever their conditions hold. Rules marked
Recommended in the [conformance records](../reference/conformance.md) start
enabled. A named option can relax a recommendation where the API offers one.
Select optional capabilities explicitly.

Select a signature directly on the assertion or the RSA-SHA2 signature
profile by setting its own field. Both role defaults select
`XmlSignatureProfile::ExcludeWeakAlgorithms`. It excludes MD5 and RIPEMD-160
signature and digest algorithms and RSA keys shorter than 2048 bits.
`AllowWeakAlgorithms` relaxes that library policy.

Metadata trust and replay storage are explicit caller choices.
`MetadataTrustPolicy::RequireSignature` and
`RequireSignatureAllowingInclusiveCanonicalization` apply the same algorithm
exclusions to signed metadata. `RequireSignatureAllowingWeakAlgorithms`
relaxes them.

Earlier releases had a permissive `compatibility()` preset. Selecting it for unsigned logout also allowed weak signature algorithms and skipped audience evaluation. Browser logout now requires a verified signature, and the SP checks every present audience restriction. To keep an individual relaxation, such as allowing weak signature algorithms, see the [0.8 to 0.9 migration guide](https://github.com/salasebas/saml-rs/blob/main/docs/migrations/0.8.x-to-0.9.0/compile-errors.md#126-replace-compatibility-with-the-fields-it-relaxed).

See [Configure validation](../guides/validation-preset.md) for examples.
See [0.6 to 0.7](../guides/upgrade/v0-6-to-v0-7.md) for the older presets.
