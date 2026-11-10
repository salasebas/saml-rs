# Keep two validation presets and retire the strict bundle

saml-rs keeps two validation presets, Compatibility and Recommended.
Compatibility is the legacy permissive preset: the samlify-port behaviour kept
for callers leaving the raw API. It can still relax a mandatory requirement
where that port did, and it does not claim standards conformance. It does not
name a relaxation of an OASIS recommendation. Raw settings keep their own
historical defaults and are not rewritten to match it. Recommended is the
preset for claimed features. It is not an implementation of SAML V2.0 as a
whole. For the obligated actor, mandatory requirements stay in force, and
recommendations start enabled and can be relaxed only by an explicit named
option. A producer recommendation does not by itself become a receiver
rejection. Optional capabilities stay off until selected by name. Library
hardening that OASIS does not require, such as a direct Assertion signature
or the RSA-SHA2 XML-DSig profile, is also selected by name on top of
Recommended rather than collected into a third preset. One implementation-security
default is the exception: Recommended excludes MD5 and RIPEMD-160 signature and
digest algorithms and RSA keys shorter than 2048 bits
(`XmlSignatureProfile::ExcludeWeakAlgorithms`), and
`AllowProviderSupportedForCompatibility` relaxes it. Signed metadata import
applies the same exclusion under `MetadataTrustPolicy::RequireSignature` and
`RequireSignatureAllowingOtherCanonicalization`, and
`RequireSignatureAllowingWeakAlgorithmsForCompatibility` relaxes it. A bundled strict
preset was rejected because callers need those hardenings independently, and
because a MAY is an optional capability rather than a stricter conformance
level.

Web Browser SSO, Single Logout, metadata, and replay are classified under
`docs/conformance/`. `recommended()` publishes that combination.
`strict()` is removed. `Default`, `new`, `try_new`, and the config builders
start on Recommended so typed construction has one preset. A direct Assertion
signature and the RSA-SHA2 XML-DSig profile stay independent options on that
preset. `compatibility()` remains the legacy permissive preset.
