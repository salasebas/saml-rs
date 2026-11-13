# Update Credentials struct literals for signing rollover

This unreleased change affects callers that construct `Credentials` with
every field listed, including through `opensaml`, `samlify`, or `samlet`.
The new public `additional_signing_certificates` field makes those literals
fail to compile.

Add `additional_signing_certificates: Vec::new()` to preserve existing
behaviour. For literals that use defaults, follow
[Complete struct literals](0.7-to-0.8.md#17-complete-struct-literals).
