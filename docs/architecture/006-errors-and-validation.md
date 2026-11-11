# Errors and validation

> Design record for the typed API. The live file index is
> [the module map](../module-map.md). A heading that says Proposed, Target,
> or Today describes this design.

The canonical error type remains `SamlError`. This note explains why a single
semantic error, plus an explicit validation context, replaced generic failure
buckets and hidden clocks.

## Starting point

This design started from a `SamlError` that mixed semantic SAML failures
with generic buckets:

```rust
SamlError::Xml(String)
SamlError::Invalid(String)
SamlError::Unsupported(String)
SamlError::Crypto(String)
SamlError::UnmatchIssuer
SamlError::UnmatchAudience
SamlError::UnmatchDestination
SamlError::InvalidInResponseTo
SamlError::MissingSigAlg
SamlError::UndefinedBinding
```

This works for fail-closed behaviour, but it is not enough for a polished typed
API. Callers should branch on validation rule failures without string matching.

## Target Error Shape

The semantic variants below are the ones callers match on. `UnmatchIssuer`
remains a compatibility variant beside `IssuerMismatch`.

Keep `SamlError` and make it semantic:

```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SamlError {
    IssuerMismatch {
        expected: String,
        actual: Option<String>,
    },
    AudienceMismatch {
        expected: String,
        actual: Vec<String>,
    },
    DestinationMismatch {
        expected: String,
        actual: Option<String>,
    },
    RecipientMismatch {
        expected: String,
        actual: Option<String>,
    },
    InResponseToMismatch {
        expected: Option<String>,
        actual: Option<String>,
    },
    RelayStateMismatch {
        expected: RelayStateParam,
        actual: RelayStateParam,
    },
    StatusNotSuccess {
        top: String,
        second: Option<String>,
    },
    SubjectConfirmationInvalid {
        reason: &'static str,
    },
    TimeWindowInvalid {
        field: &'static str,
    },
    SignatureMissing,
    MissingBindingParameter {
        name: &'static str,
    },
    SignatureVerification {
        reason: &'static str,
    },
    ReferenceResolution {
        reason: &'static str,
    },
    SignedReferenceMismatch,
    NoTrustedCertificate,
    MetadataTrustFailed {
        reason: &'static str,
    },
    ReplayDetected {
        key: String,
    },
    MissingBinding,
    UnsupportedBinding {
        binding: raw::Binding,
    },
    UnsupportedProfile {
        profile: &'static str,
    },
    Xml(String),
    Crypto(String),
    Unsupported(String),
}
```

Exact payload types can change during implementation. The important rule is
that each security validation rule has a branchable variant.

## Validation Context

Inbound typed browser flows should use caller-owned clock and replay:

```rust
pub struct SamlValidationContext<'a> {
    pub now: SamlInstant,
    pub clock_skew: ClockSkew,
    pub replay: ReplayPolicy<'a>,
}

pub enum ReplayPolicy<'a> {
    RequireCache(&'a mut dyn ReplayCache),
    DisabledForCompatibility,
}

pub trait ReplayCache {
    fn check_and_store(
        &mut self,
        key: ReplayKey,
        expires_at: SamlInstant,
    ) -> Result<(), SamlError>;
}
```

The raw samlify-port API can keep today's hidden process-clock behaviour. Typed browser
flows should not. Use `SamlValidationContext` in `finish_sso`,
`accept_unsolicited_sso`, `receive_sso`, `receive_slo`, `finish_slo`, and any
other inbound signed, timed, or replay-sensitive browser-message validation.

LogoutRequest time errors preserve the standards/policy boundary:

- missing, qualified, malformed, or non-UTC `IssueInstant`, and a qualified,
  malformed, or non-UTC `NotOnOrAfter`, are `ProtocolProfile` failures;
- an expired `NotOnOrAfter`, or one that is lexically conformant but cannot be
  represented for runtime comparison, is `TimeWindowInvalid` for
  `LogoutRequestNotOnOrAfter`;
- an effective deadline that cannot be represented by the caller's
  `SystemTime` replay cache is `TimeWindowInvalid` for `ReplayExpiration`.

`ReplayPolicy::DisabledForCompatibility` preserves the raw API, which has no
replay cache. It skips storage only. It does not disable the LogoutRequest
expiration policy.

RelayState comparison is exact tri-state:

```rust
pub enum RelayStateParam {
    Absent,
    PresentEmpty,
    PresentValue(RelayState),
}
```

For SP-initiated SSO/SLO, if pending state expects `Absent` and the inbound
message carries any RelayState, fail with `RelayStateMismatch` unless the
samlify-port Compatibility preset permits the extra parameter.

## Validation Order For SP SSO Response

The typed `finish_sso` path should preserve fail-closed validation and make the
order explicit:

1. Decode binding and enforce parser limits.
2. Reject malformed or disallowed XML.
3. Check response status.
4. Verify signature and signed-reference coverage.
5. Check issuer.
6. Check destination and recipient.
7. Check `InResponseTo` against `Pending<AuthnRequest>`.
8. Check RelayState exactly, including absent versus present empty.
9. Check assertion conditions time window using caller-owned `now`.
10. Check audience.
11. Check bearer subject confirmation.
12. Check replay cache for response/assertion/session keys.
13. Convert to `SsoSession`.

## Metadata Signature Validation

A `bool` is not enough for signed metadata in the typed API. The caller also
needs the signed descriptor that verification covered.

The verification result this design called for:

```rust
pub struct MetadataSignatureVerification { /* private fields */ }

impl MetadataSignatureVerification {
    pub fn verified(&self) -> bool;
    pub fn signed_entity_descriptor_xml(&self) -> Option<&str>;
}
```

Rules:

- `RequireSignature` requires `verification.verified() == true`.
- The signed root must carry an identifier and one enveloped `#id` reference.
  `RequireSignatureAllowingOtherCanonicalization` also accepts inclusive
  canonicalization. See `docs/conformance/metadata-and-replay.md`.
- `RequireSignature` and `RequireSignatureAllowingOtherCanonicalization`
  reject an MD5 or RIPEMD-160 signature or digest algorithm with
  `AlgorithmUnsupported` on a build that verifies it, and do not verify with
  a pinned RSA certificate shorter than 2048 bits.
  `RequireSignatureAllowingWeakAlgorithmsForCompatibility` accepts them.
- It must prove that signed root is covered and preserve its XML as trust
  evidence.
- If the signature shape or coverage cannot be determined, fail closed with
  `SignedReferenceMismatch`.
- If no pinned certificate verifies the metadata signature, fail closed with a
  branchable signature/trust error such as `SignatureVerification`.
