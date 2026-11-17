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
        status: Status,
    },
    StatusMissing,
    AssertionMissing,
    SubjectConfirmationInvalid {
        reason: &'static str,
    },
    TimeWindowInvalid {
        field: &'static str,
    },
    SignatureMissing,
    AuthnRequestSigningRequired,
    MissingBindingParameter {
        name: &'static str,
    },
    DuplicateBindingParameter {
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
        key: ReplayKey,
    },
    ReplayCacheUnavailable {
        source: Box<dyn Error + Send + Sync>,
    },
    RecipientEndpointNotPublished,
    RecipientEndpointAmbiguous,
    LimitExceeded {
        limit: ResourceLimit,
        maximum: usize,
    },
    UnsupportedBinding {
        binding: raw::Binding,
    },
    OutboundBindingMismatch {
        actual: raw::Binding,
    },
    UnsupportedProfile {
        profile: &'static str,
    },
    Xml {
        message: String,
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    Crypto {
        message: String,
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    Base64 {
        source: Box<dyn Error + Send + Sync>,
    },
    Deflate {
        source: Box<dyn Error + Send + Sync>,
    },
    Unsupported(String),
}
```

Exact payload types can change during implementation. The important rule is
that each security validation rule has a branchable variant.

## Payload And Source Rules

- A case callers handle differently has its own variant with typed data:
  `Status` for a peer status, `ReplayKey` for a replay, `ResourceLimit` and
  the configured maximum for a limit, and `Binding` for a binding mismatch.
- A top-level `StatusCode` outside the four values of Core §3.2.2.2 is a
  `ProtocolProfile` failure, not a status. A subordinate code keeps the
  peer's URI.
- A lower-level error stays reachable through `std::error::Error::source`, as
  `Box<dyn Error + Send + Sync>`. No third-party type or `From` impl appears
  in the public enum, so `?` never turns an unrelated `io::Error` into a
  DEFLATE failure.
- `Display` says what failed at this layer and does not repeat the source.
- `Invalid`, `ProtocolProfile`, `Unsupported`, `MissingMetadata`,
  `MissingKey`, and the `message` of `Xml` and `Crypto` cover failures callers
  do not branch on. Their text is for people and is not an API.
- `UnsupportedBinding` means the operation does not handle the binding.
  `OutboundBindingMismatch` means the caller asked an `Outbound` for another
  binding's delivery.

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
    Disabled,
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

`ReplayPolicy::Disabled` preserves the raw API, which has no
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

For SP-initiated SSO/SLO, if pending state carries RelayState and the inbound
message does not carry the same value, fail with `RelayStateMismatch`. If
pending state expects `Absent`, accept any inbound RelayState.

## Validation Order For SP SSO Response

The typed `finish_sso` path should preserve fail-closed validation and make the
order explicit:

1. Decode binding and enforce parser limits.
2. Reject malformed or disallowed XML.
3. Check response status.
4. Verify signature and signed-reference coverage.
5. Reject a success response that carries no assertion.
6. Check issuer.
7. Check destination and recipient.
8. Check `InResponseTo` against `Pending<AuthnRequest>`.
9. Check RelayState exactly when the request carried it, including present
   empty versus present value.
10. Check assertion conditions time window using caller-owned `now`.
11. Check audience.
12. Check bearer subject confirmation.
13. Check replay cache for response/assertion/session keys.
14. Convert to `SsoSession`.

## Metadata Signature Validation

A `bool` is not enough for signed metadata in the typed API. The caller also
needs the signed descriptor that verification covered.

The verification result this design called for:

```rust
pub struct MetadataSignatureVerification { /* private fields */ }

impl MetadataSignatureVerification {
    pub fn verified(&self) -> bool;
    pub fn signed_metadata_xml(&self) -> Option<&str>;
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
  `RequireSignatureAllowingWeakAlgorithms` accepts them.
- It must prove that signed root is covered and preserve its XML as trust
  evidence.
- If the signature shape or coverage cannot be determined, fail closed with
  `SignedReferenceMismatch`.
- If no pinned certificate verifies the metadata signature, fail closed with a
  branchable signature/trust error such as `SignatureVerification`.
