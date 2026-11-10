# Typed Single Logout API

> Design record for the typed API. The live file index is
> [the module map](../module-map.md). A heading that says Proposed, Target,
> or Today describes this design.

Typed Single Logout follows the SSO shape: start, receive, respond, and
finish, with the same typed correlation. Logout then carries the role and the
pending message, rather than a free-form request identifier.

## Logout Subject

```rust
pub struct LogoutSubject {
    name_id: NameId,
    session_index: Option<SessionIndex>,
}

impl SsoSession {
    pub fn logout_subject(&self) -> Option<LogoutSubject>;
}
```

`logout_subject` returns `None` if the login session does not contain enough
SAML subject data for logout.

## Options

```rust
pub struct StartSlo {
    binding: LogoutBinding,
    relay_state: Option<RelayState>,
    signing: LogoutSigning,
}

pub struct RespondSlo {
    binding: LogoutBinding,
    signing: LogoutSigning,
}

pub enum LogoutSigning {
    FollowLocalPolicy,
    Sign,
    DoNotSignForCompatibility,
}
```

Avoid a bare `want_signed: bool` in typed SLO.

## Starting Logout

Prefer explicit methods on both local roles for rustdoc readability.

```rust
impl Saml<Sp> {
    pub fn start_slo(
        &self,
        idp: &IdpDescriptor,
        subject: LogoutSubject,
        options: StartSlo,
    ) -> Result<Started<LogoutRequest>, SamlError>;
}

impl Saml<Idp> {
    pub fn start_slo(
        &self,
        sp: &SpDescriptor,
        subject: LogoutSubject,
        options: StartSlo,
    ) -> Result<Started<LogoutRequest>, SamlError>;
}
```

`PendingLogoutRequest` should include:

- request ID;
- RelayState as exact tri-state: absent, present empty, or present value;
- peer entity ID;
- selected logout binding;
- the exact generated issue instant and expiration for Session Authority
  requests; Session Participant defaults leave both unset.

`PendingLogoutRequest` exposes accessors and a
`PendingSnapshot<LogoutRequest>` persistence shape. Reconstruct with
`Pending::from_snapshot(snapshot)`, validating peer entity ID, logout binding,
timing, and RelayState state. The snapshot stores no keys, raw metadata, or raw
entity settings.

## Receiving LogoutRequest

```rust
impl Saml<Sp> {
    pub fn receive_slo(
        &self,
        idp: &IdpDescriptor,
        input: BrowserInput<LogoutRequest>,
        validation: SamlValidationContext<'_>,
    ) -> Result<Received<LogoutRequest>, SamlError>;
}

impl Saml<Idp> {
    pub fn receive_slo(
        &self,
        sp: &SpDescriptor,
        input: BrowserInput<LogoutRequest>,
        validation: SamlValidationContext<'_>,
    ) -> Result<Received<LogoutRequest>, SamlError>;
}
```

`Received<LogoutRequest>` exposes:

- request ID;
- issuer;
- normalized `IssueInstant`;
- optional normalized `NotOnOrAfter`;
- NameID;
- parsed inbound session indexes;
- RelayState;
- raw flow.

`receive_slo` uses `SamlValidationContext` for inbound signed, timed, or
replay-sensitive logout request validation.

The typed receiver resolves its actual local SingleLogoutService endpoint from
metadata using the inbound binding. A present `Destination` must equal that
endpoint, and a mismatch is rejected even when the message is unsigned. Once
the HTTP binding or root XML signature authenticates the message,
`Destination` is also required. An absent `Destination` on an unauthenticated
message is accepted only under the samlify-port preset
`SpValidationPolicy::compatibility()` or
`IdpValidationPolicy::compatibility()`, and only for a binding that permits
unsigned logout input. These checks run before replay state is written. Raw
logout parsers cannot perform the same endpoint comparison because they are
not given the local receiving endpoint.

Inbound LogoutRequest profile checks require an unqualified UTC
`IssueInstant`. They deliberately do not infer a maximum age from it.
`NotOnOrAfter` is optional, but when present it must be unqualified UTC and
saml-rs rejects the request at or after the deadline plus configured
`NotOnOrAfter` skew. OASIS permits a recipient to discard after that instant;
the rejection is saml-rs' default fail-closed policy rather than a receiver
`MUST`. Replay storage derives its expiry from the same effective deadline.
Without `NotOnOrAfter`, required replay storage retains the existing explicit
`replay_retention` fallback.

Outbound roles remain distinct. `Saml<Idp>::start_slo` models a Session
Authority and always emits an unqualified UTC `NotOnOrAfter` exactly one
configured `IdpConfig::issuance_lifetime` after the same captured
`IssueInstant`. `Saml<Sp>::start_slo` models a Session Participant and does not
synthesize the attribute. Five minutes is the typed IdP default and library
policy, not an OASIS-mandated duration. Public raw request creation remains
unchanged.

Custom typed Session Authority templates use the complete root attribute
`NotOnOrAfter="{NotOnOrAfter}"`. Final XML is validated before signing for the
exact generated identity, timing, issuer, destination, subject, and session
indexes, and a template-owned root signature is rejected.

## Responding to LogoutRequest

```rust
impl Saml<Sp> {
    pub fn respond_slo(
        &self,
        idp: &IdpDescriptor,
        request: &Received<LogoutRequest>,
        options: RespondSlo,
    ) -> Result<Outbound<LogoutResponse>, SamlError>;
}

impl Saml<Idp> {
    pub fn respond_slo(
        &self,
        sp: &SpDescriptor,
        request: &Received<LogoutRequest>,
        options: RespondSlo,
    ) -> Result<Outbound<LogoutResponse>, SamlError>;
}
```

Rules:

- `InResponseTo` comes from `Received<LogoutRequest>`.
- `respond_slo` echoes `Received<LogoutRequest>` RelayState exactly. There is
  no option to replace or suppress it.
- The typed API takes `Received<LogoutRequest>` rather than a caller-supplied
  request-identifier string, so `InResponseTo` cannot drift from the request
  that was accepted.
- Custom LogoutResponse rendering that drops or empties `InResponseTo` while a
  typed request exists would break that correlation, so generation keeps the
  identifier from `Received<LogoutRequest>`.

## Finishing Logout

```rust
impl Saml<Sp> {
    pub fn finish_slo(
        &self,
        idp: &IdpDescriptor,
        pending: &PendingLogoutRequest,
        input: BrowserInput<LogoutResponse>,
        validation: SamlValidationContext<'_>,
    ) -> Result<LogoutCompleted, SamlError>;
}

impl Saml<Idp> {
    pub fn finish_slo(
        &self,
        sp: &SpDescriptor,
        pending: &PendingLogoutRequest,
        input: BrowserInput<LogoutResponse>,
        validation: SamlValidationContext<'_>,
    ) -> Result<LogoutCompleted, SamlError>;
}
```

Rules:

- Use `PendingLogoutRequest` as the only source of expected `InResponseTo`.
- Check pending peer entity ID against the passed descriptor.
- Accept a response to a front-channel request over any front-channel binding,
  and a response to a SOAP request over SOAP only. Resolve the local
  `Destination` for the binding the response arrived on.
- Match RelayState exactly: absent, present empty, and present value are
  distinct. If pending expects absent and the inbound message carries
  RelayState, fail unless the samlify-port Compatibility preset permits it.
- Use `SamlValidationContext` for inbound signed, timed, or replay-sensitive
  logout response validation.
- Apply the same binding-aware local `Destination` validation as
  `receive_slo`, before replay state is written.
- Keep request-ID-less logout response parsing raw/compat only.

## Result

```rust
pub struct LogoutCompleted {
    status: SamlStatus,
    in_response_to: MessageId,
    raw_flow: raw::FlowResult,
}
```
