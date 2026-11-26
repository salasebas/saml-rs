# Update logout messages and response signing

[How to upgrade from 0.3 to 0.4](README.md)

For required timestamps, follow the [shared timestamp rule](timestamps.md).

## If a typed IdP starts logout with a custom template

`Saml<Idp>::start_slo` treats the local IdP as the SAML Session Authority and
always emits an unqualified `LogoutRequest@NotOnOrAfter` on Redirect, POST,
and POST-SimpleSign. The value is exactly `issuance_lifetime` after the same
captured `IssueInstant`. Both instants are stored on `PendingLogoutRequest`
and its snapshot. If you persist those snapshots, store `issued_at` and
`expires_at`.

A custom template for that call must contain exactly one complete,
unqualified root attribute:

```xml
NotOnOrAfter="{NotOnOrAfter}"
```

The rendered XML is validated before signing. The call fails before dispatch
if the template omits the placeholder, repeats or qualifies the attribute,
emits malformed XML, hard-codes another value, or changes the generated
`IssueInstant`, subject, session indexes, destination, issuer, or ID. It also
fails if the template supplies a root `ds:Signature`. The library places the
POST XML signature. Redirect and POST-SimpleSign cover the validated XML with
their detached signatures.

`Saml<Sp>::start_slo` stays a Session Participant flow. It does not generate
`NotOnOrAfter`, and its pending issue and expiration fields stay unset. Raw
`create_logout_request` and `create_logout_request_with_id` are unchanged and
still omit a generated expiration. `LOGOUT_REQUEST_TEMPLATE` is unchanged.
The Session Authority validator does not apply to SP custom templates.

Leave a generic inbound `LogoutRequest` valid when `NotOnOrAfter` is absent.
That omission is still schema-valid. Do not reject it only because a Session
Authority must set the attribute when it creates the request.

## If you accept inbound `LogoutRequest` messages

`IssueInstant` is required on the shared raw parser, on conversion to the
typed `LogoutRequest`, on both typed `receive_slo` roles, and on HTTP-POST,
HTTP-Redirect, and HTTP-POST-SimpleSign. `NotOnOrAfter` stays optional. When
it is present, it uses the same unqualified UTC form.

Add `IssueInstant`. Add `NotOnOrAfter` only when the sender supplies an
exclusive deadline:

```xml
<samlp:LogoutRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="_request"
    Version="2.0"
    IssueInstant="2026-07-23T12:00:00Z"
    NotOnOrAfter="2026-07-23T12:05:00Z">
    <!-- Issuer and logout subject -->
</samlp:LogoutRequest>
```

A `FlowResult` converted to `LogoutRequest` needs `request.issueInstant`. Add
`request.notOnOrAfter` only when the wire message has the attribute:

```json
{
  "request": {
    "id": "_request",
    "issueInstant": "2026-07-23T12:00:00Z",
    "notOnOrAfter": "2026-07-23T12:05:00Z"
  }
}
```

Optional accessors:

```rust
let issued_at = request.issue_instant().as_str();
let deadline = request.not_on_or_after().map(|instant| instant.as_str());
```

Update tests that used to accept an expired `NotOnOrAfter`. Expiration returns
`SamlError::TimeWindowInvalid` with
`TimeWindowField::LogoutRequestNotOnOrAfter`. The exclusive deadline is the
supplied instant plus the configured `NotOnOrAfter` clock skew. Validation
rejects when `now` is equal to or later than that deadline. That rejection is
saml-rs policy; SAML does not require a receiver to reject it.

When typed replay storage is required and `NotOnOrAfter` is present, the cache
entry expires at that same skew-adjusted deadline. When the attribute is
absent, the existing `replay_retention` fallback still applies.
`ReplayPolicy::DisabledForCompatibility` disables replay storage only. It does
not disable expiration checks. No maximum age is derived from `IssueInstant`.

## If you send custom `LogoutResponse` XML

`IssueInstant` is required on HTTP-POST, HTTP-Redirect, and
HTTP-POST-SimpleSign, including `parse_logout_response`,
`parse_logout_response_without_request_id`, typed conversion from
`FlowResult`, and typed `finish_slo`.

```xml
<samlp:LogoutResponse
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="_response"
    Version="2.0"
    IssueInstant="2026-07-16T23:13:10Z">
    <samlp:Status>
        <samlp:StatusCode
            Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
</samlp:LogoutResponse>
```

A hand-built `FlowResult` needs the same field:

```json
{
  "response": {
    "id": "_response",
    "issueInstant": "2026-07-16T23:13:10Z"
  }
}
```

To read it:

```rust
let issue_instant = response.issue_instant().as_str();
```

These checks add no freshness window. Callers of
`parse_logout_response_without_request_id` still own request correlation,
replay protection, and any freshness policy of their own.

## If you set `logout_response_template`

The XML rendered from `TemplatePolicy::logout_response_template` is validated
before encoding or signing. Signed HTTP-POST output is validated again after
signing. This checks what you generate. It does not add a new inbound
rejection.

Skip this section when you use the standard LogoutResponse renderer and you
do not call `RespondSlo::signing`. Review the template if it adds custom
attributes or SAML children, omits `Issuer`, `Status`, `Destination`, or
`InResponseTo`, or includes a root `ds:Signature`.

The rendered root must be a SAML protocol `LogoutResponse` with the generated
`ID`, version `2.0`, and a valid UTC `IssueInstant`. When the response answers
a known request, `InResponseTo` must be present, use the XML Schema `NCName`
form, and match that request. A signed response must set `Destination` to the
selected SLO endpoint.

Direct children use this order:

1. required SAML assertion `Issuer`;
2. optional library-generated `ds:Signature`;
3. optional protocol `Extensions`;
4. exactly one final protocol `Status`.

`Issuer` must identify the responding entity. If `Format` is present, it must
be `urn:oasis:names:tc:SAML:2.0:nameid-format:entity`, and the value must be
an absolute URI of at most 1024 characters. Entity-format qualifiers are not
allowed.

`Extensions` must contain at least one namespace-qualified element that is not
a SAML assertion or protocol element. `Status` must contain exactly one
leading `StatusCode`, then only an optional `StatusMessage` and an optional
`StatusDetail`.

Keep the generated message and the template correlated:

```xml
<samlp:LogoutResponse
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{ID}"
    Version="2.0"
    IssueInstant="{IssueInstant}"
    Destination="{Destination}"
    InResponseTo="{InResponseTo}">
    <saml:Issuer>{Issuer}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="{StatusCode}"/>
    </samlp:Status>
</samlp:LogoutResponse>
```

Omit any root `ds:Signature`. `saml-rs` builds the embedded HTTP-POST
signature, or the detached Redirect or SimpleSign signature, after the
unsigned XML validates.

Malformed structure and lexical values return `SamlError::ProtocolProfile`.
A generated ID mismatch returns `SamlError::Invalid`. Issuer, destination, and
request-correlation mismatches keep their existing semantic errors. The
failure happens before dispatch. There is no typed compatibility switch for a
template that relied on undeclared attributes, the wrong child order, SAML
content inside `Extensions`, an incomplete `Status`, or its own XML signature.

## If you call `RespondSlo::signing`

`RespondSlo::signing` is removed. Typed SLO responses are always signed, even
when local validation is in compatibility mode.

Before:

```rust
let response = idp.respond_slo(
    &sp,
    &request,
    RespondSlo::post().signing(LogoutSigning::DoNotSignForCompatibility),
)?;
```

After:

```rust
let response = idp.respond_slo(&sp, &request, RespondSlo::post())?;
```

The typed configuration needs a usable signing key and certificate. For an
unsigned compatibility response, call
`saml_rs::raw::logout::create_logout_response` with `want_signed = false` and
keep that call outside the typed flow.

`LogoutSigning` remains on `StartSlo`. Request-signing call sites stay as they
are.
