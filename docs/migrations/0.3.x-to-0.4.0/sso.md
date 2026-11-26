# Update SSO messages and issuance settings

[How to upgrade from 0.3 to 0.4](README.md)

For required timestamps, follow the [shared timestamp rule](timestamps.md).

## If you send custom `AuthnRequest` XML

The check covers HTTP-POST, HTTP-Redirect, and HTTP-POST-SimpleSign. Skip this
section when every request comes from the standard APIs.

Before, a request without `IssueInstant` could reach the normal flow:

```xml
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="_request"
    Version="2.0"/>
```

Add the timestamp:

```xml
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="_request"
    Version="2.0"
    IssueInstant="2026-07-16T23:13:10Z"/>
```

A hand-built `FlowResult` must carry the same value:

```json
{
  "request": {
    "id": "_request",
    "issueInstant": "2026-07-16T23:13:10Z"
  }
}
```

To read it from a typed request:

```rust
let issue_instant = request.issue_instant().as_str();
```

## If you send custom SSO `Response` or `Assertion` XML

An inbound SSO `Response` and its selected `Assertion` each need
`IssueInstant`. The rule covers raw POST, Redirect, and SimpleSign parsing,
conversion to `SsoResponse` or `SsoSession`, solicited `finish_sso`, and
unsolicited SSO on the bindings those typed flows support. An assertion
recovered through XML Encryption is checked again after decryption.

Before, either level could omit the timestamp:

```xml
<samlp:Response
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_response"
    Version="2.0">
    <!-- Status and other response content -->
    <saml:Assertion ID="_assertion" Version="2.0">
        <!-- Assertion content -->
    </saml:Assertion>
</samlp:Response>
```

Add both:

```xml
<samlp:Response
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_response"
    Version="2.0"
    IssueInstant="2026-07-20T16:00:00Z">
    <!-- Status and other response content -->
    <saml:Assertion
        ID="_assertion"
        Version="2.0"
        IssueInstant="2026-07-20T16:00:01Z">
        <!-- Assertion content -->
    </saml:Assertion>
</samlp:Response>
```

A `FlowResult` converted to `SsoResponse` needs `response.issueInstant`.
Conversion to `SsoSession` needs both values:

```json
{
  "response": {
    "id": "_response",
    "issueInstant": "2026-07-20T16:00:00Z"
  },
  "assertion": {
    "id": "_assertion",
    "issueInstant": "2026-07-20T16:00:01Z"
  }
}
```

The new accessors are optional:

```rust
let envelope_instant = response.issue_instant().as_str();
let response_instant = session.response_issue_instant().as_str();
let assertion_instant = session.assertion_issue_instant().as_str();
```

## If you write an `IdpConfig` struct literal

`IdpConfig::issuance_lifetime` is a `std::time::Duration`. The default is 300
seconds. That duration is saml-rs policy; SAML does not require it. Zero, and
a duration outside the internal `time::Duration` range, fail
`IdpConfig::validate` and `IdpConfigBuilder::build` as `SamlError::Invalid`.
A duration that cannot be added to the current UTC issue instant fails at
issuance as `SamlError::TimeWindowInvalid` with
`TimeWindowField::IdpIssuanceExpiration`.

Add the field to every public struct literal:

```rust
use std::time::Duration;

let config = IdpConfig {
    entity_id,
    metadata,
    credentials,
    issuance_lifetime: Duration::from_secs(300),
    validation,
    algorithms,
    xml,
    templates,
};
```

Builder call sites keep the default, or set another window:

```rust
use std::time::Duration;

let config = IdpConfig::builder(entity_id)
    .sso_endpoint(sso)
    .issuance_lifetime(Duration::from_secs(10 * 60))
    .build()?;
```

`Saml<Idp>::respond_sso` and `Saml<Idp>::initiate_sso` capture the UTC clock
once per response. The structured renderer and the placeholder renderer both
receive that `IssueInstant` and the expiration derived from
`issuance_lifetime`. A whole-second lifetime keeps the existing whole-second
UTC form. A subsecond lifetime that the clock can represent keeps nanosecond
precision in both values, so `Conditions@NotOnOrAfter` and bearer
`SubjectConfirmationData@NotOnOrAfter` match.

The raw `IdentityProvider` surface keeps its five-minute lifetime and its
custom replacement hook. Its standard renderers also use one captured instant.
