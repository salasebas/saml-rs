# Pass the authentication time of each SSO assertion

If you run an identity provider, `SsoAssertion::new` now takes the time at
which the subject authenticated as its second argument, and
`SsoAssertion::authn_instant` is removed. Before, an assertion without
`authn_instant` reported the response `IssueInstant` as its `AuthnInstant`.
That is wrong whenever the login reuses an identity provider session, and a
service provider that limits the age of an authentication then accepts a
login it should refuse.

Every caller of `SsoAssertion::new` must pass a `SystemTime`. Pass the time
of the login, or the time the reused session authenticated the user.

Before:

```rust
let assertion = SsoAssertion::new(name_id).authn_instant(session.authenticated_at);
let fresh = SsoAssertion::new(name_id);
```

After:

```rust
let assertion = SsoAssertion::new(name_id, session.authenticated_at);
let fresh = SsoAssertion::new(name_id, SystemTime::now());
```

The rules for the time are unchanged. Issuance returns `SamlError::Invalid`
when the time is later than the moment the response is issued, or before
year 1. The comparison uses the time before it is rounded down to the second,
so a time later in the same second as the issuance is also rejected.
