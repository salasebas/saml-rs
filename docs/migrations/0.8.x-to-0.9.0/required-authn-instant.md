# Pass the authentication time of each SSO assertion

If you run an identity provider, pass the time at which the subject
authenticated as the second argument of `SsoAssertion::new`. It has no
default. In 0.8, `RespondSso::authn_instant` set it, and a response without
that option reported the response `IssueInstant` as its `AuthnInstant`. That
is wrong whenever the login reuses an identity provider session, and a
service provider that limits the age of an authentication then accepts a
login it should refuse.

Pass the time of the login, or the time the reused session authenticated the
user.

Before:

```rust,ignore
let response = idp.respond_sso(
	&sp,
	&request,
	subject,
	RespondSso::post().authn_instant(session.authenticated_at),
)?;
let fresh = idp.respond_sso(&sp, &request, subject, RespondSso::post())?;
```

After:

```rust,ignore
let response = idp.respond_sso(
	&sp,
	&request,
	SsoAssertion::new(name_id, session.authenticated_at),
	RespondSso::post(),
)?;
let fresh = idp.respond_sso(
	&sp,
	&request,
	SsoAssertion::new(name_id, SystemTime::now()),
	RespondSso::post(),
)?;
```

[Answer with an `SsoAssertion` or an `SsoOutcome`](sso-results-and-identities.md#answer-with-an-ssoassertion-or-an-ssooutcome)
covers the rest of the move from `Subject` and the `RespondSso` options.

The rules for the time are unchanged. Issuance returns `SamlError::Invalid`
when the time is later than the moment the response is issued, or before
year 1. The comparison uses the time before it is rounded down to the second,
so a time later in the same second as the issuance is also rejected.
