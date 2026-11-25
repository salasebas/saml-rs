# Read the SSO session deadline as a `SystemTime`

This change affects service providers that cap their application session at
the identity provider's `SessionNotOnOrAfter`.

In 0.8, `SsoSession::authn_session().not_on_or_after()` returned the text of
the first `AuthnStatement`'s `SessionNotOnOrAfter`, and the application parsed
it with a date crate. `SsoSession::session_not_on_or_after()` now returns the
earliest `SessionNotOnOrAfter` of the consumed assertion as an
`Option<SystemTime>`, before clock skew. A fraction of a second finer than the
platform's `SystemTime` resolution is dropped, which moves the deadline
earlier.

Before the upgrade:

```rust,ignore
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

let expires_at = match session.authn_session().not_on_or_after() {
	Some(bound) => local_deadline.min(OffsetDateTime::parse(bound.as_str(), &Rfc3339)?),
	None => local_deadline,
};
```

After the upgrade, with `local_deadline` as a `SystemTime`:

```rust,ignore
let expires_at = match session.session_not_on_or_after() {
	Some(bound) => local_deadline.min(bound),
	None => local_deadline,
};
```

To read the text that the identity provider sent, use
`AuthnStatement::session_not_on_or_after` on each item of
`SsoSession::authn_statements`.
