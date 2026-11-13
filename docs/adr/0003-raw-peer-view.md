# A borrowed peer view for SLO and name identifier management

Decision for [#525](https://github.com/salasebas/saml-rs/issues/525), audit
item D2 in [#509](https://github.com/salasebas/saml-rs/issues/509).
Approve the scoped design below. Production implementation belongs to the
separate [sub-issue #542](https://github.com/salasebas/saml-rs/issues/542).
This decision changes no production code, public API, or SAML behaviour.

## Current ownership

The inspected baseline is `eba129dc567c3c432732c9ec26bef331c5cff51b`.
It includes the borrowed logout-subject change from #516, after the original
audit at `6500e0ba9608ca366c4c318d1616f293a578ae51`.

[SLO](../../src/api/slo.rs) has a private `SloPeer` with borrowed metadata
and an optional borrowed HMAC secret. Its start and respond helpers instead
take separate peer entity ID and metadata arguments. Its finish helper takes
both a peer entity ID and a `SloPeer`.
[Redirect name identifier management](../../src/api/name_id_management/redirect.rs)
has a private `Peer` with those same two fields and a borrowed peer entity ID.

Both flows already call the checked `raw_idp_descriptor` or
`raw_sp_descriptor` in [raw mapping](../../src/api/raw_mapping.rs) before
assembling their peer arguments. Those helpers call `ensure_valid_at(now)`
before returning the raw provider. They are validation boundaries, not empty
wrappers. Other flows still need their raw-provider return values.

There are exactly 16 public operations at the baseline. Each row below
represents two operations, one on each local role.

| Flow | Operation | `Saml<Sp>` peer | `Saml<Idp>` peer | Clock before helper entry |
| --- | --- | --- | --- | --- |
| SLO | `start_slo` | IdP descriptor | SP descriptor | `SystemTime::now()` |
| SLO | `receive_slo` | IdP descriptor | SP descriptor | `validation.now()` |
| SLO | `respond_slo` | IdP descriptor | SP descriptor | `SystemTime::now()` |
| SLO | `finish_slo` | IdP descriptor | SP descriptor | `validation.now()` |
| Name identifier management | `start_name_id_management_redirect` | IdP descriptor | SP descriptor | `SystemTime::now()` |
| Name identifier management | `receive_name_id_management_redirect` | IdP descriptor | SP descriptor | `validation.now()` |
| Name identifier management | `respond_name_id_management_redirect` | IdP descriptor | SP descriptor | `SystemTime::now()` |
| Name identifier management | `finish_name_id_management_redirect` | IdP descriptor | SP descriptor | `validation.now()` |

The following command locates every conversion and its clock at that revision:

```bash
git show eba129dc567c3c432732c9ec26bef331c5cff51b:src/api/slo.rs | rg 'let raw_'
git show eba129dc567c3c432732c9ec26bef331c5cff51b:src/api/name_id_management/redirect.rs | rg 'let raw_'
```

## Approved shape

Put one private borrowed `RawPeer` in `src/api/raw_mapping.rs`, visible only
inside the API module. Use the existing `Peer` data shape:

```rust
pub(super) struct RawPeer<'a> {
	pub(super) entity_id: &'a EntityId,
	pub(super) metadata: &'a Metadata,
	pub(super) hmac_secret: Option<&'a HmacSecret>,
}
```

`RawPeer::from_idp(descriptor, now)` first calls
`raw_idp_descriptor(descriptor, now)?`, then borrows the descriptor's entity
ID, the raw provider's metadata, and `raw.setting.hmac_secret.as_ref()`.
`RawPeer::from_sp` does the same through `raw_sp_descriptor`. Keep both
existing checked helpers. Neither constructor reads a clock or performs
flow-specific validation.

At each facade entry, replace the first checked conversion with the
corresponding `RawPeer` constructor, passing exactly the existing clock.
Pass the view to the four SLO implementation helpers and the Redirect name
identifier management helpers. Delete `SloPeer`, `Peer`, and their
constructors. SLO start and respond no longer take separate peer identity
and metadata arguments. SLO finish takes its peer identity inside the view.

For example, the service provider's Redirect respond path changes as follows.
The descriptor check still precedes `self.local()` and the helper's issuer
check.

Before:

```rust
let raw_idp = raw_idp_descriptor(idp, SystemTime::now())?;
respond(
	self.local(),
	Peer::new(idp.entity_id(), &raw_idp.metadata, &raw_idp.setting),
	request,
	options,
)
```

After:

```rust
let peer = RawPeer::from_idp(idp, SystemTime::now())?;
respond(self.local(), peer, request, options)
```

### Code and state balance

A formatted scratch prototype of this design changed only the three named
production files: 87 inserted lines and 145 deleted lines, a net reduction
of 58. This is a source-size measurement, not an implementation or runtime
claim. The prototype was formatted, not compiled or tested.

Most savings come from shorter calls: all eight Redirect facade calls fit
on one line. The structural reduction is smaller. Two peer view definitions
and their constructors occupy 31 lines at the baseline. One view with two
checked constructors occupies 27 lines in the prototype. SLO also loses six
separate peer-identity arguments across its two-role start, respond, and
finish calls, and three corresponding helper parameters. Import and
visibility costs are included in the total above. Recount the final
implementation after formatting rather than treating 58 as a target.

The two view definitions have five fields in total today. The shared
definition has three. This removes a duplicated description of peer data;
it does not reduce the size of every stack value. `receive_slo` gains an
unused borrowed entity ID, and SLO start/respond gain an unused optional
borrowed secret. There is no new owned identity, allocation, validity cache,
or role state. These small extra borrows are acceptable in exchange for one
checked mapping of a peer descriptor and fewer separate peer arguments.

## Scope and alternatives

The approved change preserves each operation's timestamp and first
descriptor-expiry check, all validation and error ordering, endpoint
directions, and the peer HMAC choice, including absence. Local signing,
decryption, issuer lookup, and role-specific policy stay with their current
owners. In particular, `Local::entity_id()` keeps its existing error and
fallback to local metadata. A borrowed peer identity cannot replace the
local issuer or justify another stored `EntityId`.

The detailed compatibility constraints and validation plan are in
[implementation issue #542](https://github.com/salasebas/saml-rs/issues/542).
That issue requires the four suites named in #525, plus format and Clippy
checks. It also records the missing expiry and SLO HMAC coverage to establish
before refactoring. The prototype's size comparison does not prove those
behavioural constraints.

This decision adds no receiver rule or conformance claim. The existing
[Single Logout](../conformance/single-logout.md) and
[name identifier management](../conformance/name-id-management.md) records
continue to own their protocol requirements.

Keeping both views avoids touching 16 entries, but leaves two definitions
of the same peer material and SLO's separate identity arguments. A shared
constructor taking raw metadata and settings deletes the duplicate shape,
but still leaves every facade to pair those values manually after the
checked conversion. The approved constructors keep that pairing together.
A generic role framework, unchecked descriptor accessor, or stored local
identity adds scope without removing the flow-specific responsibilities.
