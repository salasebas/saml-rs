# saml-rs Agent Guide

This is a Rust package for SAML 2.0 Service Provider and Identity Provider
support. Keep this file short and operational: it should tell agents how to
work in the repo, not restate the README.

## Repo Shape

- `src/` contains the implementation. Put protocol, XML, metadata, binding,
  validation, logout, and crypto-adapter changes there.
- `docs/module-map.md` lists the behaviour whose file name does not give it
  away.
- `tests/` contains integration tests and committed fixtures.
- `src/tests/` holds the tests that build signed, encrypted, or malformed
  input with crate-private helpers. They import through `saml_rs::` like
  integration tests do.
- `examples/` contains runnable examples.
- XML cryptography is delegated to `bergshamra` behind the default
  `crypto-bergshamra` feature. Do not add in-tree XML-DSig/XML-Enc
  implementations.
- The package forbids unsafe code.

## Working Rules

- Use English for all repository content and for project communication:
  issues, pull requests, and reviews.
- Before implementing an issue, check its claims against the code and tests
  on the latest `main`. If the problem is already solved, report the evidence.
  If it remains, judge the proposed fix against the behavior callers need.
- Read the nearby code and tests before changing behavior. Prefer existing
  module boundaries and error styles.
- Keep diffs focused. Do not mix documentation cleanup, behavior changes, and
  dependency upgrades unless the task asks for it.
- Use `rg` / `rg --files` for searches.
- Do not commit generated/vendor trees.
- Do not add dependencies without proposing them first. Keep optional
  integrations behind feature flags.
- If a user has local changes, preserve them and work around them.
- Keep non-mechanical diffs reviewable. If a change grows large, split it into
  the smallest coherent stages.
- Code, rustdoc, and tests describe current behaviour. A doc that claims to
  describe current behaviour and disagrees with them is stale: fix it in the
  same change or report it. Migration guides describe past releases.
- Report a rule or design choice without a stated reason as an open question
  instead of following or defending it.
- When an existing design conflicts with the caller's needs or the applicable
  SAML rule, explain the trade-off and the compatibility impact of changing it.
- API design, naming, error, and review rules are in `CODING_STANDARDS.md`.

## Standards Conformance

- Before reviewing or changing SAML behavior or a conformance record, read
  [Standards conformance](docs/standards-conformance.md). Use the
  [conformance index](docs/conformance/README.md) to find the affected
  sections by flow and public API.
- Verify and cite the clause, schema, and errata that govern the actor,
  condition, and binding. Use the source order in the guide for SOAP 1.1,
  other underlying standards, and interoperability profiles.
- Record one behavior per short row. Put the actor and API in its section,
  state the reason for a library policy in one sentence, and link shared rules
  at their owning record.
- When a design or interoperability decision needs an implementation example,
  consult a maintained project that implements the same flow, role, direction,
  and binding, such as OpenSAML, Shibboleth, PySAML2, `simplesamlphp/saml2`,
  `crewjam/saml`, or `ruby-saml`. Cite the relevant code, test, or documentation
  for the version examined and explain what applies to this crate.
- A producer `MUST` or `MUST NOT` does not automatically require a receiver to
  reject non-conforming input. Add rejection only when an applicable normative
  receiver or schema rule requires it.
- Mandatory requirements are always enforced. Recommendations are default-on
  and may be relaxed only by an explicit, narrowly named policy. Optional
  capabilities require intentional configuration.
- Scope conformance claims by role, direction, profile or flow, binding, and
  feature. Lower-level XML support does not imply conformance with a complete
  profile, binding, or SAML V2.0 as a whole.
- MUST NOT retroactively change existing behavior, defaults, or public APIs
  solely to align them with the conformance policy unless the task explicitly
  authorizes that change. If existing behavior appears to predate or conflict
  with the policy, preserve it, report the normative evidence and compatibility
  or security impact, and ask for direction before changing it.
- Do not present library safety or application policy as an OASIS wire
  requirement, and do not invent validation for unspecified behavior.
- A stricter receiver rule is recorded as library policy in the pull request.
  If a deployment needs an exception, weigh its interoperability benefit
  against the protection it would give up before adding an option.

## Fixture Provenance

- Historical fixture provenance is documented in
  `tests/fixtures/PROVENANCE.md`.
- Do not commit fetched upstream clones or other local reference trees.

## Checks

For Rust changes, check formatting, run Clippy, and run the smallest test
suite that covers the change and its side effects. Clippy and the test runs
must pass with zero warnings. Report the commands, results, and warning count.

```bash
cargo fmt --all --check
cargo clippy -p saml-rs --all-targets -- -D warnings
cargo nextest run -p saml-rs
```

When touching shared configuration, release metadata, or feature boundaries,
also check:

```bash
cargo test -p saml-rs --doc
RUSTDOCFLAGS="-D warnings -D missing_docs" cargo doc -p saml-rs --lib --no-deps
cargo test -p saml-rs --doc --no-default-features
RUSTDOCFLAGS="-D warnings -D missing_docs" cargo doc -p saml-rs --lib --no-deps --no-default-features
cargo check -p saml-rs --no-default-features
```

Do not use `--all-features`. Document-crypto providers are mutually exclusive.
AWS-LC, FIPS, and provider-specific rustdoc run in the Linux `provider-matrix`
job in `.github/workflows/ci.yml`. Locally, `crypto-aws-lc` also runs on macOS.
`crypto-fips` builds only on Linux: `kryptering` rejects it at compile time
elsewhere, so on macOS leave it to that job and say so in the pull request.

`codecov/patch` is a signal, not a merge gate. When it is red, the pull
request names the changed lines that no test runs and says why.

## Rust Style

- Prefer private modules and explicitly exported public crate API.
- Prefer explicit `Result` errors over panics.
- `unwrap_used`, `expect_used`, and `panic` are package `warn` lints; under
  `-D warnings` they fail builds, including tests.
- Avoid boolean or ambiguous `Option` parameters in public or SAML flow APIs.
  Prefer enums, named builders, or typed options when they make call sites
  self-documenting.
- When possible, make `match` statements exhaustive and avoid wildcard arms.
- New traits should include doc comments explaining their role and how
  implementations are expected to use them.
- Comments describe behavior and API usage. Do not justify why an
  implementation was chosen.
- A claimed rule is recorded as its row in `docs/conformance/`. A code comment
  names the behavior.
- Use inline format arguments, collapse nested `if` statements when clear, and
  prefer method references over redundant closures.
- In tests, return `Result<(), Box<dyn std::error::Error>>` and use `?` instead
  of `.unwrap()` / `.expect()`.
- Prefer focused behavior tests. Compare whole objects when practical, and
  avoid test-only helpers in implementation modules.
- Keep XML handling structured. Avoid ad hoc string parsing when the local DOM,
  extractor, metadata, or binding helpers can express the behavior.
- Keep security-sensitive validation fail-closed. Missing, malformed, unsigned,
  or untrusted inputs should produce explicit `SamlError` variants where
  practical.
- Prefer new focused modules over extending a large module listed in
  `docs/module-map.md`.

## Security-Sensitive Areas

Be especially conservative when changing:

- signature verification or signed-reference selection
- XML parsing limits, DOCTYPE/XXE handling, and extraction
- `InResponseTo`, issuer, audience, destination/recipient, and bearer checks
- HTTP-Redirect DEFLATE handling
- XML-Enc decryption and the RSA-v1.5 key-transport option
- metadata key selection and signed metadata verification

Add regression tests for security fixes.

## Docs And Releases

- Do not hardcode future release versions in prose. This repository uses
  release-plz and Conventional Commits to decide the next version. The one
  place that names the next release is the name of its migration directory.
- The published crate is `saml-rs`, and Rust imports use `saml_rs`.
- Do not edit `CHANGELOG.md` by hand. release-plz writes it from Conventional
  Commits on the release PR.
- A caller-visible change updates `docs/migrations/` in the same change: what
  breaks, who must change, and how to upgrade. That includes a breaking change,
  a new error, and a new exhaustive enum variant. Add the guide as a topic file
  in the directory of the upgrade it belongs to, named
  `<current>.x-to-<next>.0`, and link it from that directory's `README.md`.
  Name the file for what it covers, without an `unreleased-` prefix. Follow
  `docs/migrations/README.md`.
  Compatible features are recorded by their Conventional Commit.

## Agent skills

### Issue tracker

Issues and specs live as GitHub issues in `salasebas/saml-rs`. See
`docs/agents/issue-tracker.md`.

Report confirmed pre-existing bugs and conformance gaps found during the task.
For suspected vulnerabilities, follow [the security policy](SECURITY.md).
For other findings that need follow-up, search open and closed issues. Link
the existing issue or file one with the observed behavior, the expected
behavior, and the evidence.

### Triage labels

The default five-role triage label vocabulary is used. See
`docs/agents/triage-labels.md`.

### Domain docs

Domain terms are in `GLOSSARY.md`. See `docs/agents/domain.md`.
