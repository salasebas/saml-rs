# Changelog

All notable changes to `saml-rs` are documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic
Versioning while the API is still pre-1.0.

Entries before the rebrand use the package names that were current at the time.

## Unreleased

## [0.7.0](https://github.com/salasebas/saml-rs/compare/v0.6.1...v0.7.0) - 2026-10-13

### Added

- *(api)* return the identity provider discovery cookie ([#207](https://github.com/salasebas/saml-rs/pull/207))
- *(api)* add Enhanced Client/Proxy SSO over PAOS ([#211](https://github.com/salasebas/saml-rs/pull/211))
- *(api)* [**breaking**] resolve artifacts over SOAP ([#210](https://github.com/salasebas/saml-rs/pull/210))
- *(api)* [**breaking**] remove strict() and start construction on Recommended ([#212](https://github.com/salasebas/saml-rs/pull/212))

### Fixed

- [**breaking**] enforce scoped metadata endpoints for SSO and logout ([#231](https://github.com/salasebas/saml-rs/pull/231))
- *(idp)* [**breaking**] omit the NameID Format when no format is configured ([#233](https://github.com/salasebas/saml-rs/pull/233))
- *(logout)* [**breaking**] send the subject's NameID format and qualifiers in LogoutRequest ([#227](https://github.com/salasebas/saml-rs/pull/227))

### Other

- *(api)* rename unreleased PAOS and discovery names ([#214](https://github.com/salasebas/saml-rs/pull/214))
- add the public Starlight and mdBook sites ([#208](https://github.com/salasebas/saml-rs/pull/208))

## [0.6.1](https://github.com/salasebas/saml-rs/compare/v0.6.0...v0.6.1) - 2026-10-07

### Added

- *(security)* add an opt-in AuthnRequest IssueInstant age policy ([#178](https://github.com/salasebas/saml-rs/pull/178))

### Fixed

- *(api)* append AuthnRequestIssueInstant on TimeWindowField ([#185](https://github.com/salasebas/saml-rs/pull/185))

### Other

- warn that the following release removes strict() ([#182](https://github.com/salasebas/saml-rs/pull/182))
- stop publishing the deprecated rustsaml crate ([#179](https://github.com/salasebas/saml-rs/pull/179))

## [0.6.0](https://github.com/salasebas/saml-rs/compare/v0.5.3...v0.6.0) - 2026-10-06

### Added

- *(sso)* reject a later assertion that matches an outstanding logout ([#168](https://github.com/salasebas/saml-rs/pull/168))
- *(metadata)* [**breaking**] require the metadata signature shape on signed import
- *(slo)* let the logout responder choose LogoutResponse status ([#167](https://github.com/salasebas/saml-rs/pull/167))
- *(conformance)* keep metadata trust and replay as caller arguments ([#149](https://github.com/salasebas/saml-rs/pull/149))
- *(slo)* honor Recommended rules on typed Single Logout ([#146](https://github.com/salasebas/saml-rs/pull/146))
- *(sso)* follow Web Browser SSO producer rules when generating ([#144](https://github.com/salasebas/saml-rs/pull/144))
- *(sso)* honor Recommended when accepting Web Browser SSO ([#143](https://github.com/salasebas/saml-rs/pull/143))

### Fixed

- *(sso)* [**breaking**] reject unrecognized assertion conditions ([#173](https://github.com/salasebas/saml-rs/pull/173))

### Other

- *(migrations)* record the remaining 0.6 upgrade steps ([#176](https://github.com/salasebas/saml-rs/pull/176))
- separate guides, reference, and explanation ([#174](https://github.com/salasebas/saml-rs/pull/174))
- Let the identity provider return an error Response with no assertions ([#175](https://github.com/salasebas/saml-rs/pull/175))
- Enforce HTTP-Redirect signature removal and the RelayState limit ([#172](https://github.com/salasebas/saml-rs/pull/172))
- Expose ForceAuthn, IsPassive, and Subject on a received AuthnRequest ([#169](https://github.com/salasebas/saml-rs/pull/169))
- Allow five minutes of clock skew and keep replay until NotOnOrAfter ([#166](https://github.com/salasebas/saml-rs/pull/166))
- *(deps)* bump bergshamra ([#150](https://github.com/salasebas/saml-rs/pull/150))
- Publish recommended() and deprecate strict() ([#153](https://github.com/salasebas/saml-rs/pull/153))
- Point policy docs at the classification records ([#152](https://github.com/salasebas/saml-rs/pull/152))
- *(api)* [**breaking**] name the CBC signature relaxation for E93 ([#148](https://github.com/salasebas/saml-rs/pull/148))

## [0.5.3](https://github.com/salasebas/saml-rs/compare/v0.5.2...v0.5.3) - 2026-10-04

### Fixed

- *(slo)* validate Destination at typed receivers ([#97](https://github.com/salasebas/saml-rs/pull/97))

### Other

- rewrite upgrade guides and record them in AGENTS.md ([#132](https://github.com/salasebas/saml-rs/pull/132))

## [0.5.2](https://github.com/salasebas/saml-rs/compare/v0.5.1...v0.5.2) - 2026-10-04

### Added

- *(api)* expose verified XML signature evidence and strict profile ([#122](https://github.com/salasebas/saml-rs/pull/122))

### Other

- *(rustsaml)* mark the crate as no longer maintained ([#130](https://github.com/salasebas/saml-rs/pull/130))

## [0.5.1](https://github.com/salasebas/saml-rs/compare/v0.5.0...v0.5.1) - 2026-10-03

### Fixed

- *(deps)* bump transitive cryptoki to 0.12.1 ([#128](https://github.com/salasebas/saml-rs/pull/128))
- *(deps)* upgrade quick-xml to 0.42 ([#124](https://github.com/salasebas/saml-rs/pull/124))

### Other

- *(deps)* bump the cargo-maintenance group across 1 directory with 3 updates ([#123](https://github.com/salasebas/saml-rs/pull/123))
- point package pages at the saml-rs repository ([#126](https://github.com/salasebas/saml-rs/pull/126))
- *(deps)* bump bergshamra in the cargo-xml-crypto group ([#119](https://github.com/salasebas/saml-rs/pull/119))

## [0.5.0](https://github.com/salasebas/opensaml-rs/compare/v0.4.0...v0.5.0) - 2026-08-13

### Added

- *(crypto)* expose selectable Bergshamra providers ([#110](https://github.com/salasebas/opensaml-rs/pull/110))

### Other

- *(crypto)* [**breaking**] upgrade Bergshamra to 0.8 and MSRV to Rust 1.88 ([#108](https://github.com/salasebas/opensaml-rs/pull/108))

### Fixed

- *(crypto)* apply the software RSA key-transport opt-in only to RustCrypto so
  AWS-LC decrypts RSA-OAEP with default options

## [0.4.0](https://github.com/salasebas/opensaml-rs/compare/v0.3.0...v0.4.0) - 2026-08-11

### Added

- *(api)* [**breaking**] enforce standards-aware Response signature policy ([#81](https://github.com/salasebas/opensaml-rs/pull/81))

### Fixed

- *(slo)* [**breaking**] emit session authority logout expiration ([#101](https://github.com/salasebas/opensaml-rs/pull/101))
- *(slo)* [**breaking**] validate LogoutRequest time bounds ([#73](https://github.com/salasebas/opensaml-rs/pull/73))
- *(slo)* [**breaking**] reject non-conformant custom LogoutResponse templates ([#91](https://github.com/salasebas/opensaml-rs/pull/91))
- *(sso)* [**breaking**] enforce UTC IssueInstant on responses and assertions ([#90](https://github.com/salasebas/opensaml-rs/pull/90))
- *(slo)* [**breaking**] validate logout response issue instant ([#80](https://github.com/salasebas/opensaml-rs/pull/80))
- *(protocol)* [**breaking**] validate AuthnRequest IssueInstant ([#74](https://github.com/salasebas/opensaml-rs/pull/74))

### Other

- *(deps)* bump the cargo-maintenance group across 1 directory with 4 updates ([#104](https://github.com/salasebas/opensaml-rs/pull/104))
- *(slo)* add external HTTP-Redirect interoperability fixtures ([#99](https://github.com/salasebas/opensaml-rs/pull/99))
- *(migrations)* start 0.3 to 0.4 guide ([#84](https://github.com/salasebas/opensaml-rs/pull/84))
- *(deps)* bump uuid in the cargo-maintenance group ([#93](https://github.com/salasebas/opensaml-rs/pull/93))

### Fixed

- *(slo)* [**breaking**] require UTC LogoutRequest `IssueInstant`, validate
  optional `NotOnOrAfter`, and derive replay expiry from its skew-adjusted
  deadline

## [0.3.0](https://github.com/salasebas/opensaml-rs/compare/v0.2.1...v0.3.0) - 2026-07-16

### Fixed

- *(api)* [**breaking**] avoid exposing time crate types ([#72](https://github.com/salasebas/opensaml-rs/pull/72))

### Other

- *(migrations)* add 0.2 to 0.3 guide ([#83](https://github.com/salasebas/opensaml-rs/pull/83))

## [0.2.1](https://github.com/salasebas/opensaml-rs/compare/v0.2.0...v0.2.1) - 2026-07-16

### Added

- *(compat)* restore maintained crate aliases

### Fixed

- enforce SAML 2.0 namespace and version profile ([#79](https://github.com/salasebas/opensaml-rs/pull/79))
- honor repeated AuthnStatement session bounds ([#71](https://github.com/salasebas/opensaml-rs/pull/71))
- *(security)* preserve SAML audience restriction groups ([#69](https://github.com/salasebas/opensaml-rs/pull/69))
- reject repeated SAML assertion conditions ([#67](https://github.com/salasebas/opensaml-rs/pull/67))
- *(security)* enforce SP assertion signature policy ([#70](https://github.com/salasebas/opensaml-rs/pull/70))
- *(xml)* reject multiple document elements ([#68](https://github.com/salasebas/opensaml-rs/pull/68))

### Other

- add migration guide structure

### Added

- *(api)* expose every `AuthnStatement` session tuple in XML order
- *(api)* add `RespondSso::sign_response()` for explicit top-level HTTP-POST Response signing
- *(api)* add an explicit compatibility opt-out for unsigned CBC-encrypted Responses

### Changed

- *(api)* rename the SP message-signature policy and field to `ResponseSignaturePolicy`/`responses`
- *(sp)* require Response authentication for CBC-encrypted Assertions in strict typed flows
- *(idp)* sign CBC-encrypted Responses by default in typed flows

### Fixed

- *(sp)* honor the earliest `SessionNotOnOrAfter` across repeated `AuthnStatement` values
- *(security)* enforce explicit required Response signatures against verified root coverage
- *(bindings)* reject authenticated Responses whose required `Destination` is missing
- *(docs)* apply Approved Errata 05 E26/E93 to Web SSO signature guidance

## [0.2.0](https://github.com/salasebas/opensaml-rs/compare/v0.1.4...v0.2.0) - 2026-07-14

### Added

- *(api)* add typed Single Logout facade ([#59](https://github.com/salasebas/opensaml-rs/pull/59))
- *(api)* add typed Web SSO facade ([#58](https://github.com/salasebas/opensaml-rs/pull/58))
- *(api)* add typed SAML validation context
- *(api)* add typed config builders
- *(api)* refine typed SAML API contracts
- *(api)* add typed SAML browser and result models
- *(api)* add typed SAML binding subsets
- *(api)* add typed SAML configuration policies
- *(api)* add typed Saml facade contract
- *(opensaml)* support idp protocol assertion tag prefixes ([#28](https://github.com/salasebas/opensaml-rs/pull/28))
- *(opensaml)* add authn request options
- *(opensaml)* align IdP metadata ordering behavior
- *(opensaml)* support rsa pss sha256 signatures

### Fixed

- *(crypto)* preflight SAML reference URIs ([#65](https://github.com/salasebas/opensaml-rs/pull/65))
- *(sp)* fail on missing response ACS metadata
- *(api)* repair typed browser model invariants
- *(deps)* update crypto-bigint to 0.7.5 ([#48](https://github.com/salasebas/opensaml-rs/pull/48))
- *(deps)* upgrade bergshamra to 0.6.3 ([#47](https://github.com/salasebas/opensaml-rs/pull/47))
- *(deps)* upgrade quick-xml to 0.41 ([#43](https://github.com/salasebas/opensaml-rs/pull/43))
- *(opensaml)* include SimpleSign fields in POST forms
- *(opensaml)* render login response attributes structurally
- fix login attribute metadata escaping ([#36](https://github.com/salasebas/opensaml-rs/pull/36))
- reject request-bound unsolicited SSO ([#35](https://github.com/salasebas/opensaml-rs/pull/35))
- fix metadata xml escaping ([#32](https://github.com/salasebas/opensaml-rs/pull/32))
- *(opensaml)* limit redirect base64 decode ([#30](https://github.com/salasebas/opensaml-rs/pull/30))
- *(opensaml)* render optional logout session index
- *(security)* bound XML parsing before authentication
- gate XML-Enc software RSA decryption
- *(opensaml)* escape SAML template values
- *(opensaml)* validate logout request issuer
- *(opensaml)* escape SAML attribute values
- *(opensaml)* validate SAML response destination
- *(opensaml)* require logout response correlation
- *(opensaml)* bind detached SAML signatures to consumed fields
- *(opensaml)* validate bearer subject confirmation
- *(opensaml)* require AuthnRequest root signature coverage
- *(opensaml)* validate AuthnRequest issuer
- *(opensaml)* [**breaking**] limit HTTP-Redirect DEFLATE output
- *(opensaml)* require explicit SAML response correlation
- *(opensaml)* require metadata signature root coverage
- *(security)* bind extracted SAML content to verified reference

### Other

- *(deps)* bump bergshamra in the cargo-xml-crypto group ([#63](https://github.com/salasebas/opensaml-rs/pull/63))
- split large modules
- document docs.rs publication surface
- *(api)* document the typed Saml facade
- *(api)* verify builder typed user journeys
- [codex] Preserve signed metadata coverage in typed descriptors ([#57](https://github.com/salasebas/opensaml-rs/pull/57))
- *(error)* add semantic SAML validation errors
- [codex] Rebrand workspace as single saml-rs crate
- *(deps)* bump time in the cargo-maintenance group ([#46](https://github.com/salasebas/opensaml-rs/pull/46))
- [codex] split cargo dependency update lanes ([#44](https://github.com/salasebas/opensaml-rs/pull/44))
- *(opensaml)* pin crypto upgrade regressions ([#45](https://github.com/salasebas/opensaml-rs/pull/45))
- [codex] render default login responses structurally ([#42](https://github.com/salasebas/opensaml-rs/pull/42))
- [codex] validate crypto XML template inputs ([#41](https://github.com/salasebas/opensaml-rs/pull/41))
- *(opensaml)* render default logout messages structurally ([#39](https://github.com/salasebas/opensaml-rs/pull/39))
- *(opensaml)* render default authn requests structurally ([#40](https://github.com/salasebas/opensaml-rs/pull/40))
- *(readme)* clarify current SAML profile scope
- *(deps)* bump the github-actions group with 2 updates ([#34](https://github.com/salasebas/opensaml-rs/pull/34))
- *(deps)* bump the cargo-dependencies group with 2 updates ([#33](https://github.com/salasebas/opensaml-rs/pull/33))
- add validated POST binding form variant ([#31](https://github.com/salasebas/opensaml-rs/pull/31))
- update agent guidance ([#29](https://github.com/salasebas/opensaml-rs/pull/29))
- Merge pull request #27 from salasebas/advisor/002-authn-request-options
- remove tracked parity notes
- include agent files in worktrees
- refresh README and upstream samlify reference ([#22](https://github.com/salasebas/opensaml-rs/pull/22))
- fix release-plz push authentication
- add path-based PR labels
- add release-plz workflow

### Changed

- Renamed the primary package from `opensaml` to `saml-rs`; Rust imports now use
  `saml_rs`.
- Moved implementation code from `crates/opensaml/src` to `src`.
- Renamed `OpenSamlError` to `SamlError`.
- Retired alias crates from active publication; do not yank existing healthy
  alias versions.
- Added typed config builders and direction-specific AuthnRequest policy names;
  builders use strict defaults while constructors/default policy values preserve
  compatibility, and final config validation now covers policy requirements.
- Hardened detailed metadata signature verification so signed metadata evidence
  is exposed through accessors, default-limit detailed wrappers are available,
  and unsafe metadata reference transforms such as XPath/XSLT fail closed before
  descriptor coverage is accepted.

## [0.1.4] - 2026-06-21

### Changed

- Updated `quick-xml` from 0.37.5 to 0.40.1, `time` from 0.3.47 to
  0.3.49, and `uuid` from 1.23.2 to 1.23.3.
- Pinned GitHub Actions workflow dependencies to immutable commit SHAs and
  disabled checkout credential persistence.
- Added Dependabot cooldown windows for Cargo and GitHub Actions updates.

### Fixed

- Adapted the internal XML DOM parser to `quick-xml` 0.40 text/reference
  events so predefined and numeric XML entities in element text are preserved.
- Removed the auto-label workflow that used `pull_request_target`, clearing the
  remaining high-severity `zizmor` trigger finding.

## [0.1.3] - 2026-06-20

### Changed

- Updated `bergshamra` from 0.4.0 to 0.5.1.
- Re-audited the XML security trust-model comment against `bergshamra` 0.5.1
  secure `DsigContext::new()` defaults.
- XSW coverage includes duplicate SAML assertion IDs.

### Fixed

- Reject duplicate SAML `ID`/`AssertionID` values before trusting an XML-DSig
  verification result.

## [0.1.2] - 2026-06-14

### Changed

- Alias crate READMEs and crate descriptions simplified.
- Workspace version bump to 0.1.2 (packaging-only for alias crates).

## [0.1.1] - 2026-06-02

### Added

- `create_logout_request_with_id` / `create_logout_response_with_id` — optional
  caller-provided `LogoutRequest` / `LogoutResponse` IDs.

### Changed

- Root `README.md` rewrite: Rust-only positioning, opensaml vs samael
  comparison, and sectioned quick-start examples; `opensaml` on crates.io now
  uses that README.
- The published crate ships its `tests/` and `examples/` (packaging only; the
  consumed library is unchanged).

### Fixed

- XML-escape `Location` attribute values in generated SP/IdP metadata.

## [0.1.0] - 2026-06-01

### Added

- SAML 2.0 protocol layer to parity with npm `samlify` v2.10.2:
  - Constants (URNs, bindings, status codes, algorithms, NameID formats).
  - XML field extraction engine over `quick-xml` (`local-name()` XPath subset)
    with DOCTYPE hardening, plus the samlify field-sets.
  - Default message templates and tag substitution.
  - Service Provider and Identity Provider metadata parsing and generation.
  - HTTP-POST, HTTP-Redirect and HTTP-POST-SimpleSign message building.
  - `ServiceProvider`/`IdentityProvider` entities, login request/response
    creation and parsing, Single Logout, and the inbound `flow` orchestration
    (status, issuer and time validation).
- `crypto-bergshamra` feature delegating XML cryptography to
  `bergshamra` (**on by default**): key/certificate loading, XML-DSig signing
  and verification with anti-wrapping (XSW) protection, XML-Enc assertion
  encrypt/decrypt, and detached redirect/SimpleSign message signatures.
- `samlify` crate forwards the `crypto-bergshamra` feature.
- Customization to parity with samlify: a `User` subject with attributes wired
  into `IdentityProvider::create_login_response` (via `LoginResponseTemplate`),
  a `customTagReplacement` hook and custom message templates, `SignatureConfig`
  (signature prefix + placement), configurable `transformationAlgorithms`, a
  configurable encrypted-assertion tag prefix, and `SessionIndex` on logout.
- `Metadata::export_metadata` / `get_support_bindings` and `util::verify_fields`.
- Inline-certificate-vs-metadata mismatch is rejected with
  `OpenSamlError::UnmatchCertificate` (samlify rolling-cert safety).
- Conformance test suite ported 1:1 from samlify v2.10.2: all 131 active
  upstream cases (flow 64, index 47, issues 11, extractor 9) reproduced as 132
  Rust tests in `tests/{extractor,issues,index,flow}_conformance.rs`, with the
  upstream key/metadata fixtures. The crate runs 206 tests in total (89 without
  `crypto-bergshamra`); the whole suite passes.
- Security hardening: `<Audience>` restriction validation (`validate_audience`,
  on by default → `UnmatchAudience`), `InResponseTo` binding via
  `ServiceProvider::parse_login_response_with_request_id` (→ `InvalidInResponseTo`),
  metadata signature verification (`crypto::verify_metadata_signature` /
  `Metadata::verify_signature`), and XSW + robustness test suites
  (`tests/{xsw,hardening,robustness}.rs`). Schema validation remains pluggable
  via `context::set_schema_validator` on top of the always-on DOCTYPE rejection.
- Runnable end-to-end example: `cargo run -p opensaml --example sso`.
- Crypto-backend audit (bergshamra 0.4.0): documented the verification trust
  model in `crypto::verify` (signature, digest and XSW position checks always
  run; `insecure` only skips X.509 *chain* validation, irrelevant to the
  metadata key-pinning model; `trusted_keys_only` never imports inline key
  material). Hardening: signed `<Reference>` URIs must be same-document
  (`#id` or whole-document); external/remote/file references are rejected
  (`ERR_EXTERNAL_REFERENCE`).

### Changed

- `crypto-bergshamra` is now enabled by default; disable with
  `default-features = false` for the crypto-free protocol layer (operations
  requiring signing, verification or encryption then fail closed with
  `OpenSamlError::Unsupported`).
- Reworked the crate from SP-only stubs to full SP + IdP.
- Signature verification tries each metadata-declared certificate individually,
  so signatures verify against any current key (rolling-certificate support).
- When encrypting, the IdP always signs the message *after* encryption (sound
  encrypt-then-sign); signing the message then encrypting a sub-element would
  invalidate the outer signature.

### Fixed

- Decryption strips a leading XML declaration from the recovered assertion so
  it can be re-parsed in place during the inbound flow.
