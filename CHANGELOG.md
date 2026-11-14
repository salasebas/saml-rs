# Changelog

All notable changes to `saml-rs` are documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic
Versioning while the API is still pre-1.0.

Entries before the rebrand use the package names that were current at the time.

## Unreleased

## [0.8.0](https://github.com/salasebas/saml-rs/compare/v0.7.0...v0.8.0) - 2026-11-14

### Added

- *(sso)* request and inspect authentication assurance ([#554](https://github.com/salasebas/saml-rs/pull/554))
- [**breaking**] support AES-256-GCM and explicit RSA-OAEP parameters ([#552](https://github.com/salasebas/saml-rs/pull/552))
- *(metadata)* [**breaking**] publish federation organization and contacts ([#553](https://github.com/salasebas/saml-rs/pull/553))
- provide in-memory replay protection for single-process servers ([#551](https://github.com/salasebas/saml-rs/pull/551))
- *(metadata)* [**breaking**] publish signing certificates for key rollover ([#550](https://github.com/salasebas/saml-rs/pull/550))
- *(idp)* let the identity provider state when the user actually authenticated ([#475](https://github.com/salasebas/saml-rs/pull/475))
- *(metadata)* [**breaking**] stop trusting peer keys from metadata signed with MD5, RIPEMD-160, or a short RSA key ([#390](https://github.com/salasebas/saml-rs/pull/390))
- *(crypto)* [**breaking**] drop the software RSA key-transport opt-in ([#382](https://github.com/salasebas/saml-rs/pull/382))
- *(crypto)* [**breaking**] apply XmlSignatureProfile to every inbound signature and exclude weak algorithms from Recommended ([#384](https://github.com/salasebas/saml-rs/pull/384))
- *(config)* [**breaking**] roll over encryption keys without downtime by publishing and decrypting with several keys ([#368](https://github.com/salasebas/saml-rs/pull/368))
- *(artifact)* [**breaking**] expire issued artifacts after a caller-chosen lifetime ([#363](https://github.com/salasebas/saml-rs/pull/363))
- *(idp)* return the issued SessionIndex with typed SSO responses ([#367](https://github.com/salasebas/saml-rs/pull/367))
- *(metadata)* [**breaking**] publish a configured validUntil and cacheDuration ([#355](https://github.com/salasebas/saml-rs/pull/355))
- *(name-id-management)* add an opt-in IssueInstant age policy for received requests ([#364](https://github.com/salasebas/saml-rs/pull/364))
- *(paos)* [**breaking**] send typed attributes and answer at the default assertion consumer ([#340](https://github.com/salasebas/saml-rs/pull/340))

### Fixed

- enforce inbound CBC policy and bound decryption work ([#561](https://github.com/salasebas/saml-rs/pull/561))
- *(crypto)* [**breaking**] preflight XML signatures and require covered content ([#560](https://github.com/salasebas/saml-rs/pull/560))
- *(sp)* [**breaking**] reject an SSO response that carries a signature that does not verify ([#497](https://github.com/salasebas/saml-rs/pull/497))
- *(idp)* [**breaking**] refuse unsigned AuthnRequests from a service provider whose metadata says it signs (Errata 05 E7) ([#495](https://github.com/salasebas/saml-rs/pull/495))
- *(bindings)* decode SimpleSign messages under the configured XML size limit ([#490](https://github.com/salasebas/saml-rs/pull/490))
- *(idp)* [**breaking**] issue only the requested Subject under Web Browser SSO generation rules ([#480](https://github.com/salasebas/saml-rs/pull/480))
- *(xml)* [**breaking**] reject the remaining malformed XML inputs at the DOM boundary ([#489](https://github.com/salasebas/saml-rs/pull/489))
- *(bindings)* [**breaking**] reject a repeated RelayState on HTTP-POST and unsigned HTTP-Redirect ([#486](https://github.com/salasebas/saml-rs/pull/486))
- *(sp)* [**breaking**] honor with_recipient_endpoint in accept_unsolicited_sso ([#477](https://github.com/salasebas/saml-rs/pull/477))
- *(sso)* accept a signed Response that mixes a plaintext Assertion and an EncryptedAssertion ([#487](https://github.com/salasebas/saml-rs/pull/487))
- *(logout)* reject replayed and stale requests before decrypting their identifiers in SLO and Redirect name identifier management ([#483](https://github.com/salasebas/saml-rs/pull/483))
- *(template)* write attribute names that contain {Placeholder} literally ([#485](https://github.com/salasebas/saml-rs/pull/485))
- *(sso)* [**breaking**] make replay storage give the same verdict under every ReplayPolicy for an unchecked bearer NotOnOrAfter ([#478](https://github.com/salasebas/saml-rs/pull/478))
- *(bindings)* [**breaking**] accept a received RelayState longer than 80 bytes and echo it ([#479](https://github.com/salasebas/saml-rs/pull/479))
- *(crypto)* [**breaking**] reject ds:Object in message signatures under Recommended ([#481](https://github.com/salasebas/saml-rs/pull/481))
- *(logout)* [**breaking**] let receive_slo answer a logout request whose EncryptedID does not decrypt ([#472](https://github.com/salasebas/saml-rs/pull/472))
- *(paos)* [**breaking**] refuse PAOS headers the receiver must understand but does not process, by reading envelopes with the shared SOAP reader ([#473](https://github.com/salasebas/saml-rs/pull/473))
- *(metadata)* [**breaking**] find SSO, artifact, and NameID management endpoints whose Binding or Location is padded ([#476](https://github.com/salasebas/saml-rs/pull/476))
- *(crypto)* [**breaking**] accept a trusted key's signature when its KeyInfo carries a re-issued certificate ([#469](https://github.com/salasebas/saml-rs/pull/469))
- *(sp)* [**breaking**] allow a signed AuthnRequest when the IdP does not require one ([#471](https://github.com/salasebas/saml-rs/pull/471))
- *(flow)* [**breaking**] accept RelayState a responder adds when the request carried none ([#474](https://github.com/salasebas/saml-rs/pull/474))
- *(flow)* [**breaking**] compare the Response Issuer with the identity provider on successful SSO responses ([#470](https://github.com/salasebas/saml-rs/pull/470))
- *(metadata)* [**breaking**] stop SAML 1.1 roles from supplying keys, flags, and endpoints to SAML 2.0 peers ([#392](https://github.com/salasebas/saml-rs/pull/392))
- *(xml)* [**breaking**] normalize line endings in DOM text and CDATA ([#391](https://github.com/salasebas/saml-rs/pull/391))
- *(idp)* [**breaking**] issue NameID qualifiers and refuse a response outside the requested SPNameQualifier ([#387](https://github.com/salasebas/saml-rs/pull/387))
- *(crypto)* report signature coverage for the consumed bearer assertion ([#380](https://github.com/salasebas/saml-rs/pull/380))
- *(status)* [**breaking**] read subordinate status codes with the anyURI rule NameID formats use ([#366](https://github.com/salasebas/saml-rs/pull/366))
- *(flow)* [**breaking**] keep NameIDPolicy SPNameQualifier in the typed AuthnRequest ([#360](https://github.com/salasebas/saml-rs/pull/360))
- *(attributes)* [**breaking**] keep every attribute value per Name and NameFormat and require an absolute NameFormat ([#347](https://github.com/salasebas/saml-rs/pull/347))
- *(config)* [**breaking**] require a URI of at most 1024 characters as the local entity ID ([#350](https://github.com/salasebas/saml-rs/pull/350))
- *(sso)* [**breaking**] report an SSO error status only after correlating the response ([#349](https://github.com/salasebas/saml-rs/pull/349))
- *(metadata)* [**breaking**] stop using peer metadata at validUntil ([#356](https://github.com/salasebas/saml-rs/pull/356))
- *(api)* [**breaking**] reject an empty InResponseTo on typed unsolicited SSO ([#361](https://github.com/salasebas/saml-rs/pull/361))
- *(idp)* [**breaking**] omit InResponseTo on unsolicited login responses ([#357](https://github.com/salasebas/saml-rs/pull/357))
- *(flow)* collapse XML Schema whitespace in AuthnRequest booleans and indexes ([#358](https://github.com/salasebas/saml-rs/pull/358))
- *(flow)* [**breaking**] read RequestedAuthnContext and honor an exact request in IdP responses ([#354](https://github.com/salasebas/saml-rs/pull/354))
- *(xml)* [**breaking**] reject malformed and namespace-malformed XML at the DOM boundary ([#353](https://github.com/salasebas/saml-rs/pull/353))
- *(xml)* [**breaking**] declare every inherited namespace on extracted and encrypted elements ([#351](https://github.com/salasebas/saml-rs/pull/351))
- *(soap)* [**breaking**] read SOAP envelopes under the configured XML limits ([#348](https://github.com/salasebas/saml-rs/pull/348))
- *(logout)* [**breaking**] echo the received RelayState and accept any front-channel LogoutResponse binding ([#346](https://github.com/salasebas/saml-rs/pull/346))
- *(idp)* [**breaking**] reject a Subject with confirmations when issuing an assertion ([#345](https://github.com/salasebas/saml-rs/pull/345))
- *(template)* [**breaking**] rewrite tag prefixes in one pass and require distinct NCNames ([#344](https://github.com/salasebas/saml-rs/pull/344))
- *(flow)* [**breaking**] apply a present bearer SubjectConfirmationData NotBefore ([#343](https://github.com/salasebas/saml-rs/pull/343))
- *(name-id-management)* [**breaking**] classify padded NameID formats and enforce the request child order ([#342](https://github.com/salasebas/saml-rs/pull/342))
- *(logout)* [**breaking**] preserve subordinate status and the received NameID attributes ([#341](https://github.com/salasebas/saml-rs/pull/341))
- [**breaking**] ignore only ASCII whitespace in base64_decode ([#334](https://github.com/salasebas/saml-rs/pull/334))
- *(metadata)* skip empty endpoint locations in single-endpoint accessors ([#339](https://github.com/salasebas/saml-rs/pull/339))
- *(metadata)* [**breaking**] generate unique ACS indexes and write isDefault only on indexed endpoints ([#338](https://github.com/salasebas/saml-rs/pull/338))
- *(binding)* add Redirect and Artifact parameters to the query before any fragment ([#336](https://github.com/salasebas/saml-rs/pull/336))
- *(crypto)* place Prepend and Append signatures inside the reference element ([#335](https://github.com/salasebas/saml-rs/pull/335))
- *(crypto)* reject non-ASCII bare certificate text instead of panicking ([#332](https://github.com/salasebas/saml-rs/pull/332))
- *(compat)* ship the MIT license text in compatibility crate packages ([#331](https://github.com/salasebas/saml-rs/pull/331))

### Other

- *(api)* [**breaking**] reserve growth in capability and diagnostic enums ([#555](https://github.com/salasebas/saml-rs/pull/555))
- *(idp)* share PAOS and Artifact posted response rendering ([#549](https://github.com/salasebas/saml-rs/pull/549))
- *(artifact)* replace manual SHA-1 with maintained digest ([#547](https://github.com/salasebas/saml-rs/pull/547))
- *(api)* share checked peer mapping across logout flows ([#548](https://github.com/salasebas/saml-rs/pull/548))
- *(config)* reuse NameID format URI mapping ([#540](https://github.com/salasebas/saml-rs/pull/540))
- *(xml)* reuse one internal character predicate ([#543](https://github.com/salasebas/saml-rs/pull/543))
- *(crypto)* reuse uppsala direct-child lookups ([#541](https://github.com/salasebas/saml-rs/pull/541))
- *(xml)* share Redirect and DOM resource limit checks ([#544](https://github.com/salasebas/saml-rs/pull/544))
- *(xml)* centralize local-name child lookups on Node ([#545](https://github.com/salasebas/saml-rs/pull/545))
- *(api)* borrow logout subjects and issued NameID formats ([#539](https://github.com/salasebas/saml-rs/pull/539))
- *(binding)* reuse Redirect query assembly for signed octets ([#538](https://github.com/salasebas/saml-rs/pull/538))
- *(xml)* state common protocol-root requirements once ([#534](https://github.com/salasebas/saml-rs/pull/534))
- *(browser)* share request and response field mappings ([#535](https://github.com/salasebas/saml-rs/pull/535))
- *(metadata)* remove redundant dispatch and certificate clones ([#536](https://github.com/salasebas/saml-rs/pull/536))
- share signing-only credentials across 18 binaries ([#537](https://github.com/salasebas/saml-rs/pull/537))
- *(binding)* characterize Redirect scanner resource limits ([#533](https://github.com/salasebas/saml-rs/pull/533))
- *(crypto)* keep stronger encryption checks in one provider round trip ([#530](https://github.com/salasebas/saml-rs/pull/530))
- *(paos)* pin response transforms inside SOAP ([#532](https://github.com/salasebas/saml-rs/pull/532))
- remove repeated conformance workloads ([#531](https://github.com/salasebas/saml-rs/pull/531))
- reorganize the 0.8 upgrade guide, fill gaps in the 0.7 guide, and slim the README ([#506](https://github.com/salasebas/saml-rs/pull/506))
- *(util)* [**breaking**] replace collection helpers with direct Rust operations ([#500](https://github.com/salasebas/saml-rs/pull/500))
- centralize crypto provider availability checks ([#505](https://github.com/salasebas/saml-rs/pull/505))
- *(flow)* isolate detached signature verification ([#504](https://github.com/salasebas/saml-rs/pull/504))
- *(sp)* avoid reparsing confirmations and audience restrictions ([#501](https://github.com/salasebas/saml-rs/pull/501))
- *(idp)* resolve response ACS once across typed SSO transports ([#498](https://github.com/salasebas/saml-rs/pull/498))
- *(flow)* reuse parsed XML for inbound message probes ([#502](https://github.com/salasebas/saml-rs/pull/502))
- *(bindings)* share detached signing across SAML flows ([#499](https://github.com/salasebas/saml-rs/pull/499))
- *(api)* lend typed operations the descriptor's raw peer instead of cloning its metadata ([#496](https://github.com/salasebas/saml-rs/pull/496))
- *(crypto)* derive signature coverage and signature placement from one definition each ([#484](https://github.com/salasebas/saml-rs/pull/484))
- *(crypto)* run every XML-Enc entry point through one decrypt and one encrypt pipeline ([#494](https://github.com/salasebas/saml-rs/pull/494))
- *(logout)* remove duplicated validators and pass-through layers from the logout paths ([#493](https://github.com/salasebas/saml-rs/pull/493))
- *(conformance)* scope the HTTP-Redirect claim to builds that support DSA-SHA1 and RSA-SHA1 ([#491](https://github.com/salasebas/saml-rs/pull/491))
- *(logout)* share the front-channel https endpoint check between SLO and NameID management ([#488](https://github.com/salasebas/saml-rs/pull/488))
- *(config)* state which messages use signed_reference_transforms ([#482](https://github.com/salasebas/saml-rs/pull/482))
- *(metadata)* prove a dual-role entity reads and issues only its own role's NameIDFormat ([#468](https://github.com/salasebas/saml-rs/pull/468))
- *(metadata)* cover the SAML 2.0 role selection branches from #392 ([#393](https://github.com/salasebas/saml-rs/pull/393))
- *(crypto)* verify rollover signatures with one multi-key manager ([#381](https://github.com/salasebas/saml-rs/pull/381))
- *(crypto)* [**breaking**] upgrade bergshamra to 0.12 so rsa 0.9 and its RUSTSEC-2023-0071 ignore are gone ([#386](https://github.com/salasebas/saml-rs/pull/386))
- *(coverage)* gate on Codecov statuses and measure every crypto backend ([#379](https://github.com/salasebas/saml-rs/pull/379))
- *(flow)* state which assertions back the typed SSO session ([#375](https://github.com/salasebas/saml-rs/pull/375))
- *(crypto)* refresh bergshamra versions and the RSA advisory rationale ([#373](https://github.com/salasebas/saml-rs/pull/373))
- *(readme)* install with cargo add and require the POST replay cache ([#371](https://github.com/salasebas/saml-rs/pull/371))
- load each fixture from one canonical path ([#362](https://github.com/salasebas/saml-rs/pull/362))
- *(api)* build typed raw peers from the descriptor's parsed metadata ([#369](https://github.com/salasebas/saml-rs/pull/369))
- run the full test suite in feature and provider jobs ([#365](https://github.com/salasebas/saml-rs/pull/365))

## [0.7.0](https://github.com/salasebas/saml-rs/compare/v0.6.1...v0.7.0) - 2026-11-09

### Added

- *(api)* [**breaking**] decrypt every encrypted element a provider receives, and record the IdP and SP operational modes ([#271](https://github.com/salasebas/saml-rs/pull/271))
- *(crypto)* resolve a peer EncryptedKey for EncryptedAssertion ([#269](https://github.com/salasebas/saml-rs/pull/269))
- *(crypto)* [**breaking**] refuse inbound RSA-v1.5 key transport unless selected ([#261](https://github.com/salasebas/saml-rs/pull/261))
- *(api)* keep the identifier confidential in name identifier management with EncryptedID and NewEncryptedID ([#263](https://github.com/salasebas/saml-rs/pull/263))
- *(api)* [**breaking**] process and generate EncryptedID in a Single Logout LogoutRequest ([#262](https://github.com/salasebas/saml-rs/pull/262))
- *(api)* [**breaking**] change or end a name identifier over HTTP-Redirect ([#247](https://github.com/salasebas/saml-rs/pull/247))
- *(crypto)* keep the NameID and attributes confidential with EncryptedID and EncryptedAttribute ([#244](https://github.com/salasebas/saml-rs/pull/244))
- *(api)* [**breaking**] let the identity provider change or end a NameID over SOAP ([#245](https://github.com/salasebas/saml-rs/pull/245))
- *(api)* [**breaking**] implement the Conformance §4 algorithms, with SHA-1, Triple DES, and RSA-v1.5 off until selected ([#246](https://github.com/salasebas/saml-rs/pull/246))
- *(api)* [**breaking**] send and accept Single Logout over SOAP ([#243](https://github.com/salasebas/saml-rs/pull/243))
- *(api)* [**breaking**] deliver a Web SSO response over HTTP-Artifact ([#217](https://github.com/salasebas/saml-rs/pull/217))
- *(api)* [**breaking**] add attribute name formats and persistent and transient identifiers ([#215](https://github.com/salasebas/saml-rs/pull/215))
- *(api)* return the identity provider discovery cookie ([#207](https://github.com/salasebas/saml-rs/pull/207))
- *(api)* add Enhanced Client/Proxy SSO over PAOS ([#211](https://github.com/salasebas/saml-rs/pull/211))
- *(api)* [**breaking**] resolve artifacts over SOAP ([#210](https://github.com/salasebas/saml-rs/pull/210))
- *(api)* [**breaking**] remove strict() and start construction on Recommended ([#212](https://github.com/salasebas/saml-rs/pull/212))

### Fixed

- *(xml)* aggregate extracted attributes in linear time ([#290](https://github.com/salasebas/saml-rs/pull/290))
- *(metadata)* [**breaking**] select signing and encryption certificates by KeyDescriptor use ([#285](https://github.com/salasebas/saml-rs/pull/285))
- *(metadata)* [**breaking**] verify and encrypt with the keys of the peer's own role ([#287](https://github.com/salasebas/saml-rs/pull/287))
- *(metadata)* [**breaking**] honor WantAuthnRequestsSigned="1" and the other xs:boolean signing flags ([#288](https://github.com/salasebas/saml-rs/pull/288))
- *(idp)* [**breaking**] reject a signed AuthnRequest without Destination under RequireSigned, as the weaker policy already does ([#286](https://github.com/salasebas/saml-rs/pull/286))
- *(artifact)* expire ArtifactUses entries after a caller-chosen period ([#283](https://github.com/salasebas/saml-rs/pull/283))
- *(api)* [**breaking**] check every EncryptedAssertion in a response, not only the first ([#282](https://github.com/salasebas/saml-rs/pull/282))
- [**breaking**] write only absolute URI references as NameID formats ([#270](https://github.com/salasebas/saml-rs/pull/270))
- *(api)* [**breaking**] generate SAML IDs with 160 random bits to meet Core §1.3.4 ([#268](https://github.com/salasebas/saml-rs/pull/268))
- *(xml)* reject a non-digit in an xs:dateTime field without overflowing ([#267](https://github.com/salasebas/saml-rs/pull/267))
- *(metadata)* [**breaking**] send and accept Single Logout at the peer's own role endpoints ([#260](https://github.com/salasebas/saml-rs/pull/260))
- *(api)* [**breaking**] report a LogoutResponse status only after it is authenticated ([#259](https://github.com/salasebas/saml-rs/pull/259))
- *(metadata)* [**breaking**] generate SP and IdP metadata in the schema element order ([#254](https://github.com/salasebas/saml-rs/pull/254))
- [**breaking**] keep template values literal, parse extractor shortcuts once, and ignore only ASCII whitespace in limited base64 ([#229](https://github.com/salasebas/saml-rs/pull/229))
- *(crypto)* match protocol response roots by namespace and share verifier prechecks ([#230](https://github.com/salasebas/saml-rs/pull/230))
- *(validator)* stop verify_time_at from panicking on out-of-range skew ([#242](https://github.com/salasebas/saml-rs/pull/242))
- [**breaking**] enforce scoped metadata endpoints for SSO and logout ([#231](https://github.com/salasebas/saml-rs/pull/231))
- *(idp)* [**breaking**] omit the NameID Format when no format is configured ([#233](https://github.com/salasebas/saml-rs/pull/233))
- *(logout)* [**breaking**] send the subject's NameID format and qualifiers in LogoutRequest ([#227](https://github.com/salasebas/saml-rs/pull/227))

### Other

- consolidate 0.7 upgrade steps in one guide ([#292](https://github.com/salasebas/saml-rs/pull/292))
- *(entity)* state that iso8601_offset panics past year 9999 ([#289](https://github.com/salasebas/saml-rs/pull/289))
- gate crypto-dependent typed config and model tests on a crypto provider ([#272](https://github.com/salasebas/saml-rs/pull/272))
- *(deps)* bump the cargo-maintenance group across 1 directory with 2 updates ([#265](https://github.com/salasebas/saml-rs/pull/265))
- *(deps)* bump bergshamra ([#237](https://github.com/salasebas/saml-rs/pull/237))
- gate crypto-dependent builder policy tests on a crypto provider ([#258](https://github.com/salasebas/saml-rs/pull/258))
- *(deps)* bump uuid ([#235](https://github.com/salasebas/saml-rs/pull/235))
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
