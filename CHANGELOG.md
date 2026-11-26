# Changelog

All notable changes to `saml-rs` are documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic
Versioning while the API is still pre-1.0.

Entries before the rebrand use the package names that were current at the time.

## Unreleased

## [0.9.0](https://github.com/salasebas/saml-rs/compare/v0.8.0...v0.9.0) - 2026-11-26

### Added

- *(sp)* add AuthnRequestSigningPolicy::SignWhenIdpWants ([#980](https://github.com/salasebas/saml-rs/pull/980))
- *(sp)* send AuthnRequests to an https SingleSignOnService when the IdP publishes one ([#979](https://github.com/salasebas/saml-rs/pull/979))
- *(sp)* report whether the consumed assertion carries OneTimeUse ([#1022](https://github.com/salasebas/saml-rs/pull/1022))
- *(sp)* [**breaking**] return the SSO session deadline as a SystemTime ([#1012](https://github.com/salasebas/saml-rs/pull/1012))
- *(idp)* [**breaking**] return refusal data for requests refused for their signature or age ([#981](https://github.com/salasebas/saml-rs/pull/981))
- *(metadata)* let importers require a root validUntil within a maximum validity interval ([#941](https://github.com/salasebas/saml-rs/pull/941))
- *(metadata)* import federation peers from a signed aggregate
- *(crypto)* add ECDSA and Ed25519 signing options
- *(sso)* authorize scoped attributes for their issuing IdP ([#876](https://github.com/salasebas/saml-rs/pull/876))
- *(sso)* request an affiliation-qualified NameID ([#875](https://github.com/salasebas/saml-rs/pull/875))
- *(slo)* accept authenticated asynchronous logout at the IdP ([#874](https://github.com/salasebas/saml-rs/pull/874))
- *(artifact)* add ArtifactStore trait for shared IdP artifact storage ([#873](https://github.com/salasebas/saml-rs/pull/873))
- *(slo)* expose reason from received logout requests ([#870](https://github.com/salasebas/saml-rs/pull/870))
- *(sso)* enforce exact authentication context for opted-in pending logins ([#871](https://github.com/salasebas/saml-rs/pull/871))
- *(sso)* resolve trusted IdPs for unsolicited browser POST ([#867](https://github.com/salasebas/saml-rs/pull/867))
- *(saml)* opt in to signing SOAP artifact requests ([#866](https://github.com/salasebas/saml-rs/pull/866))
- *(slo)* match IdP logout requests to local SP sessions ([#864](https://github.com/salasebas/saml-rs/pull/864))
- *(sso)* send optional status messages for failed logins ([#863](https://github.com/salasebas/saml-rs/pull/863))
- *(api)* expose explicit CBC encryption constant names ([#858](https://github.com/salasebas/saml-rs/pull/858))
- *(saml)* expose verified peer status messages ([#856](https://github.com/salasebas/saml-rs/pull/856))
- *(sso)* carry the IdP session deadline to the SP ([#854](https://github.com/salasebas/saml-rs/pull/854))
- *(api)* [**breaking**] send AuthnRequest extensions and align fluent option names ([#802](https://github.com/salasebas/saml-rs/pull/802))
- *(slo)* let the IdP finish asynchronous browser logout ([#842](https://github.com/salasebas/saml-rs/pull/842))
- *(slo)* send optional logout status messages ([#841](https://github.com/salasebas/saml-rs/pull/841))
- *(slo)* set the logout reason from start options ([#831](https://github.com/salasebas/saml-rs/pull/831))
- [**breaking**] remove Enhanced Client/Proxy SSO, which no dependent uses and enterprise IdPs do not offer ([#809](https://github.com/salasebas/saml-rs/pull/809))
- *(sso)* [**breaking**] identify subjects with the subject-id and pairwise-id attributes saml2int requires ([#800](https://github.com/salasebas/saml-rs/pull/800))
- *(metadata)* read and publish entity categories, Sirtfi, and subject-id requirements ([#797](https://github.com/salasebas/saml-rs/pull/797))
- *(attributes)* read and write Attribute FriendlyName ([#781](https://github.com/salasebas/saml-rs/pull/781))
- *(api)* say how an Outbound is delivered ([#694](https://github.com/salasebas/saml-rs/pull/694))
- *(api)* [**breaking**] add a serde feature for pending snapshots and let them gain fields without breaking callers ([#687](https://github.com/salasebas/saml-rs/pull/687))
- *(crypto)* deprecate the signature verifiers that accept unsigned input as Ok ([#638](https://github.com/salasebas/saml-rs/pull/638))
- *(raw)* deprecate the raw message functions for removal in the next minor ([#619](https://github.com/salasebas/saml-rs/pull/619))
- *(crypto)* deprecate the hidden crypto and DOM helpers and move their tests into the crate ([#630](https://github.com/salasebas/saml-rs/pull/630))

### Fixed

- *(idp)* let an SSO refusal carry a RelayState the identity provider chooses, and record seven flow policy reasons ([#1063](https://github.com/salasebas/saml-rs/pull/1063))
- *(metadata)* keep artifact resolution working when one endpoint is blank, and record seven policy reasons ([#1062](https://github.com/salasebas/saml-rs/pull/1062))
- *(idp)* [**breaking**] send no Requester or Responder answer to a SOAP request of a later major version ([#1060](https://github.com/salasebas/saml-rs/pull/1060))
- *(idp)* [**breaking**] answer an AuthnRequest of a later version and refuse an ACS URL with an ACS index ([#1059](https://github.com/salasebas/saml-rs/pull/1059))
- *(idp)* [**breaking**] answer AuthnRequests with an unusable ProtocolBinding or unreadable content ([#1056](https://github.com/salasebas/saml-rs/pull/1056))
- *(idp)* answer SOAP requests it cannot process with an error status ([#1053](https://github.com/salasebas/saml-rs/pull/1053))
- *(sp)* [**breaking**] refuse a blank NameID string or NewID in service provider requests ([#1052](https://github.com/salasebas/saml-rs/pull/1052))
- *(binding)* [**breaking**] do not send a message with signed content over HTTP-Redirect ([#1049](https://github.com/salasebas/saml-rs/pull/1049))
- *(sp)* [**breaking**] refuse a selected assertion with a second Subject ([#1033](https://github.com/salasebas/saml-rs/pull/1033))
- *(idp)* [**breaking**] refuse an AuthnRequest with more than one NameIDPolicy ([#999](https://github.com/salasebas/saml-rs/pull/999))
- *(sp)* [**breaking**] refuse child elements inside the selected assertion's text values ([#1032](https://github.com/salasebas/saml-rs/pull/1032))
- [**breaking**] write a request ID as InResponseTo only when it is an NCName ([#997](https://github.com/salasebas/saml-rs/pull/997))
- *(sp)* [**breaking**] refuse Conditions attributes that the schema does not declare ([#1031](https://github.com/salasebas/saml-rs/pull/1031))
- *(idp)* [**breaking**] refuse a blank NameID string that the identity provider writes ([#1019](https://github.com/salasebas/saml-rs/pull/1019))
- *(slo)* accept an inner space in the entity ID of the LogoutResponse Issuer ([#1018](https://github.com/salasebas/saml-rs/pull/1018))
- *(sp)* pass a non-URI or overlong unsolicited Issuer to the IdP resolver ([#1017](https://github.com/salasebas/saml-rs/pull/1017))
- *(soap)* trim only XML whitespace from mustUnderstand ([#1034](https://github.com/salasebas/saml-rs/pull/1034))
- *(metadata)* [**breaking**] refuse peer metadata with a malformed indexed endpoint ([#993](https://github.com/salasebas/saml-rs/pull/993))
- *(slo)* record any received NameID and use XML whitespace for logout subjects ([#974](https://github.com/salasebas/saml-rs/pull/974))
- *(config)* [**breaking**] require the enveloped-signature transform first ([#1003](https://github.com/salasebas/saml-rs/pull/1003))
- *(slo)* recognize the asynchronous marker by its element name ([#969](https://github.com/salasebas/saml-rs/pull/969))
- *(nim)* answer an authenticated malformed ManageNameIDRequest with Requester ([#1029](https://github.com/salasebas/saml-rs/pull/1029))
- *(sign)* [**breaking**] put embedded signatures in the schema slot ([#1002](https://github.com/salasebas/saml-rs/pull/1002))
- *(slo)* accept a SOAP LogoutRequest without Destination at several SOAP endpoints ([#971](https://github.com/salasebas/saml-rs/pull/971))
- *(status)* accept any absolute xs:anyURI as a subordinate status code ([#970](https://github.com/salasebas/saml-rs/pull/970))
- *(nim)* accept a SOAP ManageNameIDRequest without Destination at several SOAP endpoints ([#1027](https://github.com/salasebas/saml-rs/pull/1027))
- *(nim)* refuse a relative subordinate status code in ManageNameIDResponse ([#1026](https://github.com/salasebas/saml-rs/pull/1026))
- *(binding)* read received base64 by one rule, artifacts included ([#1023](https://github.com/salasebas/saml-rs/pull/1023))
- *(idp)* [**breaking**] answer ArtifactResolve after store and signature failures ([#983](https://github.com/salasebas/saml-rs/pull/983))
- *(idp)* resolve an outstanding artifact after its endpoint index is retired ([#985](https://github.com/salasebas/saml-rs/pull/985))
- *(idp)* answer an empty ArtifactResolve artifact without the message ([#984](https://github.com/salasebas/saml-rs/pull/984))
- *(sp)* [**breaking**] reject SSO responses whose bearer assertions have no AuthnStatement ([#1010](https://github.com/salasebas/saml-rs/pull/1010))
- *(sp)* [**breaking**] accept other SSO assertions whose Subject names the principal differently ([#1011](https://github.com/salasebas/saml-rs/pull/1011))
- *(sp)* [**breaking**] report unsigned SimpleSign error responses without SigAlg ([#1009](https://github.com/salasebas/saml-rs/pull/1009))
- *(xml)* [**breaking**] reject a malformed XML declaration in received documents ([#975](https://github.com/salasebas/saml-rs/pull/975))
- *(sp)* [**breaking**] refuse an AuthnContext that its schema type does not allow ([#1000](https://github.com/salasebas/saml-rs/pull/1000))
- [**breaking**] decide that a SAML string is empty by XML whitespace only ([#998](https://github.com/salasebas/saml-rs/pull/998))
- *(idp)* [**breaking**] require the authentication time of each SSO assertion ([#966](https://github.com/salasebas/saml-rs/pull/966))
- *(idp)* [**breaking**] refuse success when no requested SubjectConfirmation is bearer ([#965](https://github.com/salasebas/saml-rs/pull/965))
- *(sp)* [**breaking**] refuse a blank ProviderName in AuthnRequests ([#978](https://github.com/salasebas/saml-rs/pull/978))
- *(sp)* [**breaking**] refuse every SAML-defined namespace for AuthnRequest extensions ([#977](https://github.com/salasebas/saml-rs/pull/977))
- *(metadata)* [**breaking**] require a detail in each published ContactPerson ([#992](https://github.com/salasebas/saml-rs/pull/992))
- *(metadata)* count only XML signature elements in signed metadata ([#991](https://github.com/salasebas/saml-rs/pull/991))
- *(metadata)* read NameIDFormat only in the metadata namespace ([#990](https://github.com/salasebas/saml-rs/pull/990))
- *(replay)* [**breaking**] store only authenticated requests that pass every refusal check ([#962](https://github.com/salasebas/saml-rs/pull/962))
- *(idp)* [**breaking**] apply the Core 8.3 NameID rules to identity provider logout and management requests ([#961](https://github.com/salasebas/saml-rs/pull/961))
- [**breaking**] encrypt logout and name identifier management for the receiving role ([#960](https://github.com/salasebas/saml-rs/pull/960))
- *(discovery)* skip a common domain cookie entry whose bytes are not UTF-8 ([#1007](https://github.com/salasebas/saml-rs/pull/1007))
- *(idp)* [**breaking**] encrypt for the receiving SP role's entity certificate ([#942](https://github.com/salasebas/saml-rs/pull/942))
- *(metadata)* [**breaking**] ignore same-named foreign elements when reading metadata endpoints ([#939](https://github.com/salasebas/saml-rs/pull/939))
- *(soap)* accept escaped XML namespace declarations in responses ([#937](https://github.com/salasebas/saml-rs/pull/937))
- *(sp)* [**breaking**] verify decrypted assertion signatures in their response context ([#934](https://github.com/salasebas/saml-rs/pull/934))
- *(sp)* [**breaking**] accept SSO assertions whose Subject has no NameID ([#922](https://github.com/salasebas/saml-rs/pull/922))
- [**breaking**] encrypt for a usable peer key in every flow, name it in EncryptedKey, and give crypto-fips a working default ([#923](https://github.com/salasebas/saml-rs/pull/923))
- *(slo)* [**breaking**] send participant logout to an https endpoint, refuse blank status text, and accept schema hints on the async marker ([#921](https://github.com/salasebas/saml-rs/pull/921))
- *(metadata)* [**breaking**] select assertion consumer services within one SP role ([#920](https://github.com/salasebas/saml-rs/pull/920))
- *(soap)* read envelopes that declare the xml prefix with a character reference ([#918](https://github.com/salasebas/saml-rs/pull/918))
- *(idp)* [**breaking**] read requested NameID formats by their schema value ([#916](https://github.com/salasebas/saml-rs/pull/916))
- *(sp)* [**breaking**] judge SSO responses by the session assertion and compare InResponseTo values ([#911](https://github.com/salasebas/saml-rs/pull/911))
- *(idp)* [**breaking**] reject attribute strings SAML cannot carry and encrypt for a usable SP key ([#912](https://github.com/salasebas/saml-rs/pull/912))
- [**breaking**] enforce protocol status shape, report SOAP faults, and protect every artifact answer ([#910](https://github.com/salasebas/saml-rs/pull/910))
- *(sp)* [**breaking**] allow identifier creation in AuthnRequests by default
- *(slo)* [**breaking**] keep the session authority logout reasons off service provider requests
- *(idp)* [**breaking**] reject values a login response cannot carry and report AuthnRequest authentication ([#901](https://github.com/salasebas/saml-rs/pull/901))
- *(bindings)* [**breaking**] round-trip RelayState and reserve SAML Redirect parameters
- *(slo)* report an unresolved SOAP endpoint after verifying the reply
- *(slo)* check a SOAP reply Destination after signature verification
- *(sso)* keep the requested assertion consumer contract with a supplied receiving URL
- [**breaking**] check SSO, ArtifactResolve, and SOAP logout against the receiving URL
- *(idp)* accept XML whitespace in AuthnRequest ProtocolBinding
- *(sso)* [**breaking**] preserve authentication and signature evidence ([#880](https://github.com/salasebas/saml-rs/pull/880))
- *(api)* [**breaking**] clarify outbound delivery errors and artifact refusals ([#859](https://github.com/salasebas/saml-rs/pull/859))
- *(saml)* [**breaking**] reject invalid SOAP artifact resolution signatures ([#855](https://github.com/salasebas/saml-rs/pull/855))
- *(saml)* [**breaking**] reject invalid SOAP NameID management signatures ([#828](https://github.com/salasebas/saml-rs/pull/828))
- *(metadata)* [**breaking**] honor assertion signing across SAML 2.0 SP roles ([#823](https://github.com/salasebas/saml-rs/pull/823))
- *(crypto)* sign embedded XML with provider-supported algorithms ([#824](https://github.com/salasebas/saml-rs/pull/824))
- *(soap)* [**breaking**] reject processing instructions in outbound SAML ([#825](https://github.com/salasebas/saml-rs/pull/825))
- *(config)* [**breaking**] reject unsupported signature placement paths ([#826](https://github.com/salasebas/saml-rs/pull/826))
- *(template)* [**breaking**] preserve literal content in custom logout templates ([#820](https://github.com/salasebas/saml-rs/pull/820))
- *(saml)* read received status codes and bearer methods as anyURI values ([#817](https://github.com/salasebas/saml-rs/pull/817))
- *(saml)* return protocol responses for authenticated refusals ([#812](https://github.com/salasebas/saml-rs/pull/812))
- [**breaking**] read received URIs as xs:anyURI values and compare every Issuer exactly ([#814](https://github.com/salasebas/saml-rs/pull/814))
- *(config)* [**breaking**] catch unusable or mismatched credentials in build() instead of at every peer ([#815](https://github.com/salasebas/saml-rs/pull/815))
- *(sso)* [**breaking**] reject a NotBefore at or after NotOnOrAfter within the clock skew ([#811](https://github.com/salasebas/saml-rs/pull/811))
- *(replay)* report expired assertion keys with the error custom caches can return ([#810](https://github.com/salasebas/saml-rs/pull/810))
- *(slo)* [**breaking**] require one principal identifier on received logout requests ([#808](https://github.com/salasebas/saml-rs/pull/808))
- *(metadata)* [**breaking**] stop publishing relative endpoint locations and duplicate artifact resolution indexes ([#813](https://github.com/salasebas/saml-rs/pull/813))
- *(sso)* [**breaking**] read SSO time bounds only as SAML UTC dateTimes ([#779](https://github.com/salasebas/saml-rs/pull/779))
- *(template)* [**breaking**] stop reading text in logout templates as markup ([#766](https://github.com/salasebas/saml-rs/pull/766))
- *(sso)* [**breaking**] reject an AuthnInstant that is not a SAML UTC dateTime ([#770](https://github.com/salasebas/saml-rs/pull/770))
- *(sso)* [**breaking**] reject an AuthnStatement without its AuthnInstant ([#765](https://github.com/salasebas/saml-rs/pull/765))
- *(sso)* [**breaking**] reject repeated SubjectLocality in one AuthnStatement ([#757](https://github.com/salasebas/saml-rs/pull/757))
- *(sso)* [**breaking**] reject an AuthnStatement without its AuthnContext ([#760](https://github.com/salasebas/saml-rs/pull/760))
- *(saml)* [**breaking**] honor replay limits and report ambiguous or malformed SAML input ([#752](https://github.com/salasebas/saml-rs/pull/752))
- *(config)* accept any encryption algorithm in protocol-only builds ([#753](https://github.com/salasebas/saml-rs/pull/753))
- *(xml)* resolve protocol names during the DOM parse ([#751](https://github.com/salasebas/saml-rs/pull/751))
- *(paos)* [**breaking**] accept longer responder-added RelayState when the SP sent none ([#747](https://github.com/salasebas/saml-rs/pull/747))
- *(soap)* [**breaking**] process mandatory headers only for their SOAP actor ([#745](https://github.com/salasebas/saml-rs/pull/745))
- *(sp)* [**breaking**] report SSO response errors before comparing RelayState ([#743](https://github.com/salasebas/saml-rs/pull/743))
- *(metadata)* [**breaking**] reject invalid signing booleans on import ([#742](https://github.com/salasebas/saml-rs/pull/742))
- *(crypto)* [**breaking**] enforce per-algorithm XML HMAC truncation limits ([#740](https://github.com/salasebas/saml-rs/pull/740))
- *(slo)* let recipients answer an encrypted BaseID ([#741](https://github.com/salasebas/saml-rs/pull/741))
- *(metadata)* count only members of metadata groups ([#738](https://github.com/salasebas/saml-rs/pull/738))
- *(sp)* [**breaking**] report SSO failures when InResponseTo is absent ([#739](https://github.com/salasebas/saml-rs/pull/739))
- *(paos)* accept legacy ECP client headers with single quotes ([#737](https://github.com/salasebas/saml-rs/pull/737))
- *(metadata)* accept hour 24 in validUntil ([#736](https://github.com/salasebas/saml-rs/pull/736))
- *(sp)* [**breaking**] require encryption of every assertion when configured ([#735](https://github.com/salasebas/saml-rs/pull/735))
- *(metadata)* read only unqualified validUntil bounds ([#733](https://github.com/salasebas/saml-rs/pull/733))
- *(status)* allow URI sub-delimiters in subordinate status codes ([#730](https://github.com/salasebas/saml-rs/pull/730))
- *(idp)* preserve attribute types with xs and xsi assertion prefixes ([#731](https://github.com/salasebas/saml-rs/pull/731))
- *(slo)* [**breaking**] authenticate every browser logout request and response ([#720](https://github.com/salasebas/saml-rs/pull/720))
- *(sp)* [**breaking**] evaluate present audience restrictions before accepting SSO ([#718](https://github.com/salasebas/saml-rs/pull/718))
- *(xml)* [**breaking**] honor configured SAML prefixes across bindings ([#719](https://github.com/salasebas/saml-rs/pull/719))
- *(idp)* [**breaking**] verify signatures on every signed AuthnRequest ([#717](https://github.com/salasebas/saml-rs/pull/717))
- *(metadata)* [**breaking**] always publish role children in schema order ([#715](https://github.com/salasebas/saml-rs/pull/715))
- *(sp)* [**breaking**] require replay storage for HTTP-POST SSO ([#716](https://github.com/salasebas/saml-rs/pull/716))
- *(idp)* [**breaking**] honor requested NameID formats in SSO responses ([#714](https://github.com/salasebas/saml-rs/pull/714))
- *(metadata)* add a default cache duration to generated metadata ([#712](https://github.com/salasebas/saml-rs/pull/712))
- *(sp)* verify every SSO response and assertion signature under every profile ([#713](https://github.com/salasebas/saml-rs/pull/713))
- *(idp)* write an SSO error Response when a response template is set ([#690](https://github.com/salasebas/saml-rs/pull/690))
- *(metadata)* [**breaking**] normalize formats and make metadata access explicit ([#644](https://github.com/salasebas/saml-rs/pull/644))
- *(xml)* [**breaking**] isolate schema validation and cover inbound XML ([#642](https://github.com/salasebas/saml-rs/pull/642))
- *(metadata)* [**breaking**] preserve configured groups in custom element orders ([#641](https://github.com/salasebas/saml-rs/pull/641))
- *(ci)* verify the declared MSRV with its actual toolchain ([#640](https://github.com/salasebas/saml-rs/pull/640))
- *(idp)* accept a signed PAOS AuthnRequest without Destination under every policy ([#639](https://github.com/salasebas/saml-rs/pull/639))
- *(config)* [**breaking**] make build() catch every metadata error and require SSO/ACS endpoints ([#637](https://github.com/salasebas/saml-rs/pull/637))
- *(sp)* [**breaking**] reject an SSO response with an Attribute that has no Name ([#636](https://github.com/salasebas/saml-rs/pull/636))
- *(logout)* check the outbound LogoutResponse status in the profile validator ([#633](https://github.com/salasebas/saml-rs/pull/633))
- *(xml)* keep source offsets when input starts with a UTF-8 BOM ([#635](https://github.com/salasebas/saml-rs/pull/635))
- *(idp)* [**breaking**] reject a template login response attribute with no value ([#634](https://github.com/salasebas/saml-rs/pull/634))
- *(config)* [**breaking**] remove XmlPolicy::clock_drifts, which typed flows silently ignored ([#632](https://github.com/salasebas/saml-rs/pull/632))
- *(config)* [**breaking**] remove Default from security policy enums ([#614](https://github.com/salasebas/saml-rs/pull/614))

### Other

- say that a received authentication context reference has its whitespace collapsed ([#1061](https://github.com/salasebas/saml-rs/pull/1061))
- build the test templates without warnings when no crypto provider is enabled ([#1058](https://github.com/salasebas/saml-rs/pull/1058))
- *(conformance)* record that SOAP artifact and name ID replies keep Destination uncompared ([#987](https://github.com/salasebas/saml-rs/pull/987))
- *(conformance)* scope algorithm claims by build and give each exclusion one owner ([#1008](https://github.com/salasebas/saml-rs/pull/1008))
- *(conformance)* scope XML Encryption by build and record key resolution ([#1006](https://github.com/salasebas/saml-rs/pull/1006))
- *(nim)* record who owns each name identifier management duty and why ([#1030](https://github.com/salasebas/saml-rs/pull/1030))
- *(conformance)* scope and give reasons to the XML signature rows ([#1001](https://github.com/salasebas/saml-rs/pull/1001))
- *(slo)* record the reasons and application duties of Single Logout ([#972](https://github.com/salasebas/saml-rs/pull/972))
- *(conformance)* keep the shared browser binding rules in one record ([#1024](https://github.com/salasebas/saml-rs/pull/1024))
- *(conformance)* record the service provider signature and decryption rules ([#1021](https://github.com/salasebas/saml-rs/pull/1021))
- *(conformance)* settle SP SSO acceptance levels and reasons ([#1013](https://github.com/salasebas/saml-rs/pull/1013))
- *(conformance)* record what typed receipt checks without a schema validator ([#996](https://github.com/salasebas/saml-rs/pull/996))
- *(conformance)* record the IdP response signing, window, and ACS choices ([#968](https://github.com/salasebas/saml-rs/pull/968))
- *(migrations)* move the unreleased guides into 0.8.x-to-0.9.0 ([#1036](https://github.com/salasebas/saml-rs/pull/1036))
- make conformance guidance easy to find ([#957](https://github.com/salasebas/saml-rs/pull/957))
- *(metadata)* state that Metadata::parse reads roles of any namespace and protocol ([#944](https://github.com/salasebas/saml-rs/pull/944))
- *(metadata)* [**breaking**] use plural names for metadata generation collections ([#935](https://github.com/salasebas/saml-rs/pull/935))
- *(crypto)* [**breaking**] make XML signature reference digest selection internal ([#933](https://github.com/salasebas/saml-rs/pull/933))
- *(error)* describe SAML field and derived expiration checks on TimeWindowField ([#932](https://github.com/salasebas/saml-rs/pull/932))
- *(config)* document DigestAlgorithm as RSA-OAEP configuration ([#931](https://github.com/salasebas/saml-rs/pull/931))
- *(sp)* separate the AllowCreate opt-out from the E14 recommendation
- Merge pull request #903 from salasebas/ss/relaystate-redirect-params
- Merge pull request #902 from salasebas/ss/actual-recipient-checks
- *(slo)* require the SOAP endpoint error before peer status
- align release guides with supported exchanges
- Merge pull request #884 from salasebas/ss/metadata-cert-scope-fixes
- remove redundant comments and restore Clippy checks in tests
- Merge pull request #879 from salasebas/ss/nameid-namespace-constraints
- Merge pull request #882 from salasebas/ss/correlated-idp-refusal
- Merge pull request #881 from salasebas/ss/outstanding-logout-identity-match
- clear workspace Clippy warnings ([#868](https://github.com/salasebas/saml-rs/pull/868))
- *(metadata)* [**breaking**] name trust policies for the checks they apply ([#862](https://github.com/salasebas/saml-rs/pull/862))
- *(soap)* [**breaking**] name body elements and channel attestations precisely ([#861](https://github.com/salasebas/saml-rs/pull/861))
- *(api)* [**breaking**] distinguish signing from signature validation ([#860](https://github.com/salasebas/saml-rs/pull/860))
- *(xml)* [**breaking**] name resource limits for what the parser counts ([#857](https://github.com/salasebas/saml-rs/pull/857))
- *(saml)* remove leftover raw browser binding code ([#838](https://github.com/salasebas/saml-rs/pull/838))
- *(slo)* [**breaking**] generate logout messages from typed inputs ([#837](https://github.com/salasebas/saml-rs/pull/837))
- *(deps)* bump the cargo-maintenance group with 2 updates ([#834](https://github.com/salasebas/saml-rs/pull/834))
- describe public API behavior and restore upgrade navigation ([#830](https://github.com/salasebas/saml-rs/pull/830))
- remove unused samlify port settings and fixtures ([#829](https://github.com/salasebas/saml-rs/pull/829))
- *(sso)* remove obsolete AuthnRequest renderer requirement ([#827](https://github.com/salasebas/saml-rs/pull/827))
- share common SAML message processing steps ([#822](https://github.com/salasebas/saml-rs/pull/822))
- require explicit handling for new bindings and XML events ([#818](https://github.com/salasebas/saml-rs/pull/818))
- *(conformance)* cut the conformance records by 38% to one short row per rule ([#807](https://github.com/salasebas/saml-rs/pull/807))
- *(migrations)* correct the upgrade from published 0.8 ([#821](https://github.com/salasebas/saml-rs/pull/821))
- *(replay)* reuse retention when a message has no deadline ([#780](https://github.com/salasebas/saml-rs/pull/780))
- *(flow)* name the states internal flow code passed as booleans and tuples ([#767](https://github.com/salasebas/saml-rs/pull/767))
- move iterator side effects out of closures ([#758](https://github.com/salasebas/saml-rs/pull/758))
- *(xml)* read extracted fields through the keys their field sets write ([#761](https://github.com/salasebas/saml-rs/pull/761))
- *(saml)* split long flow, SSO, and logout functions into named stages ([#762](https://github.com/salasebas/saml-rs/pull/762))
- *(config)* read NameID formats through the as_uri table ([#754](https://github.com/salasebas/saml-rs/pull/754))
- *(api)* [**breaking**] retire hidden public imports ([#750](https://github.com/salasebas/saml-rs/pull/750))
- distinguish SAML requirements from library policy ([#734](https://github.com/salasebas/saml-rs/pull/734))
- clarify which SOAP exchanges the typed API supports ([#732](https://github.com/salasebas/saml-rs/pull/732))
- *(sp)* select received encrypted elements by message type ([#727](https://github.com/salasebas/saml-rs/pull/727))
- Use Default for validation policies and enforce SSO and logout producer rules ([#706](https://github.com/salasebas/saml-rs/pull/706))
- *(api)* [**breaking**] replace the Saml<Role> typestate with ServiceProvider and IdentityProvider ([#698](https://github.com/salasebas/saml-rs/pull/698))
- *(api)* [**breaking**] remove the raw API so every message goes through the typed checks ([#695](https://github.com/salasebas/saml-rs/pull/695))
- *(api)* [**breaking**] let policies, limits, and inputs gain fields and variants without a breaking change ([#689](https://github.com/salasebas/saml-rs/pull/689))
- *(api)* [**breaking**] remove constants and options the crate never read, hide internal helpers, and pass every limit as an argument ([#684](https://github.com/salasebas/saml-rs/pull/684))
- *(api)* [**breaking**] stop answering Success by default in logout and name identifier management ([#686](https://github.com/salasebas/saml-rs/pull/686))
- *(api)* [**breaking**] report an SSO failure without a NameId and share one outcome type with PAOS ([#685](https://github.com/salasebas/saml-rs/pull/685))
- *(api)* [**breaking**] set each SSO template on the builder of the role that renders it ([#683](https://github.com/salasebas/saml-rs/pull/683))
- *(api)* [**breaking**] give each typed operation option one name and drop PAOS arguments that carried no data
- *(api)* [**breaking**] send SOAP headers as one list and keep resolved artifacts in the shared replay cache ([#678](https://github.com/salasebas/saml-rs/pull/678))
- *(api)* [**breaking**] keep SSO audiences grouped by restriction and name accessors for what they return ([#677](https://github.com/salasebas/saml-rs/pull/677))
- *(api)* [**breaking**] issue SSO responses from a NameId and remove misleading SSO result APIs ([#669](https://github.com/salasebas/saml-rs/pull/669))
- *(config)* [**breaking**] catch config mistakes at compile time and stop sending an unrecorded RelayState ([#674](https://github.com/salasebas/saml-rs/pull/674))
- *(browser)* [**breaking**] drop the turbofish from received messages and rename BrowserInput to Inbound ([#673](https://github.com/salasebas/saml-rs/pull/673))
- *(browser)* [**breaking**] name pending accessors for the value they return ([#671](https://github.com/salasebas/saml-rs/pull/671))
- *(browser)* [**breaking**] simplify RelayState and pending state, and make respond_sso echo RelayState ([#670](https://github.com/salasebas/saml-rs/pull/670))
- replace stale design records with rules that state their reason ([#667](https://github.com/salasebas/saml-rs/pull/667))
- *(error)* [**breaking**] make SamlError matchable and keep error sources ([#646](https://github.com/salasebas/saml-rs/pull/646))
- organize upgrade guides by version and topic ([#645](https://github.com/salasebas/saml-rs/pull/645))
- *(api)* [**breaking**] simplify logout completion, validation and replay ([#643](https://github.com/salasebas/saml-rs/pull/643))
- *(api)* [**breaking**] name relaxed options for what they allow ([#617](https://github.com/salasebas/saml-rs/pull/617))
- *(raw)* [**breaking**] keep one public path per raw item ([#618](https://github.com/salasebas/saml-rs/pull/618))
- *(config)* [**breaking**] make a built config valid by construction ([#620](https://github.com/salasebas/saml-rs/pull/620))
- *(error)* [**breaking**] delete compatibility SamlError variants ([#615](https://github.com/salasebas/saml-rs/pull/615))
- *(deps)* bump uuid ([#627](https://github.com/salasebas/saml-rs/pull/627))
- *(api)* [**breaking**] give hidden public items a documented path ([#621](https://github.com/salasebas/saml-rs/pull/621))
- *(config)* [**breaking**] bind every peer descriptor to an expected entity ID and hide secret accessors ([#616](https://github.com/salasebas/saml-rs/pull/616))

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
