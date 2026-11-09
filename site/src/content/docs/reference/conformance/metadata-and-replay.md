---
title: "Metadata and replay"
description: "Facts for metadata trust and replay on the typed browser flows. `recommended()` does not select signed metadata, invent trust anchors, or store replay. `Default`, `new`, and..."
---

Facts for metadata trust and replay on the typed browser flows.
`recommended()` does not select signed metadata, invent trust anchors, or
store replay. `Default`, `new`, `try_new`, and the config builders are
Recommended. Raw settings keep their historical defaults. The preset
distinction is recorded in
[Validation presets](../../explanation/validation-presets.md).

Metadata trust is `MetadataTrustPolicy`, passed to
`IdpDescriptor::from_metadata_xml_for` and
`SpDescriptor::from_metadata_xml_for`. Replay is `ReplayPolicy`, passed to
`SamlValidationContext::new`. Neither value is a field of
`SpValidationPolicy` or `IdpValidationPolicy`. The Web Browser SSO and Single
Logout field combinations do not select signed metadata, invent trust anchors,
or store replay.

Normative text is SAML Metadata 2.0 and Profiles 2.0, as corrected by Approved
Errata 05, plus Core 2.0 where a condition is named. Schema citations are the
OASIS metadata schema.

## Metadata trust

Typed import accepts a document the caller already holds. It does not publish
metadata, resolve a well-known location, query DNS, refresh a cache, or follow
TLS server authentication. Metadata §4 describes those mechanisms and says
other out-of-band mechanisms are permitted. Rules that obligate only that
resolution path stay outside this import.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| `ds:Signature` on `EntityDescriptor` or `EntitiesDescriptor` | Metadata publisher | Generate metadata | Optional. The schema marks the element optional. Metadata §3 says a signature is not always required when the relying party obtains the document directly over an authenticated secure channel |
| Sign at least the root element when that channel is absent | Metadata publisher | Generate metadata | Recommendation. Metadata §3. §4.3.3.2 also says published metadata documents should be signed. This import does not reject unsigned metadata because of that publisher recommendation. `UnsignedForCompatibility` remains the samlify-port import |
| Employ some document-integrity mechanism, and validate a signature that is present, when metadata is resolved through §4 | Metadata publisher and metadata consumer | Resolve metadata | Mandatory for that resolution path. Metadata §4.3.3 and §4.3.3.2. Typed import does not resolve metadata, so the field combination does not apply this duty and does not turn it into a rejection of every unsigned document |
| A relying party has some means to establish trust before using metadata | Metadata consumer | Inbound | Recommendation for resolved metadata. Metadata §4. The means here is the caller-supplied `MetadataTrustPolicy`. The field combination does not choose it |
| `KeyInfo` on a metadata signature may be absent, and a certificate in `KeyDescriptor` is not a trust anchor | Metadata consumer | Inbound | Optional material, with no implied trust. Metadata §3.1.5 lets `KeyInfo` be absent. Errata 05 E69 takes no position on `KeyDescriptor`'s `ds:KeyInfo` and says no trust implication follows from including a certificate. `RequireSignature` verifies only the caller-pinned certificates and rejects the document when none of them verifies it. `UnsignedForCompatibility` may still parse a signed document and does not record that signature as verified. The field combination does not turn an unverified signature into trust |
| `entityID` is unique across every entity that interacts in one deployment | Metadata publisher | A deployment | Mandatory. Metadata §2.2.1. The generator writes the caller-supplied identifier and does not police uniqueness across a deployment |
| An enveloped signature on the signed root | Metadata publisher, when signing | Generate the signed element | Mandatory. Metadata §3.1.1. `RequireSignature` rejects a signature that is not enveloped. The same rule applies to a root `EntitiesDescriptor` and a root `EntityDescriptor` |
| An identifier on the signed root, and one reference whose URI is `#` plus that identifier | Metadata publisher, when signing | Generate the signed element | Mandatory. Metadata §3.1.2. `RequireSignature` rejects a signed root with no identifier and a signature that does not contain exactly that one reference. The signature must still cover the signed root |
| No transform other than enveloped signature or exclusive canonicalization, with or without comments | Signer and verifier | Inbound `RequireSignature` | Recommendation. Metadata §3.1.4. `RequireSignature` rejects other transforms. `RequireSignatureAllowingOtherCanonicalization` also accepts inclusive canonicalization, and still rejects a transform that can drop part of the signed element |
| No `ds:Object` in a metadata signature | Verifier | Inbound `RequireSignature` | Recommendation. Approved Errata 05 E91 says verifiers should reject `ds:Object` because it can carry unsigned data. Both require-signature options reject it. There is no relaxation |
| When `RequireSignature` is selected, the signature covers the signed root | Metadata consumer | Inbound | Mandatory once that caller option is selected. Metadata §3.1.2 requires the signature to cover the signed element and its children. The import rejects a signature that does not cover the root |
| A root `EntityDescriptor` or `EntitiesDescriptor` carries `validUntil` or `cacheDuration` | Metadata publisher | Generate a root metadata instance | Mandatory. Metadata §2.3.1 and §2.3.2. This crate's metadata generator does not emit either attribute, and the importer does not reject the omission. That is existing behaviour, preserved here, and it is not a preset field |
| Do not use metadata at or after `validUntil` | Metadata consumer | Use metadata | Mandatory when the attribute is present. Errata 05 E94 adds §4.3.2: metadata must be treated as invalid at that time, and invalid metadata must not be used. A nested value may only shorten the parent (E76). Typed import does not evaluate `validUntil` |
| Base caching on `cacheDuration` | Metadata consumer | Cache resolved metadata | Mandatory for a consumer that caches. Errata 05 E94 replaces §4.3.1: caching follows `cacheDuration`, and a stale copy may still be used. E76 lets a nested value only shorten the parent. Typed import does not cache metadata, so this is not a preset field |

## Replay

`ReplayPolicy::DisabledForCompatibility` skips storage. It is the samlify-port
hatch. It is not a named relaxation of a recommendation.
`ReplayPolicy::RequireCache` stores only in the cache the caller passes.
`SamlValidationContext` has no hidden cache.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Bearer assertions delivered by HTTP POST are not replayed | Accepting service provider | Inbound `finish_sso` and `accept_unsolicited_sso` | Mandatory for HTTP POST. Profiles §4.1.4.5. Approved Errata 05 E26 replaces only the signing sentence at lines 600–601 and leaves this paragraph in place. The check stays on `ReplayPolicy`. The accept combination does not enable it. `DisabledForCompatibility` is the samlify-port hatch for this mandatory rule |
| The kept HTTP POST identifier is the bearer assertion `ID`, for the `SubjectConfirmationData@NotOnOrAfter` window | Accepting service provider | Inbound | Mandatory for the HTTP POST rule above. Profiles §4.1.4.5 names that identifier and that window. The stored deadline is that attribute plus the context `NotOnOrAfter` skew. Profiles §4.1.4.3 checks bearer `NotOnOrAfter` subject to allowable clock skew, and Approved Errata 05 E92 is the guidance for that allowance. An earlier `Conditions` or `AuthnStatement` instant does not shorten the assertion identifier |
| Also store the Response `ID` | Accepting service provider | Inbound | Library policy. It is stored only when the caller supplies a cache. Its deadline remains the earliest of `Conditions`, bearer `SubjectConfirmationData`, and every `AuthnStatement`, plus the same skew. That deadline can be earlier than the assertion identifier |
| The same caller cache on HTTP-Redirect or HTTP-POST-SimpleSign responses | Accepting service provider | Inbound | Library policy. Profiles §4.1.4.5 states the replay duty for HTTP POST. Security considerations §7.1.1.4 defers replay countermeasures to the binding and does not add a second receiver requirement. Storage on the other response bindings happens only when the caller supplies a cache |
| `AuthnRequest` `ID` | Identity provider | Inbound `receive_sso` | Library policy. Web Browser SSO does not require the identity provider to remember request identifiers. `receive_sso` stores the ID only when the caller supplies a cache, and that path always requires `SamlValidationContext::with_replay_retention`. It does not read `NotOnOrAfter` |
| `LogoutRequest` `ID` | Logout recipient | Inbound `receive_slo` | Library policy. Single Logout does not require an identifier cache. Storage happens only when the caller supplies a cache. The deadline is `NotOnOrAfter` plus the context `NotOnOrAfter` skew when that attribute is present; otherwise the caller must set `with_replay_retention`. Rejecting an expired `LogoutRequest@NotOnOrAfter` remains the separate library policy already recorded for logout |
| `LogoutResponse` `ID` | Original requester | Inbound `finish_slo` | Library policy. Single Logout does not require an identifier cache. `finish_slo` stores the ID only when the caller supplies a cache, and that path always requires `with_replay_retention`. It does not read `NotOnOrAfter` |
| Do not retain an assertion that carries `<OneTimeUse>` | Relying party that would retain the assertion | Inbound | Mandatory when the element is present. Core §2.5.1.5 `MUST NOT` be retained for future use. For validity, the condition is always Valid. Typed SSO does not retain the assertion for later protocol use, so this is not a preset field and it is not part of the caller replay cache |
| Use a `<OneTimeUse>` assertion immediately | Relying party | Inbound | Recommendation. Core §2.5.1.5. It does not become a rejection of an assertion that arrives later |
