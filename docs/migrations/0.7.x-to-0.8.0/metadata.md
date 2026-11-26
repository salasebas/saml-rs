# 5. Metadata

[How to upgrade from 0.7 to 0.8](README.md)

| Change | Affects | Section |
| --- | --- | --- |
| Duplicate explicit ACS indexes are refused | Generated metadata | [5.1](#51-give-each-acs-its-own-index) |
| An ACS without an index can get a new one | Generated metadata | [5.2](#52-check-the-index-of-an-acs-without-one) |
| `isDefault` only on ACS | Generated metadata | [5.3](#53-stop-relying-on-isdefault-outside-acs) |
| Local entity ID must be a URI of at most 1024 characters | Your configuration | [5.4](#54-use-a-uri-of-at-most-1024-characters-as-your-entity-id) |
| Peer metadata stops at `validUntil` | Imported metadata | [5.5](#55-refresh-peer-metadata-before-its-validuntil) |
| Only SAML 2.0 role descriptors are read | Imported metadata | [5.6](#56-list-saml-20-on-the-peers-role-descriptor) |
| Padded endpoint attributes are read | Imported metadata | [5.7](#57-expect-padded-endpoint-attributes-in-peer-metadata-to-be-read) |

The metadata lifetime you publish is in
[section 1.7](compile-errors.md#17-complete-struct-literals).

Sections 5.1 to 5.3 apply when you generate metadata through `Saml::sp`,
`ServiceProvider::from_config`, `IdentityProvider::from_config`,
`generate_sp_metadata`, `generate_idp_metadata`, or
`try_generate_idp_metadata`. See
[metadata rules](../../conformance/metadata-and-replay.md).

## 5.1 Give each ACS its own index

**Before:** two `AssertionConsumerService` endpoints with the same explicit
index were both published, and looking up that index failed.
**Now:** they return `SamlError::Invalid`. More than 65,536
`AssertionConsumerService` endpoints return `SamlError::Invalid` too, because
no `unsignedShort` index is left.

**Upgrade:** set a different index with `AcsEndpoint::with_index`, or
`Endpoint::index` on raw configuration, or leave one unset.

## 5.2 Check the index of an ACS without one

**Before:** when an explicit index on another ACS already used the position of
an ACS without an index, both were written with the same index.
**Now:** an ACS without an explicit index is still written with its position
in the list, unless another ACS uses that position. Then it gets the smallest
index no other ACS uses. Metadata that already had unique indexes is written
unchanged.

**Upgrade:** if you published metadata with a duplicate index, check which
index each ACS has now. Update peers or stored
`AssertionConsumerServiceIndex` values that expected the old one. To keep an
index stable, set it explicitly.

## 5.3 Stop relying on `isDefault` outside ACS

**Before:** `Endpoint::is_default` wrote `isDefault` on every endpoint.
**Now:** it writes `isDefault` on `AssertionConsumerService` only.
`SingleSignOnService`, `SingleLogoutService`, and `ManageNameIDService` no
longer carry it, because the metadata schema does not define it on them.

**Upgrade:** if a peer read the flag on one of them, tell it which endpoint to
use.

## 5.4 Use a URI of at most 1024 characters as your entity ID

**Affects:** `SpConfig`, `IdpConfig`, `Saml::sp`, `Saml::idp`,
`EntityId::try_new`, `EntityId::from_str`, `EntityId::try_from`,
`generate_sp_metadata`, `generate_idp_metadata`, `try_generate_idp_metadata`,
`ServiceProvider::from_config`, and `IdentityProvider::from_config`. See
[entity identifiers](../../conformance/identifiers.md#entity-identifiers).

**Before:** any value with a non-whitespace character was accepted, and raw
metadata generation also accepted an empty `entity_id`, which is what
`SpMetadataConfig::default()` and `IdpMetadataConfig::default()` hold.
**Now:** these return `SamlError::Invalid` when the entity ID is not an
absolute URI reference, is longer than 1024 characters, or has leading or
trailing whitespace, a tab, a line break, or consecutive spaces.

**Upgrade:** give your own service provider or identity provider an absolute
URI, such as `https://sp.example.com/metadata` or `urn:example:sp`, and trim
whitespace from a value you read from configuration. Changing it changes the
`entityID` and `Issuer` your peers see, so register the new value with them.
In raw `SpMetadataConfig` and `IdpMetadataConfig`, set `entity_id`
explicitly.

## 5.5 Refresh peer metadata before its `validUntil`

**Affects:** peer metadata imported into `IdpDescriptor` or `SpDescriptor`
that carries `validUntil`. Metadata without `validUntil` is not affected, and
an elapsed `cacheDuration` does not make metadata unusable. See
[metadata rules](../../conformance/metadata-and-replay.md).

**Before:** the attribute was ignored and expired metadata stayed in use.
**Now:** every typed flow refuses a descriptor once the earliest `validUntil`
of the peer's role descriptor, its `EntityDescriptor`, and any enclosing
`EntitiesDescriptor` has been reached. It returns
`SamlError::TimeWindowInvalid` with `TimeWindowField::MetadataValidUntil`.
Flows that take a `SamlValidationContext` compare with its clock. The others,
such as `start_sso`, `respond_sso`, and `start_slo`, compare with the system
clock.

Import returns the same error when a `validUntil` is not an `xs:dateTime` with
a timezone, such as `2030-01-01T00:00:00` without `Z`. As library policy, it
also rejects hour 24 (`2030-01-01T24:00:00Z`), a leap second other than
23:59:60 UTC on the last day of a month, and a year outside 0001 through 9999,
although XML Schema allows them.

**Upgrade:** fetch fresh metadata from the publisher and import it again. Ask a
peer that publishes a value without a timezone, or one of those values, to
publish a UTC instant such as `2030-01-01T00:00:00Z`.

## 5.6 List SAML 2.0 on the peer's role descriptor

**Affects:** peer metadata imported with `IdpDescriptor` or `SpDescriptor`, or
parsed with `IdpMetadata`, `SpMetadata`, `IdentityProvider::from_metadata`, or
`ServiceProvider::from_metadata`. `Metadata::parse` is unchanged. See
[metadata trust](../../conformance/metadata-and-replay.md#metadata-trust).

**Before:** every element named `IDPSSODescriptor` or `SPSSODescriptor` was
read. **Now:** only one in the `urn:oasis:names:tc:SAML:2.0:metadata`
namespace whose `protocolSupportEnumeration` lists
`urn:oasis:names:tc:SAML:2.0:protocol` is read.

- Metadata with no such role returns
  `SamlError::MissingMetadata("IDPSSODescriptor")` or
  `SamlError::MissingMetadata("SPSSODescriptor")`. Before, a role that listed
  only SAML 1.1, or a role element outside the metadata namespace, was accepted
  as the SAML 2.0 peer.
- Keys, `WantAuthnRequestsSigned`, `AuthnRequestsSigned`,
  `WantAssertionsSigned`, `NameIDFormat`, endpoints, and `validUntil` of a role
  for another protocol are ignored. Before, its certificates verified SAML 2.0
  messages, and its flags and endpoints were used when it came first. A message
  signed only with such a role's key now fails signature verification.
- With a second `SPSSODescriptor` for another protocol, `AuthnRequestsSigned`
  and `WantAssertionsSigned` were read as false. They are now read from the
  SAML 2.0 role. For a service provider whose SAML 2.0 role sets
  `WantAssertionsSigned`, an identity provider now signs the assertion, and
  over HTTP-POST signs the `Response` only when `want_message_signed` is set.
- `get_name_id_format` returns only the formats of the role read. Before, it
  also returned the formats of the entity's other SSO roles.
  `IdentityProvider::from_metadata` and `ServiceProvider::from_metadata` copy
  that list into `EntitySetting::name_id_format` when it is not empty, and
  otherwise keep the `name_id_format` you pass.
- A raw entity built from its own metadata with both an `IDPSSODescriptor` and
  an `SPSSODescriptor`, such as a proxy, now writes the first format of its own
  role wherever it writes its first configured NameID format: an issued
  `NameID`, an AuthnRequest `NameIDPolicy`, and a LogoutRequest or
  ManageNameIDRequest `NameID` without a format. Before, it wrote the first
  `NameIDFormat` of the entity, whichever role it was in. To keep a format,
  list it first in the `NameIDFormat` elements of that role.

**Upgrade:** ask the peer to list `urn:oasis:names:tc:SAML:2.0:protocol` in the
`protocolSupportEnumeration` of its SAML 2.0 role and to publish its role
elements in the metadata namespace. An element written without a prefix needs
`xmlns="urn:oasis:names:tc:SAML:2.0:metadata"` on it or on an ancestor:

```xml
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    ...
  </IDPSSODescriptor>
</EntityDescriptor>
```

## 5.7 Expect padded endpoint attributes in peer metadata to be read

**Affects:** metadata parsed with `IdpMetadata`, `SpMetadata`,
`IdpDescriptor`, `SpDescriptor`, `IdentityProvider::from_metadata`, or
`ServiceProvider::from_metadata` that writes leading, trailing, or repeated
whitespace in an endpoint attribute. See
[metadata trust](../../conformance/metadata-and-replay.md#metadata-trust).

**Now:** `SingleSignOnService`, `ArtifactResolutionService`, and
`ManageNameIDService` collapse whitespace in `Binding`, `Location`,
`ResponseLocation`, and `index`, as `SingleLogoutService` and
`AssertionConsumerService` already did.

| Peer metadata | Before | Now |
| --- | --- | --- |
| Padded `Binding` on `SingleSignOnService` | `get_single_sign_on_service` returned `None` | Endpoint returned, trimmed |
| Padded `Location` on these three endpoints | Untrimmed URL returned and used | Trimmed URL returned, sent to, and matched against a received `Destination` |
| `ArtifactResolutionService` `index` with surrounding whitespace | `SamlError::Invalid` | Read as its number |
| `ArtifactResolutionService` whose `Binding` or `Location` is only whitespace | Whitespace returned | `SamlError::Invalid`, as for an empty value |
| `SingleSignOnService` or `ManageNameIDService` whose `Location` is only whitespace | Whitespace returned as the URL | Skipped for requests. A `ManageNameIDService` response still goes to a non-empty `ResponseLocation` |
| Namespace-qualified attribute such as `x:Location` | Read by its local name | Not read. An `ArtifactResolutionService` with only the qualified attribute returns `SamlError::Invalid`; the other two are skipped |

**Upgrade:** compare a returned endpoint with the trimmed string. Ask a peer
whose endpoints use a whitespace-only or qualified `Binding` or `Location` to
publish the unqualified attribute with its URI.
