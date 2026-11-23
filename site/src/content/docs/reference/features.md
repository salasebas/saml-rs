---
title: "Cargo features"
description: "The default feature turns signing and encryption on. Turn it off when you want messages without cryptography. The optional `serde` feature serializes pending snapshots."
---

The default feature turns signing and encryption on. Turn it off when you want messages without cryptography. The optional `serde` feature serializes pending snapshots.

```toml
[features]
default = ["crypto-bergshamra"]
crypto-bergshamra = [
    "crypto-rustcrypto",
    "crypto-legacy-algorithms",
    "crypto-post-quantum",
    "crypto-pkcs11",
]
crypto-rustcrypto = ["dep:bergshamra", "bergshamra/rustcrypto"]
crypto-aws-lc = ["dep:bergshamra", "bergshamra/aws-lc"]
crypto-fips = ["dep:bergshamra", "bergshamra/fips"]
serde = ["dep:serde"]
```

With `default-features = false`, the crate still builds messages, parses metadata, and extracts fields. Signing, verification, and encryption return `SamlError::Unsupported`.

At most one of `crypto-rustcrypto`, `crypto-aws-lc`, and `crypto-fips` can be selected. Combinations are rejected at compile time. AWS-LC and FIPS are selected with the default features off.

`crypto-legacy-algorithms`, `crypto-post-quantum`, and `crypto-pkcs11` forward bergshamra capabilities. They do not select a provider. The default `crypto-bergshamra` feature enables those capabilities together with RustCrypto.

Bergshamra supports AWS-LC and FIPS on Linux x86_64 and aarch64. This repository's provider tests run on Linux x86_64.

`crypto-fips` means the selected AWS-LC provider attested FIPS mode. It does not certify the consuming binary or deployment. FIPS policy rejects algorithms outside its approved set, including SHA-1 `RSA_OAEP_MGF1P` key transport and both signing and verifying `RSA_SHA1`. Non-FIPS AWS-LC still verifies inbound RSA-SHA1 Redirect and XML-DSig signatures.

Custom algorithm URIs are listed in bergshamra's [provider capabilities](https://github.com/kushaldas/bergshamra/blob/v0.12.0/docs/provider-capabilities.md). How to select a provider is [Crypto provider](../guides/crypto-provider.md).

## Serialize pending snapshots with `serde`

The `serde` feature is off by default. It implements `Serialize` and `Deserialize` for the three pending snapshot types, and for no other type:

| Snapshot | Returned by |
| --- | --- |
| `PendingAuthnRequestSnapshot` | `PendingAuthnRequest::snapshot` |
| `PendingLogoutRequestSnapshot` | `PendingLogoutRequest::snapshot` |
| `PendingManageNameIdRequestSnapshot` | `PendingManageNameIdRequest::snapshot` |

```sh
cargo add saml-rs --features serde
```

```rust
store.set(key, serde_json::to_string(&started.pending.snapshot())?)?;

let stored = store.get(key)?;
let pending = PendingAuthnRequest::from_snapshot(serde_json::from_str(&stored)?)?;
```

`store`, `key`, and `started` come from your application. The block is the shape of the calls, not a file that compiles alone. Deserializing checks only the shape of the data. `from_snapshot` checks the values, as it does for a snapshot built with `new`.

### Stored format

A `PendingAuthnRequestSnapshot` in JSON:

```json
{
  "request_id": "_request123",
  "relay_state": "return-to-cart",
  "idp_entity_id": "https://idp.example.com/metadata",
  "acs_binding": "post",
  "acs_url": "https://sp.example.com/acs",
  "acs_index": null,
  "acs_is_default": false,
  "required_authn_context_class_refs": [],
  "required_authn_context_decl_refs": []
}
```

Each snapshot stores these fields:

| Field | JSON value | Snapshots | On read |
| --- | --- | --- | --- |
| `request_id` | String | All | Required |
| `relay_state` | String, or `null` when the request carried no RelayState. `""` is an empty RelayState | All | Optional, absent reads as `None` |
| `idp_entity_id` | String | AuthnRequest | Required |
| `peer_entity_id` | String | LogoutRequest, ManageNameIDRequest | Required |
| `acs_binding` | Binding short name | AuthnRequest | Required |
| `acs_url` | String | AuthnRequest | Required |
| `acs_index` | Integer or `null` | AuthnRequest | Optional, absent reads as `None` |
| `acs_is_default` | Boolean | AuthnRequest | Optional, absent reads as `false` |
| `required_authn_context_class_refs` | Array of strings | AuthnRequest | Optional, absent reads as `[]` |
| `required_authn_context_decl_refs` | Array of strings | AuthnRequest | Optional, absent reads as `[]` |
| `request_binding` | Binding short name | LogoutRequest | Required |
| `not_on_or_after` | String or `null` | LogoutRequest | Optional, absent reads as `None` |

The format follows these rules in JSON, and in any other format that stores field names:

1. Field names are stable. They are the Rust field names, and they are what your session store holds.
2. Serializing writes every field. An absent optional value is written as `null`, `false`, or `[]`.
3. Deserializing requires the fields marked Required. An optional field may be absent. It then reads as `None`, `false` for `acs_is_default`, or `[]` for the authentication context lists.
4. Deserializing ignores a field this release does not know, so data written by a newer release still reads.
5. A field that a later release adds is optional on read. When it is absent, the crate behaves as it did before the field existed.
6. `snapshot` writes a binding as the short name that `Binding::short_name` returns: `post`, `redirect`, `simpleSign`, `artifact`, or `soap`. `from_snapshot` also reads a binding URN.

A positional format, such as bincode or postcard, stores no field names. Rules 3 to 5 do not hold there: a stored snapshot stops reading when a release adds a field. Store snapshots in a format that stores field names when they must survive an upgrade.

The stored form has no type tag, and one kind of snapshot can read as another: a LogoutRequest snapshot also reads as a ManageNameIDRequest snapshot. Store each kind of snapshot under its own key.

### Keep the stored snapshot unchanged

The finish operation checks the response against the pending state you pass it: the request ID, the peer entity ID, the RelayState, and for SSO the assertion consumer service and any required authentication context. It trusts that state. The stored snapshot must come back unchanged and stay tied to the browser session that started the request. Keep it in server-side session storage. If the browser carries it, for example in a cookie, authenticate the value so that a changed snapshot is refused. A snapshot holds no key material.

During a rolling upgrade or rollback, an older release ignores `required_authn_context_class_refs` and `required_authn_context_decl_refs` when reading stored JSON and will finish the login without enforcing them. Upgrade every instance that can finish a login before enabling `StartSso::require_exact_authn_context`, and drain or invalidate pending step-up logins before rolling back.
