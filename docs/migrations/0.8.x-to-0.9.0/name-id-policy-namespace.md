# Honor the requested NameID namespace

[How to upgrade from 0.8 to 0.9](README.md)

This change affects `IdentityProvider::respond_sso` and
`IdentityProvider::respond_sso_artifact`. If the request's `NameIDPolicy`
sets `SPNameQualifier` and its `Format` is omitted or `unspecified`, the
issued `NameId` must belong to the requested namespace. A mismatch returns
`SamlError::Invalid` before the IdP issues a response.

Read the qualifier with `request.message().name_id_policy()` and
`NameIdPolicy::sp_name_qualifier`. Use trusted affiliation metadata or
local federation configuration to authorize the requesting SP. Once you
authorize it, look up the principal's identifier in the requested
namespace and supply that namespace on the `NameId`.

```diff
-let name_id = NameId::persistent(direct_sp_pseudonym)?;
+let name_id = NameId::persistent(affiliation_pseudonym)?
+	.with_sp_name_qualifier(authorized_affiliation);
```

For a persistent or pairwise transient identifier scoped to the direct
recipient, you can omit the qualifier when the request leaves the format
open. If you cannot satisfy the policy, [send a failure outcome](name-id-policy.md#return-an-error-to-the-requester).
