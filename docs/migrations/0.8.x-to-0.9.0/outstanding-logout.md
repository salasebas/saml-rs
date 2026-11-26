# Record the issuer of outstanding logouts

If your SP constructs an `OutstandingLogout`, pass the issuer from the same
authenticated `LogoutRequest` as its `NameID`, session indexes, and deadline.
Read the issuer after `ServiceProvider::receive_slo` succeeds.

```diff
 let request = received.message();
-let outstanding = OutstandingLogout::try_new(name_id, indexes, deadline)?;
+let outstanding = OutstandingLogout::try_new(request.issuer().clone(), name_id, indexes, deadline)?;
```

If your application persists these fields, store the authenticated issuer
with them and restore it with the rest of the record. For older records,
recover the issuer from trusted data associated with the original logout. If
you cannot establish the issuer of an older record, discard that record.

Both SSO methods that take an outstanding logout now compare the assertion
issuer and the full `NameID`, including `NameQualifier`, `SPNameQualifier`,
and `SPProvidedID`. An omitted `Format` matches `unspecified`. Preserve the
complete `NameId` from the accepted request when writing and restoring the
record.
