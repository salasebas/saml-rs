# Replace collection helpers (unreleased)

If you call the collection helpers listed below, update those calls before
upgrading. This also applies to the `opensaml`, `samlify`,
and `samlet` compatibility crates, which re-export the same API.
Typed `Saml<Sp>` and `Saml<Idp>` operations need no changes.

## Replace collection helpers

These items are removed from `util`, including its compatibility-crate
re-exports:

| Removed item | Replacement |
| --- | --- |
| `OneOrMany::One(value)` | `vec![value]` |
| `OneOrMany::Many(values)` | `values` (a `Vec<T>`) |
| `OneOrMany::into_vec()` | Store a `Vec<T>` directly |
| `cast_array_opt(value)` | For `Option<Vec<T>>`, use `value.unwrap_or_default()` |
| `is_non_empty_array(items)` | `!items.is_empty()` |
| `verify_fields(field, meta_field)` | `!field.is_empty() && field.iter().all(\|value\| value == meta_field)` |
| `last(items)` | `items.last()` |

If an application needs a single-or-many input type, keep that type and its
conversion in the application. Preserve the empty-input mismatch when replacing
`verify_fields`.
