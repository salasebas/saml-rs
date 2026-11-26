# saml-rs docs site

The public guides at [samlrs.vercel.app](https://samlrs.vercel.app), built with [Starlight](https://starlight.astro.build).

```bash
pnpm install
pnpm dev      # Stable at http://localhost:4321/
pnpm dev:next # Next at http://localhost:4321/next/
pnpm build    # builds both versions and checks their routes and links
pnpm preview  # serves both versions from dist/
```

Stable uses the existing public URLs. Edit `versions/stable/docs/` to correct a guide for the published crate. The first copy came from the `v0.8.0` tag. Edit `src/content/docs/` for API changes on `main`, which appear under `/next/`.

The site generates conformance pages from `versions/stable/conformance/` for Stable and `../docs/conformance/` for Next. Edit the records in those directories. A `README.md` in the records directory supplies that version's conformance index. Each version keeps its record titles in `conformance.mjs` and its navigation in `sidebar.mjs` under `versions/`. The Next build fails when a `Code:` line in a record lists anything other than existing files under the repository's `src/`, each in backticks.

Vercel builds both versions from `main` using `vercel.json` at the repository root. Each version has its own search index, sitemap, and `llms.txt`.

## Promote a crate release to Stable

1. Confirm that the release is available on [crates.io](https://crates.io/crates/saml-rs). Use the matching release tag as the source for the next steps.
2. Copy the tag's `site/src/content/docs/` into `site/versions/stable/docs/` and its `docs/conformance/` into `site/versions/stable/conformance/`. Use the tag's `site/versions/next/` for the sidebar and conformance page titles. If the promoted records contain a `README.md`, remove any tracked `site/versions/stable/docs/reference/conformance.md` so the build can generate the index. Remove files from the old release that the new release no longer documents. Carry forward Stable corrections that still apply.
3. Set `stableVersion` in `site/src/docs-version.mjs`. In the Stable home page, import `FeatureGrid` from `../../../src/components/FeatureGrid.astro`. Replace installs from `main` with crates.io commands throughout the Stable copy. Keep the feature flags supported by the published crate. Point example and API links at the release tag and versioned docs.rs. Update the migration links and retain redirects for any public routes the release moved.
4. Update `site/scripts/check-docs.mjs` to check the published API and the current Next migration link. Run `pnpm build` from `site/` and open a PR. Vercel deploys the promoted docs when the PR merges.
