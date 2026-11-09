# saml-rs docs site

The public guides at [samlrs.vercel.app](https://samlrs.vercel.app), built with [Starlight](https://starlight.astro.build).

```bash
pnpm install
pnpm dev      # http://localhost:4321
pnpm build    # writes dist/, with the search index, sitemap, and llms.txt
pnpm preview  # serves dist/
```

Pages are Markdown in `src/content/docs/`. The sidebar is in `astro.config.mjs`. The theme is `src/styles/custom.css`.

Vercel builds this directory from the `vercel.json` at the repository root.
