# site — the Meridian portfolio website

Static Astro site: home page with the architecture overview and project cards,
per-project pages (`/projects/<name>`), and the ten-chapter engineering guide
(`/guide`). No UI framework, hand-rolled CSS, system fonts, dark/light via
`prefers-color-scheme` with a toggle. The only client-side JavaScript is the
theme toggle.

## Develop

```sh
npm install
npm run dev        # http://localhost:4321
```

## Build & check

```sh
npm run build      # static output in dist/
npm run check      # astro check (TypeScript + template diagnostics)
npm run preview    # serve dist/ locally
```

## Content model

- `src/content/projects/*.md` — one file per project (card frontmatter + page body).
- `src/content/guide/*.md` — guide chapters, ordered by the `chapter` frontmatter field.
- `src/config.ts` — **all external URLs live here.** When the platform deploys
  to AWS, put each live demo URL into `demoUrls`; the "deploy pending" badges
  switch to demo links with no other edits.

Content accuracy rule: every claim on the site must trace to the repo — READMEs,
ADRs, threat models, or a test run. No invented features or metrics.

## Deploy

**S3 + CloudFront (target, pending AWS credentials):**

```sh
npm run build
aws s3 sync dist/ s3://<bucket> --delete
aws cloudfront create-invalidation --distribution-id <id> --paths '/*'
```

**GitHub Pages (works today):** the site builds with `base` unset for a
root-domain deploy. For `https://aikazzh.github.io/portfolio/`, edit
`astro.config.mjs`:

```js
export default defineConfig({
  site: 'https://aikazzh.github.io',
  base: '/portfolio',
});
```

Layout and component links use `import.meta.env.BASE_URL` and survive the base
change. Note: absolute internal links inside the markdown content
(`/projects/...`, `/guide/...`) assume a root deploy; for a subpath deploy,
prefix them or serve from a custom domain.
