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

S3 + CloudFront, provisioned by `platform/terraform/envs/dev/site.tf`. Upload is
out-of-band:

```sh
npm run build
aws s3 sync dist/ s3://<bucket> --delete
aws cloudfront create-invalidation --distribution-id <id> --paths '/*'
```

`astro.config.mjs` sets `site` to the apex domain (the CloudFront alias) and
leaves `base` unset for a root deploy. Layout and component links use
`import.meta.env.BASE_URL` and survive a `base` change, but absolute internal
links inside the markdown content (`/projects/...`, `/guide/...`) assume a root
deploy — prefix them if you ever serve from a subpath.
