// @ts-check
import { defineConfig } from 'astro/config';

// Deployed to S3 + CloudFront under the apex domain — see
// platform/terraform/envs/dev/site.tf (`aliases = [var.domain, "www.…"]`).
// `site` is the canonical origin: keep it in sync with that domain, because a
// sitemap or <link rel="canonical"> added later reads it. All internal links
// use import.meta.env.BASE_URL, so a subpath deploy only needs `base` set.
export default defineConfig({
  site: 'https://iammeridian.cc',
  output: 'static',
});
