// @ts-check
import { defineConfig } from 'astro/config';

// Deploy targets:
//  - S3 + CloudFront (pending AWS credentials): leave `base` unset, `site` is
//    the CloudFront/custom domain.
//  - GitHub Pages (works today): if publishing to
//    https://aikazzh.github.io/portfolio/, set base: '/portfolio' and
//    site: 'https://aikazzh.github.io'. All internal links use
//    import.meta.env.BASE_URL so they survive a base-path change.
export default defineConfig({
  site: 'https://aikazzh.github.io',
  // base: '/portfolio',
  output: 'static',
});
