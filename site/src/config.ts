// Central link configuration. When the platform is deployed to AWS, fill in
// the demo URLs here — nothing else in the site needs to change.

export const GITHUB_REPO = 'https://github.com/aigerimzhalgasbekova/meridian';

/** Path within the monorepo → full GitHub URL (tree = directory, blob = file). */
export const repoTree = (path: string) => `${GITHUB_REPO}/tree/main/${path}`;
export const repoFile = (path: string) => `${GITHUB_REPO}/blob/main/${path}`;

/**
 * Live demo URLs per project. `null` = deployment pending (no AWS account
 * yet — see /guide/running-it). Swap in real URLs when Terraform applies.
 */
export const demoUrls: Record<string, string | null> = {
  keysmith: null,
  idp: null,
  sessiond: null,
  sentinel: null,
  bridge: null,
  portal: null,
  console: null,
};

export const AUTHOR = {
  name: 'aikazzh',
  github: 'https://github.com/aigerimzhalgasbekova',
};
