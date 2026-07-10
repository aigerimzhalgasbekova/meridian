// Central link configuration. When the platform is deployed to AWS, fill in
// the demo URLs here — nothing else in the site needs to change.

export const GITHUB_REPO = 'https://github.com/aigerimzhalgasbekova/meridian';

/** Path within the monorepo → full GitHub URL (tree = directory, blob = file). */
export const repoTree = (path: string) => `${GITHUB_REPO}/tree/main/${path}`;
export const repoFile = (path: string) => `${GITHUB_REPO}/blob/main/${path}`;

/**
 * Live demo URLs per project. `null` = no public endpoint: keysmith,
 * sessiond and sentinel are internal services by design — reachable only
 * inside the VPC, which is itself part of the story.
 */
export const demoUrls: Record<string, string | null> = {
  keysmith: null,
  idp: 'https://idp.iammeridian.cc/realms/demo/.well-known/openid-configuration',
  sessiond: null,
  sentinel: null,
  bridge: 'https://sso.iammeridian.cc/',
  portal: 'https://portal.iammeridian.cc/',
  console: 'https://console.iammeridian.cc/',
};

export const AUTHOR = {
  name: 'aikazzh',
  github: 'https://github.com/aigerimzhalgasbekova',
};
