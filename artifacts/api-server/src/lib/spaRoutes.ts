/**
 * The paths the client router actually renders.
 *
 * Extracted from app.ts so it can be tested directly: the production SPA
 * fallback only runs when NODE_ENV is production and a built bundle is on
 * disk, which is exactly the condition a test does not have. The list is also
 * the part most likely to drift — a route added to the client and missed here
 * works perfectly in development, where Vite serves the shell for everything,
 * and 404s only once deployed.
 *
 * Keep in sync with the <Route> list in artifacts/vibescan/src/App.tsx.
 */
export const SPA_ROUTES: RegExp[] = [
  /^\/$/,
  /^\/dashboard\/?$/,
  /^\/scan\/?$/,
  /^\/scan\/[A-Za-z0-9_-]+\/?$/,
  /^\/report\/[A-Za-z0-9_-]+\/?$/,
  /^\/share\/[A-Za-z0-9_-]+\/?$/,
  /^\/monitor\/?$/,
  /^\/learn\/?$/,
  // The scanner's own User-Agent points every scanned site at /bot. If it is
  // missing here the shell 404s on a direct hit — which is the state that
  // prompted this page to be built in the first place.
  /^\/bot\/?$/,
  /^\/domains\/?$/,
  /^\/settings\/?$/,
  /^\/feedback\/?$/,
  /^\/about\/?$/,
  /^\/privacy\/?$/,
  /^\/terms\/?$/,
  /^\/sign-in\/?$/,
  /^\/register\/?$/,
  /^\/forgot-password\/?$/,
  /^\/reset-password\/?$/,
  /^\/verify-email\/?$/,
  // Where an AI editor sends the person to approve a connection (lib/oauthConsent.ts).
  /^\/oauth\/authorize\/?$/,
  // A trust page. The domain is the address, so it has dots, which is why this is not the generic id pattern used above;
  // only a well-formed domain name gets the shell.
  /^\/trust\/[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\/?$/,
  // The page an invitation email links to, and the reports a teammate was invited to read.
  /^\/team\/accept\/?$/,
  /^\/team\/shared\/[A-Za-z0-9_-]+\/?$/,
];

/** /learn/<id>: one page per documented check. The ids come from the frontend build. */
const LEARN_CHECK = /^\/learn\/([a-z0-9-]+)\/?$/;

let learnCheckIds: ReadonlySet<string> | null = null;

/**
 * The ids the frontend build says have a page (prerender/checks.json). A path
 * naming any other id is a 404 here, not the app shell: otherwise every
 * /learn/<anything> would be a 200, which is the soft-404 shape the list above
 * exists to prevent. Null (the build did not write the list) lets any well-formed
 * id through, so the pages keep working and the client shows its own not-found.
 */
export function setLearnCheckIds(ids: Iterable<string> | null): void {
  learnCheckIds = ids === null ? null : new Set(ids);
}

/** Whether the SPA shell should be served for this path. */
export function isSpaRoute(path: string): boolean {
  const check = LEARN_CHECK.exec(path);
  if (check) return learnCheckIds === null || learnCheckIds.has(check[1]!);
  return SPA_ROUTES.some((re) => re.test(path));
}
