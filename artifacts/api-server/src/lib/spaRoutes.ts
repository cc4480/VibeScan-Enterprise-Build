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
  /^\/domains\/?$/,
  /^\/settings\/?$/,
  /^\/privacy\/?$/,
  /^\/terms\/?$/,
  /^\/sign-in\/?$/,
  /^\/register\/?$/,
  /^\/forgot-password\/?$/,
  /^\/reset-password\/?$/,
  /^\/verify-email\/?$/,
];

/** Whether the SPA shell should be served for this path. */
export function isSpaRoute(path: string): boolean {
  return SPA_ROUTES.some((re) => re.test(path));
}
