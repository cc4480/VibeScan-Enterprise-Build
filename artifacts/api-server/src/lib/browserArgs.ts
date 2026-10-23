/**
 * Chromium launch flags, in one place because two modules launch browsers.
 *
 * browser.ts (SPA rendering) had the full set. scanCredentials.ts (form login)
 * called `chromium.launch({ headless: true })` with no flags at all, which is
 * a different browser in the ways that matter inside a container:
 *
 *   --no-sandbox / --disable-setuid-sandbox
 *       The container runs as the unprivileged `node` user with no
 *       CAP_SYS_ADMIN, so Chromium's sandbox cannot initialise and the launch
 *       fails outright.
 *
 *   --disable-dev-shm-usage
 *       Chromium writes to /dev/shm, which Docker gives 64 MB by default.
 *       docker-compose.yml raises it for the scanner, but a managed platform
 *       (Railway, Fly, Render) gives no control over it at all, so the flag is
 *       the only reliable fix there.
 *
 * The consequence of the mismatch was quiet in the worst way: form login caught
 * its own launch failure, logged "Headless browser unavailable", returned null,
 * and let the scan continue — unauthenticated, against an app the customer
 * supplied credentials for, reporting a clean bill of health for pages it never
 * saw. Exactly the failure the session-loss detection exists to prevent,
 * arriving through a door nobody was watching.
 *
 * This module deliberately imports nothing. scanCredentials.ts loads Playwright
 * lazily so the web bundle stays free of it, and importing browser.ts to reach
 * these flags would undo that.
 */

export const CHROMIUM_ARGS: readonly string[] = [
  "--no-sandbox",
  "--disable-setuid-sandbox",
  "--disable-dev-shm-usage",
  "--disable-gpu",
  "--disable-background-networking",
  "--disable-sync",
  "--no-first-run",
  "--disable-extensions",
  "--disable-default-apps",
  "--disable-component-update",
  "--disable-client-side-phishing-detection",
  "--disable-popup-blocking",
  "--no-zygote",
];

/** The flags that switch Chromium's sandbox off. Chromium's own sandbox is the layer meant to contain a renderer exploit. */
export const NO_SANDBOX_FLAGS: readonly string[] = ["--no-sandbox", "--disable-setuid-sandbox", "--no-zygote"];

/** The launch flags with the sandbox left on (--no-zygote only works without it). */
export const SANDBOXED_ARGS: readonly string[] = CHROMIUM_ARGS.filter((a) => !NO_SANDBOX_FLAGS.includes(a));

/**
 * CHROMIUM_SANDBOX=true asks for the sandbox. It needs the container to allow user namespaces (or a
 * seccomp profile that does) and an unprivileged user, which not every platform grants; see launchChromium.
 */
export function sandboxRequested(): boolean {
  return process.env["CHROMIUM_SANDBOX"] === "true";
}
