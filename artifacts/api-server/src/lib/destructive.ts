/**
 * Destructive-action guard.
 *
 * An unauthenticated scan mostly bounces off action endpoints: the app either
 * hides them or rejects the request. With a session attached that protection is
 * gone, and a crawler following "Delete account" — or an injection probe firing
 * payloads at /account/delete — does real damage to a real customer's data.
 *
 * Badly built apps perform destructive actions on GET, which is itself a
 * finding, but it is not one worth confirming by triggering it.
 *
 * The guard errs toward skipping. Missing a finding on /users/deleted is a poor
 * trade against emptying someone's account, so a page whose URL merely reads as
 * destructive is skipped even when it is harmless.
 */

// Verbs that suggest the URL performs an action rather than showing a page.
// Substring matching, not word boundaries: /doDelete and /deleteAll should both
// be caught, and over-blocking is the safe direction.
const DESTRUCTIVE_VERBS = [
  // Removal
  "delete", "destroy", "remove", "erase", "wipe", "purge", "drop", "truncate",
  "clear", "empty", "trash", "discard",
  // Account and access lifecycle
  "deactivate", "disable", "suspend", "ban", "block", "revoke", "unsubscribe",
  "cancel", "terminate", "close-account", "closeaccount", "unregister",
  "uninstall", "leave", "resign", "withdraw",
  // Session — following one of these ends the scan's own session
  "logout", "log-out", "signout", "sign-out",
  // State changes that are hard to undo
  "reset", "restore", "rollback", "revert", "archive", "unpublish", "retract",
  "transfer", "merge", "migrate", "rotate", "regenerate",
  // Payment
  "refund", "chargeback", "unsubscribe-billing",
];

const VERB_PATTERN = new RegExp(DESTRUCTIVE_VERBS.join("|"), "i");

/**
 * True when a URL should not be requested during a scan.
 *
 * Checks the path *and* the query string: an endpoint like
 * `/account?action=delete` carries its verb in the query, and the path alone
 * would look harmless.
 */
export function isDestructiveUrl(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    // An unparseable URL is not worth requesting either.
    return true;
  }

  if (VERB_PATTERN.test(decodeSafely(parsed.pathname))) return true;

  // Query values as well as keys: ?action=delete and ?delete=1 both matter.
  for (const [key, value] of parsed.searchParams) {
    if (VERB_PATTERN.test(decodeSafely(key)) || VERB_PATTERN.test(decodeSafely(value))) {
      return true;
    }
  }

  return false;
}

/** Percent-decoding so an encoded verb cannot slip past the pattern. */
function decodeSafely(input: string): string {
  try {
    return decodeURIComponent(input);
  } catch {
    return input;
  }
}

/**
 * Filter a list of URLs, returning the safe ones and what was skipped.
 *
 * Callers surface the skipped list so a user can see the scan deliberately left
 * parts of the app alone, rather than wondering why coverage looks thin.
 */
export function partitionDestructive(urls: string[]): { safe: string[]; skipped: string[] } {
  const safe: string[] = [];
  const skipped: string[] = [];
  for (const url of urls) {
    if (isDestructiveUrl(url)) skipped.push(url);
    else safe.push(url);
  }
  return { safe, skipped };
}
