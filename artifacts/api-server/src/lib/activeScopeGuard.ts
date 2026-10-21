/**
 * Keeps active probing on the host the requester proved they own.
 *
 * The ownership check (activeProbeGate.ts) looks at the hostname the requester TYPED. The scan then
 * runs its probes against the URL it ended up at after redirects. Without this, someone who verifies
 * a domain they own can have it answer 302 to a stranger's site and the injection, path-traversal and
 * API tests are then sent to the stranger. So when the final host differs from the submitted one,
 * active probing continues only if that final host is the submitted host's own subdomain or one the
 * requester has verified too. Anything else stays passive, and the report says why. A subdomain of the
 * submitted host counts as "else": it is verified by the same check as any other host.
 */

export interface ActiveScopeDecision {
  allowed: boolean;
  /** Set when active probing was withdrawn: the host the scan ended up on. */
  redirectedTo?: string;
}

/** Answers whether the requester has verified the host of this URL. */
export type VerifyHost = (url: string) => Promise<boolean>;

function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

export async function activeProbesStillAllowed(
  submittedUrl: string,
  finalUrl: string,
  verifyHost?: VerifyHost,
): Promise<ActiveScopeDecision> {
  const submitted = hostOf(submittedUrl);
  const final = hostOf(finalUrl);
  // A URL we cannot read is not one we can show is the verified host: fail closed.
  if (!submitted || !final) return { allowed: false, redirectedTo: final ?? finalUrl };
  // The submitted host itself was verified by the caller. A subdomain of it was not: "a.myhost.com" can be
  // another party's tenant under the same parent, so it needs its own verification like any other host.
  if (final === submitted) return { allowed: true };
  if (verifyHost) {
    try {
      if (await verifyHost(finalUrl)) return { allowed: true };
    } catch {
      // Could not tell: treated as not verified.
    }
  }
  return { allowed: false, redirectedTo: final };
}
