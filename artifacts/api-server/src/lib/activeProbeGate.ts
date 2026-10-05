/**
 * THE single decision for whether ACTIVE offensive probes may run against a
 * target. Centralised deliberately: every entry point that can start a scan
 * must gate identically, and the alternative — each route re-implementing the
 * check — is how one path ends up unguarded without anyone noticing.
 *
 * Active probes are allowed when EITHER:
 *   - the operator has explicitly unlocked this instance, via
 *     ALLOW_UNVERIFIED_ACTIVE_PROBES (any environment) or
 *     DEV_SKIP_DOMAIN_VERIFICATION (non-production only); or
 *   - the user has proven ownership of the target's domain, by DNS TXT record
 *     or a well-known file, and the proof was last seen within
 *     VERIFICATION_VALID_DAYS. A verification that stops being re-proved lapses
 *     (see lib/domainReverify.ts for the job that keeps live ones fresh), so a
 *     domain that is sold or abandoned does not stay open to its previous owner.
 *
 * With neither, only passive checks run. That is the control which stops this
 * platform being used as an anonymous attack proxy, so it fails closed: any
 * error looking up the verification is treated as "not verified".
 */
import { db, domainVerificationsTable } from "@workspace/db";
import { and, eq, gt, type SQL } from "drizzle-orm";
import { extractDomain, verificationCutoff } from "./domainVerify";
import { logger } from "./logger";

/** Operator override. Intended for self-hosted installs scanning their own estate. */
function allowUnverifiedActiveProbes(): boolean {
  return process.env.ALLOW_UNVERIFIED_ACTIVE_PROBES === "true";
}

/**
 * Development override. Guarded on NODE_ENV as well as the flag, so setting it
 * in a production environment by accident does not silently open the gate.
 */
function devSkipDomainVerification(): boolean {
  return (
    process.env.DEV_SKIP_DOMAIN_VERIFICATION === "true" &&
    process.env.NODE_ENV !== "production"
  );
}

/**
 * "This verification is still valid", as a where-clause fragment. Done in SQL,
 * not on a fetched row, so no caller can read `verified_at IS NOT NULL` and
 * forget the expiry. A NULL verified_at compares false, so this also covers
 * "has been verified at all". Every query that treats a domain as verified
 * (this gate, the badge issuer, the MCP listing) uses it.
 */
export function verificationIsCurrent(now: Date = new Date()): SQL {
  return gt(domainVerificationsTable.verifiedAt, verificationCutoff(now));
}

export async function activeProbesUnlocked(userId: string, targetUrl: string): Promise<boolean> {
  if (allowUnverifiedActiveProbes() || devSkipDomainVerification()) return true;

  let domain: string;
  try {
    domain = extractDomain(targetUrl);
  } catch {
    return false;
  }

  try {
    const [row] = await db
      .select({ id: domainVerificationsTable.id })
      .from(domainVerificationsTable)
      .where(
        and(
          eq(domainVerificationsTable.userId, userId),
          eq(domainVerificationsTable.domain, domain),
          verificationIsCurrent(),
        ),
      )
      .limit(1);
    return Boolean(row);
  } catch (err) {
    // Failing open here would mean a database blip turns the scanner into the
    // exact thing this gate exists to prevent.
    logger.error({ err, userId, domain }, "Domain verification lookup failed; denying active probes");
    return false;
  }
}
