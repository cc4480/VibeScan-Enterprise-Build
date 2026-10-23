/**
 * Which alerts a user actually wants.
 *
 * Until now this was one boolean. The only way to stop a noisy alert was to
 * stop every alert — including the certificate expiring in seven days — so the
 * realistic user response to noise was to silence the thing that was supposed
 * to protect them. These let someone turn off one kind, or raise the floor,
 * and keep the rest.
 *
 * Two rules worth knowing before changing anything here:
 *
 *   1. Defaults reproduce today's behaviour exactly. Every opt-out defaults
 *      false and the severity floor defaults to "info", so nobody's
 *      notifications change until they choose to change them.
 *
 *   2. The email master switch does NOT silence webhooks. alertEmailsOptedOut
 *      is what the one-click List-Unsubscribe header toggles, and someone who
 *      unsubscribed their inbox has not asked us to stop posting to their
 *      team's Slack. Per-kind and severity preferences DO apply to both.
 */
import { db, usersTable } from "@workspace/db";
import { eq } from "drizzle-orm";

export type AlertKind =
  | "cve"
  | "regression"
  | "cert_expiry"
  | "scan_complete"
  // The hourly pulse check's two alerts. Separate kinds because downtime is the
  // one alert that can flap, and muting a site that drops a request every other
  // hour must not also mute "your HSTS header disappeared".
  | "availability"
  | "drift";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Channel = "email" | "webhook";

/** Ascending, so a higher index is more urgent. */
const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export interface NotificationPrefs {
  /** The master email switch — List-Unsubscribe. Email only, never webhooks. */
  emailOptedOut: boolean;
  optedOutKinds: Set<AlertKind>;
  minSeverity: Severity;
}

/** Today's behaviour: everything on, no floor. Used when a user has no row. */
export function defaultPrefs(): NotificationPrefs {
  return { emailOptedOut: false, optedOutKinds: new Set(), minSeverity: "info" };
}

/**
 * Normalise an arbitrary severity string to a known rank.
 *
 * Alert sources disagree on case — CVE severities arrive from NVD uppercase
 * ("CRITICAL"), scan findings are lowercase ("critical"). An unrecognised
 * value ranks as "critical" rather than "info": a severity we cannot read is
 * not a reason to silently drop the alert.
 */
export function normaliseSeverity(raw: string | null | undefined): Severity {
  if (!raw) return "critical";
  const lower = raw.toLowerCase();
  return (lower in SEVERITY_RANK ? lower : "critical") as Severity;
}

/**
 * The most urgent severity in a batch.
 *
 * A CVE alert and a regression alert each describe SEVERAL findings in one
 * message. The floor has to be applied to the worst of them: judging by the
 * first, or by the lowest, would throw away a mail containing a critical
 * because it also mentioned a low. An empty list ranks as "critical" for the
 * same reason unreadable severities do — never drop on ambiguity.
 */
export function highestSeverity(items: Array<{ severity?: string | null }>): Severity {
  if (items.length === 0) return "critical";
  let worst: Severity = "info";
  for (const item of items) {
    const s = normaliseSeverity(item.severity);
    if (SEVERITY_RANK[s] > SEVERITY_RANK[worst]) worst = s;
  }
  return worst;
}

/**
 * Whether one alert should be delivered on one channel.
 *
 * Pure, because this decides whether somebody hears that their certificate is
 * about to expire, and that should be testable without a database or a mailer.
 */
export function shouldNotify(
  prefs: NotificationPrefs,
  opts: { kind: AlertKind; severity?: string | null; channel: Channel },
): boolean {
  if (opts.channel === "email" && prefs.emailOptedOut) return false;
  if (prefs.optedOutKinds.has(opts.kind)) return false;

  // cert_expiry and scan_complete carry no severity — a days-remaining count
  // is not a severity, and treating its absence as "info" would hide expiry
  // warnings from anyone who raised their floor.
  if (opts.severity != null && opts.severity !== "") {
    const rank = SEVERITY_RANK[normaliseSeverity(opts.severity)];
    if (rank < SEVERITY_RANK[prefs.minSeverity]) return false;
  }

  return true;
}

/** Read a user's preferences, falling back to today's behaviour on any error. */
export async function notificationPrefs(userId: string): Promise<NotificationPrefs> {
  try {
    const [row] = await db
      .select({
        emailOptedOut: usersTable.alertEmailsOptedOut,
        cve: usersTable.notifyCveOptedOut,
        regression: usersTable.notifyRegressionOptedOut,
        certExpiry: usersTable.notifyCertExpiryOptedOut,
        scanComplete: usersTable.notifyScanCompleteOptedOut,
        availability: usersTable.notifyAvailabilityOptedOut,
        drift: usersTable.notifyDriftOptedOut,
        minSeverity: usersTable.notifyMinSeverity,
      })
      .from(usersTable)
      .where(eq(usersTable.id, userId))
      .limit(1);

    if (!row) return defaultPrefs();

    const optedOutKinds = new Set<AlertKind>();
    if (row.cve) optedOutKinds.add("cve");
    if (row.regression) optedOutKinds.add("regression");
    if (row.certExpiry) optedOutKinds.add("cert_expiry");
    if (row.scanComplete) optedOutKinds.add("scan_complete");
    if (row.availability) optedOutKinds.add("availability");
    if (row.drift) optedOutKinds.add("drift");

    return {
      emailOptedOut: row.emailOptedOut,
      optedOutKinds,
      minSeverity: normaliseSeverity(row.minSeverity),
    };
  } catch (err) {
    // Fails OPEN, like alertEmailsAllowed: an extra email is an annoyance, a
    // missed one is somebody not hearing their certificate expires.
    console.error("[notificationPrefs] Could not read preferences; allowing:", err);
    return defaultPrefs();
  }
}
