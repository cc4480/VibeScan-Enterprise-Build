/**
 * What the "I fixed this: check it" control says. The server decides the verdict
 * (lib/scanDiff.ts verdictFor); this only words it, and never words more than the
 * server established. In particular "not_rechecked" is never shown as fixed.
 */

export type Verdict = "pending" | "fixed" | "still_present" | "not_rechecked" | "failed";

export interface VerificationStatus {
  findingId: string;
  verdict: Verdict;
  scanId: string;
  createdAt: string;
  completedAt: string | null;
}

export type Tone = "idle" | "busy" | "good" | "warn" | "neutral";

export interface VerifyView {
  tone: Tone;
  /** The main line. */
  label: string;
  /** What it does and does not mean. */
  detail: string;
  /** The action offered, or null when nothing more to do. */
  action: string | null;
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
export function shortDate(iso: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}`;
}

export function viewOf(status: VerificationStatus | undefined, starting: boolean): VerifyView {
  if (starting || status?.verdict === "pending") {
    return { tone: "busy", label: "Checking your fix…", detail: "Re-scanning the site. This takes about a minute and does not use a scan.", action: null };
  }
  const when = shortDate(status?.completedAt ?? null);
  switch (status?.verdict) {
    case "fixed":
      return { tone: "good", label: `Fixed and verified${when ? ` (${when})` : ""}`, detail: "The test that finds this ran again and no longer reports it.", action: null };
    case "still_present":
      return { tone: "warn", label: `Still present when re-checked${when ? ` (${when})` : ""}`, detail: "The scan found it again. If you have just deployed, give it a minute and check again.", action: "Check again" };
    case "not_rechecked":
      return {
        tone: "neutral",
        label: `Could not be re-checked${when ? ` (${when})` : ""}`,
        detail: "It is gone from the new scan, but the test that finds it did not run this time, so this is not confirmed as fixed. Verify your domain to run it.",
        action: "Check again",
      };
    case "failed":
      return { tone: "neutral", label: "The check did not finish", detail: "Nothing was changed. Try again in a moment.", action: "Try again" };
    default:
      return { tone: "idle", label: "Fixed this?", detail: "Re-check just this finding. It does not use a scan.", action: "Check my fix" };
  }
}

/** True while any verification is still running, so the page keeps polling. */
export function anyPending(list: VerificationStatus[] | undefined): boolean {
  return Boolean(list?.some((v) => v.verdict === "pending"));
}

/** The message for a refusal from the server (its own words, with a fallback). */
export function refusalMessage(err: unknown): string {
  const data = (err as { data?: { error?: unknown } } | null)?.data;
  return typeof data?.error === "string" ? data.error : "That did not start. Please try again.";
}
