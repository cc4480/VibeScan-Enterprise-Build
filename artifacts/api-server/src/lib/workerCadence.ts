import { and } from "drizzle-orm";

/**
 * How soon a pending nextScanAt has to be to count as a deliberate follow-up
 * rather than an anti-double-pick sentinel.
 *
 * The CVE job sets nextScanAt = now + 24h before its scan runs, and that must
 * survive. Both the sweep and subscription creation ALSO write a placeholder —
 * now + 3 days — whose only job is to stop the next sweep tick picking a
 * subscription whose scan is still in flight. Those two intents were
 * indistinguishable, and the placeholder always won.
 */
const FOLLOW_UP_WINDOW_MS = 48 * 60 * 60 * 1000;

/**
 * Decide the next scan time after a completed scan.
 *
 * Exported for tests. The bug this replaces made the entire published cadence
 * a fiction: the sweep wrote a 3-day placeholder, the worker saw 3 days was
 * sooner than an A grade's 14 and "preserved" it, so every A and B/C site was
 * rescanned every 3 days instead of 14 or 7 — roughly five times the intended
 * scanning, and a claim on the marketing page that was never true. It shipped
 * in the same commit as the cadence it broke (e0a9372, 2026-05-31) and the
 * cadence tests never caught it, because they test the interval function in
 * isolation and nothing tested the two halves together.
 */
export function resolveNextScanAt(
  pending: Date | null,
  gradeCadenceAt: Date,
  completedAt: Date,
): Date {
  if (!pending) return gradeCadenceAt;
  if (pending <= completedAt) return gradeCadenceAt;

  // Only a genuinely imminent follow-up wins. A placeholder days out does not,
  // however much sooner than the grade cadence it happens to be.
  const isFollowUp = pending.getTime() - completedAt.getTime() <= FOLLOW_UP_WINDOW_MS;
  return isFollowUp && pending < gradeCadenceAt ? pending : gradeCadenceAt;
}
