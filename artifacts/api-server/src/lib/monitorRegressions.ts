/**
 * Which of a monitored scan's findings are new since the previous scan, by fingerprint. The scan's
 * own notes ("Scan started from an error response", "Active security testing was skipped") are not
 * findings about the site (see scanNotes.ts), so one that appears is not a regression and must not
 * raise an alert, a stored regression row or a webhook.
 */
import { findingFingerprint } from "./fingerprint";
import { splitScanNotes } from "./scanNotes";

type Fingerprinted = { category: string; name: string; evidence?: string | null };

export function findRegressions<T extends Fingerprinted>(vulnerabilities: readonly T[], previous: ReadonlySet<string>): T[] {
  return splitScanNotes(vulnerabilities).findings.filter(
    (v) => !previous.has(findingFingerprint(v.category, v.name, v.evidence)),
  );
}
