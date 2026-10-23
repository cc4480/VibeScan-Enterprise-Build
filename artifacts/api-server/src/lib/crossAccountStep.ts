/**
 * The scanner's cross-account access-control step: decide whether the test has anything to run
 * on, get a second identity (the user's, or a disposable one made through the target's own signup
 * form), run accessControlProbe.ts, and record honestly what happened.
 *
 * This was inline in scanner.ts. Reviewers found that it:
 *   - created an account on the customer's system BEFORE knowing the probe could use it (the
 *     probe returns nothing when no crawled URL names a record, so the account was made for a
 *     test with nothing to do);
 *   - recorded "ran" for a probe that compared nothing, so the report said "all tests ran";
 *   - described a signup that WAS submitted (up to six of them) as "no form was found";
 *   - left no trace in the report of an account it had created on the customer's site;
 *   - had no test at all.
 *
 * Decisions are ordered so nothing is created unless every earlier condition holds.
 */
import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import type { ScanCredentials } from "./http";
import { attemptAutoSecondAccount } from "./autoSecondAccount";
import { accessControlCandidates, runAccessControlProbesDetailed } from "./accessControlProbe";
import { NOT_VERIFIED, type TestLedger } from "./testLedger";

const NAME = "cross-account access control (IDOR)";

export interface CrossAccountStepInput {
  allowActiveProbes: boolean;
  /** The scan's own signed-in identity. */
  primary?: ScanCredentials | undefined;
  /** A second identity the user supplied, if any. */
  secondary?: ScanCredentials | undefined;
  /**
   * Whether this scan may create a second account itself, through the target's public signup form.
   * Opt-in per scan: it submits a form on the customer's system, so it never happens unasked.
   */
  allowAutoAccount?: boolean;
  finalUrl: string;
  /** Pages the authenticated crawl reached. */
  pagesVisited: string[];
  ledger: TestLedger;
  /** Names of check groups that could not run; the scanner turns a non-empty list into a coverage finding. */
  unrunFamilies: string[];
}

function accountNotice(email: string, usable: boolean): ScanVulnerability {
  return {
    id: randomUUID(),
    name: usable
      ? "A disposable test account was created on your site during this scan"
      : "A disposable test account may have been created on your site by this scan",
    severity: "info",
    category: "Scan Coverage",
    description:
      "To test whether one signed-in user can read another user's records, the scan submitted your site's public signup " +
      "form once, with a throwaway address it made up. " +
      (usable
        ? "The signup gave the scan a working second session, which it used for the access-control comparison."
        : "The signup did not give the scan a working signed-in session, so the account, if it was created, was not used for anything.") +
      " This is not a finding about your site; it is here because a scan should not leave an account behind without saying so.",
    evidence:
      `Signup form submitted once as ${email}\n` +
      "The address is at example.com, a domain reserved so that it never delivers mail to anyone.",
    solution:
      `Delete the account registered as ${email} from your user records. This happened because "Create one for me" was chosen ` +
      "for this scan; to avoid it, supply a second test account of your own instead, or leave that option off.",
    confidence: 95,
  };
}

/** Why a scan that submitted a signup could not use the result, in words that do not claim nothing was tried. */
function attemptReason(a: { skippedReason?: string; submitted?: boolean; email?: string }): string {
  const why = a.skippedReason ?? "no second account available";
  return a.submitted
    ? `no second test account was supplied, and the automatic attempt submitted the target's signup form once (as ${a.email ?? "a throwaway address"}) without getting a usable signed-in account, so an account may exist on the target: ${why}`
    : `no second test account was supplied, and an automatic attempt to create one did not succeed: ${why}`;
}

export async function runCrossAccountStep(
  input: CrossAccountStepInput,
): Promise<ScanVulnerability[]> {
  const { ledger, primary } = input;

  if (!input.allowActiveProbes) {
    ledger.skip("active", NAME, NOT_VERIFIED);
    return [];
  }
  if (!primary) {
    ledger.skip("active", NAME, "needs sign-ins for two test accounts on the scan");
    return [];
  }

  // Before anything is created on the customer's system: is there a record to compare at all?
  const urls = [input.finalUrl, ...input.pagesVisited];
  if (accessControlCandidates(urls).length === 0) {
    ledger.skip(
      "active",
      NAME,
      "no URL naming a specific record (like /orders/123) was reached while signed in, so there was nothing to compare between two accounts",
    );
    return [];
  }

  const extra: ScanVulnerability[] = [];
  let secondary = input.secondary;
  let autoCreated = false;

  if (!secondary) {
    if (!input.allowAutoAccount) {
      ledger.skip(
        "active",
        NAME,
        "no second test account was supplied, and creating one automatically was not requested for this scan (opt-in only, because it submits the target's signup form)",
      );
      return [];
    }
    if (!primary.cookie) {
      ledger.skip(
        "active",
        NAME,
        "no second test account was supplied, and one made automatically through a signup form is a cookie session, which cannot be compared with a sign-in that uses headers rather than a cookie",
      );
      return [];
    }
    let made;
    try {
      made = await attemptAutoSecondAccount(input.finalUrl);
    } catch (err) {
      console.error("[scan] auto second-account creation failed", err);
      input.unrunFamilies.push(NAME);
      ledger.records.push({
        group: "active", name: NAME, status: "failed", findings: 0, durationMs: 0,
        reason: err instanceof Error ? err.message.slice(0, 200) : String(err).slice(0, 200),
      });
      return [];
    }
    if (made.submitted && made.email) extra.push(accountNotice(made.email, made.secondary !== null));
    if (!made.secondary) {
      ledger.skip("active", NAME, attemptReason(made));
      return extra;
    }
    secondary = made.secondary;
    autoCreated = true;
  }

  const findings = await ledger
    .trackOutcome(
      "active",
      NAME,
      runAccessControlProbesDetailed({ urls, primary, secondary, secondaryAutoCreated: autoCreated }).then((r) => ({
        findings: r.findings,
        ...(r.compared === 0
          ? { notTested: r.notTested ?? "nothing was compared: none of the record URLs could be read by the first account, or a request for the second account or the anonymous check did not complete" }
          : {}),
      })),
    )
    .catch((err: unknown) => {
      input.unrunFamilies.push(NAME);
      console.error("[scan] access control probes failed", err);
      return [] as ScanVulnerability[];
    });
  return [...extra, ...findings];
}
