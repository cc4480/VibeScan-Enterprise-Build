import { vuln, type ScanVulnerability, type RunScanAuth } from "./scannerTypes";
import { TestLedger, NOT_VERIFIED } from "./testLedger";
import { isOobConfigured } from "./oobServer";
import { collectFirstPartyJavaScript } from "./jsScanner";
import { extractSystemPromptText } from "./aiFeatureProbe";
import { runPromptInjectionProbeDetailed } from "./promptInjectionProbe";
import { runRaceConditionProbeDetailed } from "./raceConditionProbe";
import { collectApiSurface, runApiProbes } from "./apiProbe";
import { runSsrfProbes } from "./ssrfProbe";
import type { ApiEndpoint } from "./apiSurface";
import type { ObservedRequest } from "./apiRuntime";

/** Inputs to the active API stage: what discovery reads, and who the probes may act as. */
export interface ActiveStageInput {
  finalUrl: string;
  html: string;
  observedRequests: ObservedRequest[];
  allowActiveProbes: boolean;
  auth?: RunScanAuth;
  raceConditionTesting?: boolean;
  scanId: string | null;
  ledger: TestLedger;
  /** Appended to when a check group throws, so the report can say it was not completed. */
  unrunFamilies: string[];
}

/** API surface discovery and the active checks that depend on it (API probes, LLM injection, races, SSRF). */
export async function runActiveApiStage({
  finalUrl, html, observedRequests, allowActiveProbes, auth, raceConditionTesting, scanId, ledger, unrunFamilies,
}: ActiveStageInput): Promise<ScanVulnerability[]> {
  const vulnerabilities: ScanVulnerability[] = [];

  // ── API surface testing ────────────────────────────────────────────────────
  // Discovery reads the JS bundles, and the probes spend a few requests per
  // endpoint. On an API-first SPA this is the only path that finds anything at
  // all — the HTML carries no forms, links or parameters to collect.
  //
  // Each stage used to swallow its own failure with `.catch(() => [])`, the
  // same defect the coverage note above exists to catch on the passive probes
  // — a thrown error and a clean "nothing found" produced byte-identical
  // output. SSRF is the one that matters most here: its whole method is a
  // negative result ("no callback arrived"), so a failed OOB registration or a
  // network fault looked exactly like a target that is not vulnerable.
  if (!allowActiveProbes) {
    ledger.skip("active", "API surface discovery", NOT_VERIFIED);
    ledger.skip("active", "API endpoint testing (auth, injection, IDOR, mass assignment)", NOT_VERIFIED);
    ledger.skip("active", "SSRF (out-of-band callback)", NOT_VERIFIED);
    ledger.skip("active", "LLM prompt injection (system prompt extraction)", NOT_VERIFIED);
    ledger.skip("active", "race condition (one-time action)", NOT_VERIFIED);
  }
  if (allowActiveProbes) {
    const origin = new URL(finalUrl).origin;
    const discoveryStarted = Date.now();
    const endpoints = await collectApiSurface(origin, html, observedRequests)
      .then((found) => {
        ledger.records.push({
          group: "active", name: `API surface discovery (${found.length} endpoints)`, status: "ran",
          findings: 0, durationMs: Date.now() - discoveryStarted,
        });
        return found;
      })
      .catch((err: unknown) => {
        ledger.records.push({
          group: "active", name: "API surface discovery", status: "failed", findings: 0,
          durationMs: Date.now() - discoveryStarted,
          reason: err instanceof Error ? err.message.slice(0, 200) : String(err).slice(0, 200),
        });
        unrunFamilies.push("API surface discovery");
        console.error("[scan] API surface discovery failed", err);
        return [] as ApiEndpoint[];
      });
    if (endpoints.length === 0) {
      ledger.skip("active", "API endpoint testing (auth, injection, IDOR, mass assignment)", "no API endpoints were found to test");
    }

    const apiFindings = await (async () => {
      if (endpoints.length === 0) return [] as ScanVulnerability[];
      return ledger.track("active", "API endpoint testing (auth, injection, IDOR, mass assignment)", runApiProbes({
        endpoints,
        ...(auth?.credentials ? { credentials: auth.credentials } : {}),
        ...(auth?.secondary ? { secondary: auth.secondary } : {}),
      }));
    })().catch((err: unknown) => {
      unrunFamilies.push("API endpoint testing (auth, injection, IDOR, mass assignment)");
      console.error("[scan] API probes failed", err);
      return [] as ScanVulnerability[];
    });
    vulnerabilities.push(...apiFindings);

    // ── LLM prompt injection (system prompt extraction) ──────────────────────
    // Only meaningful when the passive AI-feature check already found the
    // target's system prompt sitting in its own client-side JS — that known
    // text is what makes this a stable check rather than a judged one. See
    // promptInjectionProbe.ts.
    // The site's OWN code only (inline plus first-party scripts), like the passive finding: a chat
    // widget vendor's script that ships a system prompt is not evidence about this site's prompt.
    const knownSystemPrompt = extractSystemPromptText(await collectFirstPartyJavaScript(html, finalUrl));
    if (!knownSystemPrompt) {
      ledger.skip(
        "active",
        "LLM prompt injection (system prompt extraction)",
        "no system prompt was found in this site's client-side code to check against",
      );
    } else {
      const injectionFindings = await ledger
        .trackOutcome(
          "active",
          "LLM prompt injection (system prompt extraction)",
          runPromptInjectionProbeDetailed({
            knownSystemPrompt,
            endpoints,
            ...(auth?.credentials ? { credentials: auth.credentials } : {}),
          }),
        )
        .catch((err: unknown) => {
          unrunFamilies.push("LLM prompt injection (system prompt extraction)");
          console.error("[scan] prompt injection probe failed", err);
          return [] as ScanVulnerability[];
        });
      vulnerabilities.push(...injectionFindings);
    }

    // ── Race condition (one-time action) ──────────────────────────────────────
    // Explicit per-scan opt-in only — see raceConditionProbe.ts for why this is
    // gated separately from every other active check.
    if (raceConditionTesting) {
      if (!auth?.credentials) {
        ledger.skip("active", "race condition (one-time action)", "needs a signed-in test account to run against");
      } else {
        const raceFindings = await ledger
          .trackOutcome(
            "active",
            "race condition (one-time action)",
            runRaceConditionProbeDetailed({ endpoints, credentials: auth.credentials }),
          )
          .catch((err: unknown) => {
            unrunFamilies.push("race condition (one-time action)");
            console.error("[scan] race condition probe failed", err);
            return [] as ScanVulnerability[];
          });
        vulnerabilities.push(...raceFindings);
      }
    } else {
      // Logged so every scan shows this test and why it did not run, rather than leaving no trace.
      ledger.skip("active", "race condition (one-time action)", "not requested for this scan (opt-in only, because it acts on the test account)");
    }

    // ── A10: SSRF via the out-of-band collector ─────────────────────────────
    // Runs only when a public callback host is configured, since the target's
    // server is what has to reach it. Reuses the discovered endpoints.
    // runSsrfProbes returns nothing when no callback host is configured —
    // recorded as a skip, so it cannot read as "not vulnerable".
    let ssrfRun: Promise<ScanVulnerability[]>;
    if (isOobConfigured()) {
      ssrfRun = ledger.track("active", "SSRF (out-of-band callback)", runSsrfProbes({
        scanId,
        targetUrl: finalUrl,
        endpoints,
        ...(auth?.credentials ? { credentials: auth.credentials } : {}),
      }));
    } else {
      ledger.skip("active", "SSRF (out-of-band callback)", "no public callback host is configured (OOB_BASE_URL / APP_ORIGIN)");
      ssrfRun = Promise.resolve([]);
    }
    const ssrfFindings = await ssrfRun.catch((err: unknown) => {
      unrunFamilies.push("SSRF (out-of-band callback)");
      console.error("[scan] SSRF probe failed", err);
      return [] as ScanVulnerability[];
    });
    vulnerabilities.push(...ssrfFindings);
  }

  return vulnerabilities;
}
