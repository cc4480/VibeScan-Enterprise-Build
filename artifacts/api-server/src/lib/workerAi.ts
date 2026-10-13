import type { ScanResult } from "./scanner";
import type { Log } from "./workerTypes";
import { and } from "drizzle-orm";
import { type ScanVulnerability } from "./scanner";
import { type TestRecord } from "./testLedger";
import { analyseFindings, describeAiFailure } from "./aiAnalysis";
import type { AiFailure } from "./deepseek";
import { isAiAnalysisOptedOut, AI_OPT_OUT_NOTE } from "./aiOptOut";
import { randomUUID } from "node:crypto";

/**
 * The written analysis. Skipped for ownership-verification scans and for owners who opted out;
 * when it fails the reader is told, via a Scan Coverage finding pushed onto the scan.
 */
export async function runAiStage(input: {
  scanResult: ScanResult;
  targetUrl: string;
  tier: string;
  tests: TestRecord[];
  userId: string;
  verificationId: string | null | undefined;
  log: Log;
}) {
  const { scanResult, targetUrl, tier, tests, userId, verificationId, log } = input;
  let aiAnalysis: Awaited<ReturnType<typeof analyseFindings>>["analysis"] | null = null;
  {
    log.info("Calling DeepSeek AI analysis");
    // Confidence gate: only pass high-confidence findings to the AI to reduce noise
    const AI_CONFIDENCE_GATE = 65;
    const vulnsForAi = scanResult.vulnerabilities.filter(
      (v) => (v.confidence ?? 100) >= AI_CONFIDENCE_GATE,
    );
    log.info(
      { total: scanResult.vulnerabilities.length, gated: vulnsForAi.length },
      "Confidence-gated findings passed to AI",
    );

    // The owner may have chosen not to have findings sent to the language-model provider.
    const aiOptedOut = verificationId ? false : await isAiAnalysisOptedOut(userId).catch(() => false);
    if (aiOptedOut) log.info("AI analysis skipped: turned off by the account owner");

    let aiFailure: AiFailure | null = null;
    if (!verificationId && !aiOptedOut) {
      // What ran and what was skipped is passed so the analysis never calls an
      // untested area safe. When the AI writer gives nothing, a fix prompt built
      // from the findings takes its place (labelled source: "template").
      const result = await analyseFindings(targetUrl, vulnsForAi, scanResult.technologies, tier, tests);
      aiAnalysis = result.analysis;
      aiFailure = result.failure;
    }
    if (aiOptedOut) {
      scanResult.vulnerabilities.push({
        id: randomUUID(),
        ...AI_OPT_OUT_NOTE,
        severity: "info",
        category: "Scan Coverage",
        cweId: null,
        cvssScore: null,
        wstgId: null,
        confidence: 100,
      } satisfies ScanVulnerability);
    } else if (aiAnalysis && !aiFailure) {
      log.info("DeepSeek analysis complete");
    } else if (verificationId) {
      log.info("AI analysis not run for an ownership verification scan");
    } else {
      log.warn("DeepSeek analysis skipped or failed — continuing without AI");

      // Tell the reader, not just the log. The written analysis is the part of
      // a report a developer without a security team actually acts on, and
      // when it is missing the report does not look degraded — it looks like a
      // report with less to say. Under load that is exactly when this happens:
      // the AI call has a 30s timeout and no retry, so one rate-limited
      // response costs a scan its entire analysis.
      //
      // Only when a key is configured. Where none is set the deployment simply
      // does not have this feature, and saying so on every scan would be noise.
      if (process.env["DEEPSEEK_API_KEY"] && aiFailure) {
        const why = describeAiFailure(aiFailure);
        scanResult.vulnerabilities.push({
          id: randomUUID(),
          name: "AI analysis could not be completed for this scan",
          severity: "info",
          category: "Scan Coverage",
          description:
            "Every security check ran and the findings below are complete — but the written analysis that normally accompanies them (the plain-English risk summary, the prioritised fixes and the fix prompt) could not be generated for this scan. " + why.reason + " A fix prompt has been built from the findings instead, without the AI writer's summary. This says nothing about your site: it is a gap in the explanation, not in the testing.",
          evidence: why.evidence,
          solution:
            "Re-run the scan to get the written analysis. The findings themselves do not change — only the commentary on them is missing — so you can also act on the list below, or use the fix prompt built from them.",
          cweId: null,
          cvssScore: null,
          wstgId: null,
          confidence: 100,
        } satisfies ScanVulnerability);
      }
    }
  }
  return aiAnalysis;
}
