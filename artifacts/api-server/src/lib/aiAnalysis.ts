/**
 * The analysis step of a scan: the AI writer when it answers, a template built from the findings
 * when it does not. Lives apart from deepseek.ts so the fallback can import types from it.
 */
import type { ScanVulnerability } from "./scanner";
import type { TestRecord } from "./testLedger";
import { withEveryFinding } from "./fixPromptCoverage";
import {
  callDeepSeekDetailed,
  detectAgentEnvironment,
  type AiAnalysisResult,
  type AiCallOptions,
  type AiFailure,
} from "./deepseek";
import { buildFallbackAnalysis } from "./fixPromptFallback";

export interface AnalysisOutcome {
  analysis: AiAnalysisResult;
  /** Set when the analysis is the template, and says why the AI writer gave none. */
  failure: AiFailure | null;
}

export async function analyseFindings(
  targetUrl: string,
  vulnerabilities: ScanVulnerability[],
  technologies: string[],
  tier: string,
  tests: TestRecord[] = [],
  opts: AiCallOptions = {},
): Promise<AnalysisOutcome> {
  const outcome = await callDeepSeekDetailed(targetUrl, vulnerabilities, technologies, tier, tests, opts);
  if (outcome.ok) {
    // The written prompt names only some findings, so every finding in the report is listed under it.
    const agentFixPrompt = withEveryFinding(outcome.result.agentFixPrompt, vulnerabilities);
    return { analysis: { ...outcome.result, agentFixPrompt, source: "ai" }, failure: null };
  }
  const fallback = buildFallbackAnalysis({
    targetUrl,
    vulnerabilities,
    agent: detectAgentEnvironment(technologies, targetUrl),
    tests,
  });
  return {
    analysis: { ...fallback, agentFixPrompt: withEveryFinding(fallback.agentFixPrompt, vulnerabilities) },
    failure: outcome.failure,
  };
}

/** A reader-facing reason and short evidence for a failed AI call. Never carries a provider response body. */
export function describeAiFailure(f: AiFailure): { reason: string; evidence: string } {
  const tries = f.attempts === 1 ? "1 attempt" : `${f.attempts} attempts`;
  const status = f.status ? `HTTP ${f.status}, ` : "";
  const evidence = `AI provider call failed (${f.kind}; ${status}${tries}).`;
  switch (f.kind) {
    case "rate_limit":
      return { reason: "The AI provider was busy and asked us to slow down.", evidence };
    case "provider_error":
      return { reason: "The AI provider had an error on its side.", evidence };
    case "timeout":
      return { reason: "The AI provider did not answer in time.", evidence };
    case "network":
      return { reason: "SecScan could not reach the AI provider.", evidence };
    case "empty":
      return { reason: "The AI provider answered without a usable analysis.", evidence };
    case "not_configured":
    case "auth":
    case "billing":
    case "rejected":
      return { reason: "The AI writer is unavailable because of a configuration problem on SecScan's side.", evidence };
  }
}
