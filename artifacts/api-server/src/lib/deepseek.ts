/**
 * DeepSeek AI client for security report analysis.
 * Model: DEEPSEEK_MODEL (default deepseek-flash, i.e. DeepSeek-V4.1-Flash)
 * Endpoint: https://api.deepseek.com/v1/chat/completions
 *
 * Per-agent fix routing: detects the user's build tool from the scanned
 * technology stack and generates fix prompts formatted for that specific tool.
 */

import type { ScanVulnerability } from "./scanner";
import type { TestRecord } from "./testLedger";
import type { AgentEnvironment } from "./deepseek-prompts";
import { buildPrompt } from "./deepseekPrompt";
export { describeCoverage } from "./deepseekPrompt";
export { redactForLlm } from "./llmRedact";
export type { AgentEnvironment } from "./deepseek-prompts";

// ─── Agent environment detection ─────────────────────────────────────────────

/**
 * Detects which AI coding tool / platform the scanned app was most likely
 * built with, based on the technology fingerprints from the scanner.
 *
 * Priority order matters: more specific signals win over generic ones.
 */
export function detectAgentEnvironment(
  technologies: string[],
  targetUrl: string,
): AgentEnvironment {
  const techs = technologies.map((t) => t.toLowerCase());
  const hostname = (() => {
    try { return new URL(targetUrl).hostname.toLowerCase(); } catch { return ""; }
  })();

  // Lovable — highly specific signals
  if (
    techs.some((t) => t.startsWith("lovable")) ||
    hostname.endsWith(".lovable.app") ||
    hostname.endsWith(".gptengineer.app")
  ) return "lovable";

  // Bolt.new — Stackblitz web container
  if (
    techs.some((t) => t.startsWith("bolt.new")) ||
    hostname.endsWith(".bolt.new") ||
    hostname.endsWith(".stackblitz.io")
  ) return "bolt";

  // Next.js — Cursor / Claude Code / Vercel workflow
  if (techs.some((t) => t.startsWith("next.js"))) return "nextjs";

  // WordPress — plugin/admin-based remediation
  if (techs.some((t) => t.startsWith("wordpress"))) return "wordpress";

  // Supabase without a major framework — raw BaaS fix instructions
  const hasSupabase = techs.some((t) => t.startsWith("supabase"));
  const hasMajorFramework = techs.some((t) =>
    ["next.js", "nuxt", "gatsby", "remix", "astro", "angular", "svelte"].some((f) =>
      t.startsWith(f),
    ),
  );
  if (hasSupabase && !hasMajorFramework) return "supabase";

  // Hosted site builders: the owner cannot edit server code, only what the platform exposes.
  if (techs.some((t) => ["shopify", "wix", "squarespace", "webflow"].some((p) => t.startsWith(p)))) return "hosted";

  // Host or backend platforms, only when no framework already says how the code is edited.
  if (!hasMajorFramework) {
    if (techs.some((t) => t.startsWith("firebase"))) return "firebase";
    if (techs.some((t) => t.startsWith("vercel"))) return "vercel";
    if (techs.some((t) => t.startsWith("netlify"))) return "netlify";
  }

  return "generic";
}

// ─── Types ────────────────────────────────────────────────────────────────────

export interface AiAnalysisResult {
  overallRisk: string;
  topPriorities: string[];
  quickWins: string[];
  complianceNotes: string | null;
  agentFixPrompt: string;
  detectedAgent: AgentEnvironment;
  /**
   * Who wrote it. Absent on older reports, which were all written by the AI provider. "template"
   * means the AI call failed and the text was assembled from the findings themselves
   * (fixPromptFallback.ts), so the report says so instead of presenting it as AI-written.
   */
  source?: "ai" | "template";
}

// ─── Prompt builder ───────────────────────────────────────────────────────────

// LLM_ENDPOINT points the same call at any OpenAI-compatible provider (a US or EU host) without a deploy.
const DEEPSEEK_ENDPOINT = process.env["LLM_ENDPOINT"]?.trim() || "https://api.deepseek.com/v1/chat/completions";

// ─── Main export ──────────────────────────────────────────────────────────────

/**
 * The model. DeepSeek's current name is `deepseek-flash` (served by
 * DeepSeek-V4.1-Flash); the old `deepseek-chat` is no longer in their docs.
 * DEEPSEEK_MODEL switches it on Railway without a deploy — e.g. to
 * `deepseek-v4-pro` — if Flash ever falls short.
 */
export const DEEPSEEK_MODEL = process.env["DEEPSEEK_MODEL"]?.trim() || "deepseek-flash";

/**
 * The rules the analysis is written under. SecScan's promise is that a report
 * says what was found and what was checked, and nothing else — the AI writes
 * the explanation, never the findings. A clean site once got "add a
 * Content-Security-Policy header" for a header it already sent; these rules
 * exist so that cannot happen again. Exported for tests.
 */
export const SYSTEM_PROMPT = [
  "You are the writer for SecScan, an automated security scanner. You turn one scan's results into a plain-English report for a developer who built their app with an AI coding tool and is not a security expert.",
  "",
  "ACCURACY RULES — these override everything else:",
  "1. The scan data in the user message is your ONLY source of truth. Do not use general knowledge to add problems, and do not assume anything about the site beyond it.",
  "2. Write only about the findings listed. Never say a header, file, key, setting or weakness is present, missing or misconfigured unless a listed finding says so. Anything not listed was checked and passed, or was not tested — the 'What this scan tested' section says which.",
  "3. Never call an area safe, secure or clean if the scan did not test it. If active tests were skipped, say they were skipped and why; do not describe the site as free of injection, XSS or access-control problems.",
  "4. Keep every severity exactly as given. Never raise or lower one, and never call an INFO or LOW finding urgent.",
  "5. Quote evidence and names as they appear. Never invent file paths, endpoints, keys, versions, CVE numbers, statistics, percentages or studies.",
  "6. Recommend only fixes for listed findings. No general best-practice advice presented as a problem with this site.",
  "7. If a fix is not a code change (DNS, hosting settings, domain verification), say so plainly.",
  "8. If there are no findings, say the scan found nothing to fix — do not fill the space.",
  "9. Compliance: mention a framework only if a listed finding clearly relates to it, and never state or imply the site is compliant, certified or audited.",
  "10. INFO findings are informational, not problems to fix. Put them after every other finding; never make one a top priority or quick win while any CRITICAL, HIGH, MEDIUM or LOW finding exists; and keep any condition they carry ('only needed if …', 'only if you use …') wherever you mention them, including the fix prompt, so the reader can decide it does not apply.",
  "",
  "STYLE: short sentences, plain words, no jargon without a one-line explanation, specific over general.",
  "",
  "OUTPUT: respond with a single JSON object exactly as the user message specifies. No markdown fences, no preamble, no commentary.",
].join("\n");

/** Never more priorities or quick wins than there are real findings. Exported for tests. */
export function capToFindings(items: unknown, findingCount: number): string[] {
  if (!Array.isArray(items)) return [];
  return items.filter((s): s is string => typeof s === "string" && s.trim() !== "").slice(0, Math.min(5, findingCount));
}

/** Why a call to the AI provider produced no analysis. Only categories and a status code, never a response body. */
export type AiFailureKind =
  | "not_configured" // no DEEPSEEK_API_KEY on this deployment
  | "auth" // 401 / 403: the provider refused the key
  | "billing" // 402: the provider account has no balance
  | "rejected" // other 4xx (400, 404, 422): our request was refused, e.g. an unknown model name
  | "rate_limit" // 429
  | "provider_error" // 5xx
  | "timeout"
  | "network"
  | "empty"; // a 200 with no usable analysis in it

export interface AiFailure {
  kind: AiFailureKind;
  /** The provider's HTTP status, when it answered. */
  status?: number;
  /** How many times the call was made before giving up. */
  attempts: number;
}

export type AiCallOutcome = { ok: true; result: AiAnalysisResult } | { ok: false; failure: AiFailure };

export function classifyAiStatus(status: number): AiFailureKind {
  if (status === 401 || status === 403) return "auth";
  if (status === 402) return "billing";
  if (status === 429) return "rate_limit";
  if (status >= 500) return "provider_error";
  return "rejected";
}

/** Failures worth a second try: busy, down, slow or a garbled answer. A wrong key or model will not fix itself. */
const RETRYABLE: ReadonlySet<AiFailureKind> = new Set(["rate_limit", "provider_error", "timeout", "network", "empty"]);

const AI_ATTEMPT_TIMEOUT_MS = 30_000;
const AI_MAX_ATTEMPTS = 2;
const AI_RETRY_PAUSE_MS = 1_500;
const AI_RETRY_AFTER_CAP_MS = 5_000;

export interface AiCallOptions {
  /** Test seam: replaces the pause between attempts. */
  sleep?: (ms: number) => Promise<void>;
  maxAttempts?: number;
  attemptTimeoutMs?: number;
}

/** One request to the provider. Throws an AiAttemptError describing what went wrong. */
class AiAttemptError extends Error {
  constructor(readonly kind: AiFailureKind, readonly status: number | undefined, readonly retryAfterMs: number | undefined, detail: string) {
    super(detail);
  }
}

async function attemptOnce(body: unknown, apiKey: string, timeoutMs: number, vulnCount: number, agent: AgentEnvironment): Promise<AiAnalysisResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let res: Response;
    try {
      res = await fetch(DEEPSEEK_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (err) {
      const aborted = err instanceof Error && err.name === "AbortError";
      throw new AiAttemptError(aborted ? "timeout" : "network", undefined, undefined, err instanceof Error ? err.message : String(err));
    }

    if (!res.ok) {
      const errText = await res.text().catch(() => "");
      const retryAfter = Number(res.headers.get("retry-after"));
      throw new AiAttemptError(
        classifyAiStatus(res.status),
        res.status,
        Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : undefined,
        `DeepSeek API error ${res.status}: ${errText.slice(0, 300)}`,
      );
    }

    let content: string | undefined;
    let shape = "";
    try {
      const json = (await res.json()) as {
        choices?: Array<{ finish_reason?: string; message?: { content?: string; reasoning_content?: string } }>;
        usage?: { completion_tokens?: number };
      };
      content = json.choices?.[0]?.message?.content;
      // Operator log only: why a 200 carried no analysis (token budget spent on reasoning, a filter, a bad shape).
      shape = ` (finish_reason=${json.choices?.[0]?.finish_reason ?? "none"}, choices=${json.choices?.length ?? 0}, reasoning=${json.choices?.[0]?.message?.reasoning_content ? "yes" : "no"}, completion_tokens=${json.usage?.completion_tokens ?? "?"}, model=${DEEPSEEK_MODEL})`;
    } catch {
      throw new AiAttemptError("empty", res.status, undefined, "DeepSeek answered with a body that is not JSON");
    }
    if (!content) throw new AiAttemptError("empty", res.status, undefined, `Empty response from DeepSeek${shape}`);

    let parsed: Partial<AiAnalysisResult>;
    try {
      parsed = JSON.parse(content) as Partial<AiAnalysisResult>;
    } catch {
      throw new AiAttemptError("empty", res.status, undefined, "DeepSeek's analysis was not valid JSON");
    }

    return {
      overallRisk:
        typeof parsed.overallRisk === "string"
          ? parsed.overallRisk
          : "Risk assessment unavailable.",
      // Enforced here, not only asked for in the prompt: a list longer than
      // the findings can only have been padded with things the scan never said.
      topPriorities: capToFindings(parsed.topPriorities, vulnCount),
      quickWins: capToFindings(parsed.quickWins, vulnCount),
      complianceNotes:
        typeof parsed.complianceNotes === "string" ? parsed.complianceNotes : null,
      agentFixPrompt:
        typeof parsed.agentFixPrompt === "string" ? parsed.agentFixPrompt : "",
      detectedAgent: agent,
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * The AI call with one retry for the failures that are usually momentary (busy, slow, unreachable,
 * a garbled answer), and a classified reason when it still fails, so the report and the logs can
 * say why instead of a bare "could not be completed". A wrong key, an empty account or an unknown
 * model is not retried: it would fail the same way.
 */
export async function callDeepSeekDetailed(
  targetUrl: string,
  vulnerabilities: ScanVulnerability[],
  technologies: string[],
  tier: string,
  /** What the scan ran and skipped (testLedger.ts), so the analysis never calls an untested area safe. */
  tests: TestRecord[] = [],
  opts: AiCallOptions = {},
): Promise<AiCallOutcome> {
  const apiKey = process.env.DEEPSEEK_API_KEY;
  if (!apiKey) {
    console.warn("[deepseek] DEEPSEEK_API_KEY is not set — skipping AI analysis");
    return { ok: false, failure: { kind: "not_configured", attempts: 0 } };
  }

  const agent = detectAgentEnvironment(technologies, targetUrl);
  const prompt = buildPrompt(targetUrl, vulnerabilities, technologies, tier, agent, tests);

  const body = {
    model: DEEPSEEK_MODEL,
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: prompt },
    ],
    // Low: this is transcription and explanation of fixed facts, not creative
    // writing, and every point of temperature is room to embellish.
    temperature: 0.1,
    max_tokens: 3000,
    response_format: { type: "json_object" },
  };

  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const maxAttempts = opts.maxAttempts ?? AI_MAX_ATTEMPTS;
  const timeoutMs = opts.attemptTimeoutMs ?? AI_ATTEMPT_TIMEOUT_MS;

  let last: AiFailure = { kind: "network", attempts: 0 };
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const result = await attemptOnce(body, apiKey, timeoutMs, vulnerabilities.length, agent);
      return { ok: true, result };
    } catch (err) {
      if (!(err instanceof AiAttemptError)) throw err;
      last = { kind: err.kind, ...(err.status !== undefined ? { status: err.status } : {}), attempts: attempt };
      // The detail (a provider response snippet) goes to the operator's log only, never into a report.
      console.error(`[deepseek] AI analysis attempt ${attempt}/${maxAttempts} failed (${err.kind}): ${err.message}`);
      if (attempt < maxAttempts && RETRYABLE.has(err.kind)) {
        await sleep(Math.min(err.retryAfterMs ?? AI_RETRY_PAUSE_MS, AI_RETRY_AFTER_CAP_MS));
        continue;
      }
      break;
    }
  }
  return { ok: false, failure: last };
}

/** The analysis, or null when the provider gave none. Kept for callers that only need that. */
export async function callDeepSeek(
  targetUrl: string,
  vulnerabilities: ScanVulnerability[],
  technologies: string[],
  tier: string,
  tests: TestRecord[] = [],
): Promise<AiAnalysisResult | null> {
  const outcome = await callDeepSeekDetailed(targetUrl, vulnerabilities, technologies, tier, tests);
  return outcome.ok ? outcome.result : null;
}
