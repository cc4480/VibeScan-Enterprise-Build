/** The DeepSeek HTTP call: attempts, retries, and failure classification. */
import type { ScanVulnerability } from "./scanner";
import type { TestRecord } from "./testLedger";
import type { AgentEnvironment } from "./deepseek-prompts";
import { buildPrompt } from "./deepseekPrompt";
import { DEEPSEEK_MODEL, capToFindings, detectAgentEnvironment, SYSTEM_PROMPT, type AiAnalysisResult } from "./deepseek";

// ─── Prompt builder ───────────────────────────────────────────────────────────

// LLM_ENDPOINT points the same call at any OpenAI-compatible provider (a US or EU host) without a deploy.
export const DEEPSEEK_ENDPOINT = process.env["LLM_ENDPOINT"]?.trim() || "https://api.deepseek.com/v1/chat/completions";

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
export const RETRYABLE: ReadonlySet<AiFailureKind> = new Set(["rate_limit", "provider_error", "timeout", "network", "empty"]);

export const AI_ATTEMPT_TIMEOUT_MS = 90_000;

export const AI_MAX_ATTEMPTS = 2;

export const AI_RETRY_PAUSE_MS = 1_500;

export const AI_RETRY_AFTER_CAP_MS = 5_000;

export interface AiCallOptions {
  /** Test seam: replaces the pause between attempts. */
  sleep?: (ms: number) => Promise<void>;
  maxAttempts?: number;
  attemptTimeoutMs?: number;
}

/** One request to the provider. Throws an AiAttemptError describing what went wrong. */
export class AiAttemptError extends Error {
  constructor(readonly kind: AiFailureKind, readonly status: number | undefined, readonly retryAfterMs: number | undefined, detail: string) {
    super(detail);
  }
}

export async function attemptOnce(body: unknown, apiKey: string, timeoutMs: number, vulnCount: number, agent: AgentEnvironment): Promise<AiAnalysisResult> {
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
    // Room for the model's own reasoning plus the full analysis and fix prompt; a tight cap left the visible reply empty.
    max_tokens: 16000,
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
