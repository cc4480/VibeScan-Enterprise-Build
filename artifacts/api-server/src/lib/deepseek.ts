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
import { agentPromptInstructions, type AgentEnvironment } from "./deepseek-prompts";
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
}

// ─── Prompt builder ───────────────────────────────────────────────────────────

const DEEPSEEK_ENDPOINT = "https://api.deepseek.com/v1/chat/completions";

// Frameworks that indicate a vibe-coded / AI-generated application
const VIBE_FRAMEWORKS = [
  "react", "vue", "next.js", "nuxt", "vite", "svelte", "sveltekit",
  "remix", "angular", "astro", "gatsby", "vercel", "netlify",
];

/**
 * The coverage section of the prompt: how many tests ran, and each one that
 * was skipped or failed with its reason. Exported for tests.
 */
export function describeCoverage(tests: TestRecord[]): string {
  if (tests.length === 0) return "Not recorded for this scan. Do not claim any area was or was not tested.";
  const ran = tests.filter((t) => t.status === "ran").length;
  const notRun = tests.filter((t) => t.status !== "ran");
  return [
    `${ran} of ${tests.length} tests ran.`,
    ...(notRun.length
      ? ["NOT tested on this scan — never describe these areas as safe:", ...notRun.map((t) => `- ${t.name}: ${t.status === "failed" ? "failed to run" : t.reason ?? "skipped"}`)]
      : ["Every test ran."]),
  ].join("\n");
}

function buildPrompt(
  targetUrl: string,
  vulnerabilities: ScanVulnerability[],
  technologies: string[],
  tier: string,
  agent: AgentEnvironment,
  tests: TestRecord[] = [],
): string {
  const techStack = technologies.length > 0 ? technologies.join(", ") : "unknown";
  const coverage = describeCoverage(tests);

  const domain = (() => {
    try { return new URL(targetUrl).hostname; } catch { return targetUrl; }
  })();

  // Detect if this looks like a vibe-coded / AI-generated app
  const techLower = techStack.toLowerCase();
  const isVibeCoded = VIBE_FRAMEWORKS.some((f) => techLower.includes(f));
  const vibeCodingContext = isVibeCoded
    ? `\nContext: This is a ${techStack} app — a typical vibe-coded / AI-generated stack. ` +
      `Common issues in these stacks are: (1) secrets exposed in the frontend bundle via VITE_/REACT_APP_ env vars, ` +
      `(2) client-side-only authentication that can be bypassed by calling APIs directly, ` +
      `(3) missing Content-Security-Policy leaving XSS fully exploitable, and ` +
      `(4) unauthenticated API endpoints (BOLA/IDOR). When a finding below is one of these, say so. ` +
      `Never assume one of them is present: if no finding below reports it, the scanner checked and it was fine.`
    : "";

  // Most severe first, so "Finding 1" is always the one that matters most and
  // INFO items sit at the end of what the model reads — the order it writes in
  // should not depend on the order the scanner happened to find things.
  const RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const structuredVulns = [...vulnerabilities]
    .sort((a, b) => (RANK[a.severity] ?? 5) - (RANK[b.severity] ?? 5))
    .map((v, i) => {
      const parts = [
        `Finding ${i + 1}: ${v.name}`,
        `  Severity: ${v.severity.toUpperCase()}`,
        `  Category: ${v.category}`,
      ];
      if (v.cvssScore != null) parts.push(`  CVSS: ${v.cvssScore}`);
      if (v.cweId) parts.push(`  CWE: ${v.cweId}`);
      parts.push(`  Description: ${v.description}`);
      if (v.evidence) parts.push(`  Evidence: ${v.evidence.slice(0, 250)}`);
      parts.push(`  Fix: ${v.solution}`);
      return parts.join("\n");
    })
    .join("\n\n");

  const agentInstructions = agentPromptInstructions(agent, domain);

  return `You are a senior application security engineer (AppSec) writing an automated security scan summary for a developer who built their app with an AI coding assistant and is not a security expert. This is the output of an automated black-box scanner, not a manual penetration test — do not describe it as a pentest or imply exploitation was attempted.${vibeCodingContext}

Target: ${targetUrl}
Scan tier: ${tier}
Detected technologies: ${techStack}

─── Security Findings ───
${structuredVulns || "No findings. The scan found nothing to fix."}

─── What this scan tested ───
${coverage}

─── Fix Prompt Instructions ───
${agentInstructions}

Return a JSON object with EXACTLY these five fields:

{
  "overallRisk": "<2-3 sentence plain-English assessment: biggest risk and its real-world impact. Reference the most dangerous finding by name. Mention if this is a common pattern in AI-generated code. No jargon without explanation.>",
  "topPriorities": [
    "<1 to 3 items, one per finding above, most important first — never more items than findings. Specific, actionable fix: what to do and in which file/config. Max 150 chars.>"
  ],
  "quickWins": [
    "<0 to 2 items: findings above whose fix takes under 5 minutes — e.g. adding a response header. Empty array if none qualify. Max 150 chars.>"
  ],
  "complianceNotes": "<1-2 sentences on OWASP Top 10 or regulatory (GDPR/PCI-DSS) implications, or null if none apply>",
  "agentFixPrompt": "<Follow the Fix Prompt Instructions above EXACTLY. Generate the fix prompt formatted specifically for the detected agent target. Self-contained and paste-ready.>"
}

Rules:
- Every statement must come from the findings listed above. Never say something is missing, misconfigured, exposed or vulnerable unless a finding above reports it — the scanner ran many more checks than it reported, and anything not listed either passed or was not tested (see "What this scan tested"). Do not add general best-practice advice as if it were a problem with this site.
- Never describe an area listed under "NOT tested on this scan" as safe or clean.
- The agentFixPrompt covers the findings above and nothing else. If there are no findings, say the scan found nothing to fix.
- If none of the findings needs a code change (for example the only one is to verify domain ownership), end the agentFixPrompt with "None of these needs a code change." instead of the closing line above, which asks for code changes.
- Write for a developer who used AI to build their app and may not understand security concepts
- topPriorities must be specific: what to change, not just what is wrong
- quickWins are changes under 5 minutes
- Keep overallRisk, each topPriorities item, and each quickWins item under 150 characters
- The agentFixPrompt MUST follow the Fix Prompt Instructions for the detected agent — not a generic format
- If an exposed secret was found, it MUST be the first topPriority and first agentFixPrompt item
- Return ONLY the JSON object — no markdown fences, no preamble, no explanation`;
}

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

export async function callDeepSeek(
  targetUrl: string,
  vulnerabilities: ScanVulnerability[],
  technologies: string[],
  tier: string,
  /** What the scan ran and skipped (testLedger.ts), so the analysis never calls an untested area safe. */
  tests: TestRecord[] = [],
): Promise<AiAnalysisResult | null> {
  const apiKey = process.env.DEEPSEEK_API_KEY;
  if (!apiKey) {
    console.warn("[deepseek] DEEPSEEK_API_KEY is not set — skipping AI analysis");
    return null;
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

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30_000);

  try {
    const res = await fetch(DEEPSEEK_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => "");
      throw new Error(`DeepSeek API error ${res.status}: ${errText}`);
    }

    const json = (await res.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
    };

    const content = json.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty response from DeepSeek");

    const parsed = JSON.parse(content) as Partial<AiAnalysisResult>;

    return {
      overallRisk:
        typeof parsed.overallRisk === "string"
          ? parsed.overallRisk
          : "Risk assessment unavailable.",
      // Enforced here, not only asked for in the prompt: a list longer than
      // the findings can only have been padded with things the scan never said.
      topPriorities: capToFindings(parsed.topPriorities, vulnerabilities.length),
      quickWins: capToFindings(parsed.quickWins, vulnerabilities.length),
      complianceNotes:
        typeof parsed.complianceNotes === "string" ? parsed.complianceNotes : null,
      agentFixPrompt:
        typeof parsed.agentFixPrompt === "string" ? parsed.agentFixPrompt : "",
      detectedAgent: agent,
    };
  } catch (err) {
    console.error("[deepseek] AI analysis failed:", err);
    return null;
  } finally {
    clearTimeout(timeout);
  }
}
