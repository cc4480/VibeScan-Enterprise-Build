/**
 * DeepSeek AI client for security report analysis.
 * Model: deepseek-chat
 * Endpoint: https://api.deepseek.com/v1/chat/completions
 */

import type { ScanVulnerability } from "./scanner";

export interface AiAnalysisResult {
  overallRisk: string;
  topPriorities: string[];
  quickWins: string[];
  complianceNotes: string | null;
  agentFixPrompt: string;
}

const DEEPSEEK_ENDPOINT = "https://api.deepseek.com/v1/chat/completions";

function buildPrompt(
  targetUrl: string,
  vulnerabilities: ScanVulnerability[],
  technologies: string[],
  tier: string,
): string {
  const techStack = technologies.length > 0 ? technologies.join(", ") : "unknown";

  const domain = (() => {
    try { return new URL(targetUrl).hostname; } catch { return targetUrl; }
  })();

  const structuredVulns = vulnerabilities
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

  return `You are a senior application security engineer (AppSec) writing a penetration test summary for a developer who is not a security expert.

Target: ${targetUrl}
Scan tier: ${tier}
Detected technologies: ${techStack}

─── Security Findings ───
${structuredVulns || "No significant vulnerabilities detected."}

Return a JSON object with EXACTLY these five fields:

{
  "overallRisk": "<2-3 sentence plain-English assessment: biggest risk and its real-world impact. Reference the most dangerous finding by name. No jargon without explanation.>",
  "topPriorities": [
    "<Specific, actionable fix — what to do, not just what is wrong. Max 150 chars.>",
    "<Second priority>",
    "<Third priority>"
  ],
  "quickWins": [
    "<A change that takes under 5 minutes — e.g. adding a response header or disabling a setting. Max 150 chars.>",
    "<Second quick win>"
  ],
  "complianceNotes": "<1-2 sentences on OWASP Top 10 or regulatory (GDPR/PCI-DSS) implications, or null if none apply>",
  "agentFixPrompt": "<A complete, paste-ready prompt for a coding AI agent such as Cursor, Claude, or GitHub Copilot. Structure it as follows — (1) open with: 'I ran a penetration test on ${domain} and found the following security issues that need to be fixed in my codebase.'; (2) for each finding use a markdown heading like '### 1. <Finding Name> (<SEVERITY>)' followed by a one-sentence description and then the exact remediation the developer should implement in their code; (3) close with: 'Please fix all of the above issues in my codebase. For each fix, show me the exact code change.' Use plain text with markdown headings only — do not wrap the entire thing in a code fence. Keep the total under 3000 characters.>"
}

Rules:
- Write for a developer who is not a security expert
- topPriorities must be specific and actionable (what to do, not just what is wrong)
- quickWins are changes under 5 minutes (adding a header, disabling a config flag, etc.)
- Keep overallRisk, each topPriorities item, and each quickWins item under 150 characters
- agentFixPrompt must be self-contained and paste-ready — a developer should be able to copy it directly into any coding agent and get working fixes
- Return ONLY the JSON object — no markdown fences, no preamble, no explanation`;
}

export async function callDeepSeek(
  targetUrl: string,
  vulnerabilities: ScanVulnerability[],
  technologies: string[],
  tier: string,
): Promise<AiAnalysisResult | null> {
  const apiKey = process.env.DEEPSEEK_API_KEY;
  if (!apiKey) {
    console.warn("[deepseek] DEEPSEEK_API_KEY is not set — skipping AI analysis");
    return null;
  }

  const prompt = buildPrompt(targetUrl, vulnerabilities, technologies, tier);

  const body = {
    model: "deepseek-chat",
    messages: [
      {
        role: "system",
        content:
          "You are a cybersecurity expert. You respond only with valid JSON as instructed. Do not add markdown, preamble, or explanation.",
      },
      {
        role: "user",
        content: prompt,
      },
    ],
    temperature: 0.3,
    max_tokens: 2000,
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
      topPriorities: Array.isArray(parsed.topPriorities)
        ? (parsed.topPriorities as string[]).slice(0, 5)
        : [],
      quickWins: Array.isArray(parsed.quickWins)
        ? (parsed.quickWins as string[]).slice(0, 5)
        : [],
      complianceNotes:
        typeof parsed.complianceNotes === "string" ? parsed.complianceNotes : null,
      agentFixPrompt:
        typeof parsed.agentFixPrompt === "string" ? parsed.agentFixPrompt : "",
    };
  } catch (err) {
    console.error("[deepseek] AI analysis failed:", err);
    return null;
  } finally {
    clearTimeout(timeout);
  }
}
