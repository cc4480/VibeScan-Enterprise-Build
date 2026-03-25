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
}

const DEEPSEEK_ENDPOINT = "https://api.deepseek.com/v1/chat/completions";

function buildPrompt(
  targetUrl: string,
  vulnerabilities: ScanVulnerability[],
  technologies: string[],
  tier: string,
): string {
  const vulnSummary = vulnerabilities
    .map(
      (v) =>
        `- [${v.severity.toUpperCase()}] ${v.name} (${v.category}): ${v.description}`,
    )
    .join("\n");

  const techStack = technologies.length > 0 ? technologies.join(", ") : "unknown";

  return `You are a senior application security engineer writing a plain-English penetration test summary for a developer.

Target URL: ${targetUrl}
Scan Tier: ${tier}
Detected Technologies: ${techStack}

Identified Security Issues:
${vulnSummary || "No significant vulnerabilities detected."}

Based on the above, provide a JSON response with exactly these fields:
{
  "overallRisk": "<2-3 sentences: plain-English overall risk level and most dangerous finding>",
  "topPriorities": ["<actionable fix 1>", "<actionable fix 2>", "<actionable fix 3>"],
  "quickWins": ["<easy 5-min fix 1>", "<easy 5-min fix 2>"],
  "complianceNotes": "<1-2 sentences about OWASP Top 10 or compliance implications, or null>"
}

Rules:
- Write for a developer who isn't a security expert. No jargon without explanation.
- topPriorities must be specific and actionable (what to do, not just what's wrong)
- quickWins are changes that take under 5 minutes to implement (adding a header, disabling a setting)
- Keep each string under 150 characters
- Return ONLY the JSON object, no markdown fences, no explanations`;
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
    max_tokens: 800,
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
    };
  } catch (err) {
    console.error("[deepseek] AI analysis failed:", err);
    return null;
  } finally {
    clearTimeout(timeout);
  }
}
