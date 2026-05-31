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

// Frameworks that indicate a vibe-coded / AI-generated application
const VIBE_FRAMEWORKS = [
  "react", "vue", "next.js", "nuxt", "vite", "svelte", "sveltekit",
  "remix", "angular", "astro", "gatsby", "vercel", "netlify",
];

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

  // Detect if this looks like a vibe-coded / AI-generated app
  const techLower = techStack.toLowerCase();
  const isVibeCoded = VIBE_FRAMEWORKS.some((f) => techLower.includes(f));
  const vibeCodingContext = isVibeCoded
    ? `\nContext: This is a ${techStack} app — a typical vibe-coded / AI-generated stack. ` +
      `Studies show 91.5% of AI-generated apps have at least one critical vulnerability. ` +
      `The most common issues are: (1) secrets accidentally exposed in the frontend bundle via VITE_/REACT_APP_ env vars, ` +
      `(2) client-side-only authentication that can be bypassed by calling APIs directly, ` +
      `(3) missing Content-Security-Policy leaving XSS fully exploitable, and ` +
      `(4) unauthenticated API endpoints (BOLA/IDOR). Weight your analysis with these patterns in mind.`
    : "";

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

  return `You are a senior application security engineer (AppSec) writing a penetration test summary for a developer who built their app with an AI coding assistant and is not a security expert.${vibeCodingContext}

Target: ${targetUrl}
Scan tier: ${tier}
Detected technologies: ${techStack}

─── Security Findings ───
${structuredVulns || "No significant vulnerabilities detected."}

Return a JSON object with EXACTLY these five fields:

{
  "overallRisk": "<2-3 sentence plain-English assessment: biggest risk and its real-world impact. Reference the most dangerous finding by name. Mention if this is a common pattern in AI-generated code. No jargon without explanation.>",
  "topPriorities": [
    "<Specific, actionable fix — what to do and in which file/config. Max 150 chars.>",
    "<Second priority>",
    "<Third priority>"
  ],
  "quickWins": [
    "<A change that takes under 5 minutes — e.g. adding a response header, moving an env var server-side. Max 150 chars.>",
    "<Second quick win>"
  ],
  "complianceNotes": "<1-2 sentences on OWASP Top 10 or regulatory (GDPR/PCI-DSS) implications, or null if none apply>",
  "agentFixPrompt": "<A complete, paste-ready prompt for Cursor, Claude Code, or Windsurf. (1) Open with: 'I ran a penetration test on ${domain} and found the following security vulnerabilities that need to be fixed in my codebase. This app was built with AI assistance so please check for these common patterns throughout the code, not just in one place.' (2) For each finding use '### N. <Finding Name> (<SEVERITY>)' — one sentence on what is wrong and WHY it is dangerous in plain English, then the EXACT code fix: which file to change, which header/config/env var, and the specific line. For any exposed secret, the fix must say: move it to a server-side .env file and create a backend API route. For any client-side auth, the fix must say: add server-side middleware to validate the request. (3) Close with: 'For each fix, show me the exact code change and the specific file to edit. If a fix requires creating a new API route, show the full route code.' Plain markdown headings only — no code fences wrapping the whole thing. Under 3500 chars.>"
}

Rules:
- Write for a developer who used AI to build their app and may not understand security concepts
- topPriorities must be specific: what to change, not just what is wrong
- quickWins are changes under 5 minutes
- Keep overallRisk, each topPriorities item, and each quickWins item under 150 characters
- agentFixPrompt must be paste-ready into Cursor or Claude Code — include file-level specificity
- If an exposed secret was found, it MUST be the first topPriority and first agentFixPrompt item
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
          "You are a senior application security engineer specializing in securing AI-generated (vibe-coded) web applications. Your audience is developers who built their app with Cursor, Claude, or Lovable and have limited security knowledge. Your writing is direct, jargon-free, and highly actionable — every finding includes the exact file/config to change and why it matters in plain English. You are deeply familiar with the most common security mistakes in vibe-coded apps: exposed API keys in frontend bundles, client-side-only authentication, missing CSP, and unauthenticated API endpoints. Respond only with valid JSON as instructed. Do not add markdown fences, preamble, or explanation.",
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
