/**
 * DeepSeek AI client for security report analysis.
 * Model: deepseek-chat
 * Endpoint: https://api.deepseek.com/v1/chat/completions
 *
 * Per-agent fix routing: detects the user's build tool from the scanned
 * technology stack and generates fix prompts formatted for that specific tool.
 */

import type { ScanVulnerability } from "./scanner";

// ─── Agent environment detection ─────────────────────────────────────────────

export type AgentEnvironment =
  | "lovable"
  | "nextjs"
  | "bolt"
  | "wordpress"
  | "supabase"
  | "generic";

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

// ─── Agent-specific prompt instructions ──────────────────────────────────────

function agentPromptInstructions(agent: AgentEnvironment, domain: string): string {
  switch (agent) {
    case "lovable":
      return `AGENT TARGET: Lovable (AI web app builder — https://lovable.dev)
The user built this app with Lovable. Generate the agentFixPrompt as a Lovable chat message the user pastes directly into the Lovable chat interface.

Rules for agentFixPrompt:
- Open with: "Please fix these security issues in my app:"
- Write conversationally — Lovable understands natural language, not file paths
- DO NOT reference file paths; describe what needs to change in plain English
- For Supabase issues: include Supabase dashboard instructions (e.g. "In the Supabase dashboard → Table Editor → [table], click 'Enable RLS'")
- For header/cookie fixes: say what setting to add, e.g. "Add a Content-Security-Policy header in the server settings"
- Close with: "Apply all of these fixes and tell me what you changed."
- Keep under 2000 characters`;

    case "nextjs":
      return `AGENT TARGET: Cursor or Claude Code (IDE AI agent with full file access on a Next.js project)
The site runs Next.js — the developer likely uses Cursor Composer, Claude Code, or GitHub Copilot.

Rules for agentFixPrompt:
- Open with: "I ran a security scan on ${domain} and found these issues. Please fix them in my Next.js codebase."
- For each finding: specify the exact file to edit (e.g. \`middleware.ts\`, \`next.config.ts\`, \`app/api/route.ts\`)
- Show exact code snippets — before/after blocks where helpful
- Include npm/pnpm install commands if new packages are needed
- Reference Next.js-specific APIs: middleware for security headers, next.config for rewrites, app/api/ for route handlers
- Close with: "Show me the exact code change for each file."`;

    case "bolt":
      return `AGENT TARGET: Bolt.new or Replit Agent (full-file editing agent)
The site was built with Bolt.new or a similar full-file editing environment.

Rules for agentFixPrompt:
- Open with: "Fix these security issues in my app:"
- For each finding: specify the full file path and describe the complete change
- Prefer complete file content over partial diffs — Bolt.new works best with full files
- Include package.json dependency additions if new packages are needed
- Use clear file headers: "=== FILE: src/lib/auth.ts ==="
- Close with: "Make all of these changes. Show me each complete updated file."`;

    case "wordpress":
      return `AGENT TARGET: WordPress (CMS platform)
The site runs WordPress — fixes should use plugins, wp-config.php, or .htaccess.

Rules for agentFixPrompt:
- Open with: "Fix these security issues on my WordPress site:"
- For each finding: give WordPress-specific remediation (plugin name to install, wp-config.php line to add, .htaccess rule, or Admin Panel path)
- Prefer plugin solutions: e.g. "Install Wordfence Security and configure..." rather than raw PHP code
- Reference Admin Panel paths: e.g. "Settings → General", "Users → Your Profile"
- Close with: "Implement all of these WordPress security hardening steps."`;

    case "supabase":
      return `AGENT TARGET: Supabase (Backend-as-a-Service)
The app uses Supabase. Structure fixes as SQL + dashboard instructions + code changes.

Rules for agentFixPrompt:
- Open with: "Fix these security issues in my Supabase app:"
- Group fixes into three labeled sections:
  1. "SQL to run in Supabase SQL Editor:" — exact CREATE POLICY, ALTER TABLE, ENABLE ROW LEVEL SECURITY statements
  2. "Supabase Dashboard changes:" — specific navigation paths and toggle settings
  3. "Code changes:" — environment variable and client initialization fixes
- Close with: "Apply all SQL policies, change the dashboard settings, and update the code."`;

    case "generic":
    default:
      return `AGENT TARGET: Generic AI coding agent (Cursor, Claude, GitHub Copilot)

Rules for agentFixPrompt:
- Open with: "I ran a penetration test on ${domain} and found the following security issues that need to be fixed in my codebase."
- For each finding use a markdown heading like "### 1. <Finding Name> (<SEVERITY>)" followed by a one-sentence description and the exact remediation to implement
- Close with: "Please fix all of the above issues in my codebase. For each fix, show me the exact code change."
- Use plain text with markdown headings only — do not wrap in a code fence
- Keep under 3000 characters`;
  }
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

function buildPrompt(
  targetUrl: string,
  vulnerabilities: ScanVulnerability[],
  technologies: string[],
  tier: string,
  agent: AgentEnvironment,
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

  const agentInstructions = agentPromptInstructions(agent, domain);

  return `You are a senior application security engineer (AppSec) writing a penetration test summary for a developer who is not a security expert.

Target: ${targetUrl}
Scan tier: ${tier}
Detected technologies: ${techStack}

─── Security Findings ───
${structuredVulns || "No significant vulnerabilities detected."}

─── Fix Prompt Instructions ───
${agentInstructions}

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
  "agentFixPrompt": "<Follow the Fix Prompt Instructions above EXACTLY. Generate the fix prompt formatted specifically for the detected agent target. Self-contained and paste-ready.>"
}

Rules:
- Write for a developer who is not a security expert
- topPriorities must be specific and actionable (what to do, not just what is wrong)
- quickWins are changes under 5 minutes (adding a header, disabling a config flag, etc.)
- Keep overallRisk, each topPriorities item, and each quickWins item under 150 characters
- The agentFixPrompt MUST follow the Fix Prompt Instructions for the detected agent — not a generic format
- Return ONLY the JSON object — no markdown fences, no preamble, no explanation`;
}

// ─── Main export ──────────────────────────────────────────────────────────────

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

  const agent = detectAgentEnvironment(technologies, targetUrl);
  const prompt = buildPrompt(targetUrl, vulnerabilities, technologies, tier, agent);

  const body = {
    model: "deepseek-chat",
    messages: [
      {
        role: "system",
        content:
          "You are a senior application security engineer writing penetration test reports. Your writing is direct, jargon-free, and developer-focused — every finding comes with a concrete, actionable fix. Respond only with valid JSON as instructed. Do not add markdown fences, preamble, or explanation.",
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
      detectedAgent: agent,
    };
  } catch (err) {
    console.error("[deepseek] AI analysis failed:", err);
    return null;
  } finally {
    clearTimeout(timeout);
  }
}
