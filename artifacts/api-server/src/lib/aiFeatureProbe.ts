/**
 * Checks for AI features built into the page itself, from the JavaScript the browser
 * already downloads. Passive: no request is sent to any AI provider or chat endpoint.
 *
 * Two findings, each on a literal in the code rather than a guess about behaviour:
 *
 *  1. AI PROVIDER CALLED FROM THE BROWSER. The OpenAI SDK's dangerouslyAllowBrowser
 *     option, or a fetch / baseURL pointed straight at a provider's API. Anything the
 *     browser sends to the provider carries a credential the visitor can read. A key
 *     found in the code is reported separately as Critical by the secret scanner;
 *     this catches the design even when the key is not visible (for example one the
 *     user types in, or one added at build time). It is Low for that reason: the page
 *     may be a bring-your-own-key tool, which is legitimate.
 *
 *  2. A SYSTEM PROMPT SHIPPED IN THE BUNDLE. A role:"system" message with a long literal
 *     as its content. Whatever instructions, business rules or hidden data the prompt
 *     holds is readable by anyone who opens the page.
 *
 * What it deliberately does not do: send prompt-injection or jailbreak strings at a chat
 * endpoint. The reply of a language model is not a stable signal, so any finding built
 * on it would be a coin toss, and every request costs the owner money.
 */
import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";

const PROVIDER_HOSTS = [
  "api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com", "api.groq.com",
  "api.deepseek.com", "openrouter.ai", "api.mistral.ai", "api.cohere.com", "api.together.xyz", "api.x.ai",
];
const hostAlt = PROVIDER_HOSTS.map((h) => h.replace(/\./g, "\\.")).join("|");

/** fetch("https://api.openai.com/...") or baseURL: "https://api.groq.com/..." — a call, not a mention in text. */
const DIRECT_CALL = new RegExp(`(?:fetch\\(\\s*|baseURL\\s*:\\s*|baseUrl\\s*:\\s*|url\\s*:\\s*)["'\`]https://(${hostAlt})(?:/[^"'\`\\s]*)?["'\`]`, "i");
const BROWSER_FLAG = /dangerouslyAllowBrowser\s*:\s*(?:true|!0)/;

/** {role:"system",content:"…80+ chars…"} in either key order, with any of the three quote styles. */
const SYSTEM_PROMPT = /role\s*:\s*["']system["']\s*,\s*content\s*:\s*(["'`])((?:(?!\1)[^\\\n]|\\.){80,}?)\1/;
const SYSTEM_PROMPT_REVERSED = /content\s*:\s*(["'`])((?:(?!\1)[^\\\n]|\\.){80,}?)\1\s*,\s*role\s*:\s*["']system["']/;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

export function scanAiUsage(js: string): ScanVulnerability[] {
  const out: ScanVulnerability[] = [];

  const call = DIRECT_CALL.exec(js);
  const flag = BROWSER_FLAG.test(js);
  if (call || flag) {
    const signals = [
      call ? `Request aimed straight at ${call[1]}` : null,
      flag ? "OpenAI SDK option dangerouslyAllowBrowser is enabled" : null,
    ].filter(Boolean);
    out.push(vuln({
      name: "AI Provider Called Directly From the Browser",
      severity: "low",
      category: "AI Feature Security",
      description:
        "The page's JavaScript talks to an AI provider itself instead of going through your own server. Whatever credential " +
        "authorises those calls is visible to every visitor, who can copy it and run requests billed to you. If visitors " +
        "enter their own key, this is by design; if the key is yours, it should move to a server route that adds it. " +
        "A key that is present in the code is reported separately as a critical finding.",
      evidence: signals.join("\n"),
      solution:
        "Call the provider from a server route (for example /api/chat) that holds the key in a server-side environment variable, " +
        "checks the visitor is signed in, and rate-limits requests. The browser then talks only to your route.",
      cweId: "CWE-522",
      cvssScore: 3.7,
      wstgId: "WSTG-CONF-04",
    }));
  }

  const prompt = SYSTEM_PROMPT.exec(js) ?? SYSTEM_PROMPT_REVERSED.exec(js);
  if (prompt) {
    const text = prompt[2]!;
    out.push(vuln({
      name: "AI System Prompt Shipped in Client-Side Code",
      severity: "low",
      category: "AI Feature Security",
      description:
        "A system prompt is written out in the JavaScript sent to every visitor. Anyone can read the instructions, business " +
        "rules and any data pasted into it, and can craft input around them. Treat everything in a client-side prompt as public.",
      evidence: `role: "system" message, ${text.length} characters, begins: ${text.slice(0, 60).replace(/\s+/g, " ")}…`,
      solution:
        "Keep the system prompt on the server and build the model request there. Do not put secrets, private data or " +
        "anything you rely on staying hidden in a prompt, since a model can be talked into repeating it.",
      cweId: "CWE-200",
      cvssScore: 3.7,
      wstgId: "WSTG-CONF-04",
    }));
  }
  return out;
}
