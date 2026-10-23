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
 * What this passive check deliberately does not do: send anything at a chat endpoint.
 * The reply of a language model is not a stable signal, so a finding that judged one
 * would be a coin toss, and every request costs the owner money. The one active AI check,
 * promptInjectionProbe.ts, avoids that: it only runs when this file has already found the
 * system prompt, sends at most two requests, and reports a long verbatim match against
 * that known text rather than judging the reply.
 */
import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import { unescapeJsLiteral } from "./promptOverlap";

const PROVIDER_HOSTS = [
  "api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com", "api.groq.com",
  "api.deepseek.com", "openrouter.ai", "api.mistral.ai", "api.cohere.com", "api.together.xyz", "api.x.ai",
];
const hostAlt = PROVIDER_HOSTS.map((h) => h.replace(/\./g, "\\.")).join("|");

/** fetch("https://api.openai.com/...") — the page itself issues a request to a provider. */
const FETCH_CALL = new RegExp(`fetch\\(\\s*["'\`]https://(${hostAlt})(?:/[^"'\`\\s]*)?["'\`]`, "i");
/**
 * baseURL/url naming a provider. On its own that is the default every AI SDK carries in a bundle, and
 * says nothing about who sends requests, so it counts only with a credential in the same object.
 */
const CONFIG_HOST = new RegExp(`(?:baseURL|baseUrl|url)\\s*:\\s*["'\`]https://(${hostAlt})(?:/[^"'\`\\s]*)?["'\`]`, "gi");
const CREDENTIAL_NEAR = /api[_-]?key|authorization|bearer\s/i;
const CONFIG_WINDOW = 200;

/** A configuration that names a provider host AND carries a credential right beside it. */
function configWithCredential(js: string): string | null {
  for (const m of js.matchAll(CONFIG_HOST)) {
    const at = m.index ?? 0;
    const near = js.slice(Math.max(0, at - CONFIG_WINDOW), at + m[0].length + CONFIG_WINDOW);
    if (CREDENTIAL_NEAR.test(near)) return m[1]!;
  }
  return null;
}
const BROWSER_FLAG = /dangerouslyAllowBrowser\s*:\s*(?:true|!0)/;

/**
 * {role:"system",content:"…80+ chars…"} in either key order, with JS or JSON-quoted keys and any of
 * the three quote styles. A quoted string must sit on one line; a backtick template literal, the usual
 * way to write a long prompt, may span lines (\x60 is the backtick).
 */
const ROLE = String.raw`["']?role["']?\s*:\s*["']system["']`;
const CONTENT = String.raw`["']?content["']?\s*:\s*`;
const LITERAL = String.raw`(?:(["'])((?:(?!\1)[^\\\n]|\\.){80,}?)\1|\x60((?:[^\x60\\]|\\[\s\S]){80,}?)\x60)`;
const SYSTEM_PROMPT = new RegExp(`${ROLE}\\s*,\\s*${CONTENT}${LITERAL}`, "g");
const SYSTEM_PROMPT_REVERSED = new RegExp(`${CONTENT}${LITERAL}\\s*,\\s*${ROLE}`, "g");

/**
 * A documentation or tutorial bundle prints example code that contains a role:"system" message.
 * Code fences, <pre>/<code> blocks and highlighter markup just before the literal mark it as
 * something being shown to a reader, not sent to a model.
 */
const DOCS_CONTEXT = /```|<pre\b|<code\b|\bhljs\b|language-(?:js|ts|javascript|typescript|json)\b/i;
const DOCS_LOOKBEHIND = 400;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

/**
 * The system prompt text itself, when the passive check above finds one —
 * exported so an active probe (promptInjectionProbe.ts) can use it as
 * independent ground truth, without re-parsing it back out of a finding's
 * evidence string.
 *
 * Returned UNESCAPED, as the model receives it. The raw source literal has \n and \' still
 * written out, and comparing that against a reply (which has real newlines and apostrophes) made a
 * fully leaked prompt score 49 of 182 in plain text and a prompt of short lines score zero.
 */
export function extractSystemPromptText(js: string): string | null {
  for (const re of [SYSTEM_PROMPT, SYSTEM_PROMPT_REVERSED]) {
    for (const prompt of js.matchAll(re)) {
      const at = prompt.index ?? 0;
      if (DOCS_CONTEXT.test(js.slice(Math.max(0, at - DOCS_LOOKBEHIND), at))) continue;
      const raw = prompt[2] ?? prompt[3];
      if (raw !== undefined) return unescapeJsLiteral(raw);
    }
  }
  return null;
}

export function scanAiUsage(js: string): ScanVulnerability[] {
  const out: ScanVulnerability[] = [];

  const callHost = FETCH_CALL.exec(js)?.[1] ?? configWithCredential(js);
  const flag = BROWSER_FLAG.test(js);
  if (callHost || flag) {
    const signals = [
      callHost ? `Request aimed straight at ${callHost}` : null,
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

  // The same extraction the probe uses, so the passive finding and the probe's input cannot drift apart.
  const text = extractSystemPromptText(js);
  if (text !== null) {
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
