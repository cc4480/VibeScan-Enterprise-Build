/**
 * Finding secrets in JavaScript text: the pattern scan, and the redaction that keeps a found secret out of the
 * report. Pure functions with no network. Split from jsScanner.ts, which re-exports all three.
 */
import { type SecretPattern, SECRET_PATTERNS } from "./secret-pattern-data";
import { isPlaceholderToken } from "./secretPlaceholders";

// ─────────────────────────────────────────────────────────────────────────────
// SCAN FOR SECRETS
// ─────────────────────────────────────────────────────────────────────────────

export function redactSecret(match: string): string {
  if (match.length <= 8) return "***";
  return match.slice(0, 6) + "..." + match.slice(-4);
}

/**
 * The surrounding code shown as evidence, with every secret in it masked.
 *
 * Masking only the matched value is not enough: the context window is taken
 * around that value, so it contains it in full, and bundles tend to keep their
 * keys side by side, so it usually contains the neighbours too. A report is
 * stored, emailed and sent to the AI analysis step — the one place a live key
 * must never be written out whole.
 *
 * Three passes, each catching what the last cannot: the match itself, anything
 * any secret pattern recognises, and — as a backstop for a key cut in half at
 * the window's edge, where no pattern can match it — any long unbroken
 * token-shaped run. Over-masking a harmless identifier costs nothing here.
 */
export function redactContext(context: string, match: string): string {
  let out = context.split(match).join(redactSecret(match));
  for (const p of SECRET_PATTERNS) {
    const all = new RegExp(p.pattern.source, "g" + (p.pattern.flags.includes("i") ? "i" : ""));
    out = out.replace(all, (m) => redactSecret(m));
  }
  return out.replace(/[A-Za-z0-9+/=_-]{24,}/g, (m) => redactSecret(m));
}

/**
 * Exported so a source scan of a public GitHub repository (githubSourceProbe.ts)
 * can reuse the exact same pattern list and matching logic against fetched file
 * text, rather than duplicating it.
 */
export function scanContent(content: string): Array<{ pattern: SecretPattern; match: string; context: string }> {
  const findings: Array<{ pattern: SecretPattern; match: string; context: string }> = [];

  for (const p of SECRET_PATTERNS) {
    const globalPattern = new RegExp(p.pattern.source, "g" + (p.pattern.flags.includes("i") ? "i" : ""));
    let m: RegExpExecArray | null;
    while ((m = globalPattern.exec(content)) !== null) {
      const match = m[0];
      if (p.validate && !p.validate(match, content.slice(Math.max(0, m.index - 60), m.index))) continue;
      // Algolia DocSearch's apiKey is a search-only key beside its indexName: public by design, as configSecrets.ts already says.
      if (p.name === "API Key in Client Code (verify restrictions)" && /\bindexName\b|\bdocsearch\b/i.test(content.slice(Math.max(0, m.index - 400), m.index + 400))) continue;
      // Filler in a vendor token's shape (sk_live_xxxxxxxx, ghp_0000..., Slack's documented webhook)
      // is a template, not a credential: see secretPlaceholders.ts.
      if (!p.skipPlaceholderCheck && isPlaceholderToken(match)) continue;
      // A template variable ({{ password }}, ${PASSWORD}, <%= pw %>, %(pw)s) is where a value will go, not a value.
      if (/\{\{[^}]*\}\}|\$\{[^}]*\}|<%[^%]*%>|%\([^)]*\)s/.test(match)) continue;

      // Get surrounding context (2 lines before/after)
      const start = Math.max(0, m.index - 100);
      const end = Math.min(content.length, m.index + match.length + 100);
      const context = content.slice(start, end).replace(/\n/g, " ").trim();

      findings.push({ pattern: p, match, context });
      break; // Only report once per pattern per file
    }
  }

  return findings;
}
