/** False-positive filters shared by the generic secret patterns. */
import { shannonEntropy, looksLikeAName, looksLikeReference } from "./secretPlaceholders";

/**
 * UI text or an i18n key that a password-named property holds, not a password:
 * "Enter your password here please", "Must contain 8 characters and a symbol", "auth.form.password".
 * Entropy cannot tell these from a secret, since English text scores as high as a passphrase.
 */
export function looksLikeInterfaceText(value: string): boolean {
  const tokens = value.trim().split(/\s+/);
  if (tokens.length >= 2 && tokens.filter((t) => /^[A-Za-z]{2,}[.,!?:;]*$/.test(t)).length >= 2) return true;
  return /^[A-Za-z]+(?:\.[A-Za-z]+)+$/.test(value.trim()) || looksLikeAName(value);
}

/**
 * Shared placeholder and entropy filter for the two generic key patterns, so
 * they cannot drift apart: a value is worth reporting only when it is neither
 * an obvious template, nor a reference to where the value comes from, nor the
 * name of a variable, nor low-entropy filler. The name and placeholder tests
 * live in secretPlaceholders.ts.
 */
export function isRealSecretValue(match: string): boolean {
  if (/your[_-]?(api[_-]?)?key|insert[_-]?key|replace[_-]?me|XXXXXXXX/i.test(match)) return false;
  if (/EXAMPLE|PLACEHOLDER|YOUR_|<|>|\*{3,}|\.{3,}/i.test(match)) return false;
  const valMatch = /[:=]\s*["']([^"']+)["']/.exec(match);
  if (!valMatch) return false;
  const value = valMatch[1]!;
  return !looksLikeReference(value) && !looksLikeAName(value) && shannonEntropy(value) >= 3.0;
}
