/** Keeps credentials out of anything sent to a third-party language model. */

/**
 * Last line of defence before anything leaves for the language model.
 *
 * The scanners already mask secrets where they find them (jsScanner, cookie
 * values). This does not rely on that: whatever evidence text reaches the
 * prompt is scrubbed of anything shaped like a credential, so a scanner that
 * forgot to redact cannot leak a customer's key to a third party. The model
 * only ever explains findings; it never needs the secret itself. Exported for tests.
 */
export function redactForLlm(text: string): string {
  return text
    .replace(/eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}/g, "<redacted-jwt>")
    .replace(/\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{8,}/g, "<redacted-key>")
    .replace(/\bsk-[A-Za-z0-9_-]{16,}/g, "<redacted-key>")
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "<redacted-key>")
    .replace(/\bgh[pousr]_[A-Za-z0-9]{20,}/g, "<redacted-key>")
    .replace(/\bAIza[0-9A-Za-z_-]{30,}/g, "<redacted-key>")
    .replace(/(\/\/[^\s:@/]+:)[^\s@/]+@/g, "$1<redacted>@")
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{12,}/gi, "Bearer <redacted>")
    .replace(
      /\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|auth)(["']?\s*[:=]\s*["']?)[^\s"',;&]{6,}/gi,
      "$1$2<redacted>",
    )
    .replace(/[A-Za-z0-9+/_-]{40,}={0,2}/g, "<redacted-long-value>");
}

/** DEEPSEEK_SEND_EVIDENCE=false sends finding names and descriptions only, no evidence text. */
export const sendEvidence = () => process.env["DEEPSEEK_SEND_EVIDENCE"]?.trim().toLowerCase() !== "false";
