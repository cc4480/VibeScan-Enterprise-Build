/**
 * A URL is only ever rendered as a link when it is plainly a web address. A scanned or user-entered
 * value such as `javascript:` or `data:` must never become an href, so anything else returns undefined
 * and the caller renders the text without a link.
 */
export function safeHref(value: string | null | undefined): string | undefined {
  if (!value) return undefined;
  try {
    const u = new URL(value);
    return u.protocol === "http:" || u.protocol === "https:" ? u.href : undefined;
  } catch {
    return undefined;
  }
}
