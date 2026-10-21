/**
 * The consent screen's decisions, kept out of the component so they can be tested.
 * The server has already verified the request (routes/oauthConsent.ts); this only
 * decides what the person sees and where the browser goes.
 */

export interface ConsentPreview {
  client: { name: string };
  redirect: { host: string; kind: "web" | "local" | "app" };
  account: string;
  access: string[];
  consent: string;
}

export type PreviewOutcome =
  /** Not signed in (or not a registered account): send them to sign in and back here. */
  | { kind: "signin"; to: string }
  /** The request itself is bad (unknown app, unregistered address). Tell the person; never redirect. */
  | { kind: "invalid"; message: string }
  /** The request was fine to read but wrong; the standard says tell the app. */
  | { kind: "back"; url: string }
  | { kind: "consent"; preview: ConsentPreview };

/** Sign-in, returning to this same authorization request afterwards. */
export function signInUrl(pathWithSearch: string): string {
  return `/sign-in?returnTo=${encodeURIComponent(pathWithSearch)}`;
}

/** Turn the server's answer (or failure) to the preview call into what the page does next. */
export function outcomeOf(status: number, body: unknown, pathWithSearch: string): PreviewOutcome {
  const b = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
  if (status === 401) return { kind: "signin", to: signInUrl(pathWithSearch) };
  if (status >= 400) {
    const message = typeof b["error_description"] === "string" ? b["error_description"] : "This link is not valid.";
    return { kind: "invalid", message };
  }
  if (typeof b["redirectUrl"] === "string") return { kind: "back", url: b["redirectUrl"] };
  if (typeof b["consent"] === "string" && typeof b["client"] === "object" && b["client"] !== null) return { kind: "consent", preview: b as unknown as ConsentPreview };
  return { kind: "invalid", message: "This link is not valid." };
}

/** The sentence under the buttons: where they will land, in words that fit what the address is. */
export function whereTo(redirect: ConsentPreview["redirect"]): string {
  if (redirect.kind === "local") return "You'll be sent back to an app running on your own computer.";
  if (redirect.kind === "app") return `You'll be sent back to an app on your device (${redirect.host}).`;
  return `You'll be sent back to ${redirect.host}. Only continue if you started this from that service.`;
}

/** Only ever navigate to what the server built: an app's own return address, never something the page assembled. */
export function isSafeReturn(url: string): boolean {
  try {
    const u = new URL(url);
    return !["javascript:", "data:", "file:", "vbscript:", "blob:", "about:"].includes(u.protocol);
  } catch {
    return false;
  }
}

/**
 * The return address must be the one the consent preview described: the same scheme and host as the
 * registered redirect (the preview carries the host, not the whole URL). A scheme check alone would let
 * any https address through.
 */
export function isReturnFor(url: string, redirect: ConsentPreview["redirect"]): boolean {
  if (!isSafeReturn(url)) return false;
  try {
    const u = new URL(url);
    if (redirect.kind === "web") return u.protocol === "https:" && u.host === redirect.host;
    if (redirect.kind === "local") return u.protocol === "http:" && u.host === redirect.host;
    // App addresses are shown as "scheme://host" (see describeRedirect on the server).
    return `${u.protocol.slice(0, -1)}://${u.host}`.replace(/\/$/, "") === redirect.host;
  } catch {
    return false;
  }
}
