/**
 * One-time tokens (email verification, password reset) arrive in the address bar. They are read once,
 * then removed from the address bar so they stay out of history, screenshots and copied links.
 */

type UrlWindow = { location: { href: string }; history: { state: unknown; replaceState: (state: unknown, unused: string, url?: string | URL | null) => void } };

/** The `token` query parameter of the current address, or "". Reading does not change the address. */
export function tokenInUrl(win: UrlWindow | undefined = typeof window === "undefined" ? undefined : window): string {
  if (!win) return "";
  return new URL(win.location.href).searchParams.get("token") ?? "";
}

/** Removes the `token` query parameter from the address bar, keeping the path, other parameters and hash. Idempotent. */
export function clearTokenFromUrl(win: UrlWindow | undefined = typeof window === "undefined" ? undefined : window): void {
  if (!win) return;
  const url = new URL(win.location.href);
  if (!url.searchParams.has("token")) return;
  url.searchParams.delete("token");
  win.history.replaceState(win.history.state, "", url.pathname + url.search + url.hash);
}
