/**
 * A page that is fetched when someone first opens it, instead of being part of the first download.
 *
 * Every page used to ship in one 1.4 MB script, so a first visit to the landing page paid for the dashboard, the report
 * viewer and the settings screens too. The signed-in pages are loaded on demand; the public pages stay in the main file
 * (they are prerendered and should paint at once).
 *
 * A deploy replaces the files an already-open tab was built against, so its next page load can ask for a file that no
 * longer exists. That is a reload away from working, so it reloads once (and says nothing); if it fails again after the
 * reload, the error is shown as it would have been.
 */
import { lazy, type ComponentType } from "react";

const RELOADED = "secscan:page-reload";

export const isStaleChunkError = (err: unknown): boolean =>
  err instanceof Error && /Failed to fetch dynamically imported module|Importing a module script failed|error loading dynamically imported module|Loading chunk/i.test(err.message);

function once(action: "get" | "set" | "clear"): boolean {
  try {
    if (action === "set") sessionStorage.setItem(RELOADED, "1");
    if (action === "clear") sessionStorage.removeItem(RELOADED);
    return action === "get" ? sessionStorage.getItem(RELOADED) === "1" : true;
  } catch {
    // Storage blocked: reloading could loop, so behave as if it had already been tried.
    return action === "get";
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function lazyPage<T extends ComponentType<any>>(load: () => Promise<{ default: T }>) {
  return lazy(async () => {
    try {
      const page = await load();
      once("clear");
      return page;
    } catch (err) {
      if (isStaleChunkError(err) && !once("get")) {
        once("set");
        window.location.reload();
        return new Promise<never>(() => {}); // the page is going away; do not render an error first
      }
      throw err;
    }
  });
}
