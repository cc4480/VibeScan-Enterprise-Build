import { useEffect } from "react";

interface SeoOptions {
  title?: string;
  description?: string;
  noindex?: boolean;
  /** Defaults to the URL being viewed. Pass one only to point elsewhere. */
  canonical?: string;
}

/**
 * The canonical for the route currently on screen.
 *
 * The server renders a correct canonical for whatever URL the browser first
 * requested, and client-side routing then changes the URL without touching it —
 * so every page reached by a link inside the app carried the entry page's
 * canonical. A report page saved from the app claimed to be /dashboard.
 *
 * Only two of fifteen pages passed a canonical explicitly, and adding it to the
 * other thirteen just moves the bug to whoever adds the fourteenth. Defaulting
 * to the current location means a page cannot forget, and a page that genuinely
 * belongs to another URL still says so by passing one.
 *
 * Trailing slash is stripped except at the root, matching the server's own
 * normalisation in lib/pageMeta.ts — two spellings of the same page is the
 * duplicate-content signal the canonical exists to prevent. Query and hash are
 * dropped: ?ref=… is the same page, and listing it as canonical invites every
 * tracking variant to be indexed separately.
 */
export function canonicalFor(origin: string, pathname: string): string {
  const path = pathname.replace(/\/+$/, "") || "/";
  return `${origin.replace(/\/+$/, "")}${path}`;
}

function currentCanonical(): string {
  return canonicalFor(window.location.origin, window.location.pathname);
}

export function useSeo({ title, description, noindex, canonical }: SeoOptions) {
  useEffect(() => {
    const prev = document.title;

    if (title) {
      document.title = title.includes("SecScan") ? title : `${title} — SecScan.us`;
    }

    let metaRobots = document.querySelector<HTMLMetaElement>('meta[name="robots"]');
    const prevRobots = metaRobots?.content ?? "index, follow";
    if (noindex) {
      if (!metaRobots) {
        metaRobots = document.createElement("meta");
        metaRobots.name = "robots";
        document.head.appendChild(metaRobots);
      }
      metaRobots.content = "noindex, nofollow";
    }

    let metaDesc = document.querySelector<HTMLMetaElement>('meta[name="description"]');
    const prevDesc = metaDesc?.content ?? "";
    if (description && metaDesc) {
      metaDesc.content = description;
    }

    let linkCanonical = document.querySelector<HTMLLinkElement>('link[rel="canonical"]');
    const prevCanonical = linkCanonical?.href ?? "";
    const href = canonical ?? currentCanonical();
    if (!linkCanonical) {
      linkCanonical = document.createElement("link");
      linkCanonical.rel = "canonical";
      document.head.appendChild(linkCanonical);
    }
    linkCanonical.href = href;

    return () => {
      document.title = prev;
      if (metaRobots) metaRobots.content = prevRobots;
      if (metaDesc && prevDesc) metaDesc.content = prevDesc;
      if (linkCanonical && prevCanonical) linkCanonical.href = prevCanonical;
    };
  }, [title, description, noindex, canonical]);
}
