import { useEffect } from "react";

interface SeoOptions {
  title?: string;
  description?: string;
  noindex?: boolean;
  canonical?: string;
}

export function useSeo({ title, description, noindex, canonical }: SeoOptions) {
  useEffect(() => {
    const prev = document.title;

    if (title) {
      document.title = title.includes("Seclayer") ? title : `${title} — Seclayer`;
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
    if (canonical) {
      if (!linkCanonical) {
        linkCanonical = document.createElement("link");
        linkCanonical.rel = "canonical";
        document.head.appendChild(linkCanonical);
      }
      linkCanonical.href = canonical;
    }

    return () => {
      document.title = prev;
      if (metaRobots) metaRobots.content = prevRobots;
      if (metaDesc && prevDesc) metaDesc.content = prevDesc;
      if (linkCanonical && prevCanonical) linkCanonical.href = prevCanonical;
    };
  }, [title, description, noindex, canonical]);
}
