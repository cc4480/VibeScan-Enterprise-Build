import type { Category } from "./learn-types";

function esc(v: string): string {
  return v.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/**
 * The documentation as plain HTML, for readers that do not run JavaScript.
 *
 * The /learn page is drawn by React, so a crawler that does not execute scripts
 * (most AI crawlers) used to receive a one-line description of it. This renders
 * the same check data the page is built from, so the two cannot disagree. It is
 * written into dist/public/prerender/learn.html at build time (see the
 * prerender plugin in vite.config.ts) and the API server adds it to the
 * <noscript> block of /learn.
 */
export function renderLearnStatic(categories: Category[]): string {
  const out: string[] = [];
  for (const cat of categories) {
    out.push(`<section><h2>${esc(cat.label)}</h2><p>${esc(cat.description)}</p>`);
    for (const c of cat.checks) {
      const refs = [c.owasp && `OWASP ${c.owasp}`, c.cweId, c.wstgId].filter(Boolean).join(" · ");
      out.push(
        `<article id="${esc(c.id)}"><h3>${esc(c.title)}</h3>` +
          `<p><strong>Severity:</strong> ${esc(c.severity)}${refs ? ` — ${esc(refs)}` : ""}</p>` +
          `<h4>What it is</h4><p>${esc(c.what)}</p>` +
          `<h4>Why it matters</h4><p>${esc(c.why)}</p>` +
          `<h4>How SecScan tests it</h4><p>${esc(c.howTested)}</p>` +
          `<h4>How to fix it</h4><p>${esc(c.fix)}</p>` +
          (c.fixCode ? `<pre><code>${esc(c.fixCode)}</code></pre>` : "") +
          `</article>`,
      );
    }
    out.push("</section>");
  }
  return out.join("\n");
}
