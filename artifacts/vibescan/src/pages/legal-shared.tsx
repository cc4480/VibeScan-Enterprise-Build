/** Shared bits of the legal pages. */
// Privacy Policy and Terms of Service, rendered from one component because they
// share a layout and differ only in content. Both are real, indexable pages at
// stable paths (/privacy, /terms) rather than anchors inside a larger page:
// Google's OAuth consent screen requires a reachable privacy-policy URL, and
// Stripe requires published terms. An anchor is both weaker legally and fragile
// if the surrounding page is reorganised.
//
// Deliberately plain: these are read, not marketed at.

// Per document: a change to one must not re-date the other.
export const LAST_UPDATED: Record<"privacy" | "terms", string> = {
  privacy: "September 30, 2026", // AI opt-out described; GitHub option, created test account, credential deletion, Google named
  terms: "October 3, 2026", // One unlimited plan replaces Starter, Pro and credit packs; fair use stated
};

export const CONTACT = "hello@secscan.us";

export function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-10">
      <h2 className="text-lg sm:text-xl font-bold tracking-tight mb-4">{title}</h2>
      <div className="space-y-3 text-sm sm:text-[15px] leading-relaxed text-muted-foreground">
        {children}
      </div>
    </section>
  );
}
