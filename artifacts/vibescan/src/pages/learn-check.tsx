import { Link, useRoute } from "wouter";
import { Shield, ArrowRight, AlertTriangle, ExternalLink, Info } from "lucide-react";
import { useSeo } from "@/lib/seo";
import { APP_ORIGIN } from "@/lib/origin";
import NotFound from "./not-found";
import { SeverityBadge, CodeBlock } from "./learn-parts";
import { LEARN_LAST_REVIEWED, checkById, categoryOfCheck, checkPath, checkPageTitle, checkPageDescription } from "./learn-checks";

/** One check on its own page, at /learn/<id>: the answer first, then the detail. */
export default function LearnCheckPage() {
  const [, params] = useRoute("/learn/:id");
  const check = params ? checkById(params.id) : undefined;
  const category = check ? categoryOfCheck(check.id) : undefined;

  // An unknown id must not become an indexable page: NotFound sets noindex itself, and
  // the server answers 404 for it before the client is involved.
  useSeo(
    check
      ? { title: checkPageTitle(check), description: checkPageDescription(check), canonical: `${APP_ORIGIN}${checkPath(check.id)}` }
      : {},
  );

  if (!check || !category) return <NotFound />;
  const related = category.checks.filter((c) => c.id !== check.id);

  return (
    <article className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 pb-24">
      <nav aria-label="Breadcrumb" className="pt-4 pb-6 text-sm text-muted-foreground">
        <Link href="/learn" className="hover:text-foreground">Security documentation</Link>
        <span aria-hidden="true"> › </span>
        <span>{category.label}</span>
      </nav>

      <header className="mb-8">
        <div className="flex flex-wrap items-center gap-2 mb-4">
          <SeverityBadge severity={check.severity} />
          {check.owasp && (
            <span className="px-2.5 py-1 rounded-full bg-primary/10 border border-primary/20 text-xs text-primary font-semibold font-mono">
              OWASP {check.owasp}
            </span>
          )}
          {check.cweId && (
            <a
              href={`https://cwe.mitre.org/data/definitions/${check.cweId.replace("CWE-", "")}.html`}
              target="_blank" rel="noopener noreferrer"
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-white/5 border border-white/10 text-xs text-muted-foreground hover:text-foreground font-mono"
            >
              {check.cweId} <ExternalLink className="w-2.5 h-2.5" />
            </a>
          )}
          {check.wstgId && (
            <span className="px-2.5 py-1 rounded-full bg-white/5 border border-white/10 text-xs text-muted-foreground font-mono">{check.wstgId}</span>
          )}
        </div>
        <h1 className="text-3xl md:text-4xl font-bold tracking-tight mb-4">{check.title}</h1>
        {/* The answer, before anything else: what a search result or an answer engine quotes. */}
        <p className="text-lg text-muted-foreground leading-relaxed">{check.what}</p>
      </header>

      <section className="mb-6 flex gap-3 p-4 rounded-xl bg-orange-500/5 border border-orange-500/20">
        <AlertTriangle className="w-4 h-4 text-orange-400 shrink-0 mt-1" aria-hidden="true" />
        <div>
          <h2 className="text-xs font-semibold uppercase tracking-wider text-orange-400/70 mb-1">Why it matters</h2>
          <p className="text-sm text-muted-foreground leading-relaxed">{check.why}</p>
        </div>
      </section>

      <section className="mb-6 flex gap-3 p-4 rounded-xl bg-primary/5 border border-primary/20">
        <Shield className="w-4 h-4 text-primary shrink-0 mt-1" aria-hidden="true" />
        <div>
          <h2 className="text-xs font-semibold uppercase tracking-wider text-primary/70 mb-1">How SecScan tests this</h2>
          <p className="text-sm text-muted-foreground leading-relaxed">{check.howTested}</p>
        </div>
      </section>

      <section className="mb-6">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground/60 mb-2">How to fix it</h2>
        <p className="text-sm text-muted-foreground leading-relaxed mb-1">{check.fix}</p>
        {check.fixCode && <CodeBlock code={check.fixCode} lang={check.fixCodeLang} />}
        {check.learnMore && (
          <a href={check.learnMore} target="_blank" rel="noopener noreferrer" className="mt-4 inline-flex items-center gap-1.5 text-sm text-primary hover:underline">
            <Info className="w-3.5 h-3.5" aria-hidden="true" /> Learn more <ExternalLink className="w-3 h-3" aria-hidden="true" />
          </a>
        )}
      </section>

      {related.length > 0 && (
        <section className="mb-10">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground/60 mb-2">Related checks in {category.label}</h2>
          <ul className="space-y-1.5">
            {related.map((c) => (
              <li key={c.id}>
                <Link href={checkPath(c.id)} className="text-sm text-primary hover:underline">{c.title}</Link>
              </li>
            ))}
          </ul>
        </section>
      )}

      <p className="text-xs text-muted-foreground mb-8">
        Last reviewed {LEARN_LAST_REVIEWED}. The full list of checks is in the{" "}
        <Link href="/learn" className="text-primary hover:underline">security documentation</Link>.
      </p>

      <div className="glass-card rounded-2xl p-8 text-center border border-primary/20 bg-primary/5">
        <h2 className="text-xl font-bold mb-2">Does your app pass this check?</h2>
        <p className="text-muted-foreground mb-5 text-sm">SecScan tests it, and dozens more, in one scan. Usually in under a minute.</p>
        <Link href="/scan" className="inline-flex items-center gap-2 px-8 py-3 bg-primary text-primary-foreground font-bold rounded-xl hover:brightness-110">
          Scan your app <ArrowRight className="w-4 h-4" aria-hidden="true" />
        </Link>
      </div>
    </article>
  );
}
