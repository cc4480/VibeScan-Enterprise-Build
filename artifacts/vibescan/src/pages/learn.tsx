import { useState, useEffect, useRef } from "react";
import { Link } from "wouter";
import { Shield, ArrowRight } from "lucide-react";
import { cn } from "@/lib/utils";
import { useSeo } from "@/lib/seo";
import { APP_ORIGIN } from "@/lib/origin";
import type { Severity } from "./learn-types";
import { LEARN_CATEGORIES as CATEGORIES, LEARN_LAST_REVIEWED } from "./learn-checks";
import { SEV_CONFIG, CheckAccordion } from "./learn-parts";

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function LearnPage() {
  useSeo({
    title: "Security Documentation — SecScan.us",
    description: "Plain-English guides to the key security checks SecScan runs: HTTPS, HSTS, CSP, CORS, cookie flags and Supabase RLS, each with a code fix to paste.",
    canonical: `${APP_ORIGIN}/learn`,
  });

  const [activeCategory, setActiveCategory] = useState(CATEGORIES[0].id);
  const tabsRef = useRef<HTMLDivElement>(null);

  const currentCategory = CATEGORIES.find((c) => c.id === activeCategory) ?? CATEGORIES[0];
  const CategoryIcon = currentCategory.icon;

  const allChecks = CATEGORIES.flatMap((c) => c.checks);
  const totalChecks = allChecks.length;
  const criticalCount = allChecks.filter((c) => c.severity === "critical").length;

  // Scroll active tab into view on mobile
  useEffect(() => {
    const el = tabsRef.current?.querySelector(`[data-cat="${activeCategory}"]`) as HTMLElement | null;
    el?.scrollIntoView({ inline: "center", block: "nearest", behavior: "smooth" });
  }, [activeCategory]);

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 pb-24">

      {/* Page header */}
      <div className="pt-4 pb-10 max-w-2xl">
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-semibold mb-6 uppercase tracking-wider">
          <Shield className="w-3.5 h-3.5" /> Security Reference
        </div>
        <h1 className="text-4xl md:text-5xl font-bold mb-4 tracking-tight">
          Security checks documentation
        </h1>
        <p className="text-lg text-muted-foreground mb-3">
          Plain-English explanations of the most important vulnerabilities SecScan detects — what each is, why attackers exploit it, how we test for it, and exactly how to fix it.
        </p>
        {/* This page covers the key checks, not all of them. It used to say
            "every vulnerability" while documenting 19; the complete reference is
            secscan.info, so say so rather than overclaim. */}
        <p className="text-sm text-muted-foreground mb-5">
          Every check SecScan runs is documented in full on{" "}
          <a href="https://secscan.info/coverage" className="text-primary hover:underline">secscan.info</a>
          {" "}· Last reviewed {LEARN_LAST_REVIEWED}
        </p>
        <div className="flex flex-wrap gap-4 text-sm text-muted-foreground">
          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-primary" />{totalChecks} checks documented</span>
          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-red-500" />{criticalCount} critical severity</span>
          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-zinc-400" />OWASP Top 10 mapped</span>
        </div>
      </div>

      {/* Category tabs */}
      <div
        ref={tabsRef}
        className="flex gap-1 overflow-x-auto pb-px mb-8 scrollbar-none border-b border-white/5"
        style={{ scrollbarWidth: "none" }}
      >
        {CATEGORIES.map((cat) => {
          const Icon = cat.icon;
          const isActive = cat.id === activeCategory;
          const critCount = cat.checks.filter((c) => c.severity === "critical").length;
          return (
            <button
              key={cat.id}
              data-cat={cat.id}
              onClick={() => setActiveCategory(cat.id)}
              className={cn(
                "flex items-center gap-2 px-4 py-2.5 text-sm font-medium rounded-t-lg whitespace-nowrap transition-all duration-150 border-b-2 -mb-px",
                isActive
                  ? "text-primary border-primary bg-primary/5"
                  : "text-muted-foreground border-transparent hover:text-foreground hover:bg-white/5"
              )}
            >
              <Icon className="w-3.5 h-3.5 shrink-0" />
              {cat.label}
              {critCount > 0 && (
                <span className="ml-0.5 px-1.5 py-0.5 rounded-full bg-red-500/20 text-red-400 text-xs font-bold leading-none">
                  {critCount}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Active category panel */}
      <div className="space-y-6">
        {/* Category header */}
        <div className="flex items-start gap-4 p-5 rounded-xl bg-white/[0.03] border border-white/8">
          <div className="w-10 h-10 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0">
            <CategoryIcon className="w-5 h-5 text-primary" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-3 mb-1">
              <h2 className="text-lg font-bold text-foreground">{currentCategory.label}</h2>
              <span className="px-2 py-0.5 rounded-full bg-white/5 border border-white/10 text-xs text-muted-foreground font-mono">
                {currentCategory.checks.length} {currentCategory.checks.length === 1 ? "check" : "checks"}
              </span>
            </div>
            <p className="text-sm text-muted-foreground">{currentCategory.description}</p>
          </div>
        </div>

        {/* Severity legend */}
        <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
          <span className="font-medium text-muted-foreground/60 mr-1">Severity:</span>
          {(["critical", "high", "medium", "low", "info"] as Severity[]).map((s) => {
            const count = currentCategory.checks.filter((c) => c.severity === s).length;
            if (count === 0) return null;
            const cfg = SEV_CONFIG[s];
            return (
              <span key={s} className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded-full border", cfg.pill)}>
                <span className={cn("w-1.5 h-1.5 rounded-full", cfg.dot)} />
                {cfg.label} ({count})
              </span>
            );
          })}
        </div>

        {/* Accordion list */}
        <div className="space-y-2">
          {currentCategory.checks.map((check) => (
            <CheckAccordion key={check.id} check={check} />
          ))}
        </div>

        {/* Category nav footer */}
        <div className="flex items-center justify-between pt-4 border-t border-white/5">
          <button
            onClick={() => {
              const idx = CATEGORIES.findIndex((c) => c.id === activeCategory);
              if (idx > 0) setActiveCategory(CATEGORIES[idx - 1].id);
            }}
            disabled={activeCategory === CATEGORIES[0].id}
            className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
          >
            ← Previous
          </button>
          <span className="text-xs text-muted-foreground">
            {CATEGORIES.findIndex((c) => c.id === activeCategory) + 1} / {CATEGORIES.length}
          </span>
          <button
            onClick={() => {
              const idx = CATEGORIES.findIndex((c) => c.id === activeCategory);
              if (idx < CATEGORIES.length - 1) setActiveCategory(CATEGORIES[idx + 1].id);
            }}
            disabled={activeCategory === CATEGORIES[CATEGORIES.length - 1].id}
            className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
          >
            Next →
          </button>
        </div>
      </div>

      {/* Footer CTA */}
      <div className="mt-12 glass-card rounded-2xl p-8 text-center border border-primary/20 bg-primary/5">
        <Shield className="w-10 h-10 text-primary mx-auto mb-4" />
        <h2 className="text-2xl font-bold mb-2">See how your app scores</h2>
        <p className="text-muted-foreground mb-6 max-w-md mx-auto">
          SecScan tests all of the above — plus dozens more checks — in a single automated scan. Get your grade, usually in under a minute.
        </p>
        <Link href="/scan"
          className="inline-flex items-center gap-2 px-8 py-3 bg-primary text-primary-foreground font-bold rounded-xl hover:shadow-[0_0_20px_rgba(20,184,120,0.4)] hover:-translate-y-0.5 transition-all duration-200">
          Scan your app <ArrowRight className="w-4 h-4" />
        </Link>
      </div>
    </div>
  );
}