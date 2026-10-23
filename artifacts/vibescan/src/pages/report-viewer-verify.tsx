/** The banner under the report cover: what is waiting on domain verification, and where to fix it. */
import { Link } from "wouter";
import { ShieldCheck, ArrowRight } from "lucide-react";
import { verificationGap, scannedHost, verifyHref, exampleList } from "@/lib/coverage-gap";
import type { CoverageTest } from "./shared-report-coverage";

/**
 * Shown to the report's owner only. A public share link has no business sending a reader to
 * verify somebody else's domain, so the shared report does not render this.
 *
 * Renders nothing when the scan skipped nothing for want of a verified domain, so a scan of a
 * verified site is unchanged. It makes no promise about what verifying will find, and none that
 * every listed test will then run: some also need a test login, or only run when the site uses
 * that service. It does not say the rest of the report ran either, because tests skipped for
 * other reasons (no repository supplied, say) are not counted here; the coverage card lists them.
 */
export function VerifyBanner({ tests, targetUrl }: { tests: CoverageTest[] | null | undefined; targetUrl: string }) {
  const gap = verificationGap(tests);
  if (gap.count === 0) return null;

  const host = scannedHost(targetUrl);
  const examples = exampleList(gap.names);

  return (
    <div
      role="region"
      aria-label="Tests waiting on domain verification"
      className="mb-8 rounded-2xl border border-primary/30 bg-primary/5 p-5 sm:p-6 flex flex-col sm:flex-row sm:items-center gap-4"
    >
      <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0">
        <ShieldCheck className="w-5 h-5 text-primary" />
      </div>
      <div className="flex-1 min-w-0">
        <h2 className="font-bold text-base mb-1">
          {gap.count} of {gap.total} tests are waiting on domain verification
        </h2>
        <p className="text-sm text-muted-foreground">
          Active tests only run against a site you have proven you own. Verifying is free: add one DNS record or
          upload one small file.
          {examples && <> Once it is verified, the next scan can try {examples}; some of these also need a test login, or only run when the site uses that service.</>}{" "}
          Tests skipped for any other reason are listed, each with its reason, under &ldquo;What this scan tested&rdquo;.
        </p>
      </div>
      <Link
        href={verifyHref(targetUrl)}
        className="shrink-0 inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-primary text-primary-foreground text-sm font-semibold hover:shadow-[0_0_20px_rgba(20,184,120,0.4)] transition-all"
      >
        <span className="break-all text-center">Verify {host ?? "this domain"}</span> <ArrowRight className="w-4 h-4 shrink-0" />
      </Link>
    </div>
  );
}
