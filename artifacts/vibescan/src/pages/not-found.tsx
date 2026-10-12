import { Link } from "wouter";
import { AlertCircle } from "lucide-react";
import { Layout } from "@/components/layout";
import { useSeo } from "@/lib/seo";

export default function NotFound() {
  // A URL that does not exist must not be offered to a search engine, and the
  // canonical has to name this URL rather than whatever page was entered on.
  useSeo({ title: "Page not found", noindex: true });

  return (
    <Layout>
      <div className="flex min-h-[60vh] flex-col items-center justify-center px-4 text-center">
        <div className="glass-panel max-w-md rounded-2xl p-8">
          <AlertCircle className="mx-auto mb-4 h-10 w-10 text-primary" aria-hidden="true" />
          <h1 className="mb-2 text-2xl font-bold text-foreground">Page not found</h1>
          <p className="mb-6 text-sm text-muted-foreground">
            That address doesn't exist on SecScan. It may have moved, or the link may have a typo.
          </p>
          <div className="flex flex-col items-center justify-center gap-3 sm:flex-row">
            <Link
              href="/"
              className="rounded-xl bg-primary px-5 py-2.5 text-sm font-bold text-primary-foreground shadow-[0_0_24px_rgba(20,184,120,0.25)] transition-all hover:brightness-110"
            >
              Back to the home page
            </Link>
            <Link href="/scan" className="text-sm text-primary underline-offset-4 hover:underline">
              Scan an app
            </Link>
          </div>
        </div>
      </div>
    </Layout>
  );
}
