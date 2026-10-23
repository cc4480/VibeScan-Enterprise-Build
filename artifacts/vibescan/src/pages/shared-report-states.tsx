import { Link } from "wouter";
import { Shield, Loader2, AlertCircle, Clock } from "lucide-react";

export function SharedReportLoading() {
  return (
    <div className="min-h-[80vh] flex flex-col items-center justify-center gap-4">
      <Loader2 className="w-8 h-8 animate-spin text-primary" />
      <p className="text-sm text-muted-foreground">Loading shared report…</p>
    </div>
  );
}

/** Expired link vs. invalid or revoked link. */
export function SharedReportError({ error }: { error: { status: number; message: string } }) {
  const isExpired = error.status === 410;
  return (
    <div className="min-h-[80vh] flex flex-col items-center justify-center gap-4 max-w-md mx-auto px-4 text-center">
      <div className="w-16 h-16 rounded-full bg-secondary flex items-center justify-center">
        {isExpired ? (
          <Clock className="w-8 h-8 text-muted-foreground" />
        ) : (
          <AlertCircle className="w-8 h-8 text-muted-foreground" />
        )}
      </div>
      <h1 className="text-2xl font-bold">
        {isExpired ? "Link Expired" : "Report Not Found"}
      </h1>
      <p className="text-muted-foreground leading-relaxed">
        {isExpired
          ? "This share link has expired. Ask the report owner to generate a new link."
          : "This share link is invalid or has been revoked. It may have been deleted by the report owner."}
      </p>
      <Link
        href="/"
        className="mt-2 inline-flex items-center gap-2 px-5 py-2.5 bg-primary text-primary-foreground rounded-lg font-semibold hover:opacity-90 transition-opacity"
      >
        <Shield className="w-4 h-4" /> Run your own scan
      </Link>
    </div>
  );
}
