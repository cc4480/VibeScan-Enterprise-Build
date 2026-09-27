/**
 * Shared chrome for the account screens.
 *
 * Sign in, register, forgot password, reset password and verify email are the
 * same object with different fields, so they share one shell rather than five
 * near-identical copies that drift apart.
 */

import { type FormEvent, type ReactNode } from "react";
import { Link } from "wouter";
import { Loader2, ShieldCheck, MailSearch } from "lucide-react";

/**
 * Shown wherever the next step depends on an email actually arriving.
 *
 * secscan.us is a young sending domain, so mail authenticates correctly
 * (SPF, DKIM and DMARC all pass) and still lands in Junk for some recipients
 * on reputation alone — most often Outlook and Hotmail. A sign-in code in the
 * spam folder is indistinguishable from a broken login, and the person is
 * already locked out, so telling them where to look costs nothing and is the
 * difference between signing in and giving up.
 *
 * The "not spam" ask is not filler: it is the one action the recipient can
 * take that actually improves where our next message lands for them, and it
 * feeds the provider's own reputation signal for the domain.
 */
export function CheckSpamNote({ what = "email" }: { what?: string }) {
  return (
    <div className="mt-5 flex gap-2.5 rounded-lg border border-border bg-muted/40 px-3.5 py-3">
      <MailSearch className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
      <p className="text-xs leading-relaxed text-muted-foreground">
        <span className="font-medium text-foreground">Don't see the {what}?</span>{" "}
        Check your spam or junk folder — we're a new sender, so mail sometimes
        lands there. Marking it <span className="font-medium text-foreground">"Not spam"</span>{" "}
        helps the next one reach your inbox.
      </p>
    </div>
  );
}

export function AuthShell({
  title,
  subtitle,
  children,
  footer,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
  footer?: ReactNode;
}) {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center px-4 py-12">
      <Link href="/" className="flex items-center gap-2 mb-8 group">
        <ShieldCheck className="w-6 h-6 text-primary" />
        <span className="text-lg font-bold tracking-tight">SecScan<span className="text-primary">.us</span></span>
      </Link>

      <div className="w-full max-w-sm">
        <h1 className="text-2xl font-bold tracking-tight mb-1.5">{title}</h1>
        {subtitle ? (
          <p className="text-sm text-muted-foreground mb-6 leading-relaxed">{subtitle}</p>
        ) : (
          <div className="mb-6" />
        )}

        {children}

        {footer ? <div className="mt-6 text-sm text-muted-foreground">{footer}</div> : null}
      </div>
    </div>
  );
}

export function AuthForm({
  onSubmit,
  error,
  notice,
  submitting,
  submitLabel,
  submittingLabel,
  children,
  disabled,
}: {
  onSubmit: (e: FormEvent<HTMLFormElement>) => void;
  error?: string | null;
  notice?: string | null;
  submitting: boolean;
  submitLabel: string;
  submittingLabel: string;
  children: ReactNode;
  disabled?: boolean;
}) {
  return (
    <form onSubmit={onSubmit} className="flex flex-col gap-4">
      {children}

      {/* role="alert" so the message is announced, not just shown. */}
      {error ? (
        <p role="alert" className="text-sm text-red-400 leading-relaxed">
          {error}
        </p>
      ) : null}
      {notice ? (
        <p role="status" className="text-sm text-green-400 leading-relaxed">
          {notice}
        </p>
      ) : null}

      <button
        type="submit"
        disabled={submitting || disabled}
        className="w-full px-4 py-2.5 bg-primary text-primary-foreground rounded-lg text-sm font-semibold disabled:opacity-60 disabled:cursor-not-allowed flex items-center justify-center gap-2 transition-opacity"
      >
        {submitting ? (
          <>
            <Loader2 className="w-4 h-4 animate-spin" />
            {submittingLabel}
          </>
        ) : (
          submitLabel
        )}
      </button>
    </form>
  );
}

export function Field({
  label,
  hint,
  ...props
}: { label: string; hint?: string } & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="text-sm font-medium">{label}</span>
      <input
        {...props}
        className="px-3 py-2.5 rounded-lg bg-secondary border border-white/10 text-sm outline-none focus:border-primary/60 focus:ring-2 focus:ring-primary/20 transition-colors"
      />
      {hint ? <span className="text-xs text-muted-foreground">{hint}</span> : null}
    </label>
  );
}
