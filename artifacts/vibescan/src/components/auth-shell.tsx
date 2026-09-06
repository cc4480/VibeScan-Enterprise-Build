/**
 * Shared chrome for the account screens.
 *
 * Sign in, register, forgot password, reset password and verify email are the
 * same object with different fields, so they share one shell rather than five
 * near-identical copies that drift apart.
 */

import { type FormEvent, type ReactNode } from "react";
import { Link } from "wouter";
import { Loader2, ShieldCheck } from "lucide-react";

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
        <span className="text-lg font-bold tracking-tight">SecScan</span>
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
        <p role="status" className="text-sm text-emerald-400 leading-relaxed">
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
