/**
 * "Continue with Google".
 *
 * Deliberately an <a>, not a <button> with a fetch. OAuth requires a top-level
 * navigation: the browser has to leave the site, land on Google, and come back
 * with a code in the URL. An XHR cannot do that, and a popup adds a blocker to
 * work around for no benefit here.
 *
 * `returnTo` is passed through so the server can send the person back where
 * they started; the server only honours same-site paths.
 */

export function GoogleButton({
  returnTo = "/dashboard",
  label = "Continue with Google",
}: {
  returnTo?: string;
  label?: string;
}) {
  const href = `/api/auth/google?returnTo=${encodeURIComponent(returnTo)}`;

  return (
    <a
      href={href}
      className="w-full px-4 py-2.5 bg-secondary/60 hover:bg-secondary border border-white/10 rounded-lg text-sm font-semibold flex items-center justify-center gap-2.5 transition-colors"
    >
      {/* Google's mark, in its published colours. Sized to the text, and
          aria-hidden because the label already names the action. */}
      <svg width="16" height="16" viewBox="0 0 18 18" aria-hidden="true" focusable="false">
        <path
          fill="#4285F4"
          d="M17.64 9.2c0-.64-.06-1.25-.16-1.84H9v3.48h4.84a4.14 4.14 0 0 1-1.8 2.72v2.26h2.92c1.7-1.57 2.68-3.88 2.68-6.62Z"
        />
        <path
          fill="#34A853"
          d="M9 18c2.43 0 4.47-.8 5.96-2.18l-2.92-2.26c-.81.54-1.84.86-3.04.86-2.34 0-4.32-1.58-5.03-3.7H.96v2.34A8.997 8.997 0 0 0 9 18Z"
        />
        <path
          fill="#FBBC05"
          d="M3.97 10.72A5.41 5.41 0 0 1 3.68 9c0-.6.1-1.18.29-1.72V4.94H.96A8.997 8.997 0 0 0 0 9c0 1.45.35 2.82.96 4.06l3.01-2.34Z"
        />
        <path
          fill="#EA4335"
          d="M9 3.58c1.32 0 2.5.45 3.44 1.35l2.58-2.59C13.46.89 11.43 0 9 0A8.997 8.997 0 0 0 .96 4.94l3.01 2.34C4.68 5.16 6.66 3.58 9 3.58Z"
        />
      </svg>
      {label}
    </a>
  );
}

/** A labelled divider, for placing the button beside the email form. */
export function AuthDivider({ label = "or" }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 my-4" role="separator">
      <span className="h-px flex-1 bg-white/10" />
      <span className="text-xs uppercase tracking-wider text-muted-foreground">{label}</span>
      <span className="h-px flex-1 bg-white/10" />
    </div>
  );
}
