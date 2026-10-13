/**
 * Stack notes for sites on a hosting or site-builder platform, where the right fix is a
 * platform setting or config file rather than framework code.
 *
 * These are facts about the platform that go into the one tool-neutral fix prompt (see
 * deepseek-prompts.ts). Each note tells the model to stay inside what the platform really
 * offers and to say so when a finding cannot be fixed there. A fix that names a setting the
 * platform does not have is worse than "this cannot be changed on <platform>".
 */

export type HostEnvironment = "vercel" | "netlify" | "firebase" | "hosted";

export function hostStackNotes(host: HostEnvironment): string {
  switch (host) {
    case "vercel":
      return `Vercel-hosted site, no framework detected (likely static or a small serverless project).
- Response headers and redirects go in vercel.json under "headers" (source, then a headers array of key/value) or in the framework's own config if one exists
- Environment variables and secrets are set in the Vercel dashboard under Project Settings, Environment Variables, never committed
- For each finding give the exact file and the exact JSON or code to add
- If a finding cannot be fixed on Vercel or needs the app's own code, say so instead of guessing`;

    case "netlify":
      return `Netlify-hosted site, no framework detected (likely static).
- Response headers go in a _headers file in the publish directory, or in netlify.toml under [[headers]] with for = "/*" and [headers.values]
- Redirects go in _redirects or netlify.toml; environment variables are set in Site configuration, Environment variables
- For each finding give the exact file and the exact lines to add
- If a finding cannot be fixed on Netlify or needs the app's own code, say so instead of guessing`;

    case "firebase":
      return `Firebase project (backend and hosting), no framework detected.
- Group Firebase fixes under labeled parts: "Security rules" (Firestore, Realtime Database and Storage rules, exact rule text), "Firebase Console changes" (navigation paths), "firebase.json" (hosting headers), "Code changes"
- A Firebase web API key is designed to be public; never tell the user to hide it. The protection is in the security rules and, where offered, App Check and API key restrictions in Google Cloud Console
- Never suggest rules that allow all reads or writes; require request.auth and scope by ownership`;

    case "hosted":
    default:
      return `Hosted site builder (Shopify, Wix, Squarespace or Webflow): the owner cannot edit server code or response headers directly.
- Split every finding into "I can fix this" (a setting or content change the platform really offers, with the dashboard path) and "The platform controls this" (server headers, TLS and similar), and be explicit about which is which
- For "the platform controls this", recommend reporting it to the platform's support, and do not invent a setting to change it
- For scripts and apps the owner added, tell them to remove or replace the specific third-party app or embed
- Never suggest editing server files, .htaccess or code the owner has no access to`;
  }
}
