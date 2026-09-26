/**
 * Fix-prompt instructions for sites on a hosting or site-builder platform, where the
 * right fix is a platform setting or config file rather than framework code.
 *
 * Each instruction tells the model to stay inside what the platform really offers and
 * to say so when a finding cannot be fixed there. A fix that names a setting the
 * platform does not have is worse than "this cannot be changed on <platform>".
 */

export type HostEnvironment = "vercel" | "netlify" | "firebase" | "hosted";

export function hostPromptInstructions(host: HostEnvironment, domain: string): string {
  switch (host) {
    case "vercel":
      return `AGENT TARGET: Vercel-hosted site (IDE AI agent with file access)
The site is served by Vercel and no framework was detected, so it is likely static or a small serverless project.

Rules for agentFixPrompt:
- Open with: "I ran a security scan on ${domain} and found these issues. Please fix them in my Vercel project."
- Response headers and redirects go in vercel.json under "headers" (source, then a headers array of key/value) or in the framework's own config if one exists
- Environment variables and secrets are set in the Vercel dashboard under Project Settings, Environment Variables, never committed
- For each finding give the exact file and the exact JSON or code to add
- If a finding cannot be fixed on Vercel or needs the app's own code, say so instead of guessing
- Close with: "Show me the exact change for each file."`;

    case "netlify":
      return `AGENT TARGET: Netlify-hosted site (IDE AI agent with file access)
The site is served by Netlify and no framework was detected, so it is likely static.

Rules for agentFixPrompt:
- Open with: "I ran a security scan on ${domain} and found these issues. Please fix them in my Netlify site."
- Response headers go in a _headers file in the publish directory, or in netlify.toml under [[headers]] with for = "/*" and [headers.values]
- Redirects go in _redirects or netlify.toml; environment variables are set in Site configuration, Environment variables
- For each finding give the exact file and the exact lines to add
- If a finding cannot be fixed on Netlify or needs the app's own code, say so instead of guessing
- Close with: "Show me the exact change for each file."`;

    case "firebase":
      return `AGENT TARGET: Firebase (backend and hosting)
The app uses Firebase and no framework was detected.

Rules for agentFixPrompt:
- Open with: "Fix these security issues in my Firebase project:"
- Group fixes into labeled sections: "Security rules:" (Firestore, Realtime Database and Storage rules, exact rule text), "Firebase Console changes:" (navigation paths), "firebase.json:" (hosting headers), "Code changes:"
- A Firebase web API key is designed to be public; never tell the user to hide it. The protection is in the security rules and, where offered, App Check and API key restrictions in Google Cloud Console
- Never suggest rules that allow all reads or writes; require request.auth and scope by ownership
- Close with: "Apply the rules, the console changes and the code changes, and tell me what you changed."`;

    case "hosted":
    default:
      return `AGENT TARGET: Hosted site builder (Shopify, Wix, Squarespace or Webflow)
The site runs on a hosted platform where the owner cannot edit server code or response headers directly.

Rules for agentFixPrompt:
- Open with: "Here are the security findings for ${domain} and what I can do about each:"
- Split every finding into "I can fix this" (a setting or content change the platform really offers, with the dashboard path) and "The platform controls this" (server headers, TLS and similar), and be explicit about which is which
- For "the platform controls this", recommend reporting it to the platform's support, and do not invent a setting to change it
- For scripts and apps the owner added, tell them to remove or replace the specific third-party app or embed
- Never suggest editing server files, .htaccess or code the owner has no access to
- Close with: "Tell me which of these you can do yourself and which need the platform."`;
  }
}
