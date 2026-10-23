/**
 * Data module: secret patterns for AI and email/media API vendors (OpenAI, Anthropic, Resend, Replicate, ElevenLabs).
 * Extracted from secret-pattern-data.ts to keep that file's line count down.
 */

import type { SecretPattern } from "./secret-pattern-data";

export const AI_VENDOR_PATTERNS: SecretPattern[] = [
  // ── OpenAI ────────────────────────────────────────────────────────────────
  {
    name: "OpenAI API Key Exposed",
    // New project-scoped format: sk-proj-... (55+ chars)
    // Legacy format: sk-[20 random chars]T3BlbkFJ[48 chars]
    pattern: /\bsk-(?:proj-[a-zA-Z0-9_-]{50,}|[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9_-]{40,})\b/,
    severity: "critical", cvssScore: 9.8, cweId: "CWE-798",
    description: "An OpenAI API key was found in client-side JavaScript. This is the #1 secret leaked in AI-generated (vibe-coded) apps. Anyone who visits the page can copy this key and make API calls billed to your account — running up unlimited charges, accessing uploaded files, and completely bypassing your application logic.",
    solution: "IMMEDIATELY revoke this key at platform.openai.com/api-keys. Never put OpenAI keys in frontend code or prefix them with VITE_/REACT_APP_. Move all AI API calls to a backend server route (e.g. /api/chat) where the key stays in a server-side environment variable, unreachable by browsers.",
    validate: (m) => !/(EXAMPLE|YOUR.KEY|sk-xxxx|placeholder)/i.test(m),
  },

  // ── Anthropic ─────────────────────────────────────────────────────────────
  {
    name: "Anthropic (Claude) API Key Exposed",
    pattern: /\bsk-ant-(?:api03|admin|[a-zA-Z0-9]{4})-[a-zA-Z0-9_-]{90,}\b/,
    severity: "critical", cvssScore: 9.8, cweId: "CWE-798",
    description: "An Anthropic (Claude) API key was found in client-side JavaScript. This grants full API access — any visitor to your site can make Claude requests billed to your account, access your usage data, and potentially reach organization-level settings.",
    solution: "Immediately revoke this key at console.anthropic.com/settings/keys. Move all Claude API calls to a backend function. Never expose Anthropic keys in frontend code or VITE_/REACT_APP_ environment variables.",
  },

  // ── Resend ────────────────────────────────────────────────────────────────
  {
    name: "Resend API Key Exposed",
    // Resend keys are `re_` plus 8 base58 characters, `_`, and 24 base58 characters (TruffleHog's Resend
    // detector, checked 2026-10-02; base58 has no 0, O, I or l). The single run of 32+ is an older form
    // that no public detector lists, so it stays but is unverified. The prefix alone is two letters and an underscore, so it must also follow a key-ish
    // word: a bare `re_…` identifier in a bundle is not evidence of a Resend key.
    pattern: /(?<=(?:resend|api[_-]?key|bearer|authorization|token|secret)[^\n]{0,40})\bre_(?:[1-9A-HJ-NP-Za-km-z]{8}_[1-9A-HJ-NP-Za-km-z]{24}|[A-Za-z0-9]{32,})\b/i,
    severity: "high", cvssScore: 8.1, cweId: "CWE-798",
    description: "A value in Resend's API key format (re_…), next to a key or token name, was found in client-side JavaScript. If it is a live key it allows anyone to send emails from your verified domain — enabling phishing campaigns, spam, and permanent damage to your sending reputation.",
    solution: "Revoke this key at resend.com/api-keys. Move all email sending to a backend API route. Resend keys must never appear in frontend bundles.",
    validate: (m) => !/(EXAMPLE|YOUR.KEY|re_xxxx|test)/i.test(m) && m.length > 10,
  },

  // ── Replicate ─────────────────────────────────────────────────────────────
  {
    name: "Replicate API Token Exposed",
    pattern: /\br8_[a-zA-Z0-9]{40}\b/,
    severity: "high", cvssScore: 8.1, cweId: "CWE-798",
    description: "A Replicate API token was found in client-side JavaScript. Anyone can run AI models billed to your account — enabling cost exhaustion attacks and unauthorized use of any model you have access to.",
    solution: "Revoke this token at replicate.com/account/api-tokens. Move Replicate calls to a backend proxy endpoint. Never include API tokens in frontend JavaScript.",
  },

  // ── ElevenLabs ───────────────────────────────────────────────────────────
  {
    name: "ElevenLabs API Key Exposed",
    pattern: /(?:ELEVENLABS(?:_API)?_KEY|xi[_-]api[_-]key)\s*[:=]\s*["'`]?([a-f0-9]{32})["'`]?/i,
    severity: "high", cvssScore: 8.1, cweId: "CWE-798",
    description: "An ElevenLabs API key was found in client-side JavaScript. This grants access to voice synthesis billed per character — attackers can exhaust your credit and use cloned voices associated with your account.",
    solution: "Revoke this key in ElevenLabs profile settings. Move all TTS/voice synthesis calls to a backend proxy. API keys must never appear in frontend code.",
  },
];
