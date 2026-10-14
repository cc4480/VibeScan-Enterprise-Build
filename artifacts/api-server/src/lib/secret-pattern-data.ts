/**
 * Data module: regex patterns used to detect secrets in JavaScript source.
 * Extracted from jsScanner.ts to reduce that file's line count.
 */

import { VENDOR_SECRET_PATTERNS } from "./secret-pattern-vendors";
import { GENERIC_SECRET_PATTERNS } from "./secret-pattern-generic";
import { MORE_VENDOR_PATTERNS } from "./secret-pattern-more";
import type { ScanVulnerability } from "./scanner";

export interface SecretPattern {
  name: string;
  pattern: RegExp;
  severity: ScanVulnerability["severity"];
  cvssScore?: number;
  description: string;
  solution: string;
  cweId: string;
  // Return false to suppress a match (false positive filter)
  // `before` is up to 60 characters of the text that precedes the match, for validators that
  // need to see what the value is the value OF (an `example:` field, say).
  validate?: (match: string, before?: string) => boolean;
  /**
   * Set for patterns that recognise a value by the NAME it is assigned to (password, secret, apiKey)
   * rather than by a vendor's token format. In a third party's script that name is the vendor's own
   * widget code, so the match says nothing about the scanned site and is not attributed to it.
   */
  firstPartyOnly?: boolean;
  /**
   * Set for patterns whose match is not a vendor token and has its own way of telling real from
   * template (JWTs are judged by their payload, PEM keys by their body). Every other pattern also
   * has its match checked by isPlaceholderToken in scanContent, so xxxxxxxx and 00000000 filler
   * is never reported as a live credential.
   */
  skipPlaceholderCheck?: boolean;
}

export const SECRET_PATTERNS: SecretPattern[] = [...VENDOR_SECRET_PATTERNS, ...MORE_VENDOR_PATTERNS, ...GENERIC_SECRET_PATTERNS];
