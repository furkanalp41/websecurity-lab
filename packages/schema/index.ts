// SPDX-License-Identifier: MIT
import enums from './enums.json' with { type: 'json' };

export const OWASP_TOP10_2021: readonly string[] = enums.owasp_top10_2021;
export const OWASP_API_TOP10_2023: readonly string[] = enums.owasp_api_top10_2023;
export const CWE: readonly string[] = enums.cwe;

/** The 20 canonical track/category slugs (mirror `data/catalog.json`). */
export const CATEGORIES = [
  'sqli',
  'xss',
  'auth-oauth-jwt-saml',
  'ssrf',
  'idor-bola-access-control',
  'smuggling-cache-desync',
  'deserialization',
  'ssti-csti',
  'race-and-logic',
  'xxe-xml-xslt-xpath',
  'command-injection-upload-fileread',
  'prototype-pollution',
  'graphql-api-owasp-top10',
  'client-side-and-browser-attacks',
  'crypto-in-web',
  'modern-and-misc',
  'hackerone-2024-2026',
  'yeswehack-intigriti-2024-2026',
  'ctftime-web-2024-2026',
  'cve-web-2024-2026',
] as const;
export type Category = (typeof CATEGORIES)[number];

export const DIFFICULTIES = ['apprentice', 'practitioner', 'expert', 'elite'] as const;
export type Difficulty = (typeof DIFFICULTIES)[number];

/** Materialized flag literal shape: FLAG{<64 lowercase hex>}. */
export const FLAG_RE = /^FLAG\{[0-9a-f]{64}\}$/;

export function isOwasp(value: string): boolean {
  return OWASP_TOP10_2021.includes(value) || OWASP_API_TOP10_2023.includes(value);
}
export function isCwe(value: string): boolean {
  return CWE.includes(value);
}
