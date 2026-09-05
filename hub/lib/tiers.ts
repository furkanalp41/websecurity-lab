// SPDX-License-Identifier: MIT
export const TIER_COLOR: Record<string, string> = {
  apprentice: 'var(--tier-apprentice)',
  practitioner: 'var(--tier-practitioner)',
  expert: 'var(--tier-expert)',
  elite: 'var(--tier-elite)',
};

export const TIER_LABEL: Record<string, string> = {
  apprentice: 'Apprentice',
  practitioner: 'Practitioner',
  expert: 'Expert',
  elite: 'Elite',
};

export const TRACK_LABEL: Record<string, string> = {
  sqli: 'SQL Injection',
  xss: 'XSS',
  'auth-oauth-jwt-saml': 'Auth · OAuth · JWT · SAML',
  ssrf: 'SSRF',
  'idor-bola-access-control': 'IDOR · BOLA · Access Control',
  'smuggling-cache-desync': 'Smuggling · Cache Desync',
  deserialization: 'Deserialization',
  'ssti-csti': 'SSTI · CSTI',
  'race-and-logic': 'Race · Logic',
  'xxe-xml-xslt-xpath': 'XXE · XML · XSLT · XPath',
  'command-injection-upload-fileread': 'Cmd Injection · Upload · File Read',
  'prototype-pollution': 'Prototype Pollution',
  'graphql-api-owasp-top10': 'GraphQL · API Top 10',
  'client-side-and-browser-attacks': 'Client-Side · Browser',
  'crypto-in-web': 'Crypto in Web',
  'modern-and-misc': 'Modern · Misc',
  'hackerone-2024-2026': 'HackerOne 2024–2026',
  'yeswehack-intigriti-2024-2026': 'YesWeHack · Intigriti',
  'ctftime-web-2024-2026': 'CTFtime Web',
  'cve-web-2024-2026': 'CVE Web',
};

export function trackLabel(track: string): string {
  return TRACK_LABEL[track] ?? track;
}
