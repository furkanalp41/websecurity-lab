<?php
// SPDX-License-Identifier: MIT
//
// waf.php — an application-level, CRS-baseline "paranoia 1" SQLi filter (homage).
//
// This is NOT ModSecurity + the full OWASP Core Rule Set. It is a small, honest
// stand-in modelled on the *shape* of the CRS 4.0 942xxx SQLi rules at paranoia
// level 1: it flags the loud, unmistakable injection tokens (UNION SELECT, a bare
// SLEEP(/BENCHMARK( call, `OR 1=1`, SQL line comments, information_schema) and
// lets everything else through. Like many real baseline WAFs, it inspects the
// request parameter as a single decoded string and does NOT normalise inline
// C-style comments — which is precisely the gap a student must find:
//
//   *  SLEEP(5)        -> blocked (matches the SLEEP( token rule)
//   *  SLEEP /**/ (5)  -> allowed (the comment breaks the `SLEEP(` adjacency)
//   *  'admin'         -> fine, but a quoted string in a numeric context is loud;
//                         0x61646d696e (hex) is the quieter, comment-free encoding
//
// The point is pedagogy, not perfect coverage: bypassing a baseline filter with
// inline-comment obfuscation and hex literals is a real, repeatable technique.

declare(strict_types=1);

/**
 * Inspect one request value against the baseline ruleset. On a match, emit a 403
 * and terminate the request (mirroring how a WAF blocks before the app runs).
 */
function waf_inspect(string $value): void
{
    // Inspect the parameter as the WAF sees it after transport decoding. Casing
    // tricks are handled per-rule by the /i flag below, not by folding case here.
    $v = $value;

    // Each rule is [id, human-readable message, PCRE]. The patterns intentionally
    // require literal adjacency (e.g. SLEEP directly followed by optional plain
    // whitespace and a paren) so that inline-comment obfuscation slips past — the
    // documented bypass. Comparison is case-insensitive (/i).
    $rules = [
        ['942100', 'SQL keyword pair UNION ... SELECT',       '/union\s+select/i'],
        ['942160', 'blind SQLi function SLEEP()',             '/\bsleep\s*\(/i'],
        ['942160', 'blind SQLi function BENCHMARK()',         '/\bbenchmark\s*\(/i'],
        ['942190', 'schema enumeration (information_schema)', '/\binformation_schema\b/i'],
        ['942200', 'classic tautology OR <n>=<n>',            '/\bor\s+\d+\s*=\s*\d+/i'],
        ['942210', 'classic tautology quote-OR-quote',        "/['\"]\\s*or\\s*['\"]/i"],
        ['942420', 'SQL line comment (-- or #)',              '/(?:--\s|--$|#)/'],
    ];

    foreach ($rules as [$id, $msg, $re]) {
        if (preg_match($re, $v) === 1) {
            http_response_code(403);
            header('Content-Type: application/json');
            // A terse block page, like a WAF would return. No echo of the payload.
            echo json_encode([
                'success' => false,
                'data'    => ['blocked_by' => 'security-policy', 'rule_id' => $id, 'message' => $msg],
            ]);
            exit;
        }
    }
}
