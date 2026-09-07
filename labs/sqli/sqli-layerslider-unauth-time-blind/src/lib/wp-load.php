<?php
// SPDX-License-Identifier: MIT
//
// Minimal WordPress-style bootstrap + $wpdb shim (~130 LOC).
//
// This is NOT WordPress. It is a deliberately small homage that reproduces one
// real-world footgun: `$wpdb->prepare()` gives developers a false sense that a
// query is parameterised, but it only substitutes/escapes the *placeholder
// arguments* you pass. If a developer concatenates untrusted input straight into
// the query string and passes NO placeholder for it, prepare() hands the string
// back untouched — and the injection is live. This is the class of bug behind
// CVE-2024-2879 (LayerSlider). No vendor code is reproduced.

declare(strict_types=1);

/** The wpdb shim: a very small subset of WordPress' $wpdb. */
final class wpdb
{
    public string $prefix = 'wp_';
    private ?mysqli $link = null;

    public function __construct()
    {
        // mysqli in exception mode so connection failures are catchable, but note
        // that QUERY errors are swallowed on purpose in the read helpers below:
        // this endpoint must stay a pure timing oracle (no leaked SQL error).
        mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
        $this->link = new mysqli(
            getenv('DB_HOST') ?: 'db',
            getenv('DB_USER') ?: 'wpapp',
            getenv('DB_PASSWORD') ?: '',
            getenv('DB_NAME') ?: 'wpdb',
            (int) (getenv('DB_PORT') ?: 3306)
        );
        $this->link->set_charset('utf8mb4');
    }

    public function link(): mysqli
    {
        return $this->link;
    }

    /**
     * A faithful-enough model of wpdb::prepare().
     *
     * WordPress' prepare() walks the query for %d/%s/%f/%i placeholders and
     * substitutes the given $args (integers cast, strings escaped+quoted). The
     * critical property this shim preserves: it ONLY touches the placeholder
     * arguments. Any text the caller already concatenated into $query — for
     * example a raw request value spliced in with "... id = $id ..." — is passed
     * through verbatim. Call prepare() with a query that has no placeholders and
     * no args, and you get your (possibly attacker-controlled) string straight
     * back. That is exactly how the vulnerable action below misuses it.
     */
    public function prepare(string $query, ...$args): string
    {
        if (count($args) === 0) {
            // No placeholders bound -> nothing to substitute. WordPress returns
            // the query unchanged here (modern versions add a _doing_it_wrong
            // notice but still return the string). The concatenated input rides
            // straight through.
            return $query;
        }
        // Safe path (used by callers that actually bind values, e.g. /solve).
        $i = 0;
        return preg_replace_callback(
            '/%[dsfi]/',
            function (array $m) use (&$i, $args): string {
                $val = $args[$i] ?? '';
                $i++;
                switch ($m[0]) {
                    case '%d': return (string) (int) $val;
                    case '%f': return (string) (float) $val;
                    case '%i': return '`' . str_replace('`', '``', (string) $val) . '`';
                    default:   return "'" . $this->link->real_escape_string((string) $val) . "'";
                }
            },
            $query
        );
    }

    /** Run a query; return the first row as an assoc array, or null. Errors are
     *  swallowed so no SQL error text ever reaches the client. */
    public function get_row(string $sql): ?array
    {
        try {
            $res = @$this->link->query($sql);
        } catch (\Throwable $e) {
            return null;
        }
        if (!($res instanceof mysqli_result)) {
            return null;
        }
        $row = $res->fetch_assoc();
        $res->free();
        return $row ?: null;
    }

    /** Run a query; return a single scalar (first column of first row) or null.
     *  Used by the CORRECT, parameterised /solve path. */
    public function get_var(string $sql): ?string
    {
        try {
            $res = @$this->link->query($sql);
        } catch (\Throwable $e) {
            return null;
        }
        if (!($res instanceof mysqli_result)) {
            return null;
        }
        $row = $res->fetch_row();
        $res->free();
        return $row ? (string) $row[0] : null;
    }
}

// ---- bootstrap ------------------------------------------------------------
// Load the security-policy helpers once, then expose a global $wpdb, just like a
// WordPress plugin would find it already initialised.
require_once __DIR__ . '/waf.php';
require_once __DIR__ . '/ratelimit.php';

$GLOBALS['wpdb'] = new wpdb();
