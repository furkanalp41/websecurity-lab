<?php
// SPDX-License-Identifier: MIT
//
// wp-admin/admin-ajax.php — the WordPress AJAX front controller (homage).
//
// Real WordPress dispatches `?action=NAME` to hooks registered as
// `wp_ajax_NAME` (logged-in) or `wp_ajax_nopriv_NAME` (anonymous). The slider
// plugin registered its markup action for BOTH — so it is reachable with NO
// authentication and NO nonce, which is the pre-auth surface this lab is about.
require_once '/opt/lab/wp-load.php';

/** @var wpdb $wpdb */
global $wpdb;

$action = isset($_REQUEST['action']) ? (string) $_REQUEST['action'] : '';

switch ($action) {
    case 'ls_get_popup_markup':
        ls_get_popup_markup($wpdb);
        break;
    default:
        // WordPress admin-ajax echoes a bare '0' for any unregistered action.
        header('Content-Type: text/html; charset=UTF-8');
        echo '0';
        break;
}

/**
 * Unauthenticated action: return the popup markup for a slider by id.
 *
 * The response is ALWAYS the same 200 + static markup regardless of whether a
 * row was found, whether the SQL errored, or what the injected condition
 * evaluated to. The single observable an attacker can influence is the response
 * LATENCY — making this a pure time-based blind injection.
 */
function ls_get_popup_markup(wpdb $wpdb): void
{
    $id = isset($_REQUEST['id']) ? (string) $_REQUEST['id'] : '0';

    // Baseline security policy runs before the query, exactly like ModSecurity +
    // CRS sitting in front of Apache, and a per-IP token-bucket rate limiter.
    waf_inspect($id);
    ratelimit_check();

    // VULNERABILITY (CWE-89): the developer "used prepare(), so it's safe" — but
    // $id is concatenated into the query STRING (PHP interpolates it here) and no
    // %d placeholder is bound for it. wpdb::prepare() therefore returns the query
    // untouched, and $id is parsed as SQL. A payload like
    //   id = 0 OR (SELECT SLEEP/**/(0.6) FROM wp_users WHERE user_login=0x61...)
    // smuggles a conditional delay into the WHERE clause.
    $sql = $wpdb->prepare(
        "SELECT id, name, html FROM {$wpdb->prefix}ls_sliders WHERE id = $id AND flag_hidden = 0"
    );

    // The row is deliberately ignored: the response must not vary with it.
    $wpdb->get_row($sql);

    header('Content-Type: application/json');
    echo json_encode([
        'success' => true,
        'data'    => [
            'markup' => '<div class="ls-popup" data-ls="popup">' .
                        '<h3>Subscribe</h3><p>Join the Acme newsletter.</p></div>',
        ],
    ]);
}
