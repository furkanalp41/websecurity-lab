<?php
// SPDX-License-Identifier: MIT
//
// POST /solve  {"hash":"<16-hex>"}
//
// Submit the recovered wp_users.user_pass (for user_login='admin') to claim the
// per-container flag. Written the CORRECT way on purpose: the stored value is
// read with a bound, parameterised query and compared in constant time. /solve
// is NOT injectable — the vulnerable endpoint is the admin-ajax action.
require_once '/opt/lab/wp-load.php';

/** @var wpdb $wpdb */
global $wpdb;

header('Content-Type: application/json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'data' => ['message' => 'POST required']]);
    return;
}

$raw  = file_get_contents('php://input') ?: '';
$body = json_decode($raw, true);
$submitted = '';
if (is_array($body) && isset($body['hash']) && is_string($body['hash'])) {
    $submitted = $body['hash'];
}

// Parameterised read: the admin's stored secret, bound (never interpolated).
$link = $wpdb->link();
$stmt = $link->prepare('SELECT user_pass FROM wp_users WHERE user_login = ? LIMIT 1');
$who  = 'admin';
$stmt->bind_param('s', $who);
$stmt->execute();
$stmt->bind_result($stored);
$stmt->fetch();
$stmt->close();

if (is_string($stored) && $stored !== '' && hash_equals($stored, $submitted)) {
    $flagPath = getenv('FLAG_PATH') ?: '/var/lib/lab/flag.txt';
    $flag = @file_get_contents($flagPath);
    if ($flag === false) {
        http_response_code(500);
        echo json_encode(['success' => false, 'data' => ['message' => 'flag unavailable']]);
        return;
    }
    echo json_encode(['success' => true, 'data' => ['flag' => trim($flag)]]);
    return;
}

http_response_code(403);
echo json_encode(['success' => false, 'data' => ['message' => 'incorrect hash']]);
