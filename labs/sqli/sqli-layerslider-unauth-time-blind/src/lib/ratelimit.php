<?php
// SPDX-License-Identifier: MIT
//
// ratelimit.php — a small per-client-IP token bucket.
//
// State lives in a flock()-guarded file on the /tmp tmpfs (the root filesystem is
// read-only). The bucket is deliberately generous: a well-optimised extraction
// (binary search parallelised across a handful of character positions) stays
// comfortably inside it, while a naive one-request-at-a-time-with-retries scan is
// throttled — the "time-based extraction slows to a crawl" the brief describes.
// On exhaustion the endpoint returns HTTP 429 (fast, with no SLEEP), so a client
// must treat 429 as "retry", not as a FALSE timing reading.

declare(strict_types=1);

const RL_CAPACITY   = 60;    // burst size (tokens)
const RL_REFILL_PER_SEC = 30.0; // sustained refill rate
const RL_DIR = '/tmp/rl';

function ratelimit_check(): void
{
    $ip  = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $key = preg_replace('/[^0-9a-fA-F:.]/', '_', $ip);
    @mkdir(RL_DIR, 0700, true);
    $path = RL_DIR . '/' . $key;

    $fh = @fopen($path, 'c+');
    if ($fh === false) {
        return; // fail open: never let a bucket I/O error block the lab
    }
    try {
        flock($fh, LOCK_EX);
        $now = microtime(true);
        $raw = stream_get_contents($fh);
        $tokens = (float) RL_CAPACITY;
        $last   = $now;
        if ($raw !== '' && strpos($raw, ' ') !== false) {
            [$t, $l] = explode(' ', trim($raw), 2);
            $tokens = (float) $t;
            $last   = (float) $l;
        }
        // Refill for elapsed time, capped at capacity.
        $tokens = min((float) RL_CAPACITY, $tokens + ($now - $last) * RL_REFILL_PER_SEC);

        if ($tokens < 1.0) {
            $allowed = false;
        } else {
            $tokens -= 1.0;
            $allowed = true;
        }
        // Persist new state.
        ftruncate($fh, 0);
        rewind($fh);
        fwrite($fh, sprintf('%.4f %.4f', $tokens, $now));
        fflush($fh);
        flock($fh, LOCK_UN);
    } finally {
        fclose($fh);
    }

    if (!$allowed) {
        http_response_code(429);
        header('Content-Type: application/json');
        header('Retry-After: 1');
        echo json_encode(['success' => false, 'data' => ['message' => 'rate limit exceeded']]);
        exit;
    }
}
