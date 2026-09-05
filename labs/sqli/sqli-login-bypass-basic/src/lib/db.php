<?php
// SPDX-License-Identifier: MIT
function lab_db(): PDO {
    $path = getenv('LAB_DB') ?: '/var/lib/lab/app.db';
    $pdo = new PDO('sqlite:' . $path);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    return $pdo;
}
