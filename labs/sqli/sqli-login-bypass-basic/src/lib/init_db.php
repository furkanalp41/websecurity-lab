<?php
// SPDX-License-Identifier: MIT
// Initialises the SQLite database with a seeded, unpredictable admin password.
require_once '/opt/lab/db.php';
$db = lab_db();
$db->exec('DROP TABLE IF EXISTS users');
$db->exec('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL)');
// The root password is random and known to nobody — the point is you never need it.
$ins = $db->prepare('INSERT INTO users (username, password, role) VALUES (?,?,?)');
$ins->execute(['root',   bin2hex(random_bytes(24)), 'admin']);
$ins->execute(['editor', bin2hex(random_bytes(12)), 'user']);
$ins->execute(['guest',  'guest',                   'user']);
fwrite(STDERR, "[init_db] seeded users (root password is random and unknown)\n");
