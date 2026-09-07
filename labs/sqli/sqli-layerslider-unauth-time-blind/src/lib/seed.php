<?php
// SPDX-License-Identifier: MIT
//
// seed.php — CLI, run once at container start (entrypoint). Waits for MariaDB,
// then creates and seeds the WordPress-style schema (idempotent).
//
// A RANDOM 16-hex value is generated HERE and stored in wp_users.user_pass for
// user_login='admin'. It never touches the image or the source tree: it lives
// only in this container's MariaDB datadir (a tmpfs) and is recoverable solely
// through the time-based blind injection in the admin-ajax action. A flag lifted
// from another learner's instance can therefore never validate on yours.
//
// Lab-vs-production deviation: a real WordPress stores a ~34-char phpass hash
// ($P$B...) in user_pass. Here it is a 16-char lowercase-hex token so a rate-
// limited, time-based extraction clears the platform's "<60s exploit" gate. The
// extraction technique is byte-for-byte identical at any length. See SOLUTION.md.

declare(strict_types=1);

$cfg = [
    'host' => getenv('DB_HOST') ?: 'db',
    'user' => getenv('DB_USER') ?: 'wpapp',
    'pass' => getenv('DB_PASSWORD') ?: '',
    'name' => getenv('DB_NAME') ?: 'wpdb',
    'port' => (int) (getenv('DB_PORT') ?: 3306),
];

mysqli_report(MYSQLI_REPORT_OFF);
$link = null;
for ($attempt = 0; $attempt < 60; $attempt++) {
    $link = @new mysqli($cfg['host'], $cfg['user'], $cfg['pass'], $cfg['name'], $cfg['port']);
    if ($link instanceof mysqli && $link->connect_errno === 0) {
        break;
    }
    if ($attempt === 0) {
        fwrite(STDERR, "[seed] waiting for database...\n");
    }
    $link = null;
    sleep(1);
}
if (!($link instanceof mysqli)) {
    fwrite(STDERR, "[seed] database never became ready\n");
    exit(1);
}
$link->set_charset('utf8mb4');

$link->query(
    'CREATE TABLE IF NOT EXISTS wp_users (' .
    '  ID BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,' .
    '  user_login VARCHAR(60) NOT NULL,' .
    '  user_pass  VARCHAR(255) NOT NULL,' .
    '  user_email VARCHAR(100) NOT NULL DEFAULT ""' .
    ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
);
$link->query(
    'CREATE TABLE IF NOT EXISTS wp_options (' .
    '  option_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,' .
    '  option_name  VARCHAR(191) NOT NULL,' .
    '  option_value LONGTEXT NOT NULL' .
    ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
);
$link->query(
    'CREATE TABLE IF NOT EXISTS wp_ls_sliders (' .
    '  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,' .
    '  name VARCHAR(190) NOT NULL,' .
    '  html LONGTEXT NOT NULL,' .
    '  flag_hidden TINYINT(1) NOT NULL DEFAULT 0' .
    ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
);

// Seed the admin user with a random per-container 16-hex secret in user_pass.
$res = $link->query("SELECT COUNT(*) AS c FROM wp_users WHERE user_login='admin'");
$row = $res ? $res->fetch_assoc() : ['c' => 1];
if ((int) $row['c'] === 0) {
    $secret = bin2hex(random_bytes(8)); // 16 lowercase hex chars, 64 bits
    $stmt = $link->prepare('INSERT INTO wp_users (user_login, user_pass, user_email) VALUES (?, ?, ?)');
    $login = 'admin';
    $email = 'admin@example.test';
    $stmt->bind_param('sss', $login, $secret, $email);
    $stmt->execute();
    $stmt->close();
}

// A couple of published sliders so the "plugin" looks alive; none matter to the
// challenge (the vulnerable action ignores the returned row and always renders
// the same static markup).
$res = $link->query('SELECT COUNT(*) AS c FROM wp_ls_sliders');
$row = $res ? $res->fetch_assoc() : ['c' => 1];
if ((int) $row['c'] === 0) {
    $link->query(
        "INSERT INTO wp_ls_sliders (name, html, flag_hidden) VALUES " .
        "('Homepage Hero','<div class=\"ls-slide\">Welcome</div>',0)," .
        "('Summer Sale','<div class=\"ls-slide\">50% off</div>',0)," .
        "('Draft Promo','<div class=\"ls-slide\">unpublished</div>',1)"
    );
}

// A little flavour in wp_options, WordPress-style.
$res = $link->query("SELECT COUNT(*) AS c FROM wp_options");
$row = $res ? $res->fetch_assoc() : ['c' => 1];
if ((int) $row['c'] === 0) {
    $link->query(
        "INSERT INTO wp_options (option_name, option_value) VALUES " .
        "('blogname','Acme Marketing'),('template','twentytwentyfour')," .
        "('ls_plugin_version','7.9.11')"
    );
}

fwrite(STDERR, "[seed] wordpress-style store ready\n");
$link->close();
