<?php
// SPDX-License-Identifier: MIT
session_save_path('/tmp');
session_start();
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    header('Location: /admin/login');
    exit;
}
$flagPath = getenv('FLAG_PATH') ?: '/var/lib/lab/flag.txt';
$flag = @file_get_contents($flagPath);
$flag = ($flag === false) ? '(flag unavailable)' : trim($flag);
$user = htmlspecialchars($_SESSION['username'], ENT_QUOTES);
?>
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Guestbook Admin — Dashboard</title></head>
<body style="font-family:monospace;background:#0b0f14;color:#e6f7ee;max-width:640px;margin:4rem auto;padding:0 1rem;">
<h1>Admin Dashboard</h1>
<p>Welcome, <?php echo $user; ?> (role: admin).</p>
<h2>System flag</h2>
<pre style="color:#00ff9c;font-size:1.1rem;"><?php echo htmlspecialchars($flag, ENT_QUOTES); ?></pre>
<p><a href="/admin/login" style="color:#22d3ee;">Log out</a></p>
</body></html>
