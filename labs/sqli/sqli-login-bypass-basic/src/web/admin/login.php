<?php
// SPDX-License-Identifier: MIT
// VULNERABLE admin login: raw POST fields concatenated into a SQLite query.
require_once '/opt/lab/db.php';
session_save_path('/tmp');
session_start();

$error = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = isset($_POST['username']) ? $_POST['username'] : '';
    $p = isset($_POST['password']) ? $_POST['password'] : '';
    // VULNERABILITY (CWE-89): no prepared statement, no escaping, no allowlist.
    $sql = "SELECT id, username, role FROM users WHERE username='" . $u . "' AND password='" . $p . "'";
    $row = false;
    try {
        $stmt = lab_db()->query($sql);
        $row = $stmt ? $stmt->fetch(PDO::FETCH_ASSOC) : false;
    } catch (Throwable $e) {
        // Verbose errors on purpose — teaches error-based recon.
        $error = 'SQL error: ' . $e->getMessage();
    }
    if ($row) {
        session_regenerate_id(true);
        $_SESSION['uid'] = $row['id'];
        $_SESSION['username'] = $row['username'];
        $_SESSION['role'] = $row['role'];
        header('Location: /admin/dashboard');
        exit;
    } elseif ($error === null) {
        $error = 'Invalid credentials.';
    }
}
?>
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Guestbook Admin — Login</title></head>
<body style="font-family:monospace;background:#0b0f14;color:#e6f7ee;max-width:520px;margin:6rem auto;padding:0 1rem;">
<h1>Guestbook Admin</h1>
<p style="color:#8a9ba2;">Intranet tool v0.3 — staff only.</p>
<?php if ($error !== null): ?><p style="color:#ffb020;"><?php echo htmlspecialchars($error, ENT_QUOTES); ?></p><?php endif; ?>
<form method="post" action="/admin/login">
  <p><label>Username<br><input name="username" autofocus></label></p>
  <p><label>Password<br><input name="password" type="password"></label></p>
  <p><button type="submit">Sign in</button></p>
</form>
<!-- TODO: fix later — switch to prepared statements before launch. -->
</body></html>
