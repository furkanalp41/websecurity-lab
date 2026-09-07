<?php
// SPDX-License-Identifier: MIT
header('Content-Type: text/html; charset=UTF-8');
?><!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Acme Marketing</title></head>
<body>
<h1>Acme Marketing</h1>
<p>Powered by a WordPress-style CMS with the <strong>LS Slider</strong> plugin (v7.9.11).</p>
<p>Popup markup is served by the plugin's AJAX action:</p>
<pre>GET /wp-admin/admin-ajax.php?action=ls_get_popup_markup&amp;id=1</pre>
<p>Recovered the admin credential hash? Submit it:</p>
<pre>POST /solve   {"hash":"&lt;value&gt;"}</pre>
</body></html>
