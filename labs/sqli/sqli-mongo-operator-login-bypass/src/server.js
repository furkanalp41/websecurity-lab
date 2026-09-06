// SPDX-License-Identifier: MIT
//
// "Acme Portal" login API — deliberately vulnerable to MongoDB operator injection
// (CWE-943 / NoSQL injection).
//
// The bug lives in POST /login: the JSON request body is parsed and handed
// DIRECTLY to the native driver as the query filter:
//
//     db.collection('users').findOne(req.body)
//
// The developer expected req.body to look like {"username":"x","password":"y"} and
// reasoned "findOne with the username and password returns the user only when both
// are correct". But nothing constrains the SHAPE of the values. A caller can send
// operator OBJECTS instead of scalars, e.g.
//
//     {"username":{"$ne":null},"password":{"$ne":null}}   -> matches the first user
//
// and log in without any credentials, or turn the endpoint into a blind oracle:
//
//     {"username":"admin","reset_token":{"$regex":"^ab"}}  -> 200 iff the token
//                                                             starts with "ab"
//
// Because the WHOLE body becomes the filter, any field on the document (including
// reset_token) is probeable, and $regex lets an attacker read it one character at
// a time from the difference between a 200 (match) and a 401 (no match).
//
// /solve is written the correct way (a fixed, non-injectable query) and only
// returns the per-container flag once the attacker submits the exact reset_token.
'use strict';

const fs = require('fs');
const express = require('express');
const { connect, usersCollection } = require('./db');

const FLAG_PATH = process.env.FLAG_PATH || '/var/lib/lab/flag.txt';
const PORT = 8080;

const app = express();
// Parse JSON bodies. Nested operator objects like {"$ne": null} parse into plain
// JS objects here — which is exactly how they reach the query filter below.
app.use(express.json({ limit: '64kb' }));

app.get('/health', (_req, res) => {
  res.type('text/plain').send('ok');
});

app.get('/', (_req, res) => {
  res
    .type('text/plain')
    .send(
      [
        'Acme Portal API',
        '',
        'POST /login  {"username":"<name>","password":"<pass>"}  -> authenticate',
        'POST /solve  {"token":"<reset_token>"}                  -> claim the flag',
        '',
        'GET  /health -> ok',
      ].join('\n') + '\n',
    );
});

// ---------------------------------------------------------------------------
// VULNERABLE ENDPOINT (CWE-943): the parsed body is used as the Mongo filter
// verbatim, so operator objects reach the query engine.
// ---------------------------------------------------------------------------
app.post('/login', async (req, res) => {
  let user = null;
  try {
    const filter = req.body; // attacker-controlled shape, forwarded directly
    if (filter && typeof filter === 'object' && !Array.isArray(filter)) {
      user = await usersCollection().findOne(filter);
    }
  } catch (err) {
    // Stay "blind": a malformed/rejected query is reported like a failed login,
    // never as a distinct error, so the oracle only ever emits 200 vs 401.
    user = null;
  }

  if (user) {
    return res.status(200).json({
      authenticated: true,
      username: user.username,
      role: user.role || 'user',
      message: 'Welcome back, ' + user.username,
    });
  }
  return res.status(401).json({ authenticated: false, message: 'Invalid credentials' });
});

// ---------------------------------------------------------------------------
// /solve — NOT injectable on purpose. Uses a fixed query for the admin row and
// compares the submitted token to the stored per-container reset_token. Reads the
// flag by OPENING the file in code (never a shell-exec) only on an exact match.
// ---------------------------------------------------------------------------
app.post('/solve', async (req, res) => {
  const body = req.body || {};
  const submitted = typeof body.token === 'string' ? body.token : '';

  let realToken = '';
  try {
    const admin = await usersCollection().findOne({ username: 'admin' });
    realToken = admin && typeof admin.reset_token === 'string' ? admin.reset_token : '';
  } catch (err) {
    realToken = '';
  }

  if (submitted && realToken && submitted === realToken) {
    let flag = '(flag unavailable)';
    try {
      flag = fs.readFileSync(FLAG_PATH, 'utf8').trim();
    } catch (err) {
      /* leave placeholder */
    }
    return res.status(200).json({ ok: true, flag });
  }
  return res.status(200).json({ ok: false });
});

async function main() {
  await connect();
  app.listen(PORT, '0.0.0.0', () => {
    // eslint-disable-next-line no-console
    console.log('[app] listening on 0.0.0.0:%d', PORT);
  });
}

main().catch((err) => {
  console.error('[app] fatal:', err && err.message ? err.message : err);
  process.exit(1);
});
