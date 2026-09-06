// SPDX-License-Identifier: MIT
// Idempotent seed for the `users` collection.
//
// The admin document (inserted FIRST, so it is the first natural-order match) has:
//   - username: "admin"
//   - password: a random, unguessable value (NOT the objective)
//   - reset_token: a per-container 64-hex SHA-256 string generated with the crypto
//     module. This is the secret the learner must blind-extract through the $regex
//     login oracle and submit to /solve. It is generated fresh for every container
//     and stored only in MongoDB (on a tmpfs) — it is never baked into the image
//     or the source.
//
// A couple of decoy users follow so the collection looks realistic and so the
// {"$ne": null} bypass demonstrably selects the FIRST document (admin).
'use strict';

const crypto = require('crypto');
const { connect, usersCollection } = require('./db');

function randomHex(bytes) {
  return crypto.randomBytes(bytes).toString('hex');
}

// A 64-char hex string, SHA-256 of random entropy — matches the "reset_token =
// 64-hex SHA-256" contract while remaining unpredictable per container.
function freshResetToken() {
  return crypto.createHash('sha256').update(crypto.randomBytes(32)).digest('hex');
}

async function seed() {
  await connect();
  const users = usersCollection();

  const count = await users.countDocuments();
  if (count > 0) {
    console.log('[seed] users already present (%d) — nothing to do', count);
    return;
  }

  const docs = [
    {
      username: 'admin',
      password: randomHex(24), // random; recovering this is NOT the objective
      reset_token: freshResetToken(), // the blind-extraction target
      role: 'administrator',
      email: 'admin@lab.internal',
    },
    {
      username: 'editor',
      password: randomHex(24),
      reset_token: freshResetToken(),
      role: 'editor',
      email: 'editor@lab.internal',
    },
    {
      username: 'support',
      password: randomHex(24),
      reset_token: freshResetToken(),
      role: 'support',
      email: 'support@lab.internal',
    },
  ];

  // insertMany preserves order → admin is the first document in the collection.
  await users.insertMany(docs, { ordered: true });
  console.log('[seed] inserted %d users (admin first)', docs.length);
}

seed()
  .then(async () => {
    // Close the seed's connection so this short-lived process exits cleanly; the
    // server process opens its own connection.
    const mongoose = require('mongoose');
    await mongoose.disconnect();
    process.exit(0);
  })
  .catch((err) => {
    console.error('[seed] failed:', err && err.message ? err.message : err);
    process.exit(1);
  });
