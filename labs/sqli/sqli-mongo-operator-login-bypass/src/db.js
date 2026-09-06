// SPDX-License-Identifier: MIT
// Shared MongoDB connection helper. We use mongoose purely for connection
// management and then reach for the *native* driver collection
// (mongoose.connection.db.collection('users')) in the request handlers. That is a
// realistic pattern — teams standardise on mongoose for wiring but drop to the raw
// collection for "flexible" ad-hoc queries — and it is precisely what makes the
// operator-injection bug in server.js exploitable: the native driver forwards the
// filter object verbatim, with no schema casting to strip out $-operators.
'use strict';

const mongoose = require('mongoose');

const MONGO_URL = process.env.MONGO_URL || 'mongodb://db:27017/labdb';

let connectPromise = null;

// Connect once, retrying while MongoDB finishes coming up. Returns the shared
// mongoose connection. depends_on: service_healthy already gates the app on the
// DB healthcheck, but a short retry loop keeps startup robust regardless.
async function connect() {
  if (connectPromise) return connectPromise;
  connectPromise = (async () => {
    const attempts = 60;
    let lastErr;
    for (let i = 0; i < attempts; i += 1) {
      try {
        await mongoose.connect(MONGO_URL, {
          serverSelectionTimeoutMS: 2000,
          maxPoolSize: 20,
        });
        return mongoose.connection;
      } catch (err) {
        lastErr = err;
        if (i === 0) {
          // eslint-disable-next-line no-console
          console.log('[db] waiting for mongodb...');
        }
        await new Promise((r) => setTimeout(r, 1000));
      }
    }
    throw lastErr || new Error('could not connect to mongodb');
  })();
  return connectPromise;
}

// Native (uncast) users collection — the query surface the app trusts too much.
function usersCollection() {
  return mongoose.connection.db.collection('users');
}

module.exports = { connect, usersCollection, MONGO_URL };
