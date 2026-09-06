# MongoDB Operator Injection on Login

## Scenario

**Acme Portal** is a small internal web app backed by MongoDB. Its API team likes
how flexible Mongo documents are, so the login handler was written to be equally
flexible: it parses the JSON request body and passes it straight to the driver as
the query filter.

```js
// POST /login
const user = await db.collection('users').findOne(req.body);
if (user) {
  /* logged in */
} else {
  /* 401 */
}
```

The developer's mental model was _"findOne with the username and password only
returns the user when both are correct."_ That is true when the body contains
plain strings. It is spectacularly false when the caller controls the **shape** of
those values — which, over JSON, they always do.

## Objective

1. Log in as **admin** without knowing the password.
2. Blind-extract the value of `admin.reset_token` (a 64-character SHA-256 hex
   string) using the login endpoint as an oracle.
3. Submit the recovered token to `POST /solve` as `{"token":"<64hex>"}` to receive
   the flag.

The flag is unique to your container and has the form `FLAG{<64 hex chars>}`.

## Getting Started

The app listens on port 8080 (mapped to a `127.0.0.1` port on your host by the lab
runner). Endpoints:

| Method | Path      | Purpose                                            |
| ------ | --------- | -------------------------------------------------- |
| GET    | `/health` | Liveness probe, returns `ok`                       |
| GET    | `/`       | API description                                    |
| POST   | `/login`  | Authenticate — **the vulnerable endpoint**         |
| POST   | `/solve`  | Submit the recovered `reset_token` to get the flag |

A normal, well-behaved login looks like this:

```bash
curl -sS -X POST http://127.0.0.1:<port>/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"hunter2"}'
# -> 401 {"authenticated":false,...}
```

You do not know any real password. That is the point — send something other than a
string and watch what the query does. Work through the hints if you get stuck, then
check `SOLUTION.md` for the full walkthrough.

## What you'll learn

- How NoSQL "operator injection" differs from classic SQL injection, and why
  JSON bodies make it so easy to reach.
- Two distinct primitives from one bug: an **authentication bypass** with `$ne`,
  and a **blind read** with `$regex`.
- Why the right fix is to constrain the query at the trust boundary — validate the
  body's types/shape (or bind fields explicitly) so operator objects can never
  reach the query engine.

## Class of bug

- **CWE-943**: Improper Neutralization of Special Elements in Data Query Logic
  (NoSQL injection).
- Related: **CWE-89** (injection into a query language) and
  **A03:2021 – Injection**.
