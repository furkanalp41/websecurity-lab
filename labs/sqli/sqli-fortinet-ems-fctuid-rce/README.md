# Header SQLi to RCE with Out-of-Band Exfil

> Track: `sqli` · Difficulty: **elite** · ~70 min · Free hints.

## Scenario

`Acme EMS` is a device-management portal. Its device-registration endpoint takes
an `X-FCTUID` header and stamps it into an audit `INSERT` — and, like the
appliance it homages (Fortinet FortiClient EMS, CVE-2023-48788), does so by
string concatenation with the database driver's simple query protocol (multiple
`;`-separated statements allowed).

Two obstacles sit between you and the flag:

1. **A naive IPS** signature list blocks the header (or query string) if it
   contains `SELECT`, `UNION SELECT`, `FROM`, `INFORMATION_SCHEMA`, `SLEEP(`, or
   classic `OR n=n` tautologies. It's an over-fitted keyword list — the sort a
   real appliance ships in defaults. Loud probes get a `403 blocked_by: acme-ips`.
2. **No visible output.** The register endpoint just returns `{"ok": true}` — the
   audit rows are not queried back. And the database container is on a
   **no-egress** network, so a shell you obtain cannot reach the internet.

That "no egress" is not quite total: an in-lab **OOB collector sidecar** shares
the network and is the only listener the RCE can reach. Your job is to smuggle
command execution past the IPS, exfiltrate the flag to that collector, then read
what it captured through the app's `/oob/received` proxy.

## Objective

```
POST /device/register    header X-FCTUID: <payload that runs the RCE>
GET  /oob/received        (proxy to the in-lab collector — see what was captured)
POST /solve               {"flag":"FLAG{...}"}
```

The flag is planted on the **Postgres container filesystem** at
`/labflag/flag.txt` (never in a table), so only command execution recovers it.
The flag (`FLAG{<64 hex>}`) is unique to your container.

## Getting Started

1. Confirm the sink: send `X-FCTUID: x' ; -- ` and watch a database error come
   back. The header reaches SQL.
2. Try `X-FCTUID: any' UNION SELECT 1 -- `. You get a `403 blocked_by`. Read the
   rule name and think about what the IPS is actually pattern-matching on.
3. What Postgres feature lets you run a shell command without ever typing the
   word `SELECT`? Once you have execution, remember your listener: the DB is
   walled off from the internet, but _something_ nearby is reachable.

**CVE analog family.** Unauthenticated SQL injection in an enterprise appliance
header that reaches a superuser database role and chains into command execution
is the shape of **CVE-2023-48788 (FortiClient EMS)** and similar vendor bugs —
**CWE-89 → CWE-78**. No vendor code is reproduced.
