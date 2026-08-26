# Evidence & analysis

Target: **log4j-core 2.26.1** (Maven-Central jars, SHA-1 verified) on **eclipse-temurin:17-jdk**.
Receiver = **application code** modelling the deprecated log4j-samples `ObjectInputStreamLogEventBridge`.
It is **not** part of the log4j-core 2.26.1 jar (the in-core socket server was removed after 2.8.2).

## Oracle

Classification comes from the **receiver's own log**, never from proof-file absence alone:

- `reject` — FOIS threw on the outer stream (allowlist enforced)
- `silent` — outer object processed, but no code ran (blocked deeper, or gadget version safe)
- `rce` — proof file written by the receiver
- `infra-fail` — receiver never listened (harness fault, not a security result)

Proof files are written into a directory bind-mounted **only into the receiver container**. The
attacker container has no such mount and only writes TCP bytes; the receiver program contains no
file-writing code. So a proof file = code executed inside the receiver via deserialization.
`uid=0` is **container** root — there is no Docker escape.

## Matrix (run.sh — all PASS)

| # | Scenario | Victim classpath | jdk.serialFilter | Classified |
|---|----------|------------------|------------------|-----------|
| S1 | EvilMessage top-level (control) | log4j+cc3.2.1+EvilMessage | none | **reject** (`Class is not allowed: EvilMessage`) |
| S2 | EvilMessage wrapped (PoC-1) | log4j+cc3.2.1+EvilMessage | none | **rce** — needs attacker class on victim |
| S3 | Raw CC6 top-level (control) | log4j+cc3.2.1 | none | **reject** (`...TiedMapEntry`) |
| S4 | CC6 spliced into MarshalledObject (PoC-2) | **log4j+cc3.2.1 only** | none | **rce** — no attacker class on victim |
| S5 | S4 payload | log4j+cc3.2.1 | `!java.rmi.MarshalledObject` | **reject** (outer stream) |
| S6 | S4 payload | log4j+cc3.2.1 | `maxdepth=5;maxbytes=1000000` | **silent** — inner stream inherits filter, CC6 deeper than 5 |
| S7 | S4 payload | **log4j+cc3.2.2** | none | **silent** — 3.2.2 disables unsafe functor deser |

## Filter-inheritance detail

S6 shows the process-wide `jdk.serialFilter` **propagates into the inner `MarshalledObject`
stream** and depth counting **restarts** there: `maxdepth=5` silently blocks CC6 (which is deeper),
while `maxdepth=100` allows it (RCE). Therefore generic depth/byte limits are **chain-depth-dependent**
— they can stop a deep chain like CC6 but would miss a shallow gadget. Only a **class-pattern** filter
(`!java.rmi.MarshalledObject`, or a gadget denylist/allowlist) reliably closes the path.

## Verified conclusions

1. FOIS genuinely enforces its allowlist (S1, S3 reject).
2. The same disallowed graph, wrapped in `java.rmi.MarshalledObject`, deserializes **unfiltered**
   (`get()` opens a fresh stream over an opaque `byte[]` `resolveClass` never inspects) — S2, S4.
3. **No attacker class needed on the victim** — a usable gadget *version* is (S4 with CC 3.2.1);
   RCE is **gadget-version-dependent** (CC 3.2.2 blocks it, S7).
4. The exploit is **silent** — `message()` swallows the `ClassCastException`, falls back to `SimpleMessage`.
5. Reliable mitigation = deny filter (S5), but it also blocks legitimate serialized `LogEventProxy`.

## Scope

Application-conditional RCE, not a general Log4j 2.26.1 RCE: requires an app-provided unauthenticated
FOIS serialized-`LogEvent` receiver **and** a usable gadget version on the classpath. The primitive is
known prior art (Apache discussion #4168, 2026-07-01); the Log4j-specific auto-trigger is #4255's point.
Issue #4255 is OPEN / `waiting-for-maintainer`; best classified as a defense-in-depth hardening gap
rather than a proven standalone core CVE.
