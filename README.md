# log4j2 #4255 — `FilteredObjectInputStream` allowlist bypass via `java.rmi.MarshalledObject`

A self-contained, containerised lab that reproduces **Apache log4j2 issue
[#4255](https://github.com/apache/logging-log4j2/issues/4255)** end-to-end against the
**official Log4j 2.26.1** artifacts on **JDK 17**, with positive controls, a hardened
oracle, and a validated mitigation.

> ### ⚠️ Responsible use
> This lab contains a **working deserialization RCE** against a **currently unpatched** Log4j
> issue (#4255 is OPEN / `waiting-for-maintainer` at time of writing; no CVE assigned). It runs
> **entirely inside disposable Docker containers on your own machine** and connects to nothing
> external except Maven Central (to download the official jars) — no target is contacted.
>
> - The original reporter (U-Sec / Wujie Security) is withholding their PoC pending a fix. This
>   is an **independent reproduction** built for defender validation and detection engineering.
> - Do **not** run this against systems you do not own or are not explicitly authorised to test.
> - This demonstrates an **application-conditional** RCE, **not** a universal Log4j RCE (see *Scope*).

---

## TL;DR

Log4j's `FilteredObjectInputStream` (FOIS) is a `resolveClass`-based deserialization **allowlist**.
Its allowlist includes `java.rmi.MarshalledObject`. A `MarshalledObject` stores its payload as an
**opaque `byte[]`**, and `MarshalledObject.get()` deserializes that payload on a **fresh, unfiltered
`ObjectInputStream`** — so the allowlist never inspects the inner graph.

Log4j triggers this itself: `Log4jLogEvent$LogEventProxy` (the serialized wire form of a `LogEvent`,
since 2.8) carries the event `Message` inside a `MarshalledObject` and calls `.get()` automatically
during deserialization (`readResolve()` → `message()`). Any application that reads a serialized
`LogEvent` through FOIS therefore performs **unfiltered** deserialization of attacker bytes — and
because `message()` swallows the resulting exception and falls back to `SimpleMessage`, the receiver
logs a benign event and keeps running. **The exploit is silent.**

## Root cause (verified against `rel/2.26.1`)

| # | Location | Defect |
|---|----------|--------|
| 1 | `log4j-api …/util/internal/SerializationUtil.java` | `REQUIRED_JAVA_CLASSES` contains `java.rmi.MarshalledObject` |
| 2 | `log4j-api …/util/FilteredObjectInputStream.java` | overrides only `resolveClass()`; the `MarshalledObject` `objBytes` payload is invisible to it |
| 3 | `log4j-core …/impl/Log4jLogEvent.java` | `LogEventProxy.marshalledMessage` is a `MarshalledObject<Message>` |
| 4 | `log4j-core …/impl/Log4jLogEvent.java` | `message()` calls `marshalledMessage.get()` (filterless) and swallows all exceptions |

## What the lab runs

A faithful stand-in for the deprecated `log4j-samples` `ObjectInputStreamLogEventBridge`: an
unauthenticated TCP receiver that reads one serialized `LogEvent` per connection through FOIS.
The attacker sends a single serialized object; the oracle is a proof file written into a directory
**bind-mounted only into the receiver container**, so its appearance proves code ran inside the
receiver via deserialization.

| # | Scenario | Victim classpath | `jdk.serialFilter` | Expected |
|---|----------|------------------|--------------------|----------|
| S1 | disallowed gadget sent **top-level** | + gadget | none | **reject** — FOIS enforces its allowlist |
| S2 | same gadget **wrapped** in a `LogEvent` | + gadget | none | **rce** — auto-trigger (needs the gadget class on victim) |
| S3 | raw CommonsCollections6 **top-level** | log4j + cc-3.2.1 | none | **reject** — FOIS blocks CC |
| S4 | **CC6 spliced into the `MarshalledObject`** | log4j + cc-3.2.1 **only** | none | **rce** — no attacker class on victim |
| S5 | S4 payload | log4j + cc-3.2.1 | `!java.rmi.MarshalledObject` | **reject** — mitigation |
| S6 | S4 payload | log4j + cc-3.2.1 | `maxdepth=5;maxbytes=1000000` | **silent** — inner stream inherits the filter; CC6 too deep |
| S7 | S4 payload | log4j + **cc-3.2.2** | none | **silent** — 3.2.2 disables unsafe functor deser |

`rce` = code executed. `reject` = FOIS threw on the outer stream. `silent` = outer object processed,
no code ran (blocked deeper, or gadget version is safe).

## Run it

```bash
./run.sh            # or: make run
```

Requirements: Docker only (a JDK is pulled as `eclipse-temurin:17-jdk`). The script downloads the
official jars and **verifies them against Maven Central SHA-1** before use. Pin a different Log4j
version in the vulnerable range with `LOG4J_VERSION=2.20.0 ./run.sh`.

## Impact & attack method

* **Delivery:** a single unauthenticated ~2.8 KB TCP write of a serialized `LogEvent` to a
  FOIS-based receiver. It is **not** triggerable by getting a string logged (unlike Log4Shell) — it
  needs raw serialized bytes reaching the socket bridge.
* **Result:** arbitrary command execution in the receiver process, silently.
* **Attack path:** build a `LogEvent` → Log4j's `writeReplace()`/`writeObject()` wraps the `Message`
  in a `MarshalledObject` → the gadget hides inside its opaque `byte[]` → on the receiver,
  `readResolve()` → `message()` → `MarshalledObject.get()` opens a fresh **unfiltered** stream →
  gadget → `Runtime.exec`. `src/attacker/Attacker.java` (`poc2`) splices a pure-CommonsCollections6
  graph into the `MarshalledObject`'s `objBytes`, so **no attacker class is needed on the victim**.

## Mitigation

* **Reliable:** `-Djdk.serialFilter='!java.rmi.MarshalledObject'` on the receiver JVM (S5).
  *Caveat:* this also blocks **legitimate** serialized `LogEventProxy` objects (they use
  `MarshalledObject` too) — it is effective but not transparent to serialized-log transport.
* **Unreliable:** generic `maxdepth`/`maxbytes` filters. The process-wide filter **propagates into
  the inner `MarshalledObject` stream** and depth restarts there, so `maxdepth=5` blocks CC6 (S6)
  but a shallow gadget would pass. Chain-depth-dependent, not a boundary.
* **Structural:** eliminate Java-serialized log transport (use JSON / RFC 5424 over authenticated
  TLS); remove known gadget dependencies; don't expose legacy serialized receivers to untrusted
  networks. Upstream fix (per the issue): drop `MarshalledObject` from the allowlist **and** move
  the marshalled message to Log4j's filtered `writeWrappedObject`/`readWrappedObject`.

## Scope & honest limitations

* **Application-conditional, not a general Log4j RCE.** It requires an app that exposes an
  unauthenticated FOIS-based serialized-`LogEvent` receiver **and** has a usable gadget version on
  its classpath. Ordinary Log4j deployments run no such receiver.
* **The in-core serialized socket server existed only through 2.8.2** (`net.server.TcpSocketServer`
  was moved out of `log4j-core` in 2017; absent from 2.9.0 onward). Modern receivers are
  application/sample code, which this lab models.
* **Gadget-version-dependent.** commons-collections **3.2.1** → RCE; **3.2.2** blocks it (S7). Any
  usable gadget suffices, but "has commons-collections" is not by itself sufficient.
* `uid=0` in the lab is **container** root — there is no Docker escape; the RCE runs as the
  receiver process.
* The primitive (`MarshalledObject` defeating a `resolveClass` filter) is **known prior art**;
  see Apache discussion [#4168](https://github.com/apache/logging-log4j2/discussions/4168)
  ("Log4j 2.x deserialization hardening"). The Log4j-specific auto-trigger is the contribution of #4255.

## Layout

```
run.sh                     portable runner (checksum-pinned, hardened oracle)
Makefile                   make build | run | clean
src/victim/Receiver.java   FOIS log receiver (ObjectInputStreamLogEventBridge stand-in)
src/attacker/Attacker.java payload builder: controls, PoC-1, PoC-2 (CC6 + byte-splice)
src/attacker/EvilMessage.java  PoC-1 self-contained gadget
docs/RESULTS.md            evidence matrix + analysis
```

## References

* Issue #4255 — https://github.com/apache/logging-log4j2/issues/4255
* Discussion #4168 (deserialization hardening) — https://github.com/apache/logging-log4j2/discussions/4168
* Log4j CWE-502 FAQ — https://logging.apache.org/security/faq.html
* Apache Commons Collections security notice — https://commons.apache.org/proper/commons-collections/security.html

## Credits

Vulnerability reported by **U-Sec (Wujie Security)** in Apache log4j2 #4255. This repository is an
independent reproduction/validation lab for defensive research and detection engineering.
