# cl-tor

A from-scratch **Tor client in Common Lisp.**

The goal is a real, usable Tor client — connect to the live Tor network, build
3-hop circuits, and expose a local **SOCKS5** proxy so any program can route
through it — implemented clean-room in Lisp, with **nothing wrapping C-tor or
Arti**. It runs on SBCL today and is written to stay portable toward
[modus](https://github.com/ynniv/modus) (the bare-metal Lisp OS), where the same
protocol core can sit on the native TCP/TLS/crypto stack instead of SBCL's.

Same recipe as its siblings [cl-nostr](../cl-nostr) and
[cl-consensus](../cl-consensus): implement the protocol from the spec, prove each
layer against official vectors, then validate against the live network.

## ⚠️ Status & disclaimer

**Early — foundation only.** The crypto suite and the ntor circuit handshake are
implemented and vector-verified; the link/circuit/directory/stream layers are not
built yet (see the roadmap). This is **research / educational software**, and
anonymity is a correctness property a young implementation cannot guarantee — do
**not** rely on it to protect anyone. No warranty (see [LICENSE](LICENSE)).

## Status

- **Crypto suite** ✅ — SHA-1/256/3, HMAC-SHA256, HKDF, AES-128-CTR, X25519,
  Ed25519, over `ironclad`. Verified: X25519 vs **RFC 7748**, HKDF vs **RFC 5869**.
- **ntor handshake** ✅ — `ntor-curve25519-sha256-1` (CREATE2/EXTEND2 key
  exchange): client + server sides, KEY_SEED/AUTH, and HKDF expansion to the four
  per-hop relay keys (Df/Db/Kf/Kb). Verified by full client↔server key agreement
  (both derive identical keys; client accepts a valid AUTH and rejects a tampered
  one / mis-addressed onion-skin).

## Roadmap

The protocol is built bottom-up; each phase is independently testable, and the
**live network is the unforgeable oracle** (a real CREATE2 only succeeds if ntor
is byte-exact).

1. **Crypto + ntor** ✅ — *done, vector-verified.*
2. **Cells + link handshake** — fixed/variable cell framing; TLS to a relay
   ORPort (`cl+ssl`, certs validated via the in-protocol CERTS cell, not a CA);
   VERSIONS/CERTS/AUTH_CHALLENGE/NETINFO. *Milestone: complete a v4 link handshake
   with a real relay.*
3. **Circuits** — CREATE2/CREATED2 (ntor) to a guard; EXTEND2/EXTENDED2 over
   RELAY_EARLY to a 3-hop circuit; per-hop AES-CTR + SHA-1 onion crypto.
   *Milestone: build a real 3-hop circuit on the live network — the ntor KAT.*
4. **Directory** — hardcoded authorities/fallbacks; fetch + parse the microdesc
   consensus and microdescriptors (ntor keys); consensus signature validation;
   bandwidth-weighted guard/middle/exit selection.
5. **Streams + SOCKS5** — RELAY_BEGIN/DATA/END/CONNECTED with SENDME flow
   control; a local SOCKS5 server. *Milestone: `curl --socks5-hostname
   127.0.0.1:9050 https://check.torproject.org` reports Tor is in use.*

## Layout

```
cl-tor.asd              ASDF system
src/
  packages              package layout
  util                  bytes / hex / big-endian cell framing
  crypto                the Tor cipher suite over ironclad
  ntor                  ntor-curve25519-sha256-1 handshake + key derivation
  (soon) cell link circuit relay-crypto directory stream socks
inspect/
  offline-test.lisp     crypto + ntor gate
  run-all.sh            run it
```

## Dependencies

SBCL + Quicklisp (`ironclad`, `usocket`, `cl+ssl`, `bordeaux-threads`). The crypto
is isolated in `src/crypto.lisp` so the modus port is mostly a matter of
re-pointing that one file at `net/crypto`.

## Quick start

```sh
inspect/run-all.sh
# === 14 passed, 0 failed ===
```

## License

MIT.
