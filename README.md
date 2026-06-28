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
- **ntor handshake** ✅ — `ntor-curve25519-sha256-1`: client + server, KEY_SEED/
  AUTH, HKDF expansion to the per-hop keys (Df/Db/Kf/Kb). Full client↔server
  key agreement + AUTH accept/reject.
- **Directory bootstrap** ✅ — fetch + inflate the microdesc consensus from
  hardcoded authorities; parse relays (identity/addr/flags/bw/md-digest); fetch
  microdescriptors (ntor key + Ed25519 id); flag-filtered path selection.
  *Live: parses ~9500 relays.*
- **Link handshake** ✅ — TLS to a relay ORPort; VERSIONS negotiation; CERTS/
  NETINFO; Ed25519 cert chain validated and bound to the TLS cert + consensus
  identity. *Live: completes a v5 handshake with a real guard, validated.*
- **Circuits** ✅ — CREATE2 + EXTEND2 with per-hop AES-128-CTR + SHA-1 onion
  crypto (recognized/digest). *Live: builds real 3-hop circuits on the Tor
  network — the unforgeable ntor KAT.*
- **Streams + SOCKS5** ⏳ — next.

## Roadmap

The protocol is built bottom-up; each phase is independently testable, and the
**live network is the unforgeable oracle** (a real CREATE2 only succeeds if ntor
is byte-exact).

1. **Crypto + ntor** ✅ — *done, vector-verified.*
2. **Cells + link handshake** ✅ — *done, live-validated.*
3. **Circuits** ✅ — *done; builds real 3-hop circuits on the live network.*
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
