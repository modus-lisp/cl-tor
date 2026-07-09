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

**Functional, but research/educational — do not rely on it for anonymity.**
End to end it builds signature-validated circuits with a persistent guard, full
link-cert validation, family/subnet path constraints, and flow control. But it
is a young clean-room implementation that has not been audited or
side-channel-hardened, and anonymity is a correctness property such code can't
yet guarantee. No warranty (see [LICENSE](LICENSE)).

## Status

- **Crypto suite** ✅ — SHA-1/256/3, HMAC-SHA256, HKDF, AES-128-CTR, X25519,
  Ed25519, over `ironclad`. Verified: X25519 vs **RFC 7748**, HKDF vs **RFC 5869**.
- **ntor handshake** ✅ — `ntor-curve25519-sha256-1`: client + server, KEY_SEED/
  AUTH, HKDF expansion to the per-hop keys (Df/Db/Kf/Kb). Full client↔server
  key agreement + AUTH accept/reject.
- **Directory** ✅ — fetch + inflate the microdesc consensus; **validate its
  signatures** against the hardcoded authority v3 identities (from-scratch RSA:
  modexp + DER + PKCS#1) requiring a majority quorum; parse relays + fetch
  microdescriptors (ntor key, Ed25519 id, exit policy); **bandwidth-weighted,
  exit-policy-aware** path selection. *Live: validates the real consensus
  (≥5/9 sigs) and rejects a tampered one.*
- **Link handshake** ✅ — TLS to a relay ORPort; VERSIONS negotiation; CERTS/
  NETINFO; Ed25519 cert chain validated and bound to the TLS cert + consensus
  identity. *Live: completes a v5 handshake with a real guard, validated.*
- **Circuits** ✅ — CREATE2 + EXTEND2 with per-hop AES-128-CTR + SHA-1 onion
  crypto (recognized/digest). *Live: builds real 3-hop circuits on the Tor
  network — the unforgeable ntor KAT.*
- **Streams + SOCKS5** ✅ — RELAY_BEGIN/DATA/END streams with **SENDME flow
  control** (authenticated v1 circuit + stream); a local SOCKS5 proxy (host names
  resolved at the exit — no DNS leak), full-duplex over a dedicated reader thread.
  *Live: `curl` through it reports `{"IsTor":true}`; 10 MB downloads complete and
  the daemon stays up.*
- **Hardening** ✅ — entry-guard **persistence** (one stable guard, saved to
  `~/.cl-tor/guard`); **path constraints** (no two hops share a nickname, /16, or
  relay family); **RSA identity cross-cert** validation in the link CERTS cell
  (certs 2/7, matched to the consensus RSA fingerprint); TLS 1.2 link pinning;
  crash-safe daemon. *Live: real relays pass full cert validation.*
- **Onion services (v3 client)** ✅ — dial `.onion` addresses end to end:
  Ed25519 key **blinding**, the **HSDir** hash ring (time period + shared-random),
  fetch + **two-layer decrypt** of the descriptor (SHAKE256 KDF, SHA3-256 MAC,
  AES-256-CTR), the **hs-ntor** handshake, `ESTABLISH_RENDEZVOUS` + `INTRODUCE1`,
  and the rendezvous splice (a SHA3-256/AES-256 service hop). *Live: `connect-onion`
  reaches DuckDuckGo's onion and pulls back a real HTTP response.*

## Roadmap

The protocol is built bottom-up; each phase is independently testable, and the
**live network is the unforgeable oracle** (a real CREATE2 only succeeds if ntor
is byte-exact).

1. **Crypto + ntor** ✅ — *done, vector-verified.*
2. **Cells + link handshake** ✅ — *done, live-validated.*
3. **Circuits** ✅ — *done; builds real 3-hop circuits on the live network.*
4. **Directory** ✅ — *done; consensus signatures validated, bandwidth-weighted
   exit-policy-aware selection.*
5. **Streams + SOCKS5** ✅ — *done; `curl` through it reports Tor is in use.*
6. **Hardening** ✅ — SENDME, guard persistence, path constraints (/16 +
   nickname + family), RSA identity cross-cert validation, TLS-1.2 pinning,
   crash-safety.
7. **Onion services (v3 client)** ✅ — key blinding, HSDir ring, descriptor
   decrypt, hs-ntor, INTRODUCE1/rendezvous; `.onion` dialing verified live.

## Layout

```
cl-tor.asd              ASDF system
cl-tor-transport.asd    optional cl-transport backend (dial over Tor / .onion)
src/
  packages              package layout
  util                  bytes / hex / big-endian cell framing
  crypto                the Tor cipher suite over ironclad
  ntor                  ntor-curve25519-sha256-1 handshake + key derivation
  directory             consensus fetch + signature validation + path selection
  cell                  fixed/variable cell framing
  link                  TLS link handshake + cert-chain validation
  relay-crypto          per-hop onion crypto (AES-CTR + running digest)
  circuit               CREATE2 / EXTEND2 + relay cell send/recv
  stream                RELAY_BEGIN/DATA/END streams
  socks                 local SOCKS5 proxy onto fresh circuits
  hs-dir                v3 onion HSDir hash ring (time period, SRV, indices)
  hs-desc               v3 descriptor two-layer decrypt + intro points
  hs-intro              hs-ntor + INTRODUCE1 + rendezvous -> connect-onion
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
# === 33 passed, 0 failed ===
```

Run the proxy and route a request through Tor:

```sh
sbcl --load bin/cl-tor.lisp 9050        # SOCKS5 on 127.0.0.1:9050
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
# => {"IsTor":true,"IP":"185.220.101.22"}
```

Each connection builds its own fresh 3-hop circuit from the live consensus.

## License

MIT.
