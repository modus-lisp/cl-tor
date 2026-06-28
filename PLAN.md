# cl-tor — Plan

A working plan for a from-scratch Tor **client** in Common Lisp: connect to the
live Tor network, build 3-hop circuits, and expose a local SOCKS5 proxy. SBCL
today; portable toward modus. We build bottom-up; each phase is independently
testable, and the **live network is the unforgeable oracle** (a real CREATE2 only
succeeds if our ntor is byte-exact; a real fetch through a circuit only works if
every layer is correct).

## Principles

- **Spec-driven.** Follow `tor-spec`, `dir-spec`, `cert-spec`, `socks-extensions`
  (spec.torproject.org). Cite section names in code comments.
- **Vector-first, then live.** Prove each layer against published vectors or
  self-consistency offline; then validate against real relays.
- **Client-only.** We never act as a relay and never authenticate *ourselves* to
  relays (only relays authenticate to us). This drops the AUTHENTICATE path.
- **v3-link-and-up, ntor-only, microdesc consensus.** Skip TAP/CREATE_FAST,
  legacy link protocols, and full descriptors. Target link protocol v4+ (4-byte
  circ IDs), CREATE2/EXTEND2 ntor, and the microdescriptor consensus flavor.
- **Stage validation.** Get a working circuit first with minimal cert/consensus
  validation, then harden (consensus signatures, full CERTS chain) as its own
  pass — clearly flagged insecure until done.
- **Crypto isolated.** Everything ironclad-specific stays in `src/crypto.lisp`
  so the modus port re-points one file at `net/crypto`.

## Module layout (target)

```
src/
  packages util crypto ntor      [DONE] foundation
  cell        cell framing: fixed (514) + variable; read/write over a stream
  link        TLS to ORPort; VERSIONS/CERTS/AUTH_CHALLENGE/NETINFO; cert validation
  relay-crypto onion layers: per-hop AES-128-CTR + SHA-1 running digest, recognized
  circuit     CREATE2/CREATED2 + EXTEND2/EXTENDED2; relay-cell send/recv/route
  directory   authorities/fallbacks; fetch+parse microdesc consensus + microdescs;
              relay selection; (later) consensus signature validation
  stream      RELAY_BEGIN/DATA/END/CONNECTED; SENDME flow control
  socks       local SOCKS5 server -> stream over a circuit
  client      glue: bootstrap dir, pick path, build circuit, serve SOCKS
bin/cl-tor.lisp     run the proxy
inspect/            offline gates + live smoke tests
```

## Key facts to get right (reference, condensed from the spec)

**Cells (link v4+).** Fixed cell = CircID(4) | Cmd(1) | Payload(509), total 514.
Variable cell = CircID(4) | Cmd(1) | Len(2) | Payload(Len). VERSIONS is always
sent with a **2-byte** CircID (it precedes negotiation); its payload is a list of
u16 versions. Variable-length commands: 7 VERSIONS, 128 VPADDING, 129 CERTS, 130
AUTH_CHALLENGE, 131 AUTHENTICATE. Fixed commands incl. 8 NETINFO, 10 CREATE2,
11 CREATED2, 3 RELAY, 9 RELAY_EARLY, 4 DESTROY.

**Link handshake (client side).** TLS connect (cl+ssl, no CA verify — Tor certs
are self-signed). Send VERSIONS([4,5]); read VERSIONS, pick max common. Read
CERTS, AUTH_CHALLENGE (ignore — we don't authenticate), NETINFO. Validate the
relay identity from CERTS against the expected fingerprints. Send our NETINFO
(their address + zero of ours). Link is then up. CircID for our created circuit:
set high bit per initiator rule (v4: MSB=1).

**CERTS validation (cert-spec).** Cert types: 2 RSA1024 identity self-cert; 4
Ed25519 signing-key cert (signed by Ed25519 id); 5 Ed25519 link cert (signs the
TLS cert SHA-256, signed by signing key); 7 RSA→Ed cross-cert. Chain: Ed25519
identity → (4) signing key → (5) TLS cert; RSA identity → (7) certifies Ed25519
identity. Match Ed25519 id and RSA id (SHA1) to the consensus entry.
*Staging:* v1 = parse Ed25519 id + check link cert binds the actual TLS cert;
v2 = full RSA cross-cert + signature chain.

**ntor in cells.** CREATE2 payload: HTYPE(2)=2 | HLEN(2)=84 | HDATA(84 onion-skin).
CREATED2: HLEN(2)=64 | HDATA(64 = Y|AUTH). [ntor itself DONE.]

**Relay cells (tor-spec §6).** Decrypted RELAY payload: RelayCmd(1) | Recognized(2)
| StreamID(2) | Digest(4) | Len(2) | Data(Len) | padding, in the 509-byte body.
Onion crypto: forward = client applies Kf of hops in order n..1 (innermost =
destination); each hop CTR-decrypts with its Kf. Backward = each hop CTR-encrypts
with Kb; client peels Kb1..Kbn. A hop owns a cell when, after its decrypt,
Recognized==0 **and** the SHA-1 running digest (seeded with Df/Db, computed over
the cell with Digest field zeroed) matches Digest. Ciphers + digests are stateful
per direction per hop. Relay cmds: 1 BEGIN, 2 DATA, 3 END, 4 CONNECTED, 5 SENDME,
11 BEGIN_DIR, 14 EXTEND2, 15 EXTENDED2.

**EXTEND2 (§5.1).** A RELAY_EARLY cell, relay cmd 14, to the last hop. Body:
NSPEC(1) then link specifiers {LSTYPE(1) LSLEN(1) LSPEC}: type 0 = IPv4 (4+2),
type 2 = legacy RSA id (20), type 3 = Ed25519 id (32); then HTYPE(2)=2 HLEN(2)=84
HDATA(84). Reply EXTENDED2 carries the CREATED2 data (Y|AUTH).

**Directory (dir-spec).** Bootstrap from hardcoded authorities/fallbacks (IP +
DirPort + v3 identity fp). Fetch microdesc consensus: `GET
/tor/status-vote/current/consensus-microdesc` (often zlib-compressed). Parse: `r`
(nickname, RSA id b64, IP, ORPort), `m` (microdesc SHA-256 b64), `s` (flags),
`w` (bandwidth). Fetch microdescriptors: `GET /tor/micro/d/<b64>-<b64>...` →
each has `ntor-onion-key <b64>`, `id ed25519 <b64>`. *Staging:* v1 = fetch over
TLS from a trusted fallback, no signature check; v2 = verify directory-signature
against authority signing keys.

**Streams + flow control (§6 + §7).** BEGIN payload = "host:port\0" + flags(4),
nonzero StreamID. CONNECTED on success. DATA ≤ 498 bytes. Circuit window:
start 1000, send RELAY_SENDME every 100 received; stream window 500 / 50. (Use
authenticated v1 SENDME if negotiated; else plain.) END to close.

**SOCKS5.** Listen 127.0.0.1:9050. Negotiate (no auth). CONNECT with ATYP=domain
keeps DNS resolution inside Tor (critical: no local DNS leak). Map request →
stream → splice bytes both ways.

## Phases & acceptance

- **P1 Crypto + ntor** — ✅ done. Gate: 14/14 (X25519/HKDF vectors; ntor agreement).
- **P2 Cells + link** — frame cells; complete a v4 link handshake with a real
  relay. *Accept:* connect to a live relay, negotiate v4+, read its CERTS/NETINFO,
  send NETINFO; print negotiated version + relay addresses. (Needs a real relay —
  see "bootstrap dependency".)
- **P3 Circuit** — CREATE2 to a guard; EXTEND2 ×2; relay-cell onion crypto.
  *Accept:* build a 3-hop circuit on the live network and receive EXTENDED2 from
  hop 3 (the real ntor KAT). Sanity: a RELAY_DROP/echo round-trips recognized.
- **P4 Directory** — parse consensus + microdescs; weighted Guard/middle/Exit
  selection. *Accept:* build a circuit from relays chosen out of the live
  consensus (no hardcoded relays). Then: consensus signature verification.
- **P5 Streams + SOCKS5** — BEGIN/DATA/END + SENDME; SOCKS5 front end.
  *Accept:* `curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/`
  reports Tor is in use; fetch a real page over a 3-hop circuit.
- **P6 Hardening** — consensus + CERTS signature validation on by default; guard
  persistence; basic path constraints (no two hops in same /16 or family);
  circuit teardown/errors; docs. *Accept:* validation can't be silently skipped.

## Bootstrap dependency (why a little directory comes early)

P2/P3 need a real relay's IP/ORPort/ntor-key/ed25519-id to test against. Rather
than hardcode a relay (they rotate), we'll build a **minimal directory fetch**
first (hardcoded authorities → consensus → microdescs), expose
`pick-relay`/`pick-path`, and use it to feed the link/circuit live tests. Full
parsing/selection/validation is still finished in P4; P2 just needs "give me one
running relay with an ntor key."

## Open decisions

- **Compression**: consensus is usually served zlib/zstd. Use ironclad? No —
  ironclad doesn't do zlib. Options: request identity encoding if the dir honors
  it, or add a small inflate (chipz is in Quicklisp). *Default:* try chipz.
- **SENDME version**: start with plain SENDME; add authenticated v1 if a relay
  requires it (negotiated via consensus param/protocols).
- **Guard selection**: full guard spec is complex; *default:* pick one Guard-flag
  relay and persist it, skip the full guard-set state machine for now.
