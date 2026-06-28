;;;; src/packages.lisp — package layout for cl-tor.
;;;;
;;;; One package per concern (cl-consensus / cl-nostr style).  The crypto is the
;;;; fixed Tor cipher suite — wrapped over ironclad on SBCL today, with an eye to
;;;; swapping in modus's own net/crypto when this is adapted to the native compiler.

(defpackage #:cl-tor.util
  (:use #:cl)
  (:export
   #:octets #:bytes->hex #:hex->bytes #:ascii->bytes #:cat #:base64-decode
   #:u8 #:u16be #:u32be #:put-u8 #:put-u16be #:put-u32be
   #:read-u16be #:read-u32be #:subv #:bytes=))

(defpackage #:cl-tor.crypto
  (:use #:cl)
  (:local-nicknames (#:u #:cl-tor.util))
  (:export
   #:random-bytes
   #:sha1 #:sha256 #:sha3-256
   #:hmac-sha256 #:hkdf-expand
   #:x25519 #:x25519-basepoint #:x25519-public #:gen-x25519
   #:aes128-ctr-cipher #:ctr-apply
   #:ed25519-verify))

(defpackage #:cl-tor.ntor
  (:use #:cl)
  (:local-nicknames (#:u #:cl-tor.util)
                    (#:c #:cl-tor.crypto))
  (:export
   #:+onionskin-len+
   #:client-create #:client-finish
   #:server-handshake                ; for tests / running as a relay
   #:circuit-keys #:circuit-keys-df #:circuit-keys-db
   #:circuit-keys-kf #:circuit-keys-kb #:keys-from-seed))

(defpackage #:cl-tor.directory
  (:use #:cl)
  (:local-nicknames (#:u #:cl-tor.util))
  (:export
   #:*authorities* #:http-get #:fetch-consensus #:parse-consensus
   #:fetch-microdesc #:enrich-relay
   #:relay #:relay-nickname #:relay-rsa-id #:relay-ip #:relay-or-port
   #:relay-flags #:relay-bandwidth #:relay-md-digest
   #:relay-ntor-key #:relay-ed-id #:relay-has-flag
   #:consensus-relays #:pick-relay #:pick-path))

(defpackage #:cl-tor.cell
  (:use #:cl)
  (:local-nicknames (#:u #:cl-tor.util))
  (:export
   #:+versions+ #:+certs+ #:+auth-challenge+ #:+netinfo+ #:+create2+ #:+created2+
   #:+relay+ #:+relay-early+ #:+destroy+ #:+padding+ #:+vpadding+
   #:+payload-len+ #:variable-cell-p
   #:read-cell #:write-cell #:read-bytes))

(defpackage #:cl-tor.link
  (:use #:cl)
  (:local-nicknames (#:u #:cl-tor.util)
                    (#:c #:cl-tor.crypto)
                    (#:cell #:cl-tor.cell)
                    (#:dir #:cl-tor.directory))
  (:export
   #:link #:connect-link #:close-link
   #:link-relay #:link-version #:link-circid-len #:link-stream
   #:link-validated #:link-my-apparent-addr
   #:send-cell #:recv-cell))
