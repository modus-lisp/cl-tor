;;;; src/packages.lisp — package layout for cl-tor.
;;;;
;;;; One package per concern (cl-consensus / cl-nostr style).  The crypto is the
;;;; fixed Tor cipher suite — wrapped over ironclad on SBCL today, with an eye to
;;;; swapping in modus's own net/crypto when this is adapted to the native compiler.

(defpackage #:cl-tor.util
  (:use #:cl)
  (:export
   #:octets #:bytes->hex #:hex->bytes #:ascii->bytes #:cat #:base64-decode
   #:u8 #:u16be #:u32be #:put-u8 #:put-u16be #:put-u32be #:ipv4->bytes
   #:read-u16be #:read-u32be #:subv #:bytes= #:bytes->int #:int->bytes))

(defpackage #:cl-tor.crypto
  (:use #:cl)
  (:local-nicknames (#:u #:cl-tor.util))
  (:export
   #:random-bytes
   #:sha1 #:sha256 #:sha3-256
   #:hmac-sha256 #:hkdf-expand
   #:x25519 #:x25519-basepoint #:x25519-public #:gen-x25519
   #:aes128-ctr-cipher #:ctr-apply
   #:ed25519-verify
   #:mod-expt #:der-rsa-public-key #:rsa-verify #:x509-rsa-key))

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
  (:local-nicknames (#:u #:cl-tor.util) (#:c #:cl-tor.crypto))
  (:export
   #:*authorities* #:http-get #:fetch-consensus #:parse-consensus
   #:fetch-microdesc #:enrich-relay #:enrich-relays
   #:relay #:relay-nickname #:relay-rsa-id #:relay-ip #:relay-or-port
   #:relay-flags #:relay-bandwidth #:relay-md-digest #:relay-exit-ports
   #:relay-ntor-key #:relay-ed-id #:relay-has-flag
   #:consensus-relays #:pick-relay #:pick-path
   #:*verify-consensus* #:validate-consensus #:fetch-certs #:exit-allows-port))

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
   #:link-relay #:link-version #:link-circid-len #:link-stream #:link-sock
   #:link-validated #:link-my-apparent-addr
   #:send-cell #:recv-cell))

(defpackage #:cl-tor.relay-crypto
  (:use #:cl)
  (:local-nicknames (#:u #:cl-tor.util) (#:c #:cl-tor.crypto) (#:n #:cl-tor.ntor))
  (:export
   #:hop #:make-hop #:make-hs-hop #:hop-relay #:hop-kf #:hop-kb #:hop-df #:hop-db
   #:build-relay-body #:parse-relay-body #:recognized-and-valid #:hop-recv-digest
   #:+r-begin+ #:+r-data+ #:+r-end+ #:+r-connected+ #:+r-sendme+
   #:+r-extend2+ #:+r-extended2+ #:+r-drop+ #:+r-resolve+ #:+r-resolved+))

(defpackage #:cl-tor.circuit
  (:use #:cl)
  (:local-nicknames (#:u #:cl-tor.util) (#:c #:cl-tor.crypto) (#:n #:cl-tor.ntor)
                    (#:cell #:cl-tor.cell) (#:link #:cl-tor.link)
                    (#:dir #:cl-tor.directory) (#:rc #:cl-tor.relay-crypto)
                    (#:bt #:bordeaux-threads))
  (:export
   #:circuit #:circuit-link #:circuit-id #:circuit-hops #:circuit-length
   #:create-circuit #:extend-circuit #:build-circuit
   #:send-relay #:recv-relay #:destroy-circuit))

(defpackage #:cl-tor.stream
  (:use #:cl)
  (:local-nicknames (#:u #:cl-tor.util) (#:rc #:cl-tor.relay-crypto)
                    (#:circ #:cl-tor.circuit))
  (:export #:begin-stream #:send-stream-data #:end-stream))

(defpackage #:cl-tor.socks
  (:use #:cl)
  (:local-nicknames (#:u #:cl-tor.util) (#:rc #:cl-tor.relay-crypto)
                    (#:dir #:cl-tor.directory) (#:link #:cl-tor.link)
                    (#:circ #:cl-tor.circuit) (#:strm #:cl-tor.stream)
                    (#:bt #:bordeaux-threads))
  (:export #:run-proxy #:build-fresh-circuit))
