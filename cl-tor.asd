;;;; cl-tor.asd

(defsystem "cl-tor"
  :description "A from-scratch Tor client in Common Lisp — ntor circuit handshake,
                relay-cell crypto, link handshake, directory, and a local SOCKS5
                proxy.  Reference implementation (SBCL today; portable toward modus)."
  :version "0.0.1"
  :author "ynniv"
  :license "MIT"
  :depends-on ("ironclad"            ; crypto primitives (SHA-1/256, HMAC, AES-CTR, X25519, Ed25519, RSA)
               "usocket"             ; TCP to relay ORPorts + directory HTTP
               "cl+ssl"              ; the TLS link layer
               "chipz"               ; zlib inflate (directory documents are compressed)
               "bordeaux-threads")   ; per-circuit read loops
  :serial t
  :components
  ((:module "src"
    :serial t
    :components
    ((:file "packages")   ; package layout
     (:file "util")       ; hex, byte ops, big/little-endian framing
     (:file "crypto")     ; thin wrappers over ironclad (the cipher suite Tor uses)
     (:file "ed25519")    ; Ed25519 group arithmetic + v3 onion key blinding
     (:file "ntor")       ; ntor-curve25519-sha256-1 circuit handshake + key derivation
     (:file "directory")  ; minimal directory bootstrap: consensus + microdescs + selection
     (:file "cell")       ; cell framing (fixed + variable)
     (:file "link")       ; TLS link handshake: VERSIONS/CERTS/NETINFO + cert validation
     (:file "relay-crypto") ; per-hop onion crypto (AES-CTR layers + SHA-1 digests)
     (:file "circuit")    ; CREATE2 + EXTEND2 circuit construction; relay cell send/recv
     (:file "stream")     ; RELAY_BEGIN/DATA/END streams over a circuit
     (:file "socks")      ; local SOCKS5 proxy onto fresh circuits
     (:file "hs-dir")      ; v3 onion HSDir hash ring (time period, SRV, indices)
     (:file "hs-desc")     ; v3 descriptor 2-layer decrypt + intro points
     (:file "hs-intro")    ; hs-ntor + ESTABLISH_RENDEZVOUS + INTRODUCE1
     (:file "hs-service")))) ; onion SERVICE: build/sign/encrypt the descriptor
  :in-order-to ((test-op (test-op "cl-tor/test"))))

(defsystem "cl-tor/test"
  :depends-on ("cl-tor")
  :components ((:module "inspect"
               :components ((:file "offline-test"))))
  :perform (test-op (o c) (uiop:symbol-call :cl-tor.test :run)))
