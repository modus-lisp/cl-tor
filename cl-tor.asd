;;;; cl-tor.asd

(defsystem "cl-tor"
  :description "A from-scratch Tor client in Common Lisp — ntor circuit handshake,
                relay-cell crypto, link handshake, directory, and a local SOCKS5
                proxy.  Reference implementation (SBCL today; portable toward modus)."
  :version "0.0.1"
  :author "ynniv"
  :license "MIT"
  :depends-on ("ironclad"            ; crypto primitives (SHA-1/256, HMAC, AES-CTR, X25519, Ed25519, RSA)
               "usocket"             ; TCP to relay ORPorts
               "cl+ssl"              ; the TLS link layer
               "bordeaux-threads")   ; per-circuit read loops
  :serial t
  :components
  ((:module "src"
    :serial t
    :components
    ((:file "packages")   ; package layout
     (:file "util")       ; hex, byte ops, big/little-endian framing
     (:file "crypto")     ; thin wrappers over ironclad (the cipher suite Tor uses)
     (:file "ntor"))))   ; ntor-curve25519-sha256-1 circuit handshake + key derivation
  :in-order-to ((test-op (test-op "cl-tor/test"))))

(defsystem "cl-tor/test"
  :depends-on ("cl-tor")
  :components ((:module "inspect"
               :components ((:file "offline-test"))))
  :perform (test-op (o c) (uiop:symbol-call :cl-tor.test :run)))
