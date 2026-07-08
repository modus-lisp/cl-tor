;;;; cl-transport.asd
;;;;
;;;; A uniform outbound transport over cl-tor: one DIAL that returns a binary
;;;; stream whether the bytes go direct, through an external SOCKS5 proxy, or over
;;;; a native cl-tor circuit (gray-stream bridge).  Widens the tor client into the
;;;; project's privacy/transport layer; portable toward modus.

(defsystem "cl-transport"
  :description "Uniform outbound transport (direct / SOCKS5 / native Tor) with a
                Gray-stream bridge over cl-tor circuits."
  :version "0.0.1"
  :author "ynniv"
  :license "MIT"
  :depends-on ("cl-tor" "usocket" "bordeaux-threads")
  :serial t
  :components
  ((:module "src"
    :serial t
    :components
    ((:file "socks-client")   ; SOCKS5 CONNECT client (external proxy backend)
     (:file "gray-stream")    ; binary Gray stream over one Tor circuit stream
     (:file "transport")))))  ; DIAL: pick a backend, return (stream . closer)
