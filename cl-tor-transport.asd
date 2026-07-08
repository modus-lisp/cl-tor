;;;; cl-tor-transport.asd
;;;;
;;;; The Tor backend for cl-transport: a binary Gray-stream bridge over cl-tor
;;;; circuits, registered as the :tor transport on load.  Load THIS system (not just
;;;; cl-tor) to enable (cl-transport:dial host port :transport :tor).  Keeps the core
;;;; cl-tor client free of any cl-transport dependency — the coupling lives here.

(defsystem "cl-tor-transport"
  :description "Tor backend for cl-transport (gray-stream bridge over cl-tor circuits)."
  :version "0.1.0"
  :author "ynniv"
  :license "MIT"
  :depends-on ("cl-tor" "cl-transport")
  :serial t
  :components
  ((:module "src"
    :serial t
    :components
    ((:file "gray-stream")    ; binary Gray stream over one Tor circuit stream
     (:file "tor-backend"))))); registers :tor with cl-transport
