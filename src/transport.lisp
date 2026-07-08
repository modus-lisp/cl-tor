;;;; src/transport.lisp — one DIAL for every backend.
;;;;
;;;; DIAL host port :transport X  ->  (values binary-stream closer-thunk)
;;;;
;;;; The whole point: callers (e.g. cl-consensus's connect-peer) get a uniform
;;;; binary stream + a close thunk and never branch on how the bytes travel.
;;;;
;;;;   :direct  plain TCP (usocket)                    — clearnet, no privacy
;;;;   :socks5  through an external SOCKS5 proxy        — system tor / any proxy
;;;;   :tor     cl-tor native 3-hop circuit + gray stream — no daemon (modus)
;;;;
;;;; Outbound only for now.

(defpackage #:cl-transport
  (:use #:cl)
  (:local-nicknames (#:socks #:cl-transport.socks)
                    (#:ts #:cl-transport.stream)
                    (#:tsocks #:cl-tor.socks) (#:strm #:cl-tor.stream))
  (:export #:dial #:*default-transport* #:*socks-proxy*))

(in-package #:cl-transport)

(defparameter *default-transport* :direct
  "Transport used when DIAL is called without an explicit :TRANSPORT.")

(defparameter *socks-proxy* '("127.0.0.1" . 9050)
  "(host . port) of the SOCKS5 proxy for :SOCKS5 dials.")

(defun dial (host port &key (transport *default-transport*) (timeout 20)
                            (proxy *socks-proxy*))
  "Open an outbound connection to HOST:PORT over TRANSPORT.  Returns
   (values stream closer): a binary stream usable like a socket stream, and a
   zero-arg thunk that tears the connection fully down.  Signals on failure."
  (ecase transport
    (:direct
     (let ((sock (usocket:socket-connect host port
                                         :element-type '(unsigned-byte 8) :timeout timeout)))
       (values (usocket:socket-stream sock)
               (lambda () (ignore-errors (usocket:socket-close sock))))))
    (:socks5
     (socks:socks5-connect host port :proxy-host (car proxy) :proxy-port (cdr proxy)
                                     :timeout timeout))
    (:tor
     (let ((circ (tsocks:build-fresh-circuit :port port)))
       (handler-case
           (let ((sid (strm:begin-stream circ host port)))
             (let ((s (ts:make-tor-stream circ sid)))
               (values s (lambda () (ignore-errors (close s))))))
         (serious-condition (e)
           (ignore-errors (cl-tor.circuit:destroy-circuit circ))
           (ignore-errors (cl-tor.link:close-link (cl-tor.circuit:circuit-link circ)))
           (error e)))))))
