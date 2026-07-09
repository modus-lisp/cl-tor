;;;; src/tor-backend.lisp — register cl-tor as cl-transport's :tor backend.
;;;;
;;;; Loading the cl-tor-transport system runs the REGISTER-TRANSPORT call at the
;;;; bottom, so cl-transport:dial gains a working :tor backend.  This is the ONLY
;;;; place cl-tor and cl-transport meet — dependency is one-way (cl-tor-transport
;;;; -> cl-transport); the core Tor client knows nothing about cl-transport.

(defpackage #:cl-tor.transport
  (:use #:cl)
  (:local-nicknames (#:tsocks #:cl-tor.socks) (#:strm #:cl-tor.stream)
                    (#:gs #:cl-tor.gray-stream) (#:circ #:cl-tor.circuit)
                    (#:link #:cl-tor.link) (#:intro #:cl-tor.hs-intro))
  (:export #:dial-over-tor))

(in-package #:cl-tor.transport)

(defun %onion-p (host)
  "T if HOST is a .onion address (route it through the v3 onion client, not a clearnet exit)."
  (let ((n (length host)))
    (and (> n 6) (string-equal ".onion" host :start2 (- n 6)))))

(defun %wrap (circ sid)
  "Wrap CIRC's already-open stream SID as a gray stream; on failure tear the circuit down."
  (handler-case
      (let ((s (gs:make-tor-stream circ sid)))
        (values s (lambda () (ignore-errors (close s)))))
    (serious-condition (e)
      (ignore-errors (circ:destroy-circuit circ))
      (ignore-errors (link:close-link (circ:circuit-link circ)))
      (error e))))

(defun dial-over-tor (host port timeout)
  "cl-transport's :tor backend.  A .onion HOST is dialed end-to-end through the v3
   onion-service client (fetch+decrypt descriptor, introduce, rendezvous); any other
   HOST gets a fresh 3-hop circuit to an exit permitting PORT.  Either way the open
   stream is wrapped as a binary gray stream.  Returns (values stream closer).
   (TIMEOUT is advisory — circuit build has its own bounded retries.)"
  (declare (ignore timeout))
  (if (%onion-p host)
      (multiple-value-bind (circ sid) (intro:connect-onion host :port port)
        (%wrap circ sid))
      (let ((circ (tsocks:build-fresh-circuit :port port)))
        (handler-case
            (let* ((sid (strm:begin-stream circ host port))
                   (s (gs:make-tor-stream circ sid)))
              (values s (lambda () (ignore-errors (close s)))))
          (serious-condition (e)
            (ignore-errors (circ:destroy-circuit circ))
            (ignore-errors (link:close-link (circ:circuit-link circ)))
            (error e))))))

(cl-transport:register-transport :tor #'dial-over-tor)
