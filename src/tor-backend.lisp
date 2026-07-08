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
                    (#:link #:cl-tor.link))
  (:export #:dial-over-tor))

(in-package #:cl-tor.transport)

(defun dial-over-tor (host port timeout)
  "Build a fresh 3-hop circuit (exit permitting PORT), open a stream to HOST:PORT at
   the exit, and wrap it as a binary gray stream.  Returns (values stream closer),
   the cl-transport backend contract.  (TIMEOUT is advisory — circuit build has its
   own bounded retries.)"
  (declare (ignore timeout))
  (let ((circ (tsocks:build-fresh-circuit :port port)))
    (handler-case
        (let* ((sid (strm:begin-stream circ host port))
               (s (gs:make-tor-stream circ sid)))
          (values s (lambda () (ignore-errors (close s)))))
      (serious-condition (e)
        (ignore-errors (circ:destroy-circuit circ))
        (ignore-errors (link:close-link (circ:circuit-link circ)))
        (error e)))))

(cl-transport:register-transport :tor #'dial-over-tor)
