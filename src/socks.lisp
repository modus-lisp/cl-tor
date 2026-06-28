;;;; src/socks.lisp — a local SOCKS5 front end (RFC 1928) onto Tor circuits.
;;;;
;;;; Each accepted SOCKS CONNECT builds its own fresh 3-hop circuit, opens a
;;;; stream to the requested host:port at the exit, and splices bytes both ways.
;;;; Host *names* are passed to the exit for resolution (ATYP=domain), so DNS
;;;; never leaks to the local resolver.  A single-threaded select loop per
;;;; connection (usocket:wait-for-input + draining buffered TLS cells) keeps us
;;;; off concurrent OpenSSL access.

(in-package #:cl-tor.socks)

(defvar *relays* nil "Cached consensus relay list (loaded on first use).")

(defun build-fresh-circuit (&key (tries 6) (port 443))
  "Pick a path (exit permitting PORT) and build a 3-hop circuit, retrying churn."
  (unless *relays* (setf *relays* (dir:consensus-relays)))
  (loop for i from 1 to tries
        for circ = (ignore-errors
                    (destructuring-bind (g m e) (dir:pick-path *relays* :port port)
                      (let ((lk (link:connect-link g)))
                        (handler-case (circ:build-circuit lk m e)
                          (error (err) (link:close-link lk) (error err))))))
        when circ return circ
        finally (error "could not build a circuit after ~d tries" tries)))

;;; ---- SOCKS5 wire (RFC 1928) ---------------------------------------------

(defun %read-n (stream n)
  (let ((b (u:octets n))) (read-sequence b stream) b))

(defun %socks-handshake (s)
  "Method negotiation: accept no-auth (0x00)."
  (let* ((ver (read-byte s)) (nm (read-byte s)))
    (declare (ignore ver))
    (%read-n s nm)
    (write-sequence (u:cat (u:u8 5) (u:u8 0)) s) (force-output s)))

(defun %read-request (s)
  "Parse a CONNECT request -> (values host port).  Supports IPv4 + domain."
  (let ((ver (read-byte s)) (cmd (read-byte s)) (rsv (read-byte s)) (atyp (read-byte s)))
    (declare (ignore ver rsv))
    (unless (= cmd 1) (error "socks: only CONNECT supported"))
    (let ((host (ecase atyp
                  (1 (let ((a (%read-n s 4))) (format nil "~d.~d.~d.~d"
                                                       (aref a 0) (aref a 1) (aref a 2) (aref a 3))))
                  (3 (let ((len (read-byte s))) (map 'string #'code-char (%read-n s len))))
                  (4 (error "socks: IPv6 target not supported")))))
      (values host (u:read-u16be (%read-n s 2) 0)))))

(defun %reply (s status)
  "SOCKS5 reply with bind addr 0.0.0.0:0."
  (write-sequence (u:cat (u:u8 5) (u:u8 status) (u:u8 0) (u:u8 1) (u:octets 4) (u:octets 2)) s)
  (force-output s))

;;; ---- duplex splice ------------------------------------------------------

(defun %read-available (stream &key (max 8192))
  "Read >=1 byte then drain what's buffered, up to MAX.  :EOF on close."
  (let ((first (read-byte stream nil :eof)))
    (if (eq first :eof) :eof
        (let ((buf (make-array max :element-type '(unsigned-byte 8) :fill-pointer 0)))
          (vector-push first buf)
          (loop while (and (< (fill-pointer buf) max) (listen stream))
                do (vector-push (read-byte stream) buf))
          (coerce buf '(simple-array (unsigned-byte 8) (*)))))))

(defun %splice (app-sock circ sid)
  "Full duplex: a dedicated thread pumps tor->app with blocking reads (no
non-blocking TLS peeking, which corrupts cl+ssl under load); this thread pumps
app->tor.  Circuit writes are serialized by the circuit's write-lock."
  (let* ((app (usocket:socket-stream app-sock))
         (reader (bt:make-thread
                  (lambda ()
                    (handler-case
                        (loop
                          (multiple-value-bind (hop rcmd rsid len data) (circ:recv-relay circ)
                            (declare (ignore hop rsid len))
                            (cond
                              ((= rcmd rc:+r-data+) (write-sequence data app) (force-output app))
                              ((= rcmd rc:+r-end+) (return)))))
                      (serious-condition () nil))
                    (ignore-errors (usocket:socket-close app-sock)))   ; unblock our app read
                  :name "cl-tor tor->app")))
    (unwind-protect
         (handler-case
             (loop for chunk = (%read-available app)
                   until (eq chunk :eof)
                   do (strm:send-stream-data circ sid chunk))
           (serious-condition () nil))
      ;; Unblock the reader by closing the underlying TCP socket — NOT the SSL
      ;; object: freeing that while the reader is mid-SSL_read is a use-after-
      ;; free (segfault).  Join the reader, then %handle frees the SSL stream.
      (ignore-errors (usocket:socket-close (link:link-sock (circ:circuit-link circ))))
      (ignore-errors (bt:join-thread reader)))))

;;; ---- server -------------------------------------------------------------

(defun %handle (app-sock)
  (let ((circ nil))
    (unwind-protect
         (handler-case
             (let ((s (usocket:socket-stream app-sock)))
               (%socks-handshake s)
               (multiple-value-bind (host port) (%read-request s)
                 (setf circ (build-fresh-circuit :port port))
                 (handler-case (strm:begin-stream circ host port)
                   (error () (%reply s 5) (return-from %handle)))   ; connection refused
                 (%reply s 0)
                 (format t "[socks] CONNECT ~a:~d via ~{~a~^ -> ~}~%" host port
                         (mapcar (lambda (h) (dir:relay-nickname (rc:hop-relay h)))
                                 (circ:circuit-hops circ)))
                 (%splice app-sock circ 1)))
           (serious-condition (e) (format t "[socks] error: ~a~%" e)))
      (when circ (ignore-errors (strm:end-stream circ 1))
            (ignore-errors (circ:destroy-circuit circ))
            (ignore-errors (link:close-link (circ:circuit-link circ))))
      (ignore-errors (usocket:socket-close app-sock)))))

(defun run-proxy (&key (host "127.0.0.1") (port 9050))
  "Run a SOCKS5 proxy on HOST:PORT, each connection over a fresh Tor circuit."
  (format t "[cl-tor] SOCKS5 proxy on ~a:~d~%" host port)
  (let ((server (usocket:socket-listen host port :reuse-address t
                                                 :element-type '(unsigned-byte 8))))
    (unwind-protect
         (loop for app = (usocket:socket-accept server :element-type '(unsigned-byte 8))
               do (bordeaux-threads:make-thread
                   (lambda () (%handle app)) :name "cl-tor socks conn"))
      (ignore-errors (usocket:socket-close server)))))
