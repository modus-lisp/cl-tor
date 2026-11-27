;;;; src/socks.lisp — a local SOCKS5 front end (RFC 1928) onto Tor circuits.
;;;;
;;;; Each accepted SOCKS CONNECT builds its own fresh 3-hop circuit, opens a
;;;; stream to the requested host:port at the exit, and splices bytes both ways.
;;;; Host *names* are passed to the exit for resolution (ATYP=domain), so DNS
;;;; never leaks to the local resolver.
;;;;
;;;; THE THREADS SHARE NOTHING.  The directory state belongs to the directory's OWNER
;;;; (dirsvc.lisp): RUN-PROXY's thread, or -- given :DIRECTORY -- whichever thread serves it.
;;;; Each connection runs on a thread of its own, started on a NAMED function with the accepted
;;;; socket and its slot's channels as :ARGUMENTS, and owns everything it builds -- its link,
;;;; its circuit, its copy of the client socket.  When it needs relays it ASKS the owner
;;;; (DSVC:DIR-ASK) and gets them back as plain data, a copy; a guard that would not connect
;;;; is REPORTED the same way.  A .onion CONNECT runs CONNECT-ONION on the connection's thread
;;;; the same way.  The splice is one loop on the connection's thread (a readiness wait over
;;;; the client socket and the relay link), so a circuit is only ever touched by the thread
;;;; that built it.
;;;;
;;;; That is what modus needs -- a thread there may not store an object it made into memory
;;;; another thread made, so a connection thread could not fill the shared relay cache, and a
;;;; reader thread could not advance a circuit its connection thread made -- and SBCL runs the
;;;; same threads and channels (bobbin's), so RUN-PROXY works on any thread of either.

(in-package #:cl-tor.socks)

(defvar *onion-connect* nil
  "The v3 onion-service client (CL-TOR.HS-INTRO:CONNECT-ONION, which sets this when it loads:
it comes later in the system), so a CONNECT to a .onion name goes to the service through a
rendezvous rather than to an exit.  Called as (funcall it onion :port port) => circuit, stream,
on the connection's thread, which asks the directory owner for what it needs (DSVC:DIR-ASK).")

(defun %onion-name-p (host)
  (let ((n (length host)))
    (and (> n 6) (string-equal ".onion" host :start2 (- n 6)))))

(defun build-fresh-circuit (&key (tries 6) (port 443) path-fn guard-failed-fn)
  "Build a 3-hop circuit through a persistent entry guard (exit permitting PORT),
retrying past relay churn; a guard that won't connect is dropped from the set.

The path comes from the directory (DSVC:DIR-ASK :PATH -- the owner's, on a thread inside
DSVC:WITH-DIRECTORY-CLIENT; this thread's own state otherwise).  PATH-FN, if given, is called
with PORT for each try's (guard middle exit) path instead, and GUARD-FAILED-FN with a guard
that would not connect."
  (if (or path-fn guard-failed-fn)
      (let ((path-fn (or path-fn (lambda (port) (mapcar #'dir:plain->relay (dsvc:dir-ask :path port)))))
            (guard-failed-fn (or guard-failed-fn
                                 (lambda (g) (dsvc:dir-ask :guard-failed (dir:relay->plain g))))))
        (loop for i from 1 to tries
              for circ = (ignore-errors
                          (destructuring-bind (g m e) (funcall path-fn port)
                            (let ((lk (handler-case (link:connect-link g)
                                        (error (err) (funcall guard-failed-fn g) (error err)))))
                              (handler-case (circ:build-circuit lk m e)
                                (error (err) (link:close-link lk) (error err))))))
              when circ return circ
              finally (error "could not build a circuit after ~d tries" tries)))
      (dsvc:fresh-circuit :port port :tries tries)))

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

;;; ---- duplex splice, on one thread ---------------------------------------

(defun %read-available (stream &key (max 8192))
  "Read >=1 byte then drain what's buffered, up to MAX.  :EOF on close."
  (let ((first (read-byte stream nil :eof)))
    (if (eq first :eof) :eof
        (let ((buf (make-array max :element-type '(unsigned-byte 8) :fill-pointer 0)))
          (vector-push first buf)
          (loop while (and (< (fill-pointer buf) max) (listen stream))
                do (vector-push (read-byte stream) buf))
          (coerce buf '(simple-array (unsigned-byte 8) (*)))))))

(defun %tor-ready-p (circ)
  "Whether a relay cell can be read from CIRC's link without waiting for the network:
decrypted bytes in hand, or input pending on the link."
  (circ:circuit-input-ready-p circ))

(defun %splice (app-sock circ sid &key stop-p)
  "Full duplex on THIS thread: whenever the relay link has input, read a relay cell and
pass its data to the client; whenever the client has input, send it down the stream.
Ends on the client's EOF, the exit's RELAY_END, an error either way, or STOP-P (polled
every 50 ms) returning true."
  (let ((app (cl-transport.sockets:tcp-socket-stream app-sock))
        (lsock (link:link-sock (circ:circuit-link circ))))
    (handler-case
        (loop
          (when (and stop-p (funcall stop-p)) (return))
          (let ((did nil))
            (when (%tor-ready-p circ)
              (setf did t)
              (multiple-value-bind (hop rcmd rsid len data) (circ:recv-relay circ)
                (declare (ignore hop len))
                (cond ((and (= rcmd rc:+r-data+) (eql rsid sid))
                       (write-sequence data app) (force-output app))
                      ((and (= rcmd rc:+r-end+) (eql rsid sid)) (return)))))
            (when (cl-transport.sockets:wait-readable (list app-sock) 0)
              (setf did t)
              (let ((chunk (%read-available app)))
                (when (eq chunk :eof) (return))
                (strm:send-stream-data circ sid chunk)))
            (unless did
              (cl-transport.sockets:wait-readable (list app-sock lsock) 50))))
      (serious-condition (e) (format t "[socks] splice ended: ~a~%" e) (finish-output)))))

;;; ---- one connection, on its own thread ----------------------------------

(defun %handle (app-sock &key path-fn guard-failed-fn)
  (let ((circ nil))
    (unwind-protect
         (handler-case
             (let ((s (cl-transport.sockets:tcp-socket-stream app-sock)))
               (%socks-handshake s)
               (multiple-value-bind (host port) (%read-request s)
                 (when (%onion-name-p host)
                   ;; an onion service: introduce + rendezvous, the stream is on that circuit
                   (multiple-value-bind (c sid)
                       (handler-case (if *onion-connect*
                                         (funcall *onion-connect* host :port port)
                                         (error "no onion-service client"))
                         (error (e)
                           (format t "[socks] CONNECT ~a:~d failed: ~a~%" host port e) (finish-output)
                           (%reply s #xF2) (return-from %handle)))   ; Tor: introduction failed
                     (setf circ c)
                     (%reply s 0)
                     (format t "[socks] CONNECT ~a:~d (onion service)~%" host port) (finish-output)
                     (%splice app-sock circ sid)
                     (return-from %handle)))
                 (setf circ (build-fresh-circuit :port port :path-fn path-fn
                                                 :guard-failed-fn guard-failed-fn))
                 (handler-case (strm:begin-stream circ host port)
                   (error () (%reply s 5) (return-from %handle)))   ; connection refused
                 (%reply s 0)
                 (format t "[socks] CONNECT ~a:~d via ~{~a~^ -> ~}~%" host port
                         (mapcar (lambda (h) (dir:relay-nickname (rc:hop-relay h)))
                                 (circ:circuit-hops circ)))
                 (finish-output)
                 (%splice app-sock circ 1)))
           (serious-condition (e) (format t "[socks] error: ~a~%" e) (finish-output)))
      (when circ (ignore-errors (strm:end-stream circ 1))
            (ignore-errors (circ:destroy-circuit circ))
            (ignore-errors (link:close-link (circ:circuit-link circ))))
      (cl-transport.sockets:tcp-close app-sock))))

(defun %connection-main (sock slot requests reply free)
  "A connection thread.  SOCK is the accepted SB-BSD-SOCKETS socket (wrapped afresh here, so
its buffers are this thread's); the directory is asked over REQUESTS, answers arrive on
REPLY; SLOT goes back on FREE at the end."
  (let ((dir (dsvc:%make-directory requests (let ((v (make-array (1+ slot) :initial-element nil)))
                                              (setf (svref v slot) reply) v)
                                   free)))
    (unwind-protect
         (dsvc:with-directory-client (dir slot)
           (%handle (cl-transport.sockets:tcp-socket-from sock)))
      (dsvc:release-slot dir slot))))

;;; ---- server: the directory owner + the accept loop ----------------------
;;;
;;; The DIRECTORY (dirsvc.lisp) is the channels a connection uses to ask for paths.  Whoever
;;; calls SERVE-DIRECTORY on it is its OWNER and holds the directory state.  RUN-PROXY makes one
;;; and serves it itself, between accepts -- unless it is handed one, when another thread serves
;;; it.  That split is for modus, where a thread that is not main has a 16 MB heap and the
;;; consensus does not fit in it: there the main thread serves the directory and RUN-PROXY's
;;; accept loop runs on a thread of its own.  The names below are dirsvc's, kept here.

(defun make-directory (&key (slots 8)) (dsvc:make-directory :slots slots))
(defun %make-directory (requests replies &optional free) (dsvc:%make-directory requests replies free))
(defun socks-directory-requests (dir) (dsvc:directory-requests dir))
(defun socks-directory-replies (dir) (dsvc:directory-replies dir))
(defun socks-directory-free (dir) (dsvc:directory-free dir))
(defun serve-directory-requests (dir) (dsvc:serve-directory-requests dir))
(defun serve-directory (dir &key stop-p) (dsvc:serve-directory dir :stop-p stop-p))
(defun load-directory () (dsvc:load-directory))

(defun run-proxy (&key (host "127.0.0.1") (port 9050) (max-connections 8) on-listening stop-p
                    directory)
  "Run a SOCKS5 proxy on HOST:PORT, each connection over a fresh Tor circuit, on its own
thread (at most MAX-CONNECTIONS at once; a further one is closed at once).  PORT 0 binds
an ephemeral port; ON-LISTENING is called with the bound port.  Runs until STOP-P (a
function, polled every 50 ms) returns true, or forever.  Any thread may run it.

This thread is the directory's owner (see dirsvc.lisp) unless DIRECTORY is given -- a
MAKE-DIRECTORY (its slots are the connections that may run at once) that another thread
serves with SERVE-DIRECTORY."
  (let* ((dir (or directory (dsvc:make-directory :slots max-connections)))
         (own (null directory))
         (free (or (dsvc:directory-free dir)
                   ;; a directory rebuilt without its FREE channel: slots are handed out here
                   (let ((f (bob:make-channel :capacity 4096)))
                     (dotimes (i (min max-connections (dsvc:directory-slots dir)) f)
                       (bob:channel-send f i)))))
         (server (cl-transport.sockets:tcp-listen :host host :port port))
         (bound (cl-transport.sockets:tcp-listener-port server)))
    (format t "[cl-tor] SOCKS5 proxy on ~a:~d~%" host bound) (finish-output)
    (when on-listening (funcall on-listening bound))
    (dsvc:with-own-directory-state
      (unwind-protect
           (loop until (and stop-p (funcall stop-p))
                 do (when own (dsvc:serve-directory-requests dir))
                    (let ((app (cl-transport.sockets:tcp-accept server :timeout-ms 50)))
                      (when app
                        (multiple-value-bind (slot ok) (bob:channel-try-receive free)
                          (if (not ok)
                              (cl-transport.sockets:tcp-close app)
                              (handler-case
                                  (sb-thread:make-thread
                                   #'%connection-main :name "cl-tor socks conn"
                                   :arguments (list (cl-transport.sockets:tcp-socket-sock app)
                                                    slot (dsvc:directory-requests dir)
                                                    (svref (dsvc:directory-replies dir) slot) free))
                                (error (e)
                                  (format t "[socks] cannot start a connection: ~a~%" e)
                                  (cl-transport.sockets:tcp-close app)
                                  (bob:channel-send free slot :timeout 1))))))))
        (cl-transport.sockets:tcp-listener-close server)))))
