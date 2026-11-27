;;;; inspect/onion-live-test.lisp — onion services against the LIVE Tor network, on SBCL or modus.
;;;;
;;;;   sbcl --script inspect/onion-live-test.lisp       (cl-tor findable by ASDF; needs the network)
;;;;   modus --script inspect/onion-live-test.lisp
;;;;
;;;; The threads are the shape modus needs, on both Lisps: the MAIN thread owns the directory
;;;; (the consensus, the HSDirs, the guards) and the onion service, and pumps -- it answers the
;;;; proxy's directory, the shared directory and the service's.  Everything that holds a circuit
;;;; or a socket is a thread started on a named function with plain :ARGUMENTS.
;;;;
;;;;   a. .onion client: our own HTTP/1.0 GET through the in-process SOCKS proxy to the Tor
;;;;      Project's onion site, twice -- an HTTP status line and recognisable content;
;;;;   b. onion hosting: START-SERVICE with a :TARGET of a local HTTP responder (127.0.0.1, an
;;;;      ephemeral port), published to the real HSDirs, then reached at its own .onion through
;;;;      the proxy (retried with a bound: a descriptor takes a while to be found);
;;;;   c. cl-transport's :TOR (cl-tor-transport) from WORKER threads, through the shared
;;;;      directory: the onion of (a), and example.com:80 over an exit.
;;;;
;;;; ONION_LIVE_ONLY=a,b,c runs a subset.  Exits 0 iff all pass.  Listens only on 127.0.0.1.

(require :asdf)
(handler-bind ((warning #'muffle-warning))
  (let ((*standard-output* (make-broadcast-stream))) (asdf:load-system "cl-tor-transport")))

(defpackage #:onion-live-test
  (:use #:cl)
  (:local-nicknames (#:dsvc #:cl-tor.dirsvc) (#:socks #:cl-tor.socks) (#:host #:cl-tor.hshost)
                    (#:svc #:cl-tor.hsservice) (#:hsdir #:cl-tor.hsdir) (#:bob #:bobbin)
                    (#:sock #:cl-transport.sockets)))
(in-package #:onion-live-test)

(defparameter *torproject-onion* "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion")

(defvar *checks* 0)
(defvar *fails* 0)
(defun check (name ok &optional detail)
  (incf *checks*) (unless ok (incf *fails*))
  (format t "  ~:[FAIL~;ok  ~] ~a~@[   ~a~]~%" ok name detail) (finish-output))
(defun now () (get-universal-time))
(defvar *t0* (now))
(defun stamp () (- (now) *t0*))
(defun want (item)
  (let ((only (uiop:getenv "ONION_LIVE_ONLY")))
    (or (null only) (search (string item) only :test #'char-equal))))

(defun %bytes (string) (map '(simple-array (unsigned-byte 8) (*)) #'char-code string))
(defun %string (bytes) (map 'string #'code-char bytes))
(defun %crlf () (format nil "~c~c" #\Return #\Newline))
(defun http-get-request (hostname)
  (format nil "GET / HTTP/1.0~aHost: ~a~aUser-Agent: cl-tor-test~aConnection: close~a~a"
          (%crlf) hostname (%crlf) (%crlf) (%crlf) (%crlf)))

(defun %read-to-eof (ts max timeout)
  "Bytes from TS until EOF, MAX bytes, or TIMEOUT seconds without progress."
  (let ((s (sock:tcp-socket-stream ts))
        (out (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop while (and (< (length out) max) (sock:wait-readable (list ts) (* 1000 timeout)))
          do (let ((b (read-byte s nil nil)))
               (unless b (return))
               (vector-push-extend b out)))
    (coerce out '(simple-array (unsigned-byte 8) (*)))))

;;; --- threads (named functions, plain arguments) -------------------------------------

(defun proxy-main (requests replies free port-chan stop-chan)
  (handler-case
      (socks:run-proxy :host "127.0.0.1" :port 0 :max-connections (length replies)
                       :directory (dsvc:%make-directory requests replies free)
                       :on-listening (lambda (p) (bob:channel-send port-chan p :timeout 5))
                       :stop-p (lambda () (nth-value 1 (bob:channel-try-receive stop-chan))))
    (serious-condition (e) (bob:channel-send port-chan (princ-to-string e) :timeout 5))))

(defun socks-http (proxy-port hostname port result)
  "HTTP/1.0 GET / of HOSTNAME:PORT through the SOCKS5 proxy; reports (:reply code) or
(:http text) or (:error msg)."
  (bob:channel-send
   result
   (handler-case
       (let* ((ts (sock:tcp-connect "127.0.0.1" proxy-port)) (s (sock:tcp-socket-stream ts)))
         (unwind-protect
              (progn
                (write-sequence (%bytes (map 'string #'code-char '(5 1 0))) s) (finish-output s)
                (%read-exactly ts 2 60)
                (write-sequence (concatenate '(vector (unsigned-byte 8))
                                             (vector 5 1 0 3 (length hostname)) (%bytes hostname)
                                             (vector (ldb (byte 8 8) port) (ldb (byte 8 0) port)))
                                s)
                (finish-output s)
                (let ((reply (%read-exactly ts 10 600)))
                  (if (not (and (= (length reply) 10) (zerop (aref reply 1))))
                      (list :reply (if (>= (length reply) 2) (aref reply 1) -1))
                      (progn (write-sequence (%bytes (http-get-request hostname)) s) (finish-output s)
                             (list :http (%string (%read-to-eof ts 200000 120)))))))
           (sock:tcp-close ts)))
     (serious-condition (e) (list :error (princ-to-string e))))))

(defun %read-exactly (ts n timeout)
  (let ((s (sock:tcp-socket-stream ts)) (out '()))
    (loop repeat n
          while (sock:wait-readable (list ts) (* 1000 timeout))
          do (let ((b (read-byte s nil nil))) (if b (push b out) (return))))
    (coerce (nreverse out) '(simple-array (unsigned-byte 8) (*)))))

(defun responder-main (port-chan stop-chan text)
  "A local HTTP responder: answers every request with TEXT, then closes."
  (let ((l (sock:tcp-listen :host "127.0.0.1" :port 0)))
    (bob:channel-send port-chan (sock:tcp-listener-port l))
    (unwind-protect
         (loop until (nth-value 1 (bob:channel-try-receive stop-chan))
               do (let ((ts (sock:tcp-accept l :timeout-ms 100)))
                    (when ts
                      (ignore-errors
                        (let ((s (sock:tcp-socket-stream ts)))
                          ;; read the request head (to the blank line), then answer
                          (let ((seen '()))
                            (loop while (sock:wait-readable (list ts) 30000)
                                  do (let ((b (read-byte s nil nil)))
                                       (unless b (return))
                                       (push b seen)
                                       (when (and (>= (length seen) 4)
                                                  (equal (subseq seen 0 4) '(10 13 10 13)))
                                         (return)))))
                          (write-sequence
                           (%bytes (format nil "HTTP/1.0 200 OK~aContent-Type: text/plain~aContent-Length: ~d~a~a~a"
                                           (%crlf) (%crlf) (length text) (%crlf) (%crlf) text))
                           s)
                          (finish-output s)))
                      (sock:tcp-close ts))))
      (sock:tcp-listener-close l))))

(defun dial-worker (hostname port result)
  "On a worker: CL-TRANSPORT:DIAL HOSTNAME:PORT over :TOR, HTTP/1.0 GET /, read to EOF."
  (bob:channel-send
   result
   (handler-case
       (multiple-value-bind (stream closer) (cl-transport:dial hostname port :transport :tor :timeout 120)
         (unwind-protect
              (progn
                (write-sequence (%bytes (http-get-request hostname)) stream) (force-output stream)
                (let ((buf (make-array 200000 :element-type '(unsigned-byte 8))) (got 0))
                  (loop (let ((n (read-sequence buf stream :start got)))
                          (when (or (= n got) (>= n (length buf))) (setf got n) (return))
                          (setf got n)))
                  (list :http (%string (subseq buf 0 got)))))
           (funcall closer)))
     (serious-condition (e) (list :error (princ-to-string e))))))

;;; --- the main thread: directory owner, service owner ----------------------------------

(defvar *proxy-dir* (dsvc:make-directory :slots 6))
(defvar *shared-dir* (dsvc:make-directory :slots 4))
(defvar *service* nil)

(defun pump ()
  (dsvc:serve-directory-requests *proxy-dir*)
  (dsvc:serve-directory-requests *shared-dir*)
  (when *service* (host:service-step *service*)))

(defun receive-pumping (chan timeout)
  (let ((end (+ (now) timeout)))
    (loop (multiple-value-bind (m ok) (bob:channel-try-receive chan) (when ok (return m)))
          (when (> (now) end) (return nil))
          (pump) (sleep 0.02))))

(defun spawn (fn &rest args)
  (let ((result (bob:make-channel :capacity 262144)))
    (sb-thread:make-thread fn :name (string-downcase (symbol-name fn))
                              :arguments (append args (list result)))
    result))

(defun http-ok-p (text) (and (stringp text) (eql 0 (search "HTTP/1." text))))
(defun status-line (text)
  (and (stringp text) (subseq text 0 (or (position #\Return text) (min 40 (length text))))))

(format t "~&== cl-tor: onion client, hosting and :tor dials, LIVE network ==~%") (finish-output)
(let* ((port-chan (bob:make-channel :capacity 4096))
       (proxy-stop (bob:make-channel :capacity 4096))
       (proxy-thread (sb-thread:make-thread
                      'proxy-main :name "proxy"
                      :arguments (list (dsvc:directory-requests *proxy-dir*)
                                       (coerce (dsvc:directory-replies *proxy-dir*) 'list)
                                       (dsvc:directory-free *proxy-dir*) port-chan proxy-stop)))
       (proxy-port (receive-pumping port-chan 60)))
  (check "the proxy listens on an ephemeral loopback port" (integerp proxy-port) proxy-port)
  (format t "  (directory: ~d relays, ~d s)~%" (dsvc:load-directory) (stamp)) (finish-output)
  (dsvc:share-directory *shared-dir*)

  ;; a. the Tor Project's onion, through the proxy, twice
  (when (want :a)
    (dotimes (i 2)
      (let* ((t1 (now))
             (r (receive-pumping (spawn 'socks-http proxy-port *torproject-onion* 80) 900))
             (text (and (eq (first r) :http) (second r))))
        (check (format nil "a~d: GET / of the Tor Project's onion through the proxy (~d s)" (1+ i) (- (now) t1))
               (and (http-ok-p text) (search "Tor" text))
               (or (status-line text) r)))))

  ;; b. our own onion service, reached through the proxy
  (when (want :b)
    (let* ((t1 (now))
           (rport-chan (bob:make-channel :capacity 4096))
           (rstop (bob:make-channel :capacity 4096))
           (marker (format nil "cl-tor live onion responder ~d" (random 1000000000))))
      (sb-thread:make-thread 'responder-main :name "responder" :arguments (list rport-chan rstop marker))
      (let* ((rport (receive-pumping rport-chan 60))
             (id (svc:generate-identity))
             (onion (hsdir:pubkey->onion (svc:hs-identity-pubkey id))))
        (setf *service* (host:start-service id :target (list "127.0.0.1" rport) :num-intros 3))
        (let ((end (+ (now) 900)))
          (loop until (or (host:service-published *service*) (> (now) end)) do (pump) (sleep 0.02)))
        (check (format nil "b: the service is published to real HSDirs (~d s)" (- (now) t1))
               (host:service-published *service*)
               (format nil "~a: ~d intro points, ~d HSDirs accepted" onion
                       (host:service-live-count *service*) (host:service-accepted *service*)))
        (when (host:service-published *service*)
          (let ((text nil) (tries 0) (t2 (now)))
            (loop while (and (< tries 6) (not (and text (search marker text))))
                  do (incf tries)
                     (let ((r (receive-pumping (spawn 'socks-http proxy-port onion 80) 600)))
                       (setf text (and (eq (first r) :http) (second r)))
                       (unless (and text (search marker text))
                         (format t "    (try ~d: ~a)~%" tries r) (finish-output)
                         (let ((end (+ (now) 30))) (loop until (> (now) end) do (pump) (sleep 0.05))))))
            (check (format nil "b: our own .onion answers through the proxy (~d tries, ~d s)" tries (- (now) t2))
                   (and (http-ok-p text) (search marker text)) (status-line text))))
        (host:stop-service *service*)
        (let ((end (+ (now) 60)))
          (loop until (or (zerop (host:service-intro-count *service*)) (> (now) end)) do (pump) (sleep 0.02)))
        (bob:channel-send rstop :stop))))

  ;; c. cl-transport's :tor from worker threads
  (when (want :c)
    (let* ((t1 (now)) (r (receive-pumping (spawn 'dial-worker *torproject-onion* 80) 900))
           (text (and (eq (first r) :http) (second r))))
      (check (format nil "c: a worker dials the Tor Project's onion over :TOR (~d s)" (- (now) t1))
             (and (http-ok-p text) (search "Tor" text)) (or (status-line text) r)))
    (let* ((t1 (now)) (r (receive-pumping (spawn 'dial-worker "example.com" 80) 900))
           (text (and (eq (first r) :http) (second r))))
      (check (format nil "c: a worker dials example.com:80 over :TOR, through an exit (~d s)" (- (now) t1))
             (and (http-ok-p text) (search "Example Domain" text)) (or (status-line text) r))))

  (dsvc:share-directory nil)
  (bob:channel-send proxy-stop :stop)
  (let ((end (+ (now) 30)))
    (loop while (and (sb-thread:thread-alive-p proxy-thread) (< (now) end)) do (pump) (sleep 0.05)))
  (check "the proxy stopped" (not (sb-thread:thread-alive-p proxy-thread))))

(format t "~&checks: ~d   failures: ~d   => ~:[FAIL~;PASS~]   (~d s)~%" *checks* *fails* (zerop *fails*) (stamp))
(finish-output)
(sb-ext:exit :code (if (zerop *fails*) 0 1) :abort t)
