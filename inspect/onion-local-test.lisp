;;;; inspect/onion-local-test.lisp -- the SOCKS proxy, the onion-service client and onion
;;;; hosting, end to end against a Tor network on this machine.  The same file on SBCL and
;;;; on modus:
;;;;
;;;;   inspect/run-onion-local.sh sbcl|modus     (starts inspect/fake-tor-net.lisp first)
;;;;
;;;; FAKE_TOR="OR-PORT DIR-PORT" names the fake network (inspect/fake-tor-net.lisp): a directory
;;;; authority and nine relays on 127.0.0.1, speaking the real protocol over plain TCP.  The
;;;; threads are the shape modus needs, on both Lisps: the MAIN thread owns the directory (it
;;;; answers the proxy's directory and the onion service's) and the service; the proxy's accept
;;;; loop, its connection threads, the service's intro / rendezvous / publish threads, the
;;;; backend and the SOCKS clients are threads started on named functions with plain
;;;; :ARGUMENTS, reporting back by channel.
;;;;
;;;;   A. a SOCKS CONNECT to an ordinary name goes out through an exit (the fake exit echoes)
;;;;   B. an onion service comes up: two intro points established, the descriptor published
;;;;      to the fake HSDirs; its inbound streams go to a local TCP backend (it upper-cases)
;;;;   C. a SOCKS CONNECT to that .onion, through the same proxy: CONNECT-ONION on the
;;;;      connection thread (descriptor fetch, introduce, rendezvous) meets the service's
;;;;      rendezvous thread, and bytes go client -> service -> backend -> back; twice, the
;;;;      second while the first is still open
;;;;   D. a .onion nobody serves answers SOCKS 0xF2 (introduction failed); stopping ends every
;;;;      thread and closes the proxy's port
;;;;
;;;; Exits 0 iff all pass.  Binds only 127.0.0.1 at ephemeral ports; contacts nothing else.

(require :asdf)
(handler-bind ((warning #'muffle-warning))
  (let ((*standard-output* (make-broadcast-stream))) (asdf:load-system "cl-tor")))

(defpackage #:onion-local-test
  (:use #:cl)
  (:local-nicknames (#:dir #:cl-tor.directory) (#:link #:cl-tor.link) (#:dsvc #:cl-tor.dirsvc)
                    (#:socks #:cl-tor.socks) (#:host #:cl-tor.hshost) (#:svc #:cl-tor.hsservice)
                    (#:hsdir #:cl-tor.hsdir) (#:bob #:bobbin) (#:sock #:cl-transport.sockets)))
(in-package #:onion-local-test)

(defvar *checks* 0)
(defvar *fails* 0)
(defun check (name ok &optional detail)
  (incf *checks*) (unless ok (incf *fails*))
  (format t "  ~:[FAIL~;ok  ~] ~a~@[   ~a~]~%" ok name detail) (finish-output))

(defun now () (get-universal-time))

;;; --- the fake network -------------------------------------------------------------

(defvar *fake* (let ((s (uiop:getenv "FAKE_TOR")))
                 (unless s (error "FAKE_TOR=\"OR-PORT DIR-PORT\" is not set"))
                 (mapcar #'parse-integer (uiop:split-string (string-trim " " s) :separator " "))))
(setf dir:*authorities* (list (list "fake" "127.0.0.1" (second *fake*)
                                    "0000000000000000000000000000000000000000"))
      dir:*verify-consensus* nil
      link:*plain-links* t
      link:*dial-host* "127.0.0.1")

;;; --- threads (named functions, plain arguments) ---------------------------------------

(defun %stopped (stop-chan) (nth-value 1 (bob:channel-try-receive stop-chan)))

(defun proxy-main (requests replies free port-chan stop-chan)
  "The SOCKS proxy's accept loop; the directory it asks is served by the main thread."
  (handler-case
      (socks:run-proxy :host "127.0.0.1" :port 0 :max-connections (length replies)
                       :directory (dsvc:%make-directory requests replies free)
                       :on-listening (lambda (p) (bob:channel-send port-chan p :timeout 5))
                       :stop-p (lambda () (%stopped stop-chan)))
    (serious-condition (e) (bob:channel-send port-chan (princ-to-string e) :timeout 5))))

(defun %read-some (ts max timeout)
  "Up to MAX bytes from TS once readable within TIMEOUT seconds: an octet vector (empty on EOF
or timeout)."
  (let ((s (sock:tcp-socket-stream ts)) (out (make-array 0 :element-type '(unsigned-byte 8)
                                                           :adjustable t :fill-pointer 0)))
    (when (sock:wait-readable (list ts) (* 1000 timeout))
      (loop for b = (read-byte s nil nil)
            while b do (vector-push-extend b out)
            while (and (< (length out) max) (sock:wait-readable (list ts) 0))))
    (coerce out '(simple-array (unsigned-byte 8) (*)))))

(defun %read-exactly (ts n timeout)
  (let ((end (+ (now) timeout)) (out (make-array 0 :element-type '(unsigned-byte 8)
                                                    :adjustable t :fill-pointer 0)))
    (loop while (and (< (length out) n) (< (now) end))
          do (let ((got (%read-some ts (- n (length out)) (max 1 (- end (now))))))
               (when (zerop (length got)) (return))
               (loop for b across got do (vector-push-extend b out))))
    (coerce out '(simple-array (unsigned-byte 8) (*)))))

(defun %bytes (string) (map '(simple-array (unsigned-byte 8) (*)) #'char-code string))
(defun %string (bytes) (map 'string #'code-char bytes))

(defun socks-client (proxy-port host port payload hold-chan result-chan)
  "Connect through the proxy to HOST:PORT, send PAYLOAD, read as many bytes back.  Reports
(:reply CODE) then (:data STRING); with HOLD-CHAN, keeps the connection open until a message
arrives there."
  (handler-case
      (let* ((ts (sock:tcp-connect "127.0.0.1" proxy-port))
             (s (sock:tcp-socket-stream ts)))
        (unwind-protect
             (progn
               (write-sequence (%bytes (format nil "~c~c~c" (code-char 5) (code-char 1) (code-char 0))) s)
               (finish-output s)
               (%read-exactly ts 2 30)
               (write-sequence (concatenate '(vector (unsigned-byte 8))
                                            (vector 5 1 0 3 (length host)) (%bytes host)
                                            (vector (ldb (byte 8 8) port) (ldb (byte 8 0) port)))
                               s)
               (finish-output s)
               (let ((reply (%read-exactly ts 10 900)))
                 (bob:channel-send result-chan (list :reply (if (>= (length reply) 2) (aref reply 1) -1)))
                 (when (and (= (length reply) 10) (zerop (aref reply 1)))
                   (write-sequence (%bytes payload) s) (finish-output s)
                   (bob:channel-send result-chan
                                     (list :data (%string (%read-exactly ts (length payload) 300))))
                   (when hold-chan (bob:channel-receive hold-chan :timeout 900)))))
          (sock:tcp-close ts)))
    (serious-condition (e) (bob:channel-send result-chan (list :error (princ-to-string e))))))

(defun backend-main (port-chan stop-chan)
  "The service's target: a TCP server on 127.0.0.1 that answers each connection's bytes
upper-cased, several connections at once, until a message on STOP-CHAN."
  (let ((l (sock:tcp-listen :host "127.0.0.1" :port 0)) (conns '()))
    (bob:channel-send port-chan (sock:tcp-listener-port l))
    (unwind-protect
         (loop until (%stopped stop-chan)
               do (let ((ts (sock:tcp-accept l :timeout-ms 20)))
                    (when ts (push ts conns)))
                  (dolist (ts conns)
                    (when (sock:wait-readable (list ts) 0)
                      (let ((got (%read-some ts 4096 1)))
                        (if (zerop (length got))
                            (progn (sock:tcp-close ts) (setf conns (remove ts conns)))
                            (let ((s (sock:tcp-socket-stream ts)))
                              (write-sequence (%bytes (string-upcase (%string got))) s)
                              (finish-output s)))))))
      (dolist (ts conns) (ignore-errors (sock:tcp-close ts)))
      (sock:tcp-listener-close l))))

;;; --- the main thread: owner of the directory and the service --------------------------

(defvar *proxy-dir* (dsvc:make-directory :slots 4))
(defvar *service* nil)

(defun pump ()
  (dsvc:serve-directory-requests *proxy-dir*)
  (when *service* (host:service-step *service*)))

(defun receive-pumping (chan timeout)
  "The next message on CHAN within TIMEOUT seconds, the main thread pumping meanwhile."
  (let ((end (+ (now) timeout)))
    (loop
      (multiple-value-bind (m ok) (bob:channel-try-receive chan)
        (when ok (return (values m t))))
      (when (> (now) end) (return (values nil nil)))
      (pump) (sleep 0.02))))

(defun wait-pumping (pred timeout)
  (let ((end (+ (now) timeout)))
    (loop until (or (funcall pred) (> (now) end)) do (pump) (sleep 0.02))
    (funcall pred)))

(defun start-client (proxy-port host port payload &optional hold)
  (let ((result (bob:make-channel :capacity 65536)) (hold-chan (and hold (bob:make-channel :capacity 4096))))
    (sb-thread:make-thread 'socks-client :name "socks client"
                           :arguments (list proxy-port host port payload hold-chan result))
    (values result hold-chan)))

(defun client-result (result timeout)
  "(values reply-code data-string-or-NIL)"
  (let ((r (receive-pumping result timeout)))
    (cond ((null r) (values :timeout nil))
          ((eq (first r) :error) (values (second r) nil))
          ((not (eql (second r) 0)) (values (second r) nil))
          (t (let ((d (receive-pumping result 600))) (values 0 (and d (second d))))))))

(defun refused-p (port)
  (handler-case (progn (sock:tcp-close (sock:tcp-connect "127.0.0.1" port :timeout-secs 5)) nil)
    (error () t)))

(format t "~&== cl-tor: proxy, onion client and onion hosting against a local Tor network ==~%")
(finish-output)

(let* ((t0 (now))
       (port-chan (bob:make-channel :capacity 4096))
       (proxy-stop (bob:make-channel :capacity 4096))
       (backend-port-chan (bob:make-channel :capacity 4096))
       (backend-stop (bob:make-channel :capacity 4096))
       (proxy-thread (sb-thread:make-thread
                      'proxy-main :name "proxy"
                      :arguments (list (dsvc:directory-requests *proxy-dir*)
                                       (coerce (dsvc:directory-replies *proxy-dir*) 'list)
                                       (dsvc:directory-free *proxy-dir*) port-chan proxy-stop)))
       (proxy-port (receive-pumping port-chan 60)))
  (check "the proxy listens on an ephemeral loopback port (its accept loop on a thread)"
         (integerp proxy-port) proxy-port)
  (format t "  (directory: ~d relays, on the main thread)~%" (dsvc:load-directory)) (finish-output)

  ;; A. clearnet through an exit
  (multiple-value-bind (code data) (client-result (start-client proxy-port "echo.test" 7 "hello, exit") 600)
    (check "A: SOCKS CONNECT echo.test:7 succeeds through a 3-hop circuit" (eql code 0) code)
    (check "A: the exit's stream carries the bytes both ways" (equal data "hello, exit") data))

  ;; B. an onion service, its streams spliced to a local backend
  (sb-thread:make-thread 'backend-main :name "backend" :arguments (list backend-port-chan backend-stop))
  (let* ((bport (receive-pumping backend-port-chan 60))
         (id (svc:generate-identity))
         (onion (hsdir:pubkey->onion (svc:hs-identity-pubkey id))))
    (setf *service* (host:start-service id :target (list "127.0.0.1" bport) :num-intros 2
                                           :max-rendezvous 3))
    (wait-pumping (lambda () (host:service-published *service*)) 900)
    (check "B: the service's two intro points are up" (= 2 (host:service-live-count *service*))
           (host:service-live-count *service*))
    (check "B: its descriptor is published to the HSDirs" (host:service-published *service*)
           (host:service-accepted *service*))
    (format t "  (service ~a up after ~d s)~%" onion (- (now) t0)) (finish-output)

    ;; C. the onion through the proxy, twice, the second while the first is open
    (multiple-value-bind (r1 hold1) (start-client proxy-port onion 80 "hello, onion" t)
      (multiple-value-bind (code data) (client-result r1 900)
        (check "C: SOCKS CONNECT to the .onion succeeds (connect-onion on the connection thread)"
               (eql code 0) code)
        (check "C: client -> rendezvous -> service -> backend and back" (equal data "HELLO, ONION") data))
      (multiple-value-bind (code data) (client-result (start-client proxy-port onion 80 "second stream") 900)
        (check "C: a second .onion connection while the first is open" (eql code 0) code)
        (check "C: its bytes go through too" (equal data "SECOND STREAM") data))
      (bob:channel-send hold1 :done))
    (check "C: the service accepted both rendezvous" (= 2 (host:service-rendezvous-count *service*))
           (host:service-rendezvous-count *service*))

    ;; D. an onion nobody serves; then stop everything
    (let ((nobody (hsdir:pubkey->onion (svc:hs-identity-pubkey (svc:generate-identity)))))
      (multiple-value-bind (code) (client-result (start-client proxy-port nobody 80 "x") 900)
        (check "D: a .onion with no descriptor answers SOCKS 0xF2" (eql code #xF2) code)))
    (host:stop-service *service*)
    (wait-pumping (lambda () (null (host::service-intros *service*))) 60)
    (check "D: stopping the service ends its intro threads" (null (host::service-intros *service*)))
    (bob:channel-send backend-stop :stop))
  (bob:channel-send proxy-stop :stop)
  (wait-pumping (lambda () (not (sb-thread:thread-alive-p proxy-thread))) 30)
  (check "D: the proxy's accept loop ended and its port is closed" (refused-p proxy-port))
  (format t "  (~d s in all)~%" (- (now) t0)))

(format t "~&checks: ~d   failures: ~d   => ~:[FAIL~;PASS~]~%" *checks* *fails* (zerop *fails*))
(finish-output)
(sb-ext:exit :code (if (zerop *fails*) 0 1) :abort t)
