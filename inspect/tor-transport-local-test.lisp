;;;; inspect/tor-transport-local-test.lisp -- cl-transport's :TOR backend (cl-tor-transport's
;;;; DIAL-OVER-TOR) from WORKER threads, against the fake Tor network on 127.0.0.1.  The same
;;;; file on SBCL and on modus:
;;;;
;;;;   inspect/run-onion-local.sh sbcl|modus inspect/tor-transport-local-test.lisp
;;;;
;;;; The main thread owns the directory and shares it (DSVC:SHARE-DIRECTORY) and runs an onion
;;;; service whose streams go to a local backend (it upper-cases).  Worker threads, started on
;;;; a named function, call (CL-TRANSPORT:DIAL host port :TRANSPORT :TOR) -- they hold no
;;;; directory of their own; the backend borrows a slot of the shared one for the dial:
;;;;   1. an exit target (the fake exit echoes), from a worker
;;;;   2. the .onion, from a worker
;;;;   3. both at once, from two workers
;;;; Each stream carries bytes both ways and closes; every borrowed slot comes back.

(require :asdf)
(handler-bind ((warning #'muffle-warning))
  (let ((*standard-output* (make-broadcast-stream))) (asdf:load-system "cl-tor-transport")))

(defpackage #:tor-transport-local-test
  (:use #:cl)
  (:local-nicknames (#:dir #:cl-tor.directory) (#:link #:cl-tor.link) (#:dsvc #:cl-tor.dirsvc)
                    (#:host #:cl-tor.hshost) (#:svc #:cl-tor.hsservice) (#:hsdir #:cl-tor.hsdir)
                    (#:bob #:bobbin) (#:sock #:cl-transport.sockets)))
(in-package #:tor-transport-local-test)

(defvar *checks* 0)
(defvar *fails* 0)
(defun check (name ok &optional detail)
  (incf *checks*) (unless ok (incf *fails*))
  (format t "  ~:[FAIL~;ok  ~] ~a~@[   ~a~]~%" ok name detail) (finish-output))
(defun now () (get-universal-time))

(let ((ports (mapcar #'parse-integer
                     (uiop:split-string (string-trim " " (or (uiop:getenv "FAKE_TOR")
                                                             (error "FAKE_TOR is not set")))
                                        :separator " "))))
  (setf dir:*authorities* (list (list "fake" "127.0.0.1" (second ports)
                                      "0000000000000000000000000000000000000000"))
        dir:*verify-consensus* nil
        link:*plain-links* t
        link:*dial-host* "127.0.0.1"))

(defun %bytes (string) (map '(simple-array (unsigned-byte 8) (*)) #'char-code string))
(defun %string (bytes) (map 'string #'code-char bytes))

(defun dial-worker (host port payload result)
  "On a worker: dial HOST:PORT over :TOR, send PAYLOAD, read as many bytes back, close."
  (bob:channel-send
   result
   (handler-case
       (multiple-value-bind (stream closer) (cl-transport:dial host port :transport :tor)
         (unwind-protect
              (progn
                (write-sequence (%bytes payload) stream) (force-output stream)
                (let ((buf (make-array (length payload) :element-type '(unsigned-byte 8)))
                      (got 0))
                  (loop while (< got (length buf))
                        do (let ((n (read-sequence buf stream :start got)))
                             (when (= n got) (return))
                             (setf got n)))
                  (list :ok (%string (subseq buf 0 got)))))
           (funcall closer)))
     (serious-condition (e) (list :error (princ-to-string e))))))

(defun backend-main (port-chan stop-chan)
  (let ((l (sock:tcp-listen :host "127.0.0.1" :port 0)) (conns '()))
    (bob:channel-send port-chan (sock:tcp-listener-port l))
    (unwind-protect
         (loop until (nth-value 1 (bob:channel-try-receive stop-chan))
               do (let ((ts (sock:tcp-accept l :timeout-ms 20))) (when ts (push ts conns)))
                  (dolist (ts conns)
                    (when (sock:wait-readable (list ts) 0)
                      (let* ((s (sock:tcp-socket-stream ts)) (b (read-byte s nil nil)))
                        (if (null b)
                            (progn (sock:tcp-close ts) (setf conns (remove ts conns)))
                            (progn (write-byte (char-code (char-upcase (code-char b))) s)
                                   (finish-output s)))))))
      (dolist (ts conns) (ignore-errors (sock:tcp-close ts)))
      (sock:tcp-listener-close l))))

(defvar *dir* (dsvc:make-directory :slots 4))
(defvar *service* nil)
(defun pump () (dsvc:serve-directory-requests *dir*) (when *service* (host:service-step *service*)))
(defun receive-pumping (chan timeout)
  (let ((end (+ (now) timeout)))
    (loop (multiple-value-bind (m ok) (bob:channel-try-receive chan) (when ok (return m)))
          (when (> (now) end) (return nil))
          (pump) (sleep 0.02))))
(defun dial-from-worker (host port payload)
  (let ((result (bob:make-channel :capacity 65536)))
    (sb-thread:make-thread 'dial-worker :name "dial worker" :arguments (list host port payload result))
    result))
(defun free-slots ()
  (let ((n 0) (got '()))
    (loop (multiple-value-bind (s ok) (bob:channel-try-receive (dsvc:directory-free *dir*))
            (unless ok (return)) (push s got) (incf n)))
    (dolist (s got) (bob:channel-send (dsvc:directory-free *dir*) s))
    n))

(format t "~&== cl-tor-transport: DIAL :TOR from worker threads, local Tor network ==~%") (finish-output)
(let ((t0 (now)) (bport-chan (bob:make-channel :capacity 4096)) (bstop (bob:make-channel :capacity 4096)))
  (format t "  (directory: ~d relays, on the main thread)~%" (dsvc:load-directory))
  (dsvc:share-directory *dir*)
  (sb-thread:make-thread 'backend-main :name "backend" :arguments (list bport-chan bstop))
  (let* ((bport (receive-pumping bport-chan 60))
         (id (svc:generate-identity))
         (onion (hsdir:pubkey->onion (svc:hs-identity-pubkey id))))
    (setf *service* (host:start-service id :target (list "127.0.0.1" bport) :num-intros 2))
    (let ((end (+ (now) 900)))
      (loop until (or (host:service-published *service*) (> (now) end)) do (pump) (sleep 0.02)))
    (check "the onion service is published" (host:service-published *service*))
    (let ((r (receive-pumping (dial-from-worker "echo.test" 7 "over tor, from a worker") 900)))
      (check "1: a worker dials an exit target over :TOR; bytes both ways"
             (equal r '(:ok "over tor, from a worker")) r))
    (let ((r (receive-pumping (dial-from-worker onion 80 "an onion, from a worker") 900)))
      (check "2: a worker dials the .onion over :TOR; bytes both ways"
             (equal r '(:ok "AN ONION, FROM A WORKER")) r))
    (let* ((ra (dial-from-worker onion 80 "both at once a"))
           (rb (dial-from-worker "echo.test" 7 "both at once b"))
           (a (receive-pumping ra 900)) (b (receive-pumping rb 900)))
      (check "3: two workers dial at once (the .onion and an exit)"
             (and (equal a '(:ok "BOTH AT ONCE A")) (equal b '(:ok "both at once b")))
             (list a b)))
    (let ((end (+ (now) 30))) (loop until (or (= 4 (free-slots)) (> (now) end)) do (pump) (sleep 0.05)))
    (check "every borrowed directory slot came back" (= 4 (free-slots)) (free-slots))
    (host:stop-service *service*)
    (let ((end (+ (now) 60)))
      (loop until (or (zerop (host:service-intro-count *service*)) (> (now) end)) do (pump) (sleep 0.02)))
    (bob:channel-send bstop :stop)
    (dsvc:share-directory nil))
  (format t "  (~d s in all)~%" (- (now) t0)))
(format t "~&checks: ~d   failures: ~d   => ~:[FAIL~;PASS~]~%" *checks* *fails* (zerop *fails*))
(finish-output)
(sb-ext:exit :code (if (zerop *fails*) 0 1) :abort t)
