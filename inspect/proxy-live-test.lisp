;;;; inspect/proxy-live-test.lisp — the SOCKS5 proxy against the LIVE Tor network, run on a
;;;; thread that is NOT the main one.
;;;;
;;;;   sbcl --script inspect/proxy-live-test.lisp       (cl-tor findable by ASDF; needs the network)
;;;;
;;;; RUN-PROXY on 127.0.0.1 and an ephemeral port, on a thread this file starts; curl (a client
;;;; that is not ours) fetches https://check.torproject.org/api/ip through it twice, one
;;;; connection after the other, and each answer must say IsTor.  Then STOP-P ends the proxy
;;;; and the port must be closed.  The same on modus: there a thread may not store its objects
;;;; into another thread's, which is why RUN-PROXY's connection threads are started on a named
;;;; function and ask for paths over a channel.  With DIRECTORY_ON_MAIN=1 the MAIN thread owns
;;;; the directory (SERVE-DIRECTORY) while the proxy thread accepts -- what modus needs, where a
;;;; worker's 16 MB heap does not hold the consensus.  Exits 0 iff all pass.

(require :asdf)
(handler-bind ((warning #'muffle-warning))
  (let ((*standard-output* (make-broadcast-stream))) (asdf:load-system "cl-tor")))

(defvar *checks* 0) (defvar *fails* 0)
(defun check (name ok &optional detail)
  (incf *checks*) (unless ok (incf *fails*))
  (format t "  ~:[FAIL~;ok  ~] ~a~@[   ~a~]~%" ok name detail) (finish-output))

(defvar *port* 0)
(defvar *stop* (make-array 1 :element-type '(unsigned-byte 8) :initial-element 0))
(defun stop-p () (plusp (aref *stop* 0)))
(defun note-port (p) (setf *port* p))
(defvar *dir* (and (equal (uiop:getenv "DIRECTORY_ON_MAIN") "1") (cl-tor.socks:make-directory)))
(defun proxy-thread ()
  (handler-case (cl-tor.socks:run-proxy :port 0 :on-listening #'note-port :stop-p #'stop-p
                                        :directory *dir*)
    (error (e) (format t "~&run-proxy died: ~a~%" e) (finish-output))))

(defun curl ()
  (with-output-to-string (o)
    (sb-ext:run-program "curl" (list "-sS" "-m" "300" "--socks5-hostname"
                                     (format nil "127.0.0.1:~d" *port*)
                                     "https://check.torproject.org/api/ip")
                        :search t :output o :error o)))

(defun curl-serving (dir)
  "CURL while this thread serves DIR: curl runs as a process of its own (:WAIT NIL) and this
thread answers the directory until it exits.  Not a curl THREAD: on modus a thread waiting in
RUN-PROGRAM stalls the main thread's collections until the child exits (see the report on
this branch), and the main thread here is the one the proxy is waiting on."
  (let* ((file (format nil "~a/cl-tor-curl-~d.out" (or (uiop:getenv "TMPDIR") "/tmp") (random 1000000000)))
         (proc (sb-ext:run-program "curl" (list "-sS" "-m" "300" "-o" file "--socks5-hostname"
                                               (format nil "127.0.0.1:~d" *port*)
                                               "https://check.torproject.org/api/ip")
                                   :search t :wait nil :output nil :error nil)))
    (loop while (sb-ext:process-alive-p proc)
          do (when (zerop (cl-tor.socks:serve-directory-requests dir)) (sleep 0.05)))
    (prog1 (or (ignore-errors (with-open-file (i file) (read-line i nil ""))) "")
      (ignore-errors (delete-file file)))))

(defun refused-p (port)
  (handler-case
      (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
        (unwind-protect (progn (sb-bsd-sockets:socket-connect s #(127 0 0 1) port) nil)
          (ignore-errors (sb-bsd-sockets:socket-close s))))
    (error () t)))

(format t "~&== cl-tor: SOCKS5 proxy on a worker thread, live network ==~%")
;; With the directory on main, load it up front so the first connection does not wait for it.
(when *dir* (format t "~&  (directory: ~d relays)~%" (cl-tor.socks:load-directory)))
(let ((thread (sb-thread:make-thread #'proxy-thread :name "proxy")))
  (loop repeat 600 while (zerop *port*) do (sleep 0.1))
  (check "the proxy listens on an ephemeral loopback port" (plusp *port*) *port*)
  (when (plusp *port*)
    (let ((results (loop repeat 2 collect (string-trim '(#\Newline)
                                                    (if *dir* (curl-serving *dir*) (curl))))))
      (loop for r in results for i from 1
            do (check (format nil "connection ~d: check.torproject.org says IsTor" i)
                      (search "\"IsTor\":true" r) r))))
  (setf (aref *stop* 0) 1)
  (sb-thread:join-thread thread :default nil)
  (check "STOP-P ended the proxy and its port is closed" (refused-p *port*)))

(format t "~&checks: ~d   failures: ~d   => ~:[FAIL~;PASS~]~%" *checks* *fails* (zerop *fails*))
(finish-output)
(sb-ext:exit :code (if (zerop *fails*) 0 1) :abort t)
