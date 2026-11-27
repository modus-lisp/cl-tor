;;;; inspect/fake-tor-net.lisp -- a Tor network on 127.0.0.1, for testing cl-tor offline.
;;;;
;;;;   sbcl --script inspect/fake-tor-net.lisp PORTFILE [SECONDS]
;;;;
;;;; One SBCL process plays a whole small Tor network: a directory authority (HTTP: the
;;;; microdesc consensus, zlib'd, and microdescriptors) and NINE relays behind ONE ORPort.
;;;; Each relay has its own RSA id, ed25519 id and ntor key, and its own /16 in the consensus
;;;; (10.N.0.1) so the path rules hold; the client dials them all at 127.0.0.1
;;;; (LINK:*DIAL-HOST*) over plain TCP (LINK:*PLAIN-LINKS*: no TLS, so no cert binding).
;;;; Everything above the link is the real protocol, with cl-tor's own crypto on the relay
;;;; side: VERSIONS / NETINFO, CREATE2 and EXTEND2 with the ntor server handshake, per-hop
;;;; AES-CTR + running digests (the relay's view of a hop is the client's with the
;;;; directions swapped), and the cells each role answers:
;;;;
;;;;   exit         BEGIN -> CONNECTED, then echoes the stream's DATA back (no TCP leaves)
;;;;   HSDir        BEGIN_DIR + HTTP: POST /tor/hs/3/publish stores a descriptor under the
;;;;                blinded key its signing-key cert names; GET /tor/hs/3/<key> serves it
;;;;   intro point  ESTABLISH_INTRO -> INTRO_ESTABLISHED; INTRODUCE1 -> INTRODUCE2 down the
;;;;                service's circuit, INTRODUCE_ACK to the client
;;;;   rendezvous   ESTABLISH_RENDEZVOUS -> RENDEZVOUS_ESTABLISHED; RENDEZVOUS1 ->
;;;;                RENDEZVOUS2 to the client, and the two circuits joined: a cell neither
;;;;                relay hop recognizes passes to the other circuit (the end-to-end hop)
;;;;
;;;; It writes "OR-PORT DIR-PORT" to PORTFILE once listening, binds only 127.0.0.1 at
;;;; ephemeral ports, and exits by itself after SECONDS (default 1800) or when PORTFILE is
;;;; deleted.  It never contacts anything.

(require :asdf)
(handler-bind ((warning #'muffle-warning))
  (let ((*standard-output* (make-broadcast-stream))) (asdf:load-system "cl-tor")))

(defpackage #:fake-tor-net
  (:use #:cl)
  (:local-nicknames (#:u #:cl-tor.util) (#:c #:cl-tor.crypto) (#:n #:cl-tor.ntor)
                    (#:cell #:cl-tor.cell) (#:rc #:cl-tor.relay-crypto)
                    (#:sock #:cl-transport.sockets)))
(in-package #:fake-tor-net)

(defvar *lock* (sb-thread:make-mutex :name "fake tor net"))
(defmacro locked (&body body) `(sb-thread:with-recursive-lock (*lock*) ,@body))
(defun note (fmt &rest args)
  (locked (format t "~&[fake-tor] ~?~%" fmt args) (finish-output)))

;;; --- the relays ---------------------------------------------------------------

(defstruct relay nick rsa ed ntor-priv ntor-pub flags ip microdesc digest)

(defvar *relays* '())
(defvar *or-port* 0)

(defun b64 (bytes) (u:base64-encode bytes :pad nil))

(defun make-relays (n)
  (loop for i from 1 to n
        collect (let* ((priv (c:random-bytes 32)) (pub (c:x25519-public priv))
                       (ed (c:random-bytes 32))
                       (md (format nil "onion-key~%ntor-onion-key ~a~%p accept 1-65535~%id ed25519 ~a~%"
                                   (b64 pub) (b64 ed))))
                  (make-relay :nick (format nil "fake~d" i) :rsa (c:random-bytes 20) :ed ed
                              :ntor-priv priv :ntor-pub pub
                              :flags (format nil "Fast Guard HSDir Running Stable V2Dir Valid~:[~; Exit~]"
                                             (evenp i))
                              :ip (format nil "10.~d.0.1" i) :microdesc md
                              :digest (b64 (c:sha256 (u:ascii->bytes md)))))))

(defun relay-by-rsa (rsa) (find rsa *relays* :key #'relay-rsa :test #'equalp))

(defun utc-stamp (ut)
  (multiple-value-bind (s mi h d mo y) (decode-universal-time ut 0)
    (format nil "~4,'0d-~2,'0d-~2,'0d ~2,'0d:~2,'0d:~2,'0d" y mo d h mi s)))

(defvar *srv-prev* (c:random-bytes 32))
(defvar *srv-cur* (c:random-bytes 32))

(defun consensus-text ()
  (let ((now (get-universal-time)))
    (with-output-to-string (o)
      (format o "network-status-version 3 microdesc~%vote-status consensus~%")
      (format o "valid-after ~a~%" (utc-stamp (- now (mod now 3600))))
      (format o "shared-rand-previous-value 9 ~a~%" (u:base64-encode *srv-prev*))
      (format o "shared-rand-current-value 9 ~a~%" (u:base64-encode *srv-cur*))
      (format o "params hsdir-interval=1440~%")
      (dolist (r *relays*)
        (format o "r ~a ~a 2038-01-01 00:00:00 ~a ~d 0~%m ~a~%s ~a~%w Bandwidth=1000~%"
                (relay-nick r) (b64 (relay-rsa r)) (relay-ip r) *or-port*
                (relay-digest r) (relay-flags r))))))

;;; --- the directory authority (HTTP/1.0) ------------------------------------------

(defun read-http-request (stream)
  "The request line and headers (up to the blank line) as a string."
  (let ((bytes (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for b = (read-byte stream nil nil)
          while b
          do (vector-push-extend b bytes)
          until (and (>= (length bytes) 4)
                     (equalp (subseq bytes (- (length bytes) 4)) #(13 10 13 10))))
    (map 'string #'code-char bytes)))

(defun http-reply (stream status body)
  (write-sequence (u:ascii->bytes (format nil "HTTP/1.0 ~d OK~c~cContent-Length: ~d~c~c~c~c"
                                          status #\Return #\Newline (length body)
                                          #\Return #\Newline #\Return #\Newline))
                  stream)
  (write-sequence body stream)
  (finish-output stream))

(defun dir-response (path)
  "(values status body-bytes) for a directory GET of PATH."
  (cond ((search "/tor/status-vote/current/consensus-microdesc" path)
         (let ((text (u:ascii->bytes (consensus-text))))
           (values 200 (if (search ".z" path) (cram:zlib-compress text) text))))
        ((eql 0 (search "/tor/micro/d/" path))
         (let* ((want (uiop:split-string (subseq path 13) :separator "-"))
                (blocks (loop for r in *relays*
                              when (member (relay-digest r) want :test #'string=)
                                collect (relay-microdesc r))))
           (values (if blocks 200 404) (u:ascii->bytes (format nil "~{~a~}" blocks)))))
        (t (values 404 (u:ascii->bytes "not found")))))

(defun serve-dir-connection (ts)
  (unwind-protect
       (handler-case
           (let* ((s (sock:tcp-socket-stream ts))
                  (req (read-http-request s))
                  (path (second (uiop:split-string (subseq req 0 (position #\Return req))
                                                   :separator " "))))
             (multiple-value-bind (status body) (dir-response path)
               (http-reply s status body)))
         (error (e) (note "dir: ~a" e)))
    (sock:tcp-close ts)))

;;; --- circuits, the relay's side -------------------------------------------------

(defstruct conn stream (circs (make-hash-table)))
(defstruct circ conn id (hops '()) relays joined (streams (make-hash-table)))
;; a hop as the relay sees it: the client's keys with the directions swapped
(defun relay-hop (relay keys)
  (rc::%make-hop :relay relay
                 :kf (c:aes128-ctr-cipher (n:circuit-keys-kb keys))
                 :kb (c:aes128-ctr-cipher (n:circuit-keys-kf keys))
                 :df (c:running-digest :sha1 (n:circuit-keys-db keys))
                 :db (c:running-digest :sha1 (n:circuit-keys-df keys))))

(defvar *intro-points* (make-hash-table :test 'equalp) "auth key -> (circ . hop)")
(defvar *rendezvous* (make-hash-table :test 'equalp) "cookie -> (circ . hop)")
(defvar *descriptors* (make-hash-table :test 'equalp) "blinded key -> descriptor text")

(defun send-cell (circ cmd payload)
  (cell:write-cell (conn-stream (circ-conn circ)) 4 (circ-id circ) cmd payload))

(defun send-back (circ hop-index relay-cmd sid data)
  "A relay cell from hop HOP-INDEX of CIRC toward its client."
  (let* ((hops (circ-hops circ))
         (body (rc:build-relay-body (nth hop-index hops) relay-cmd sid data)))
    (loop for i from hop-index downto 0
          do (setf body (c:ctr-apply (rc:hop-kf (nth i hops)) body)))
    (send-cell circ cell:+relay+ body)))

(defun pass-back (circ body)
  "BODY, a cell from the joined circuit that no relay hop recognized, toward CIRC's client:
each relay hop adds its layer, as for any backward cell."
  (let ((hops (circ-hops circ)))
    (loop for i from (1- (length hops)) downto 0
          do (setf body (c:ctr-apply (rc:hop-kf (nth i hops)) body)))
    (send-cell circ cell:+relay+ body)))

(defun send-data-back (circ hop sid bytes)
  (loop for off from 0 below (length bytes) by 498
        do (send-back circ hop rc:+r-data+ sid (subseq bytes off (min (length bytes) (+ off 498))))))

;;; --- what a hop answers ---

(defun parse-link-specs (bytes)
  "-> rsa id (and the offset just past the specs)."
  (let ((n (aref bytes 0)) (i 1) rsa)
    (dotimes (k n (values rsa i))
      (let ((ty (aref bytes i)) (ln (aref bytes (1+ i))))
        (when (= ty 2) (setf rsa (subseq bytes (+ i 2) (+ i 2 ln))))
        (incf i (+ 2 ln))))))

(defun blinded-key-of (text)
  "The blinded key a descriptor's signing-key cert was signed with (its extension 04)."
  (let* ((a (search "descriptor-signing-key-cert" text))
         (b (search "-----BEGIN ED25519 CERT-----" text :start2 a))
         (e (search "-----END ED25519 CERT-----" text :start2 b))
         (cert (u:base64-decode (remove-if (lambda (ch) (member ch '(#\Newline #\Return)))
                                           (subseq text (+ b 28) e))))
         (next (aref cert 39)) (i 40))
    (dotimes (k next)
      (let ((len (u:read-u16be cert i)) (ty (aref cert (+ i 2))))
        (when (= ty 4) (return-from blinded-key-of (subseq cert (+ i 4) (+ i 4 len))))
        (incf i (+ 4 len))))))

(defun dir-stream-input (circ hop sid st data)
  "HTTP over a BEGIN_DIR stream: buffer until the request is whole, then answer and END."
  (setf (car st) (u:cat (car st) data))
  (let* ((buf (car st)) (hdr-end (search #(13 10 13 10) buf)))
    (when hdr-end
      (let* ((head (map 'string #'code-char (subseq buf 0 hdr-end)))
             (cl (let ((p (search "Content-Length: " head)))
                   (if p (parse-integer head :start (+ p 16) :junk-allowed t) 0)))
             (body-start (+ hdr-end 4)))
        (when (>= (length buf) (+ body-start cl))
          (let ((path (second (uiop:split-string (subseq head 0 (or (position #\Return head)
                                                                    (length head)))
                                                 :separator " "))))
            (cond ((eql 0 (search "POST" head))
                   (let* ((text (map 'string #'code-char (subseq buf body-start (+ body-start cl))))
                          (key (ignore-errors (blinded-key-of text))))
                     (if key
                         (progn (setf (gethash key *descriptors*) text)
                                (note "HSDir ~a stored a descriptor"
                                      (relay-nick (nth hop (circ-relays circ))))
                                (send-data-back circ hop sid (u:ascii->bytes (format nil "HTTP/1.0 200 OK~c~c~c~c" #\Return #\Newline #\Return #\Newline))))
                         (send-data-back circ hop sid (u:ascii->bytes (format nil "HTTP/1.0 400 Bad~c~c~c~c" #\Return #\Newline #\Return #\Newline))))))
                  (t
                   (let* ((key (ignore-errors (u:base64-decode (subseq path (length "/tor/hs/3/")))))
                          (text (and key (gethash key *descriptors*))))
                     (send-data-back circ hop sid
                                     (u:ascii->bytes
                                      (if text
                                          (format nil "HTTP/1.0 200 OK~c~c~c~c~a" #\Return #\Newline #\Return #\Newline text)
                                          (format nil "HTTP/1.0 404 Not found~c~c~c~c" #\Return #\Newline #\Return #\Newline)))))))
            (send-back circ hop rc:+r-end+ sid (u:u8 6))
            (remhash sid (circ-streams circ))))))))

(defun on-relay-cell (circ hop rcmd sid data)
  "A relay cell recognized at HOP of CIRC."
  (let ((relay (nth hop (circ-relays circ))))
    (cond
      ((= rcmd rc:+r-extend2+)
       (multiple-value-bind (rsa off) (parse-link-specs data)
         (let* ((r (relay-by-rsa rsa))
                (hlen (u:read-u16be data (+ off 2)))
                (skin (subseq data (+ off 4) (+ off 4 hlen))))
           (multiple-value-bind (reply keys)
               (and r (n:server-handshake skin (relay-ntor-priv r) (relay-ntor-pub r) (relay-rsa r)))
             (if (null reply)
                 (send-cell circ cell:+destroy+ (u:u8 1))
                 (progn
                   (send-back circ hop rc:+r-extended2+ 0 (u:cat (u:u16be (length reply)) reply))
                   (setf (circ-hops circ) (append (circ-hops circ) (list (relay-hop r keys)))
                         (circ-relays circ) (append (circ-relays circ) (list r)))))))))
      ((= rcmd rc:+r-begin+)                         ; exit: an echo service
       (setf (gethash sid (circ-streams circ)) :echo)
       (send-back circ hop rc:+r-connected+ sid (u:octets 8)))
      ((= rcmd 13)                                   ; BEGIN_DIR
       (setf (gethash sid (circ-streams circ)) (list (u:octets 0)))
       (send-back circ hop rc:+r-connected+ sid #()))
      ((= rcmd rc:+r-data+)
       (let ((st (gethash sid (circ-streams circ))))
         (cond ((eq st :echo) (send-data-back circ hop sid data))
               ((consp st) (dir-stream-input circ hop sid st data)))))
      ((= rcmd rc:+r-end+) (remhash sid (circ-streams circ)))
      ((= rcmd rc:+r-sendme+) nil)
      ((= rcmd 32)                                   ; ESTABLISH_INTRO
       (let ((key (subseq data 3 (+ 3 (u:read-u16be data 1)))))
         (setf (gethash key *intro-points*) (cons circ hop))
         (note "~a: an intro point" (relay-nick relay))
         (send-back circ hop 38 0 #())))
      ((= rcmd 34)                                   ; INTRODUCE1
       (let* ((key (subseq data 23 (+ 23 (u:read-u16be data 21))))
              (svc (gethash key *intro-points*)))
         (if svc
             (progn (send-back (car svc) (cdr svc) 35 0 data)    ; INTRODUCE2, same body
                    (note "~a: INTRODUCE1 passed to the service" (relay-nick relay))
                    (send-back circ hop 40 0 (u:cat (u:u16be 0) (u:u8 0))))
             (send-back circ hop 40 0 (u:cat (u:u16be 1) (u:u8 0))))))
      ((= rcmd 33)                                   ; ESTABLISH_RENDEZVOUS
       (setf (gethash (subseq data 0 20) *rendezvous*) (cons circ hop))
       (send-back circ hop 39 0 #()))
      ((= rcmd 36)                                   ; RENDEZVOUS1
       (let ((client (gethash (subseq data 0 20) *rendezvous*)))
         (when client
           (remhash (subseq data 0 20) *rendezvous*)
           (send-back (car client) (cdr client) 37 0 (subseq data 20 84))
           (setf (circ-joined (car client)) circ (circ-joined circ) (car client))
           (note "~a: rendezvous joined" (relay-nick relay)))))
      (t (note "~a: relay cmd ~d ignored" (relay-nick relay) rcmd)))))

(defun on-forward-relay (circ body)
  "A RELAY cell from CIRC's client: peel hop by hop until one recognizes it; if none does and
the circuit is joined, it belongs to the other end."
  (let ((hops (circ-hops circ)))
    (loop for i from 0 below (length hops)
          do (setf body (c:ctr-apply (rc:hop-kb (nth i hops)) body))
             (when (rc:recognized-and-valid (nth i hops) body)
               (multiple-value-bind (rcmd recognized sid len data) (rc:parse-relay-body body)
                 (declare (ignore recognized len))
                 (return (on-relay-cell circ i rcmd sid data))))
          finally (if (circ-joined circ)
                      (pass-back (circ-joined circ) body)
                      (note "unrecognized relay cell dropped")))))

(defun serve-or-connection (ts)
  (let* ((s (sock:tcp-socket-stream ts)) (conn (make-conn :stream s)))
    (unwind-protect
         (handler-case
             (progn
               ;; VERSIONS (2-byte circ ids), then NETINFO; link version 4
               (multiple-value-bind (cid cmd) (cell:read-cell s 2)
                 (declare (ignore cid))
                 (unless (= cmd cell:+versions+) (error "expected VERSIONS")))
               (locked (cell:write-cell s 2 0 cell:+versions+ (u:cat (u:u16be 4)))
                       (cell:write-cell s 4 0 cell:+netinfo+
                                        (u:cat (u:u32be (- (get-universal-time) 2208988800))
                                               (u:u8 4) (u:u8 4) (u:ipv4->bytes "127.0.0.1")
                                               (u:u8 0))))
               (loop
                 (multiple-value-bind (cid cmd payload) (cell:read-cell s 4)
                   (locked
                     (let ((circ (gethash cid (conn-circs conn))))
                       (cond
                         ((= cmd cell:+create2+)
                          (let* ((hlen (u:read-u16be payload 2))
                                 (skin (subseq payload 4 (+ 4 hlen)))
                                 (r (relay-by-rsa (subseq skin 0 20))))
                            (multiple-value-bind (reply keys)
                                (and r (n:server-handshake skin (relay-ntor-priv r)
                                                           (relay-ntor-pub r) (relay-rsa r)))
                              (let ((c (make-circ :conn conn :id cid)))
                                (if (null reply)
                                    (progn (setf (gethash cid (conn-circs conn)) c)
                                           (send-cell c cell:+destroy+ (u:u8 1))
                                           (remhash cid (conn-circs conn)))
                                    (progn
                                      (setf (circ-hops c) (list (relay-hop r keys))
                                            (circ-relays c) (list r)
                                            (gethash cid (conn-circs conn)) c)
                                      (send-cell c cell:+created2+
                                                 (u:cat (u:u16be (length reply)) reply))))))))
                         ((and circ (or (= cmd cell:+relay+) (= cmd cell:+relay-early+)))
                          (on-forward-relay circ payload))
                         ((and circ (= cmd cell:+destroy+))
                          (remhash cid (conn-circs conn)))
                         (t nil)))))))
           (error () nil))
      (sock:tcp-close ts))))

;;; --- main ------------------------------------------------------------------------

(defun accept-loop (listener fn name stop)
  (loop until (funcall stop)
        do (let ((ts (sock:tcp-accept listener :timeout-ms 200)))
             (when ts (sb-thread:make-thread fn :name name :arguments (list ts))))))

(defun main ()
  (let* ((args sb-ext:*posix-argv*)
         (portfile (or (second args) (error "usage: fake-tor-net.lisp PORTFILE [SECONDS]")))
         (seconds (if (third args) (parse-integer (third args)) 1800))
         (end (+ (get-universal-time) seconds))
         (or-l (sock:tcp-listen :host "127.0.0.1" :port 0))
         (dir-l (sock:tcp-listen :host "127.0.0.1" :port 0)))
    (setf *or-port* (sock:tcp-listener-port or-l)
          *relays* (make-relays 9))
    (with-open-file (o portfile :direction :output :if-exists :supersede)
      (format o "~d ~d~%" *or-port* (sock:tcp-listener-port dir-l)))
    (note "relays on 127.0.0.1:~d, directory on 127.0.0.1:~d" *or-port* (sock:tcp-listener-port dir-l))
    (let ((stop (lambda () (or (> (get-universal-time) end) (not (probe-file portfile))))))
      (sb-thread:make-thread #'accept-loop :name "dir accept"
                             :arguments (list dir-l #'serve-dir-connection "dir" stop))
      (accept-loop or-l #'serve-or-connection "or" stop))
    (sock:tcp-listener-close or-l) (sock:tcp-listener-close dir-l)
    (note "stopped")
    (sb-ext:exit :code 0 :abort t)))

(main)
