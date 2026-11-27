;;;; src/hs-host.lisp — v3 onion SERVICE runtime: ESTABLISH_INTRO, publish, INTRODUCE2 /
;;;; RENDEZVOUS1, and the inbound streams.
;;;;
;;;; Takes the descriptor hs-service builds and makes the service LIVE: register at
;;;; introduction points (ESTABLISH_INTRO, keeping each circuit open), upload the descriptor
;;;; to the responsible HSDirs, and answer each INTRODUCE2 with a rendezvous.
;;;;
;;;; THE THREADS SHARE NOTHING (see dirsvc.lisp).  The SERVICE -- its identity, its intro
;;;; points, its periods and revision -- belongs to the thread that calls START-SERVICE and
;;;; then SERVICE-STEP every so often: the service's OWNER, which also answers the service's
;;;; directory (the main thread on modus).  The circuits belong to threads started on NAMED
;;;; functions with plain :ARGUMENTS, each holding a directory slot to ask the owner for paths:
;;;;
;;;;   - one INTRO thread per introduction point: builds its circuit, ESTABLISH_INTRO, then
;;;;     waits for INTRODUCE2 cells and hands each (the cell's bytes) to
;;;;   - a RENDEZVOUS thread of its own: decrypts it, builds the circuit to the client's
;;;;     rendezvous point, RENDEZVOUS1, accepts the client's stream, and serves it -- spliced
;;;;     to a local TCP TARGET (Tor's HiddenServicePort: the inbound stream becomes an ordinary
;;;;     TCP connection to host:port), or given to HANDLER (a function NAME) on this thread;
;;;;   - a PUBLISH thread per upload: the descriptor texts (built on the owner) and the
;;;;     responsible HSDirs (plain) in, the count of HSDirs that took it out.
;;;;
;;;; The threads report to the owner by message on the service's EVENTS channel (an intro is
;;;; up / down, a publish is done); SERVICE-STEP reads them, keeps NUM-INTROS intro points,
;;;; and publishes once a quorum is up, again when the set changes, and every
;;;; REPUBLISH-INTERVAL seconds.  RUN-SERVICE is START-SERVICE plus stepping until the first
;;;; publish; SERVE-SERVICE steps until told to stop.

(defpackage #:cl-tor.hshost
  (:use #:cl)
  (:local-nicknames (#:u #:cl-tor.util) (#:c #:cl-tor.crypto) (#:ed #:cl-tor.ed25519)
                    (#:dir #:cl-tor.directory) (#:circ #:cl-tor.circuit) (#:link #:cl-tor.link)
                    (#:rc #:cl-tor.relay-crypto) (#:hsdir #:cl-tor.hsdir) (#:svc #:cl-tor.hsservice)
                    (#:strm #:cl-tor.stream) (#:dsvc #:cl-tor.dirsvc) (#:bob #:bobbin)
                    (#:sock #:cl-transport.sockets))
  (:export #:intro-for-relay #:establish-intro #:publish-descriptor
           #:service #:service-identity #:service-live #:service-period-num #:service-period-length
           #:handle-introduce2 #:read-introduce2 #:rendezvous-for-introduce2 #:accept-stream
           #:run-service #:republish-service #:*num-intro-points*
           #:start-service #:service-step #:serve-service #:stop-service
           #:service-directory #:service-published #:service-accepted #:service-live-count
           #:service-onion #:service-rendezvous-count #:service-stopped-p #:service-intro-count
           #:*intro-lifetime* #:*republish-interval*))

(in-package #:cl-tor.hshost)

(defparameter *num-intro-points* 3 "How many introduction points to establish.")
(defparameter *intro-establish-timeout* 30
  "Seconds to wait for INTRO_ESTABLISHED before giving up on a relay (so a relay that
   accepts the circuit but never ACKs can't strand its slot forever).")
(defparameter *intro-lifetime* 3600
  "Retire + replace an intro point after this many seconds — bounds a silently-dead
   intro circuit and rotates intros.  Rendezvous run on threads of their own, so this
   doesn't drop them.")
(defparameter *republish-interval* 3600 "Re-upload the descriptor this often (seconds).")
(defparameter *max-rendezvous* 4 "Rendezvous a service serves at once (each is a thread).")

(defconstant +r-establish-intro+ 32)
(defconstant +r-intro-established+ 38)

(defun %int8be (n)
  (let ((b (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8 b) (setf (aref b (- 7 i)) (logand (ash n (* -8 i)) #xff)))))

(defun %relay-link-specs (relay)
  "NSPEC|{IPv4,RSAid,ed25519} link specifiers for RELAY."
  (let* ((ip (map '(vector (unsigned-byte 8)) #'parse-integer
                  (uiop:split-string (dir:relay-ip relay) :separator ".")))
         (port (dir:relay-or-port relay))
         (v4 (u:cat ip (vector (ldb (byte 8 8) port) (ldb (byte 8 0) port)))))
    (u:cat (vector 3)
           (vector 0 (length v4)) v4
           (vector 2 20) (dir:relay-rsa-id relay)
           (vector 3 32) (dir:relay-ed-id relay))))

(defun intro-for-relay (relay)
  "Build an SVC:INTRO for RELAY (an enriched relay to use as an introduction point):
   its link specifiers + ntor onion-key, plus fresh per-intro auth/enc keys."
  (svc:make-intro (%relay-link-specs relay) (dir:relay-ntor-key relay)))

(defun %intro->plain (intro)
  (list (svc:intro-link-specs intro) (svc:intro-onion-key intro) (svc:intro-auth-seed intro)
        (svc:intro-enc-seed intro) (svc:intro-enc-pub intro)))

(defun %plain->intro (p)
  (destructuring-bind (link-specs onion-key auth-seed enc-seed enc-pub) p
    (svc::%make-intro :link-specs link-specs :onion-key onion-key :auth-seed auth-seed
                      :enc-seed enc-seed :enc-pub enc-pub)))

(defun %teardown (circ)
  (when circ
    (ignore-errors (circ:destroy-circuit circ))
    (ignore-errors (link:close-link (circ:circuit-link circ)))))

;;; --- ESTABLISH_INTRO --------------------------------------------------------

(defun establish-intro (relay intro &optional relays)
  "Build a circuit to RELAY on this thread and register INTRO's auth key as a service
   introduction point (rend-spec-v3 §3.1).  Returns the circuit (kept OPEN — the intro
   point forwards INTRODUCE2 over it) on INTRO_ESTABLISHED; errors otherwise.  The path
   comes from the directory; RELAYS is ignored."
  (declare (ignore relays))
  (let ((circ (dsvc:circuit-to relay)))
    (handler-case
        (let* ((kh (rc:hop-kh (car (last (circ:circuit-hops circ)))))
               (auth-seed (svc:intro-auth-seed intro))
               (auth-pub (ed:secret-to-public auth-seed))
               ;; body up to (not incl) HANDSHAKE_AUTH: AUTH_KEY_TYPE|LEN|KEY|N_EXT
               (before (u:cat (vector 2) (u:u16be 32) auth-pub (vector 0)))
               (mac (c:sha3-256 (u:cat (%int8be (length kh)) kh before)))   ; MAC keyed on circuit KH
               (signed (u:cat before mac))
               (sig (ed:sign auth-seed
                             (u:cat (u:ascii->bytes "Tor establish-intro cell v1") signed)))
               (cell (u:cat signed (u:u16be 64) sig)))
          (circ:send-relay circ +r-establish-intro+ 0 cell)
          (loop (multiple-value-bind (hop rcmd rsid len data) (circ:recv-relay circ)
                  (declare (ignore hop rsid len data))
                  (when (= rcmd +r-intro-established+) (return circ)))))
      (error (e) (%teardown circ) (error e)))))

;;; --- descriptor upload ------------------------------------------------------

(defun %upload (text hsdirs)
  "Upload descriptor TEXT to each of HSDIRS (relay structs) over a circuit of this thread's;
   the number that answered HTTP 200."
  (let ((body (u:ascii->bytes text)) (ok 0))
    (dolist (hd hsdirs ok)
      (let ((circ nil))
        (ignore-errors
          (setf circ (dsvc:circuit-to hd))
          (when (search "200" (circ:with-deadline (60)
                                (hsdir:post-over-circuit circ "/tor/hs/3/publish" body)))
            (incf ok)))
        (%teardown circ)))))

(defun publish-descriptor (pubkey desc-text relays period-num period-length srv)
  "Upload DESC-TEXT to the HSDirs responsible for PUBKEY in PERIOD-NUM (the current period,
   or the next one in the overlap).  Returns the number of HSDirs that accepted it (HTTP 200).
   The ring comes from the directory; RELAYS, PERIOD-LENGTH and SRV are ignored."
  (declare (ignore relays period-length srv))
  (let ((hsdirs (loop for next in '(nil t)
                      do (multiple-value-bind (tp plen s hs) (hsdir:hs-ring pubkey next)
                           (declare (ignore plen s))
                           (when (eql tp period-num) (return hs))))))
    (%upload desc-text hsdirs)))

;;; --- INTRODUCE2 + rendezvous (service side, S4/S5) --------------------------

(defparameter +hs-ntor-protoid+ "tor-hs-ntor-curve25519-sha3-256-1")
(defconstant +r-introduce2+ 35)
(defconstant +r-rendezvous1+ 36)

(defun %tweak (s) (u:ascii->bytes (concatenate 'string +hs-ntor-protoid+ s)))
(defun %mac (key msg) (c:sha3-256 (u:cat (%int8be (length key)) key msg)))

(defun %parse-link-specs (bytes)
  "NSPEC|{LSTYPE LSLEN LSPEC}... -> (values ip or-port rsa-id ed-id)."
  (let ((n (aref bytes 0)) (i 1) ip port rsa ed)
    (dotimes (k n (values ip port rsa ed))
      (let* ((ty (aref bytes i)) (ln (aref bytes (1+ i))) (spec (subseq bytes (+ i 2) (+ i 2 ln))))
        (case ty
          (0 (setf ip (format nil "~d.~d.~d.~d" (aref spec 0) (aref spec 1) (aref spec 2) (aref spec 3))
                   port (logior (ash (aref spec 4) 8) (aref spec 5))))
          (2 (setf rsa spec)) (3 (setf ed spec)))
        (setf i (+ i 2 ln))))))

(defun %rp-relay (link-specs ntor-key)
  (multiple-value-bind (ip port rsa ed) (%parse-link-specs link-specs)
    (dir::make-relay :ip ip :or-port port :rsa-id rsa :ed-id ed :ntor-key ntor-key)))

(defun read-introduce2 (intro-circ)
  "Block on INTRO-CIRC for an INTRODUCE2; its cell body."
  (loop (multiple-value-bind (hop rcmd rsid len data) (circ:recv-relay intro-circ)
          (declare (ignore hop rsid len))
          (when (= rcmd +r-introduce2+) (return data)))))

(defun handle-introduce2 (intro intro-circ identity period-num period-length &optional next-period-num)
  "Block on INTRO-CIRC for an INTRODUCE2 and answer it (RENDEZVOUS-FOR-INTRODUCE2).
   Returns the end-to-end circuit, ready for ACCEPT-STREAM."
  (rendezvous-for-introduce2 (read-introduce2 intro-circ) intro identity
                             period-num period-length next-period-num))

(defun rendezvous-for-introduce2 (cell intro identity period-num period-length &optional next-period-num)
  "Decrypt the INTRODUCE2 CELL (service hs-ntor), then build a circuit to the client's
   rendezvous point on this thread, send RENDEZVOUS1, and splice the client on as a
   SHA3/AES-256 hop (forward/backward keys swapped — we're the responder).  Tries
   PERIOD-NUM's subcredential and, if given, NEXT-PERIOD-NUM's — so a client that found us
   via the next-period descriptor across the rotation still introduces.  Returns the
   end-to-end circuit, ready for ACCEPT-STREAM."
  (progn
    ;; body: LEGACY(20) TYPE(1) LEN(2) AUTH_KEY(aklen) N_EXT(1)=0 | X(32) enc-data MAC(32)
    (let* ((aklen (u:read-u16be cell 21))
           (k (+ 24 aklen))                                   ; start of CLIENT_PK X
           (xpub (subseq cell k (+ k 32)))                    ; CLIENT_PK X
           (head (subseq cell 0 (- (length cell) 32)))
           (mac-recv (subseq cell (- (length cell) 32)))
           (enc-data (subseq cell (+ k 32) (- (length cell) 32)))
           (b (svc:intro-enc-seed intro)) (bigb (svc:intro-enc-pub intro))
           (auth-pub (ed:secret-to-public (svc:intro-auth-seed intro)))
           (id-pub (svc:hs-identity-pubkey identity))
           (protoid (u:ascii->bytes +hs-ntor-protoid+))
           ;; service intro handshake: EXP(X,b) | AUTH_KEY | X | B | PROTOID (period-independent)
           (secret-input (u:cat (c:x25519 b xpub) auth-pub xpub bigb protoid)))
      (flet ((keys-for (pn)
               "The ENC key if the INTRODUCE2 MAC verifies under period PN's subcredential."
               (let* ((blinded (ed:blind-public-key id-pub pn period-length))
                      (subcred (ed:subcredential id-pub blinded))
                      (info (u:cat (%tweak ":hs_key_expand") subcred))
                      (keys (ed:shake256 (u:cat secret-input (%tweak ":hs_key_extract") info) 64)))
                 (when (equalp mac-recv (%mac (subseq keys 32 64) head)) (subseq keys 0 32)))))
      (let ((enc-key (or (keys-for period-num)
                         (and next-period-num (keys-for next-period-num)))))
      (unless enc-key
        (error "hs-host: INTRODUCE2 MAC mismatch"))
      (let* ((plain (c:ctr-apply (c:aes128-ctr-cipher enc-key (u:octets 16)) enc-data))
             (cookie (subseq plain 0 20))
             ;; plain: cookie(20) N_EXT(1)=0 ONION_KEY_TYPE(1) ONION_KEY_LEN(2)=32 ONION_KEY(32) NSPEC...
             (rp-ntor (subseq plain 24 56))
             (rp-links (subseq plain 56))
             ;; rendezvous handshake (service view): rend_secret =
             ;; EXP(X,y) | EXP(X,b) | AUTH_KEY | B | X | Y | PROTOID
             (y (c:random-bytes 32)) (ybig (c:x25519-public y))
             (rend-secret (u:cat (c:x25519 y xpub) (c:x25519 b xpub)
                                 auth-pub bigb xpub ybig protoid))
             (ntor-seed (%mac rend-secret (%tweak ":hs_key_extract")))
             (verify (%mac rend-secret (%tweak ":hs_verify")))
             (auth-input (u:cat verify auth-pub bigb ybig xpub protoid (u:ascii->bytes "Server")))
             (auth (%mac auth-input (%tweak ":hs_mac")))
             (kdf (ed:shake256 (u:cat ntor-seed (%tweak ":hs_key_expand")) 128))
             (df (subseq kdf 0 32)) (db (subseq kdf 32 64))
             (kf (subseq kdf 64 96)) (kb (subseq kdf 96 128))
             ;; build a circuit to the rendezvous point + send RENDEZVOUS1
             (rp (%rp-relay rp-links rp-ntor))
             (rend-circ (dsvc:circuit-to rp)))
        (circ:send-relay rend-circ +r-rendezvous1+ 0 (u:cat cookie ybig auth))
        ;; splice the client on as the final hop — responder, so keys are swapped
        (setf (circ:circuit-hops rend-circ)
              (append (circ:circuit-hops rend-circ)
                      (list (rc:make-hs-hop nil kb kf db df))))
        rend-circ))))))

(defun accept-stream (circ)
  "On a connected rendezvous CIRC, wait for the client's RELAY_BEGIN and reply
   RELAY_CONNECTED.  Returns the stream id."
  (loop (multiple-value-bind (hop rcmd sid len data) (circ:recv-relay circ)
          (declare (ignore hop len data))
          (when (= rcmd rc:+r-begin+)
            (circ:send-relay circ rc:+r-connected+ sid #())   ; empty CONNECTED (onion service)
            (return sid)))))

;;; --- the service: its owner, and the threads that hold its circuits ----------

(defvar *service-counter* 0)
(defvar *stopped-services* '()
  "Ids of the services STOP-SERVICE ended.  Set on the services' owner only; their threads
   read it (a list of integers the owner made -- reading is all another thread does).")

(defstruct (service (:constructor %make-service))
  id identity handler target num-intros directory events
  (intros '())                  ; IRECs: intro points starting or live
  (next-key 0)
  period-num period-length next-period-num
  (revision 0)
  (published nil)               ; T once a publish has finished with an HSDir accepting
  (accepted 0)                  ; HSDirs that accepted the last publish
  (publishes 0)                 ; publishes finished
  (publishing nil)              ; a publish thread is running
  (want-publish nil)            ; the intro set changed since the last publish
  (last-publish 0)
  (republish-interval *republish-interval*)
  (spawn-after 0)               ; no new intro thread before this universal time
  (rendezvous 0)                ; rendezvous accepted
  (stopped nil))

(defstruct irec key intro relay-plain (state :starting))

(defun service-onion (service) (hsdir:pubkey->onion (svc:hs-identity-pubkey (service-identity service))))
(defun service-live (service)
  (loop for r in (service-intros service) when (eq (irec-state r) :live) collect (irec-intro r)))
(defun service-live-count (service) (length (service-live service)))
(defun service-intro-count (service)
  "Intro points whose threads are running (starting or live): 0 once a stopped service's
   threads have all ended (as SERVICE-STEP reads their reports)."
  (length (service-intros service)))
(defun service-rendezvous-count (service) (service-rendezvous service))
(defun service-stopped-p (service) (service-stopped service))

(defun %stopped-p (id) (and (member id *stopped-services*) t))
(defun %event (events msg) (ignore-errors (bob:channel-send events msg :timeout 5)))
(defun %log (fmt &rest args)
  (format *error-output* "~&[hs-host] ~?~%" fmt args) (finish-output *error-output*))

(defun %thread-directory (requests replies free)
  (dsvc:%make-directory requests replies free))

;;; --- an introduction point's thread ---

(defun %intro-main (id key slot requests replies free events intro-plain relay-plain seed target
                    handler)
  "An intro point's thread: its circuit, ESTABLISH_INTRO, then each INTRODUCE2 to a
   rendezvous thread of its own, until the intro's lifetime ends, the circuit dies, or the
   service stops."
  (let ((dir (%thread-directory requests replies free)) (circ nil) (why "ended"))
    (unwind-protect
         (handler-case
             (dsvc:with-directory-client (dir slot)
               (setf circ (circ:with-deadline (*intro-establish-timeout*)
                            (establish-intro (dir:plain->relay relay-plain)
                                             (%plain->intro intro-plain))))
               (%event events (list :intro-up key))
               (let ((end (+ (get-universal-time) *intro-lifetime*)))
                 (loop
                   (when (or (%stopped-p id) (> (get-universal-time) end)) (return))
                   (when (circ:wait-relay-input circ 1)
                     (multiple-value-bind (hop rcmd rsid len data)
                         (circ:with-deadline (30) (circ:recv-relay circ :poll t))
                       (declare (ignore hop rsid len))
                       (when (eql rcmd +r-introduce2+)
                         (%start-rendezvous id dir requests replies free events data intro-plain
                                            seed target handler)))))))
           (serious-condition (e) (setf why (princ-to-string e))))
      (%teardown circ)
      (%event events (list :intro-down key why))
      (dsvc:release-slot dir slot))))

(defun %start-rendezvous (id dir requests replies free events cell intro-plain seed target handler)
  "Hand an INTRODUCE2 CELL to a rendezvous thread of its own (when a slot is free)."
  (let ((slot (dsvc:acquire-slot dir)))
    (if (null slot)
        (%log "introduction dropped: ~d rendezvous already" (dsvc:directory-slots dir))
        (handler-case
            (sb-thread:make-thread
             '%rendezvous-main :name "hs-host rendezvous"
             :arguments (list id slot requests replies free events cell intro-plain seed
                              target handler))
          (error (e)
            (%log "cannot start a rendezvous thread: ~a" e)
            (dsvc:release-slot dir slot))))))

;;; --- a rendezvous's thread ---

(defun %rendezvous-main (id slot requests replies free events cell intro-plain seed target handler)
  "Answer one introduction: rendezvous with the client, accept its stream, and serve it --
   spliced to TARGET (host port), or by (funcall HANDLER circuit stream-id) on this thread.
   The circuit is closed when that ends."
  (let ((dir (%thread-directory requests replies free)) (rend nil))
    (unwind-protect
         (handler-case
             (dsvc:with-directory-client (dir slot)
               (destructuring-bind (tp plen ntp) (dsvc:dir-ask :hs-periods)
                 (setf rend (circ:with-deadline (60)
                              (rendezvous-for-introduce2 cell (%plain->intro intro-plain)
                                                         (svc:identity-from-seed seed)
                                                         tp plen ntp)))
                 (let ((sid (circ:with-deadline (120) (accept-stream rend))))
                   (%event events (list :rendezvous))
                   (cond
                     (target
                      (let ((app (sock:tcp-connect (first target) (second target))))
                        (unwind-protect
                             (cl-tor.socks::%splice app rend sid
                                                    :stop-p (lambda () (%stopped-p id)))
                          (sock:tcp-close app))
                        (ignore-errors (strm:end-stream rend sid))))
                     (handler (funcall handler rend sid))))))
           (serious-condition (e) (%log "rendezvous: ~a" e)))
      (%teardown rend)
      (dsvc:release-slot dir slot))))

;;; --- a publish's thread ---

(defun %publish-main (slot requests replies free events jobs)
  "Upload each of JOBS -- (descriptor-text hsdir-plains) -- and report the HSDirs that
   accepted, in all."
  (let ((dir (%thread-directory requests replies free)) (n 0))
    (unwind-protect
         (handler-case
             (dsvc:with-directory-client (dir slot)
               (dolist (job jobs)
                 (incf n (%upload (first job) (mapcar #'dir:plain->relay (second job))))))
           (serious-condition (e) (%log "publish: ~a" e)))
      (%event events (list :published n))
      (dsvc:release-slot dir slot))))

;;; --- the owner side ---

(defun start-service (identity &key handler target (num-intros *num-intro-points*)
                                    directory (revision (get-universal-time))
                                    (republish-interval *republish-interval*)
                                    (max-rendezvous *max-rendezvous*))
  "Start IDENTITY's onion service; returns the SERVICE at once.  Call it, and SERVICE-STEP
   every so often after it, on the thread that owns the directory (dirsvc.lisp: the main
   thread on modus).  Each inbound stream is spliced to TARGET, a list (host port) -- an
   ordinary TCP connection to it, as Tor's HiddenServicePort does -- or, without a target,
   given to HANDLER (a function name; on modus it must be a symbol) as (handler circuit
   stream-id) on the rendezvous's own thread, the connection lasting until it returns.
   DIRECTORY, when given, must have a slot for every intro point, rendezvous and publish
   at once; by default the service makes one."
  (unless (or handler target) (error "start-service: a TARGET or a HANDLER"))
  (%make-service :id (incf *service-counter*) :identity identity :handler handler
                 :target (and target (list (first target)
                                           (if (consp (cdr target)) (second target) (cdr target))))
                 :num-intros num-intros :revision revision
                 :republish-interval republish-interval
                 :directory (or directory
                                (dsvc:make-directory :slots (+ num-intros max-rendezvous 1)))
                 :events (bob:make-channel :capacity 65536)))

(defun %spawn-intro (service)
  "Start one more intro point's thread: T, or NIL when no relay or slot is free now."
  (let* ((dir (service-directory service))
         (relay (ignore-errors
                 (dsvc:dir-ask :intro-relay
                               (loop for r in (service-intros service)
                                     collect (ninth (irec-relay-plain r))))))
         (slot (and relay (dsvc:acquire-slot dir))))
    (when slot
      (let* ((intro (intro-for-relay (dir:plain->relay relay)))
             (rec (make-irec :key (incf (service-next-key service)) :intro intro
                             :relay-plain relay)))
        (handler-case
            (progn
              (sb-thread:make-thread
               '%intro-main :name "hs-host intro"
               :arguments (list (service-id service) (irec-key rec) slot
                                (dsvc:directory-requests dir)
                                (coerce (dsvc:directory-replies dir) 'list)
                                (dsvc:directory-free dir) (service-events service)
                                (%intro->plain intro) relay
                                (svc:hs-identity-seed (service-identity service))
                                (service-target service) (service-handler service)))
              (push rec (service-intros service))
              t)
          (error (e)
            (%log "cannot start an intro thread: ~a" e)
            (dsvc:release-slot dir slot)
            nil))))))

(defun %start-publish (service)
  "Build the descriptor(s) for the live intro points -- the current period, and the next in
   the overlap -- and start a thread to upload them.  T if one started."
  (let* ((id (service-identity service)) (pub (svc:hs-identity-pubkey id))
         (intros (service-live service)) (dir (service-directory service))
         (slot (and intros (dsvc:acquire-slot dir))))
    (when slot
      (handler-case
          (let ((rev (setf (service-revision service)
                           (max (1+ (service-revision service)) (get-universal-time))))
                (jobs '()))
            (setf (service-next-period-num service) nil)        ; NIL outside the overlap
            (dolist (next '(nil t))
              (destructuring-bind (&optional tp plen srv hsdirs) (dsvc:dir-ask :hs-ring pub next)
                (declare (ignore srv))
                (when tp
                  (if next
                      (setf (service-next-period-num service) tp)
                      (setf (service-period-num service) tp (service-period-length service) plen))
                  (push (list (svc:build-descriptor id tp plen rev intros) hsdirs) jobs))))
            (sb-thread:make-thread
             '%publish-main :name "hs-host publish"
             :arguments (list slot (dsvc:directory-requests dir)
                              (coerce (dsvc:directory-replies dir) 'list)
                              (dsvc:directory-free dir) (service-events service) (nreverse jobs)))
            (setf (service-publishing service) t (service-want-publish service) nil)
            t)
        (error (e)
          (%log "cannot publish: ~a" e)
          (dsvc:release-slot dir slot)
          nil)))))

(defun service-step (service)
  "One turn of SERVICE's owner (call it every so often -- 50 ms -- on the directory's owner):
   answer its directory, read its threads' reports, keep NUM-INTROS intro points, and publish
   when a quorum is up and the descriptor is due.  Never waits on the network itself."
  (dsvc:serve-directory-requests (service-directory service))
  (loop
    (multiple-value-bind (msg ok) (bob:channel-try-receive (service-events service))
      (unless ok (return))
      (case (first msg)
        (:intro-up
         (let ((r (find (second msg) (service-intros service) :key #'irec-key)))
           (when r (setf (irec-state r) :live)
                 (when (service-published service) (setf (service-want-publish service) t)))))
        (:intro-down
         (let ((r (find (second msg) (service-intros service) :key #'irec-key)))
           (when r
             (unless (service-stopped service)
               (%log "intro point down: ~a" (third msg)))
             (when (and (eq (irec-state r) :live) (service-published service))
               (setf (service-want-publish service) t))
             (when (eq (irec-state r) :starting)   ; failed to come up: try again in a while
               (setf (service-spawn-after service) (+ (get-universal-time) 5)))
             (setf (service-intros service) (remove r (service-intros service))))))
        (:published
         (setf (service-publishing service) nil
               (service-accepted service) (second msg)
               (service-last-publish service) (get-universal-time))
         (incf (service-publishes service))
         (when (plusp (second msg)) (setf (service-published service) t)))
        (:rendezvous (incf (service-rendezvous service))))))
  (unless (service-stopped service)
    (when (>= (get-universal-time) (service-spawn-after service))
      (loop while (< (length (service-intros service)) (service-num-intros service))
            do (unless (%spawn-intro service)
                 (setf (service-spawn-after service) (+ (get-universal-time) 5))
                 (return))))
    (when (and (not (service-publishing service))
               (>= (service-live-count service) (max 1 (ceiling (service-num-intros service) 2)))
               (or (not (service-published service))
                   (service-want-publish service)
                   (> (get-universal-time)
                      (+ (service-last-publish service) (service-republish-interval service)))))
      (%start-publish service)))
  service)

(defun serve-service (service &key stop-p)
  "Step SERVICE (SERVICE-STEP every 50 ms) until STOP-P returns true."
  (loop until (and stop-p (funcall stop-p))
        do (service-step service) (sleep 0.05)))

(defun stop-service (service)
  "Stop SERVICE: its threads end (an intro within a second, a rendezvous at its next turn)."
  (unless (service-stopped service)
    (setf (service-stopped service) t)
    (push (service-id service) *stopped-services*))
  service)

(defun run-service (identity handler &key (num-intros *num-intro-points*)
                                          (revision (get-universal-time)) target directory
                                          (timeout 300))
  "Bring IDENTITY's onion service online: START-SERVICE, then step it (on this thread, the
   directory's owner) until the first publish.  Returns (values SERVICE hsdirs-accepted).
   The service keeps running only while its owner keeps stepping it: SERVICE-STEP every so
   often, or SERVE-SERVICE.  See START-SERVICE for HANDLER and TARGET."
  (let ((service (start-service identity :handler handler :target target
                                         :num-intros num-intros :revision revision
                                         :directory directory))
        (end (+ (get-universal-time) timeout)))
    (loop until (or (service-published service)
                    (and (plusp (service-publishes service)) (not (service-publishing service))
                         (plusp (service-live-count service)) (zerop (service-accepted service))
                         (> (get-universal-time) end))
                    (> (get-universal-time) end))
          do (service-step service) (sleep 0.05))
    (when (zerop (service-live-count service))
      (stop-service service)
      (error "hs-host: no intro points established"))
    (values service (service-accepted service))))

(defun republish-service (service &key revision (timeout 300))
  "Re-upload SERVICE's descriptor(s) for its currently-LIVE intro points now, stepping the
   service (on this thread, its owner) until the upload is done.  REVISION, when given, is
   the next revision counter (it must exceed the last).  Returns HSDirs accepted."
  (when revision (setf (service-revision service) (1- revision)))
  (setf (service-want-publish service) t)
  (let ((n (service-publishes service)) (end (+ (get-universal-time) timeout)))
    (loop until (or (> (service-publishes service) n) (> (get-universal-time) end))
          do (service-step service)
             (when (and (service-want-publish service) (not (service-publishing service))
                        (plusp (service-live-count service)))
               (%start-publish service))
             (sleep 0.05)))
  (service-accepted service))
