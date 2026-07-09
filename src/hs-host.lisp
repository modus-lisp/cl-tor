;;;; src/hs-host.lisp — v3 onion SERVICE runtime: ESTABLISH_INTRO + publish (S3).
;;;;
;;;; Takes the descriptor hs-service builds and makes the service LIVE: register at
;;;; introduction points (ESTABLISH_INTRO, keeping each circuit open) and upload the
;;;; descriptor to the responsible HSDirs.  Oracle: after this, our own client's
;;;; fetch-descriptor + decrypt finds the service on the real network.

(defpackage #:cl-tor.hshost
  (:use #:cl)
  (:local-nicknames (#:u #:cl-tor.util) (#:c #:cl-tor.crypto) (#:ed #:cl-tor.ed25519)
                    (#:dir #:cl-tor.directory) (#:circ #:cl-tor.circuit) (#:link #:cl-tor.link)
                    (#:rc #:cl-tor.relay-crypto) (#:hsdir #:cl-tor.hsdir) (#:svc #:cl-tor.hsservice)
                    (#:bt #:bordeaux-threads))
  (:export #:intro-for-relay #:establish-intro #:publish-descriptor
           #:service #:service-identity #:service-live #:service-period-num #:service-period-length
           #:handle-introduce2 #:accept-stream #:run-service #:republish-service #:*num-intro-points*))

(in-package #:cl-tor.hshost)

(defparameter *num-intro-points* 3 "How many introduction points to establish.")

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

;;; --- ESTABLISH_INTRO --------------------------------------------------------

(defun establish-intro (relay intro relays)
  "Build a circuit to RELAY and register INTRO's auth key as a service introduction
   point (rend-spec-v3 §3.1).  Returns the circuit (kept OPEN — the intro point
   forwards INTRODUCE2 over it) on INTRO_ESTABLISHED; errors otherwise."
  (let* ((circ (hsdir:build-circuit-to relay relays))
         (kh (rc:hop-kh (car (last (circ:circuit-hops circ)))))
         (auth-seed (svc:intro-auth-seed intro))
         (auth-pub (ed:secret-to-public auth-seed))
         ;; body up to (not incl) HANDSHAKE_AUTH: AUTH_KEY_TYPE|LEN|KEY|N_EXT
         (before (u:cat (vector 2) (u:u16be 32) auth-pub (vector 0)))
         (mac (c:sha3-256 (u:cat (%int8be (length kh)) kh before)))     ; MAC keyed on circuit KH
         (signed (u:cat before mac))
         (sig (ed:sign auth-seed
                       (u:cat (u:ascii->bytes "Tor establish-intro cell v1") signed)))
         (cell (u:cat signed (u:u16be 64) sig)))
    (circ:send-relay circ +r-establish-intro+ 0 cell)
    (handler-case
        (loop (multiple-value-bind (hop rcmd rsid len data) (circ:recv-relay circ)
                (declare (ignore hop rsid len data))
                (when (= rcmd +r-intro-established+) (return circ))))
      (error (e)
        (ignore-errors (circ:destroy-circuit circ))
        (ignore-errors (link:close-link (circ:circuit-link circ)))
        (error e)))))

;;; --- descriptor upload ------------------------------------------------------

(defun publish-descriptor (pubkey desc-text relays period-num period-length srv)
  "Upload DESC-TEXT to the HSDirs responsible for PUBKEY this time period.  Returns
   the number of HSDirs that accepted it (HTTP 200)."
  (let* ((hsdirs (hsdir:hsdir-pool relays))
         (responsible (hsdir:responsible-hsdirs pubkey hsdirs period-num period-length srv))
         (body (u:ascii->bytes desc-text))
         (ok 0))
    (dolist (hd responsible ok)
      (ignore-errors
        (let ((circ (hsdir:build-circuit-to hd relays)))
          (unwind-protect
               (when (search "200" (hsdir:post-over-circuit circ "/tor/hs/3/publish" body))
                 (incf ok))
            (ignore-errors (circ:destroy-circuit circ))
            (ignore-errors (link:close-link (circ:circuit-link circ)))))))))

;;; --- driver -----------------------------------------------------------------

(defstruct (service (:constructor %make-service))
  identity handler num-intros relays lock
  (live '())          ; intros currently established + serving (list of SVC:INTRO)
  (used '())          ; ed-ids of relays currently in use (avoid duplicate intro relays)
  period-num period-length revision
  maint-thread)

(defun %publish-all (service)
  "Publish SERVICE's descriptor for the CURRENT time period, plus — during the overlap
   [00:00,12:00 UTC) — the NEXT period too, so clients still find us across the 12:00
   rotation.  Uses the CURRENTLY-LIVE intro points.  Returns HSDirs accepted (summed)."
  (let* ((id (service-identity service))
         (id-pub (svc:hs-identity-pubkey id))
         (relays (service-relays service))
         (rev (service-revision service))
         (intros (bt:with-lock-held ((service-lock service)) (copy-list (service-live service))))
         (total 0))
    (when (null intros) (return-from %publish-all 0))
    (multiple-value-bind (va cur prev params) (hsdir:parse-consensus-header (dir:fetch-consensus))
      (multiple-value-bind (tp plen srv) (hsdir:time-period-and-srv va cur prev params)
        (setf (service-period-num service) tp (service-period-length service) plen)
        (incf total (publish-descriptor id-pub (svc:build-descriptor id tp plen rev intros)
                                        relays tp plen srv))
        (multiple-value-bind (ntp nplen nsrv) (hsdir:next-time-period-and-srv va cur prev params)
          (when ntp
            (incf total (publish-descriptor id-pub (svc:build-descriptor id ntp nplen rev intros)
                                            relays ntp nplen nsrv))))))
    total))

(defun %spawn-intro (service)
  "Establish + serve one introduction point in its own thread, keeping it registered in
   SERVICE's LIVE set for the life of its circuit.  When the circuit dies the thread
   deregisters it (and frees its relay) so the maintenance loop replenishes it."
  (let ((relay (%pick-intro-relay (service-relays service)
                                  (bt:with-lock-held ((service-lock service))
                                    (copy-list (service-used service))))))
    (unless relay (return-from %spawn-intro nil))       ; no fresh relay right now
   (let ((intro (intro-for-relay relay)) (ed (dir:relay-ed-id relay)))
    (bt:with-lock-held ((service-lock service)) (push ed (service-used service)))
    (bt:make-thread
     (lambda ()
       (unwind-protect
            (handler-case
                (let ((circ (establish-intro relay intro (service-relays service))))
                  (bt:with-lock-held ((service-lock service)) (push intro (service-live service)))
                  (loop (let* ((rc (handle-introduce2 intro circ (service-identity service)
                                                      (service-period-num service)
                                                      (service-period-length service)))
                               (sid (accept-stream rc)))
                          (funcall (service-handler service) rc sid))))
              (serious-condition (e) (format *error-output* "~&[hs-host] intro thread: ~a~%" e)))
         (bt:with-lock-held ((service-lock service))     ; dead intro: deregister + free the relay
           (setf (service-live service) (remove intro (service-live service))
                 (service-used service) (remove ed (service-used service) :test #'equalp)))))
     :name "hs-host intro"))))

(defun %live-count (service)
  (bt:with-lock-held ((service-lock service)) (length (service-live service))))

(defun %inflight-count (service)
  "Intro points spawned and not yet dead (a relay is reserved in USED from spawn until
   the thread exits) — counting these, not just the established ones, keeps the
   maintenance loop from over-spawning replacements while intros are still connecting."
  (bt:with-lock-held ((service-lock service)) (length (service-used service))))

(defun %maintain-intros (service)
  "Keep SERVICE at NUM-INTROS intro points, spawning replacements for any whose circuit
   died — so a service stays reachable across relay churn without a restart."
  (loop
    (dotimes (i (max 0 (- (service-num-intros service) (%inflight-count service))))
      (ignore-errors (%spawn-intro service)))
    (sleep 30)))

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

(defun handle-introduce2 (intro intro-circ identity period-num period-length)
  "Block on INTRO-CIRC for an INTRODUCE2, decrypt it (service hs-ntor), then build a
   circuit to the client's rendezvous point, send RENDEZVOUS1, and splice the client
   on as a SHA3/AES-256 hop (forward/backward keys swapped — we're the responder).
   Returns the end-to-end circuit, ready for ACCEPT-STREAM."
  (let ((cell (loop (multiple-value-bind (hop rcmd rsid len data) (circ:recv-relay intro-circ)
                      (declare (ignore hop rsid len))
                      (when (= rcmd +r-introduce2+) (return data))))))
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
           (blinded (ed:blind-public-key id-pub period-num period-length))
           (subcred (ed:subcredential id-pub blinded))
           (protoid (u:ascii->bytes +hs-ntor-protoid+))
           ;; service intro handshake: EXP(X,b) | AUTH_KEY | X | B | PROTOID
           (secret-input (u:cat (c:x25519 b xpub) auth-pub xpub bigb protoid))
           (info (u:cat (%tweak ":hs_key_expand") subcred))
           (keys (ed:shake256 (u:cat secret-input (%tweak ":hs_key_extract") info) 64))
           (enc-key (subseq keys 0 32)) (mac-key (subseq keys 32 64)))
      (unless (equalp mac-recv (%mac mac-key head))
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
             (rend-circ (hsdir:build-circuit-to rp (hsdir:relay-pool))))
        (circ:send-relay rend-circ +r-rendezvous1+ 0 (u:cat cookie ybig auth))
        ;; splice the client on as the final hop — responder, so keys are swapped
        (setf (circ:circuit-hops rend-circ)
              (append (circ:circuit-hops rend-circ)
                      (list (rc:make-hs-hop nil kb kf db df))))
        rend-circ))))

(defun accept-stream (circ)
  "On a connected rendezvous CIRC, wait for the client's RELAY_BEGIN and reply
   RELAY_CONNECTED.  Returns the stream id."
  (loop (multiple-value-bind (hop rcmd sid len data) (circ:recv-relay circ)
          (declare (ignore hop len data))
          (when (= rcmd rc:+r-begin+)
            (circ:send-relay circ rc:+r-connected+ sid #())   ; empty CONNECTED (onion service)
            (return sid)))))

(defun %pick-intro-relay (relays used)
  "Pick a fresh Stable relay (enriched, distinct from USED ed-ids) for an intro point;
   NIL if none turns up in a bounded number of tries."
  (loop repeat 40
        for r = (dir:enrich-relay (dir:pick-relay :flag "Stable" :relays relays))
        when (and (dir:relay-ntor-key r) (dir:relay-ed-id r)
                  (not (member (dir:relay-ed-id r) used :test #'equalp)))
          do (return r)))

(defun run-service (identity handler &key (num-intros *num-intro-points*)
                                          (revision (get-universal-time)))
  "Bring IDENTITY's onion service online and SERVE it.  One thread per intro point
   ESTABLISHES its own circuit (so each socket is owned by the thread that reads it —
   the SBCL socket/thread-affinity rule) and loops handling introductions, calling
   (HANDLER circ sid) per inbound end-to-end stream.  Publishes the descriptor once a
   quorum of intro points is up.  Returns (values SERVICE hsdirs-accepted)."
  (let ((service (%make-service :identity identity :handler handler :num-intros num-intros
                                :relays (hsdir:relay-pool) :lock (bt:make-lock "hs-service")
                                :revision revision)))
    ;; seed the current period so introductions can be decrypted before the first publish
    (multiple-value-bind (va cur prev params) (hsdir:parse-consensus-header (dir:fetch-consensus))
      (multiple-value-bind (tp plen srv) (hsdir:time-period-and-srv va cur prev params)
        (declare (ignore srv))
        (setf (service-period-num service) tp (service-period-length service) plen)))
    ;; the maintenance loop establishes the initial intros and keeps them at NUM-INTROS
    (setf (service-maint-thread service)
          (bt:make-thread (lambda () (%maintain-intros service)) :name "hs-host maintain"))
    ;; wait for a quorum of LIVE intros, then publish (current + next period)
    (loop repeat 120 until (>= (%live-count service) (max 1 (ceiling num-intros 2))) do (sleep 1))
    (when (zerop (%live-count service)) (error "hs-host: no intro points established"))
    (values service (%publish-all service))))

(defun republish-service (service &key revision)
  "Re-upload SERVICE's descriptor(s) for the current (and, in the overlap, next) time
   period using its currently-LIVE intro points — refreshes the descriptor without
   re-establishing intros.  Bumps the revision counter so HSDirs accept the update.
   Returns HSDirs accepted."
  (setf (service-revision service) (or revision (get-universal-time)))
  (%publish-all service))
