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
                    (#:rc #:cl-tor.relay-crypto) (#:hsdir #:cl-tor.hsdir) (#:svc #:cl-tor.hsservice))
  (:export #:intro-for-relay #:establish-intro #:publish-descriptor #:publish-service
           #:service #:service-identity #:service-intros #:service-circuits
           #:service-period-num #:service-period-length
           #:*num-intro-points*))

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
  identity intros circuits period-num period-length)

(defun publish-service (identity &key (revision 1) (num-intros *num-intro-points*))
  "Bring IDENTITY's onion service online: establish NUM-INTROS introduction points,
   build + upload the descriptor.  Returns a SERVICE (intro circuits kept open) and
   the number of HSDirs that accepted the upload as a second value."
  (let* ((relays (hsdir:relay-pool))
         (consensus (dir:fetch-consensus))
         (pubkey (svc:hs-identity-pubkey identity)))
    (multiple-value-bind (va cur prev params) (hsdir:parse-consensus-header consensus)
      (multiple-value-bind (tp plen srv) (hsdir:time-period-and-srv va cur prev params)
        ;; establish intro points at distinct Stable/Fast relays
        (let ((intros '()) (circuits '()) (used '()))
          (loop for attempt from 1 to (* 6 num-intros)
                while (< (length intros) num-intros) do
            (let ((relay (dir:enrich-relay (dir:pick-relay :flag "Stable" :relays relays))))
              (when (and (dir:relay-ntor-key relay) (dir:relay-ed-id relay)
                         (not (member (dir:relay-ed-id relay) used :test #'equalp)))
                (let ((intro (intro-for-relay relay)))
                  (handler-case
                      (let ((circ (establish-intro relay intro relays)))
                        (push (dir:relay-ed-id relay) used)
                        (push intro intros) (push circ circuits))
                    (error () nil))))))          ; skip a relay that refuses; try another
          (let* ((desc (svc:build-descriptor identity tp plen revision (reverse intros)))
                 (accepted (publish-descriptor pubkey desc relays tp plen srv)))
            (values (%make-service :identity identity :intros (reverse intros)
                                   :circuits (reverse circuits) :period-num tp :period-length plen)
                    accepted)))))))
