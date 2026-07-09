;;;; src/hs-intro.lisp — v3 onion service introduction (rend-spec-v3 §3-4).
;;;;
;;;; The client establishes a rendezvous point, then sends INTRODUCE1 (through the
;;;; intro point) carrying — encrypted to the service — the rendezvous cookie and the
;;;; client's ephemeral key for the client<->service hs-ntor handshake.  This file:
;;;; hs-ntor (client side) + the ESTABLISH_RENDEZVOUS / INTRODUCE1 cells.  Getting
;;;; INTRODUCE_ACK(status=0) proves the cell format + AUTH_KEY reach the right intro
;;;; point; the hs-ntor secret is only exercised end-to-end at the rendezvous (H5).

(defpackage #:cl-tor.hs-intro
  (:use #:cl)
  (:local-nicknames (#:u #:cl-tor.util) (#:c #:cl-tor.crypto) (#:ed #:cl-tor.ed25519)
                    (#:dir #:cl-tor.directory) (#:circ #:cl-tor.circuit) (#:link #:cl-tor.link)
                    (#:rc #:cl-tor.relay-crypto) (#:strm #:cl-tor.stream)
                    (#:hsdir #:cl-tor.hsdir) (#:desc #:cl-tor.hsdesc) (#:guard #:cl-tor.guard))
  (:export #:introduce #:rend-complete #:connect-onion #:*hs-ntor-protoid*))

(in-package #:cl-tor.hs-intro)

(defconstant +r-establish-rendezvous+ 33)
(defconstant +r-introduce1+ 34)
(defconstant +r-rendezvous2+ 37)
(defconstant +r-rendezvous-established+ 39)
(defconstant +r-introduce-ack+ 40)

(defparameter *hs-ntor-protoid* "tor-hs-ntor-curve25519-sha3-256-1")

(defun %int8be (n)
  (let ((b (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8 b) (setf (aref b (- 7 i)) (logand (ash n (* -8 i)) #xff)))))

;;; --- link specifiers <-> relay ----------------------------------------------

(defun %parse-link-specs (bytes)
  "NSPEC|{LSTYPE LSLEN LSPEC}... -> (values ip or-port rsa-id ed-id)."
  (let ((n (aref bytes 0)) (i 1) ip port rsa ed)
    (dotimes (k n (values ip port rsa ed))
      (let* ((ty (aref bytes i)) (ln (aref bytes (1+ i))) (spec (subseq bytes (+ i 2) (+ i 2 ln))))
        (case ty
          (0 (setf ip (format nil "~d.~d.~d.~d" (aref spec 0) (aref spec 1) (aref spec 2) (aref spec 3))
                   port (logior (ash (aref spec 4) 8) (aref spec 5))))
          (2 (setf rsa spec))
          (3 (setf ed spec)))
        (setf i (+ i 2 ln))))))

(defun %relay-link-specs (relay)
  "Build NSPEC|{IPv4,RSAid,ed25519} link specifiers for RELAY (for a cell payload)."
  (let* ((ip (map '(vector (unsigned-byte 8)) #'parse-integer
                  (uiop:split-string (dir:relay-ip relay) :separator ".")))
         (port (dir:relay-or-port relay))
         (v4 (u:cat ip (vector (ldb (byte 8 8) port) (ldb (byte 8 0) port))))
         (specs (list (list 0 v4) (list 2 (dir:relay-rsa-id relay)))))
    (when (dir:relay-ed-id relay) (setf specs (append specs (list (list 3 (dir:relay-ed-id relay))))))
    (apply #'u:cat (vector (length specs))
           (mapcar (lambda (ls) (u:cat (vector (first ls) (length (second ls))) (second ls))) specs))))

(defun %intro-relay (ip)
  "A relay struct for the intro-point RELAY, from its link specs + descriptor ntor key."
  (multiple-value-bind (addr port rsa ed) (%parse-link-specs (desc:intro-point-link-specs ip))
    (dir::make-relay :ip addr :or-port port :rsa-id rsa :ed-id ed
                     :ntor-key (desc:intro-point-onion-key ip))))

;;; --- circuits ---------------------------------------------------------------

(defun %build-circ-to (exit relays)
  "3-hop circuit guard|middle|EXIT (a chosen, ntor-keyed relay), entering through a
   persistent entry guard."
  (let* ((guard (guard:pick-guard relays))
         (middle (loop for m = (dir:pick-relay :relays relays)
                       until (and (not (equalp (dir:relay-rsa-id m) (dir:relay-rsa-id guard)))
                                  (not (equalp (dir:relay-rsa-id m) (dir:relay-rsa-id exit))))
                       finally (return (dir:enrich-relay m))))
         (lk (handler-case (link:connect-link guard)
               (error (e) (guard:guard-failed guard) (error e)))))   ; guard down -> drop it
    (handler-case (circ:build-circuit lk middle exit)
      (error (e) (ignore-errors (link:close-link lk)) (error e)))))

;;; --- hs-ntor (client) -------------------------------------------------------

(defun hs-ntor-client (enc-key-b auth-key subcred)
  "Client hs-ntor for INTRODUCE1 encryption.  ENC-KEY-B = service ntor enc key,
   AUTH-KEY = intro auth key, SUBCRED = subcredential.  Returns
   (values X ENC_KEY MAC_KEY x) where X is the client ephemeral pubkey."
  (multiple-value-bind (x xpub) (c:gen-x25519)
    (let* ((exp-bx (c:x25519 x enc-key-b))
           (protoid (u:ascii->bytes *hs-ntor-protoid*))
           (secret-input (u:cat exp-bx auth-key xpub enc-key-b protoid))
           (t-hsenc (u:ascii->bytes (concatenate 'string *hs-ntor-protoid* ":hs_key_extract")))
           (info (u:cat (u:ascii->bytes (concatenate 'string *hs-ntor-protoid* ":hs_key_expand"))
                        subcred))
           (keys (ed:shake256 (u:cat secret-input t-hsenc info) 64)))
      (values xpub (subseq keys 0 32) (subseq keys 32 64) x))))

;;; --- INTRODUCE1 -------------------------------------------------------------

(defun %build-introduce1 (auth-key rendezvous-cookie rp-ntor-key rp-link-specs enc-key-b subcred)
  "Assemble the INTRODUCE1 cell body.  Returns (values cell-bytes X x) so H5 can finish
   the client<->service handshake."
  (multiple-value-bind (xpub enc-key mac-key x) (hs-ntor-client enc-key-b auth-key subcred)
    (let* ((plaintext (u:cat rendezvous-cookie
                             (vector 0)                       ; N_EXTENSIONS
                             (vector 1) (u:u16be 32) rp-ntor-key   ; ONION_KEY: ntor, 32
                             rp-link-specs))                  ; NSPEC + rendezvous link specs
           (ct (c:ctr-apply (c:aes128-ctr-cipher enc-key (u:octets 16)) plaintext))  ; AES-256-CTR IV=0
           (head (u:cat (u:octets 20)                         ; LEGACY_KEY_ID = 20 zeros
                        (vector 2) (u:u16be 32) auth-key       ; AUTH_KEY ed25519
                        (vector 0)                             ; N_EXTENSIONS
                        xpub ct))                              ; ENCRYPTED = CLIENT_PK | DATA
           (mac (c:sha3-256 (u:cat (%int8be 32) mac-key head))))
      (values (u:cat head mac) xpub x))))

;;; --- driver -----------------------------------------------------------------

(defun %teardown (circ)
  "Destroy CIRC and close its link (best-effort)."
  (when circ
    (ignore-errors (circ:destroy-circuit circ))
    (ignore-errors (link:close-link (circ:circuit-link circ)))))

(defun introduce (intro-point subcred relays)
  "Establish a rendezvous point, then send INTRODUCE1 for INTRO-POINT.  Returns a plist
   with :status (INTRODUCE_ACK status, 0 = success), and — for H5 — :rend-circ,
   :cookie, :x, :xpub, :auth-key, :enc-key so the rendezvous handshake can complete.
   Circuits are torn down on failure (the intro circuit always); the caller owns the
   returned :rend-circ."
  (let ((rend-circ nil) (intro-circ nil) (done nil))
    (unwind-protect
         (let* ((rp (dir:enrich-relay (dir:pick-relay :flag "Fast" :relays relays)))
                (rp-link-specs (%relay-link-specs rp))
                (cookie (c:random-bytes 20)))
           (setf rend-circ (%build-circ-to rp relays))
           ;; ESTABLISH_RENDEZVOUS on the rendezvous circuit
           (circ:send-relay rend-circ +r-establish-rendezvous+ 0 cookie)
           (loop (multiple-value-bind (hop rcmd rsid len data) (circ:recv-relay rend-circ)
                   (declare (ignore hop rsid len data))
                   (when (= rcmd +r-rendezvous-established+) (return))))
           ;; INTRODUCE1 via a separate circuit to the intro point
           (setf intro-circ (%build-circ-to (%intro-relay intro-point) relays))
           (multiple-value-bind (cell xpub x)
               (%build-introduce1 (desc:intro-point-auth-key intro-point) cookie
                                  (dir:relay-ntor-key rp) rp-link-specs
                                  (desc:intro-point-enc-key intro-point) subcred)
             (circ:send-relay intro-circ +r-introduce1+ 0 cell)
             (let ((status
                     (loop (multiple-value-bind (hop rcmd rsid len data) (circ:recv-relay intro-circ)
                             (declare (ignore hop rsid len))
                             (when (= rcmd +r-introduce-ack+)
                               (return (logior (ash (aref data 0) 8) (aref data 1))))))))
               (setf done t)
               (list :status status :rend-circ rend-circ :cookie cookie
                     :x x :xpub xpub
                     :auth-key (desc:intro-point-auth-key intro-point)
                     :enc-key (desc:intro-point-enc-key intro-point)))))
      (%teardown intro-circ)                 ; the intro circuit is never needed past ACK
      (unless done (%teardown rend-circ)))))  ; on failure, drop the rendezvous circuit too

;;; --- rendezvous completion (H5): finish hs-ntor + splice the service hop ------

(defun %mac (key message)
  "hs-ntor MAC: SHA3-256(htonll(len(key)) | key | message)."
  (c:sha3-256 (u:cat (%int8be (length key)) key message)))

(defun await-rendezvous2 (rend-circ)
  "Block on REND-CIRC until RENDEZVOUS2 arrives; return its 64-byte payload (Y|AUTH)."
  (loop (multiple-value-bind (hop rcmd sid len data) (circ:recv-relay rend-circ)
          (declare (ignore hop sid len))
          (when (= rcmd +r-rendezvous2+) (return data)))))

(defun rend-complete (result rv2)
  "Complete the client<->service hs-ntor from the RENDEZVOUS2 payload RV2 (Y|AUTH)
   and RESULT (from INTRODUCE): verify AUTH, derive the rendezvous keys, and append
   the service as a SHA3-256/AES-256-CTR hop.  Returns the circuit, ready for streams."
  (let* ((x (getf result :x)) (xpub (getf result :xpub))
         (b (getf result :enc-key)) (auth-key (getf result :auth-key))
         (rend-circ (getf result :rend-circ))
         (y (subseq rv2 0 32)) (auth-recv (subseq rv2 32 64))
         (protoid (u:ascii->bytes *hs-ntor-protoid*))
         (tweak (lambda (s) (u:ascii->bytes (concatenate 'string *hs-ntor-protoid* s))))
         (rend-secret (u:cat (c:x25519 x y) (c:x25519 x b) auth-key b xpub y protoid))
         (ntor-key-seed (%mac rend-secret (funcall tweak ":hs_key_extract")))
         (verify (%mac rend-secret (funcall tweak ":hs_verify")))
         (auth-input (u:cat verify auth-key b y xpub protoid (u:ascii->bytes "Server")))
         (auth-mac (%mac auth-input (funcall tweak ":hs_mac"))))
    (unless (equalp auth-mac auth-recv)
      (error "hs-rend: AUTH mismatch — service handshake not authenticated"))
    (let* ((k (ed:shake256 (u:cat ntor-key-seed (funcall tweak ":hs_key_expand")) 128))
           (hop (rc:make-hs-hop nil (subseq k 64 96) (subseq k 96 128)   ; Kf Kb
                                    (subseq k 0 32) (subseq k 32 64))))   ; Df Db
      (setf (circ:circuit-hops rend-circ)
            (append (circ:circuit-hops rend-circ) (list hop)))
      rend-circ)))

;;; --- full client -------------------------------------------------------------

(defun connect-onion (onion &key (port 80) (max-tries 6) (timeout 40))
  "Connect to a v3 ONION service: fetch+decrypt its descriptor, introduce, complete
   the rendezvous, and open a stream to PORT.  A single introduce+rendezvous over the
   fragile 6-hop path is only ~2/3 reliable, so RETRY up to MAX-TRIES (cycling through
   the intro points), each bounded by TIMEOUT seconds so a dead rendezvous can't hang
   us — with 6 tries the effective success rate is ~99%.  Returns (values circuit
   stream-id)."
  (let* ((pk (hsdir:onion->pubkey onion))
         (text (dir:fetch-consensus))
         (relays (dir:consensus-relays)))
    (multiple-value-bind (va cur prev params) (hsdir:parse-consensus-header text)
      (multiple-value-bind (tp plen srv) (hsdir:time-period-and-srv va cur prev params)
        (declare (ignore srv))
        (let* ((outer (hsdir:fetch-descriptor onion))
               (inner (desc:decrypt-descriptor outer pk tp plen))
               (points (desc:intro-points inner))
               (subcred (ed:subcredential pk (ed:blind-public-key pk tp plen))))
          (when (null points) (error "connect-onion: ~a has no introduction points" onion))
          (loop for try from 1 to max-tries
                for ip = (nth (mod (1- try) (length points)) points)   ; cycle intro points
                do (let ((result nil))
                     (handler-case
                         (sb-ext:with-timeout timeout
                           (setf result (introduce ip subcred relays))
                           (unless (eql 0 (getf result :status))
                             (error "INTRODUCE_ACK status ~a" (getf result :status)))
                           (let* ((circ (rend-complete result
                                                       (await-rendezvous2 (getf result :rend-circ))))
                                  (sid (strm:begin-stream circ "" port)))
                             (return-from connect-onion (values circ sid))))
                       (serious-condition (e)
                         (%teardown (getf result :rend-circ))   ; clean up the failed try
                         (format *error-output* "  onion try ~d/~d failed: ~a~%" try max-tries e))))
                finally (error "connect-onion: ~a unreachable after ~d tries" onion max-tries)))))))
